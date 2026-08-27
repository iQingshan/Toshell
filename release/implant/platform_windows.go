//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

func getUsername() string {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = "unknown"
	}
	return username
}

func getDefaultDir() string {
	return os.Getenv("USERPROFILE")
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}

// systemRoot 返回 Windows 系统根目录（如 C:\Windows），不依赖 PATH。
func systemRoot() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("WINDIR")
	}
	if root == "" {
		root = `C:\Windows`
	}
	return root
}

// sysBin 返回 System32 目录下可执行文件的绝对路径。
// 当环境变量被清理、PATH 缺失时，exec.Command("cmd") 等会报 "不是内部或外部命令"，
// 使用绝对路径可彻底摆脱对 PATH 的依赖。
func sysBin(name string) string {
	return filepath.Join(systemRoot(), "System32", name)
}

// sysPowershell 返回 PowerShell 可执行文件的绝对路径（位于 System32 子目录）。
func sysPowershell() string {
	return filepath.Join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// buildCmd 将整条命令写入临时 .bat 文件后通过 cmd /c 执行。
// 直接 exec.Command("cmd","/c",command) 存在两个问题：
//  1. 依赖 PATH，PATH 缺失时无法启动 cmd；
//  2. Go 在 Windows 会对含空格/引号的参数自动加引号并把内部引号转义为 \"，
//     cmd 不识别 \" 转义，导致带双引号的命令（如 echo "hi"）解析报错。
//
// 写入 bat 文件可原样保留用户命令，同时规避 cmd /c 的引号陷阱。
func buildCmd(command string) (*exec.Cmd, func()) {
	noop := func() {}
	if command == "" {
		return exec.Command(sysBin("cmd.exe"), "/d", "/c", command), noop
	}
	f, err := os.CreateTemp("", "toshell_*.bat")
	if err != nil {
		// 临时文件创建失败（如无写权限）时回退为直接执行
		return exec.Command(sysBin("cmd.exe"), "/d", "/s", "/c", command), noop
	}
	// cmd 批处理按系统 ANSI 代码页（中文系统为 GBK）解析，中文命令需转 GBK 写入
	f.Write(utf8ToGBK([]byte("@echo off\r\n" + command + "\r\n")))
	f.Close()
	cleanup := func() { os.Remove(f.Name()) }
	return exec.Command(sysBin("cmd.exe"), "/d", "/c", f.Name()), cleanup
}

func executeCommand(command string, args []string) (string, int32, string) {
	var cmd *exec.Cmd

	if len(args) > 0 {
		cmd = exec.Command(command, args...)
	} else {
		c, cleanup := buildCmd(command)
		defer cleanup()
		cmd = c
	}
	cmd.Dir = os.Getenv("USERPROFILE")
	cmd.SysProcAttr = getSysProcAttr()

	out, err := cmd.CombinedOutput()
	if err != nil {
		code := int32(-1)
		if ee, ok := err.(*exec.ExitError); ok {
			code = int32(ee.ExitCode())
		}
		// 附加命令输出中的具体报错(GBK 转 UTF-8),便于定位失败原因
		errMsg := err.Error()
		if len(out) > 0 {
			errMsg = errMsg + ": " + string(gbkToUTF8(out))
		}
		return string(out), code, errMsg
	}
	return string(out), 0, ""
}

func listProcesses() (string, int32, string) {
	cmd := exec.Command(sysBin("tasklist.exe"), "/fo", "csv", "/nh")
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, err.Error()
	}

	var result strings.Builder
	result.WriteString("PID      Session Name                   Name\n")
	result.WriteString("---      ------------                   ----\n")

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			name := strings.Trim(fields[0], "\"")
			pid := strings.Trim(fields[1], "\"")
			session := strings.Trim(fields[2], "\"")
			result.WriteString(fmt.Sprintf("%-8s %-30s %s\n", pid, session, name))
		}
	}

	return result.String(), 0, ""
}

func killProcess(pid uint32) (string, int32, string) {
	cmd := exec.Command(sysBin("taskkill.exe"), "/F", "/PID", fmt.Sprintf("%d", pid))
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), -1, err.Error()
	}
	return string(out), 0, ""
}

// ─── GBK ↔ UTF-8 转换（A1）───
// 移除 golang.org/x/text/encoding/simplifiedchinese 依赖（其 GBK 字符表约 1MB+），
// 改为直接调用 kernel32.dll 的 MultiByteToWideChar / WideCharToMultiByte：
//
//	GBK(CP936) → UTF-16 → UTF-8(CP65001)   （gbkToUTF8）
//	UTF-8      → UTF-16 → GBK(CP936)       （utf8ToGBK）
//
// 系统 API 无自带字符表，体积零开销，转换结果与 x/text 等价。
var (
	procMultiByteToWideChar = resolveAPI("kernel32.dll", "MultiByteToWideChar")
	procWideCharToMultiByte = resolveAPI("kernel32.dll", "WideCharToMultiByte")
)

const (
	cpGBK  = 936   // ANSI 简体中文代码页
	cpUTF8 = 65001 // UTF-8 代码页
)

// wcharBufPool 复用 UTF-16 中间缓冲，避免每次转换重复分配（B2）。
var wcharBufPool = sync.Pool{
	New: func() interface{} { return make([]uint16, 4096) },
}

// mbToWide 将指定代码页的多字节串转换为 UTF-16。
func mbToWide(cp uint32, s []byte) []uint16 {
	if len(s) == 0 {
		return nil
	}
	n, _, _ := procMultiByteToWideChar.Call(
		uintptr(cp), 0, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s)), 0, 0)
	if n == 0 {
		return nil
	}
	buf := wcharBufPool.Get().([]uint16)
	if uintptr(len(buf)) < n {
		buf = make([]uint16, n)
	}
	r, _, _ := procMultiByteToWideChar.Call(
		uintptr(cp), 0, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s)),
		uintptr(unsafe.Pointer(&buf[0])), n)
	if r == 0 {
		wcharBufPool.Put(buf)
		return nil
	}
	out := make([]uint16, r)
	copy(out, buf[:r])
	wcharBufPool.Put(buf)
	return out
}

// wideToMb 将 UTF-16 串转换为指定代码页的多字节串。
func wideToMb(cp uint32, ws []uint16) []byte {
	if len(ws) == 0 {
		return nil
	}
	n, _, _ := procWideCharToMultiByte.Call(
		uintptr(cp), 0, uintptr(unsafe.Pointer(&ws[0])), uintptr(len(ws)), 0, 0, 0, 0)
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	r, _, _ := procWideCharToMultiByte.Call(
		uintptr(cp), 0, uintptr(unsafe.Pointer(&ws[0])), uintptr(len(ws)),
		uintptr(unsafe.Pointer(&out[0])), n, 0, 0)
	if r == 0 {
		return nil
	}
	return out[:r]
}

func gbkToUTF8(data []byte) []byte {
	if ws := mbToWide(cpGBK, data); ws != nil {
		if out := wideToMb(cpUTF8, ws); out != nil {
			return out
		}
	}
	return data
}

func utf8ToGBK(data []byte) []byte {
	if ws := mbToWide(cpUTF8, data); ws != nil {
		if out := wideToMb(cpGBK, ws); out != nil {
			return out
		}
	}
	return data
}

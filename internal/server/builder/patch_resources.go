package builder

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"toshell/internal/server/logging"
)

// ─── PE 版本资源 / 图标 / 公司信息 / 时间戳（v1.4.0 S3 第二批，静态降特征）───
//
// 为什么做：`docs/EVASION.md` §2.3 的实测结论 —— 交付的载荷**没有 `.rsrc` 节**，这是
// "非典型 PE" 最扎眼的静态信号：正常商业/系统程序几乎都带版本信息（公司名/产品名/文件
// 描述/版本/原始文件名）与图标，而我们交付的载荷一样都没有。补上它们改的是**静态特征**
// 与"看起来像正经软件"这一层；**改不了**"本机未签名 PE 在进程创建阶段就被拒"那种
// 签名/信誉层拦截（那是 `sign.go` 的代码签名要解决的问题，见 §2.5）。
//
// 顺序约束（`docs/EVASION.md` §2.4）：资源修补**必须**发生在 UPX 与代码签名**之前**
// （调用点见 `builder.go` 的 `compile`/`compileLibrary`，顺序契约见 `finalize_order.go`
// 的 `StepResourcePatch`）。UPX 之后再补资源等于把压缩结果改坏；签名之后再动一个字节
// 就是"白签"（接口仍显示 `signed=true`）。
//
// 实现口径（纯标准库，不引入任何新依赖）：
//   - 自备一份**带写入偏移**的 PE 解析器：`pecheck.go` 的 `InspectPE` 只暴露预检需要的
//     只读字段（Machine/Subsystem/节名…），拿不到"可选头起点、节表起点、CheckSum 偏移"
//     这些修补必须精确知道的 offset，所以这里另有一份解析器（只解析，不预检）。
//   - 资源目录树 **内部**偏移一律是"相对资源目录起点"的，所以构造时不需要知道最终 RVA；
//     但 `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE=2]` 与每个
//     `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` 必须是**绝对 RVA**（Windows 读资源时按
//     RVA 直接寻址），因此先把新节的 RVA 算出来，再构造资源内容。
//   - 目录项必须**按 ID 升序**：`LdrFindResource_U` 对同一层的 NumberOfIdEntries 做二分
//     查找，乱序会让 `GetFileVersionInfo` 查不到资源（构建器里按 ID 顺序生成）。
//   - 原 PE 已有可用的 `.rsrc`（DataDirectory[2] 指向该节节首、且装得下）→ **原地替换 +
//     余量补零**（节表一个字节都不动，最安全）；否则**追加一个新节**（旧节留着不引用）。
//     这个取舍写在这里也写进文档：原地替换不动节表/SizeOfImage/SizeOfHeaders，风险最低，
//     但要求原节够大；追加新节要自己把 NumberOfSections / 节头 / SizeOfImage /
//     SizeOfHeaders / CheckSum 全部算对，是本文件最容易出错的地方，故单测覆盖。
//   - `CheckSum` 一律置 0：未签名 PE 的校验和本来就允许为 0（Windows 只在加载驱动等场景
//     才校验它，用户态 EXE/DLL 不校验），而且我们刚改过字节，旧的校验和必然已经不对；
//     签名发生在最后一步，signtool/Set-AuthenticodeSignature 会自己重算。
//   - `SizeOfInitializedData` **故意不更新**：它是给链接器/加载器参考的统计字段，Windows
//     用户态加载**不读**它，改它只会多改 4 个字节而没有任何收益（也因此不写错的风险为零）。
//   - **不做 RT_MANIFEST(24)**：Go 链接器本就不写 manifest，交付的载荷一直是无 manifest 的
//     PE 且能正常加载（缺 manifest 不会让 Windows 报错，只影响"安装程序探测"这类启发式）；
//     补一份 manifest 需要额外维护 XML 与 requestedExecutionLevel 语义，写错反而会触发
//     UAC 提权提示或兼容性 shim，收益（"更像正经软件"）远小于风险。故按计划不做。
//   - 幂等/可重入：第二次修补会命中"已有 `.rsrc` 且装得下"这条分支做原地替换，节表与头部
//     一个字节都不动；时间戳用 fixed/keep 策略时两次结果**逐字节一致**（单测钉住）。

// PE 资源相关常量（只取本文件需要的部分；`pecheck.go` 已有的常量直接复用）。
const (
	// peDirResource 数据目录索引 2 = IMAGE_DIRECTORY_ENTRY_RESOURCE。
	peDirResource = 2

	// 资源类型 ID（RT_*）。只做这三类：版本信息、图标、图标组。
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16

	// 节属性：INITIALIZED_DATA | MEM_READ = 0x40000040。
	// **与 `pecheck_test.go` 里 `testScnRsrc` 的口径完全一致**（测试构造 .rsrc 用的是同一个值）。
	imageScnCntInitializedData = 0x00000040
	imageScnMemRead            = 0x40000000
	rsrcCharacteristics        = imageScnCntInitializedData | imageScnMemRead

	// IMAGE_RESOURCE_DIRECTORY_ENTRY.OffsetToData 的高位标记：1 = 指向子目录，0 = 指向数据项。
	resDirEntryIsDirectory = 0x80000000

	// VS_VERSIONINFO 相关。
	vsFixedFileInfoSize = 52 // sizeof(VS_FIXEDFILEINFO) = 13 * DWORD
	// vsSignature 显式标成 uint32：0xFEEF04BD 超过 32 位平台 int 的范围，
	// 作为无类型常量传进 fmt.Errorf 的 interface{} 会在 windows/386 上编译失败。
	vsSignature       uint32 = 0xFEEF04BD // VS_FFI_SIGNATURE
	vsStrucVersion           = 0x00010000 // VS_FFI_STRUCVERSION
	vsFileTypeApp            = 1          // VFT_APP
	vsFileTypeDLL            = 2          // VFT_DLL
	vsFileOSWindows32        = 0x00040004 // VOS_NT_WINDOWS32
	// 版本信息语言/代码页：0409 = 美式英语，04B0 = 1200 (Unicode)。
	// StringTable 的键名 "040904B0" 与 VarFileInfo\Translation 的值必须是同一个数。
	vsStringTableKey  = "040904B0"
	vsTranslationWord = 0x040904B0
	// codePageUnicode IMAGE_RESOURCE_DATA_ENTRY.CodePage：1200 = Unicode（版本信息用它，
	// 图标的 CodePage 按惯例写 0）。
	codePageUnicode = 1200

	// 图标输入的硬上限。图标只从**服务端本地路径**读取（见 PEResourceConfig.IconPath），
	// 因此这里的上限是"防手滑指到大文件"，不是对抗性限制。
	maxIconFileBytes = 1 << 20 // 1 MiB
	maxIconImages    = 64      // 单个 .ico 里的图像数上限（防畸形目录项撑爆资源节）
	// PE 规范限制节数 < 96（IMAGE_FILE_HEADER.NumberOfSections 是 WORD，但官方文档写 96）。
	peMaxSections = 96

	// resourceSectionNameLen 节名固定 8 字节（".rsrc" + 3 个 NUL）。
	resourceSectionName = ".rsrc"

	// defaultResourceTimestamp 固定时间戳基准：2024-03-15 09:00:00 UTC。
	// 选"过去的整点时间"的理由：像一次真实发布构建（真实构建时间戳总是落在工作时段附近
	// 的整点/整分，而不是 0 —— Go 链接器默认置 0 本身就是"非典型 PE"的一个小信号）；
	// 同时离现在足够远，任何"构建机时钟漂移"都不会让它变成未来时间。
	defaultResourceTimestamp = "2024-03-15T09:00:00Z"
	// 随机策略的抖动窗口：在基准之后 180 天内取值（再夹到"不晚于构建机当前时间"）。
	randomTimestampWindow = 180 * 24 * time.Hour

	// timestampModeFixed 时间戳策略名（与请求里的 resource_timestamp_mode 取值一致）。
	timestampModeFixed = "fixed"

	// ─── 中性预设（resource_preset="neutral"）的取值 ───
	//
	// 口径：**自有品牌，不冒充**。写的是本工具自己的名字，所以：
	//   - 公开仓库里不出现任何真实厂商/系统组件的字符串；
	//   - 静态上仍然满足"这份 PE 有公司名/产品名/文件描述/版权/原始文件名"这一层
	//     （这正是"非典型 PE"最扎眼的信号，见 docs/EVASION.md §2.3）；
	//   - 代价如实记录：比起冒充系统文件，它在"看起来像系统组件"上没有任何收益。
	neutralPresetCompany      = "ToShell Ops Toolkit"
	neutralPresetDescription  = "ToShell Ops Toolkit (authorized red team use)"
	neutralPresetCopyright    = "Copyright (c) ToShell Ops Toolkit"
	neutralPresetInternalName = "toshell-agent"
)

// PEResourceConfig 一次 PE 资源注入的全部输入（纯数据，来自构建请求 + 服务端配置）。
//
// **零值 = 什么都不做**：`IsZero()` 为 true 时 `PatchPEResources` 原样返回输入字节，
// 由此保证"默认构建与改动前逐字节一致、体积不变"这条硬要求。
type PEResourceConfig struct {
	// 版本信息（都是 UTF-16LE 写入，键名 ASCII）。
	CompanyName      string
	ProductName      string
	FileDescription  string
	FileVersion      string // a.b.c.d，同时用于 VS_FIXEDFILEINFO 的 FileVersionMS/LS
	ProductVersion   string // 空 = 跟随 FileVersion
	LegalCopyright   string
	OriginalFilename string
	InternalName     string

	// IconPath 服务端**本地** .ico 文件路径。空 = 不注入图标。
	//
	// 为什么只允许服务端本地路径、不接受客户端上传任意字节：把"客户端可控的内容"接到
	// "服务端读文件再写进载荷"这条链上，会同时引入两个新攻击面 —— ① 路径/内容可控 = 任意
	// 文件读取原语（拿别的文件当图标读回来，再通过构建产物把内容带回给调用方）；
	// ② 上传的"图标"完全可以不是一个 ICO，而是一个被伪装成图标的 PE/脚本，被写进 .rsrc 后
	// 反而给载荷加了一段**攻击者可控的字节**（等于把"构建服务端"变成投放通道）。
	// 本地路径 + 后缀 + 大小 + 结构四道校验把这条链收窄成"操作员在自己机器上选一个图标"。
	IconPath string

	// TimestampMode COFF 头 TimeDateStamp 策略：
	//   ""/"keep"  保持原样（默认；Go 链接器置 0）
	//   "fixed"    用固定时间（TimestampFixed，空则用 defaultResourceTimestamp）
	//   "random"   在固定基准之后的随机偏移，且**绝不晚于构建机当前时间**
	TimestampMode string
	// TimestampFixed fixed 策略的取值（RFC3339，如 2024-03-15T09:00:00Z）。
	TimestampFixed string
}

// hasVersionInfo 是否要写 RT_VERSION（8 个字段里任意一个非空）。
func (c PEResourceConfig) hasVersionInfo() bool {
	for _, s := range []string{
		c.CompanyName, c.ProductName, c.FileDescription, c.FileVersion,
		c.ProductVersion, c.LegalCopyright, c.OriginalFilename, c.InternalName,
	} {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// hasIcon 是否要写 RT_ICON + RT_GROUP_ICON。
func (c PEResourceConfig) hasIcon() bool {
	return strings.TrimSpace(c.IconPath) != ""
}

// timestampWanted 是否要覆盖 COFF 时间戳（keep/空 = 不覆盖）。
func (c PEResourceConfig) timestampWanted() bool {
	switch strings.ToLower(strings.TrimSpace(c.TimestampMode)) {
	case "", "keep":
		return false
	default:
		return true
	}
}

// IsZero 是否完全不需要动这个 PE（半点都不注入 → 调用方应当直接跳过，产物逐字节不变）。
func (c PEResourceConfig) IsZero() bool {
	return !c.hasVersionInfo() && !c.hasIcon() && !c.timestampWanted()
}

// ─── 对外入口 ────────────────────────────────────────────────────────────────

// PatchPEResources 对**已经编译好的 PE 字节**做资源/图标/时间戳后处理，返回新的字节。
//
// 只处理 Windows PE（exe/bin/dll）；调用方负责按交付格式过滤（见 shouldPatchResources）。
// 任何不合法输入都返回**中文错误**并说明原因，绝不静默跳过 —— 静默跳过会让"配了图标却没有
// 图标"变成极难察觉的哑失败。cfg.IsZero() 时原样返回输入（零行为变化）。
func PatchPEResources(data []byte, cfg PEResourceConfig) ([]byte, error) {
	if cfg.IsZero() {
		return data, nil
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("PE 资源注入：输入为空，没有可修补的 PE 字节")
	}

	m, err := parsePEPatchImage(data)
	if err != nil {
		return nil, err
	}

	// 时间戳先算：三种策略都要在这一步决定，随机策略的"不晚于当前时间"夹取也在这里。
	ts, setTS, err := resolveResourceTimestamp(cfg.TimestampMode, cfg.TimestampFixed, time.Now(), randomInt63)
	if err != nil {
		return nil, err
	}

	// 只要时间戳、不要资源：直接改 COFF 头 4 个字节，不碰节表（最小改动）。
	if !cfg.hasVersionInfo() && !cfg.hasIcon() {
		out := append([]byte(nil), data...)
		if setTS {
			binary.LittleEndian.PutUint32(out[m.timeStampOff:m.timeStampOff+4], ts)
		}
		return out, nil
	}

	// 1) 组装资源类型表（这一阶段不涉及 RVA）。
	types, err := buildResourceTypes(cfg, m.isDLL())
	if err != nil {
		return nil, err
	}

	// 2) 决定"原地替换"还是"追加新节"，并先拿到资源目录的基址 RVA。
	//    资源内容里只有 IMAGE_RESOURCE_DATA_ENTRY.OffsetToData 需要绝对 RVA，
	//    所以顺序必须是"先定 RVA → 再构造内容 → 再写入"。
	plan, err := m.planResourcePlacement(types)
	if err != nil {
		return nil, err
	}
	content := buildResourceSection(types, plan.baseRVA)

	out, err := m.applyResourcePlan(plan, content, ts, setTS)
	if err != nil {
		return nil, err
	}
	// 自检：写完之后立刻按同一份解析器回读，结构不对就报错（宁可构建失败也不交付坏 PE）。
	if err := VerifyPELayout(out); err != nil {
		return nil, fmt.Errorf("PE 资源注入后结构自检失败（这属于实现缺陷，已拒绝交付该产物）：%w", err)
	}
	return out, nil
}

// ─── PE 解析（带写入偏移） ───────────────────────────────────────────────────

// pePatchSection 节表项 + 它在文件里的头部偏移（原地修改节头时用）。
type pePatchSection struct {
	name    string
	vsize   uint32
	rva     uint32
	rawSize uint32
	rawPtr  uint32
	chars   uint32
	hdrOff  int // 该节头在文件中的偏移（40 字节）
}

// endRVA 该节在内存里占用的结束 RVA（取 VirtualSize 与 SizeOfRawData 的较大者：
// 加载器映射的大小是 max(VirtualSize, SizeOfRawData)，.bss 这类 rawSize=0 的节只有 VirtualSize）。
func (s pePatchSection) endRVA() uint32 {
	size := s.vsize
	if s.rawSize > size {
		size = s.rawSize
	}
	return s.rva + size
}

// pePatchImage 解析结果：既含只读字段，也含所有"要写回去"的偏移。
type pePatchImage struct {
	data []byte

	peOff      int
	fileHdrOff int
	optHdrOff  int

	machine     uint16
	character   uint16
	is64        bool
	numSections int
	sizeOptHdr  int

	sectionAlign uint32
	fileAlign    uint32

	secTableOff int
	sections    []pePatchSection

	dataDirOff int
	numDataDir int
	dataDirMax int // 实际可安全读写的目录项数（不超过 16，也不超过可选头/文件范围）

	// 需要写回的字段偏移。
	numSectionsOff   int
	timeStampOff     int
	sizeOfImageOff   int
	sizeOfHeadersOff int
	checkSumOff      int
	// COFF 符号表指针 / 符号数（v1.4.0 S3 第三批）：Go 链接器的 strip 产物里
	// PointerToSymbolTable 仍是非 0 而 NumberOfSymbols=0（自相矛盾的组合），
	// 处置逻辑见 pe_sections.go。这两个偏移只在这里解析一次，别处不再重算。
	symTabPtrOff int
	symCountOff  int
}

// isDLL 是否 IMAGE_FILE_DLL（决定 VS_FIXEDFILEINFO 的 dwFileType = VFT_DLL/VFT_APP）。
func (m *pePatchImage) isDLL() bool {
	return m.character&imageFileDLL != 0
}

// parsePEPatchImage 解析 PE 中与"追加/原地改写节"相关的全部字段。
// 任何越界/魔数不符/字段不合理都返回中文错误。
func parsePEPatchImage(data []byte) (*pePatchImage, error) {
	if len(data) < 0x40 {
		return nil, fmt.Errorf("PE 资源注入：载荷只有 %d 字节，连 DOS 头（64 字节）都不完整，不是有效的 PE 文件", len(data))
	}
	if binary.LittleEndian.Uint16(data[0:2]) != peDOSMagic {
		return nil, fmt.Errorf("PE 资源注入：缺少 DOS 头魔数 MZ，不是 PE 文件（shellcode/文本/压缩包一律不支持）")
	}
	// e_lfanew 用 int64 比较：32 位构建下 int 只有 32 位，畸形的大偏移会在 +24 时溢出成负数
	// 从而绕过上界检查（pecheck.go 里有同样的注释与同样的处理）。
	eLfanew64 := int64(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if eLfanew64 < 0x40 || eLfanew64+4+20 > int64(len(data)) {
		return nil, fmt.Errorf("PE 资源注入：DOS 头的 e_lfanew=0x%X 越界（文件 %d 字节），PE 头不可用", eLfanew64, len(data))
	}
	peOff := int(eLfanew64)
	if binary.LittleEndian.Uint32(data[peOff:peOff+4]) != peNTSignature {
		return nil, fmt.Errorf("PE 资源注入：偏移 0x%X 处没有 PE\\0\\0 签名，不是有效的 PE 文件", peOff)
	}

	m := &pePatchImage{
		data:       data,
		peOff:      peOff,
		fileHdrOff: peOff + 4,
		optHdrOff:  peOff + 4 + 20,
	}
	m.machine = binary.LittleEndian.Uint16(data[m.fileHdrOff : m.fileHdrOff+2])
	m.numSections = int(binary.LittleEndian.Uint16(data[m.fileHdrOff+2 : m.fileHdrOff+4]))
	m.character = binary.LittleEndian.Uint16(data[m.fileHdrOff+18 : m.fileHdrOff+20])
	m.sizeOptHdr = int(binary.LittleEndian.Uint16(data[m.fileHdrOff+16 : m.fileHdrOff+18]))
	m.numSectionsOff = m.fileHdrOff + 2
	m.timeStampOff = m.fileHdrOff + 4
	// IMAGE_FILE_HEADER：Machine(0) / NumberOfSections(2) / TimeDateStamp(4) /
	// PointerToSymbolTable(8) / NumberOfSymbols(12) / SizeOfOptionalHeader(16) / Characteristics(18)。
	m.symTabPtrOff = m.fileHdrOff + 8
	m.symCountOff = m.fileHdrOff + 12

	if m.numSections <= 0 {
		return nil, fmt.Errorf("PE 资源注入：文件头声明 0 个节，无法追加 .rsrc 节（这种 PE 本身也不可加载）")
	}
	if m.numSections > peMaxSections {
		return nil, fmt.Errorf("PE 资源注入：文件头声明 %d 个节，超过 PE 规范上限 %d，拒绝修补", m.numSections, peMaxSections)
	}
	if m.numSections+1 > peMaxSections {
		return nil, fmt.Errorf("PE 资源注入：已有 %d 个节，再追加 .rsrc 会超过 PE 规范上限 %d", m.numSections, peMaxSections)
	}

	optHdr := m.optHdrOff
	if optHdr+2 > len(data) {
		return nil, fmt.Errorf("PE 资源注入：PE 文件头之后没有可选头，文件被截断")
	}
	magic := binary.LittleEndian.Uint16(data[optHdr : optHdr+2])
	switch magic {
	case peMagic32:
		m.is64 = false
		if m.sizeOptHdr < peMinOptSize32 || optHdr+m.sizeOptHdr > len(data) {
			return nil, fmt.Errorf("PE 资源注入：PE32 可选头被截断（声明 %d 字节），无法定位数据目录与节表", m.sizeOptHdr)
		}
		m.dataDirOff = optHdr + 96
		m.dataDirMax = int(binary.LittleEndian.Uint32(data[optHdr+92 : optHdr+96]))
	case peMagic64:
		m.is64 = true
		if m.sizeOptHdr < peMinOptSize64 || optHdr+m.sizeOptHdr > len(data) {
			return nil, fmt.Errorf("PE 资源注入：PE32+ 可选头被截断（声明 %d 字节），无法定位数据目录与节表", m.sizeOptHdr)
		}
		m.dataDirOff = optHdr + 112
		m.dataDirMax = int(binary.LittleEndian.Uint32(data[optHdr+108 : optHdr+112]))
	default:
		return nil, fmt.Errorf("PE 资源注入：可选头魔数 0x%04X 既不是 PE32(0x10B) 也不是 PE32+(0x20B)，不是有效的 PE 镜像（迷你 PE / ROM 镜像不支持）", magic)
	}
	// 数据目录可安全读写的项数 = min(声明项数, 可选头剩余空间能放下的项数, 16)。
	// 这样即使遇到"可选头比标准短、数据目录项少"的 PE，也能给出准确的中文错误而不是越界写。
	if m.dataDirMax < 0 {
		m.dataDirMax = 0
	}
	if avail := (optHdr + m.sizeOptHdr - m.dataDirOff) / 8; m.dataDirMax > avail {
		m.dataDirMax = avail
	}
	if m.dataDirMax > peMaxDataDirs {
		m.dataDirMax = peMaxDataDirs
	}
	if m.dataDirMax < peDirResource+1 {
		return nil, fmt.Errorf("PE 资源注入：可选头里只放得下 %d 项数据目录，没有 IMAGE_DIRECTORY_ENTRY_RESOURCE(索引 2) 的位置，无法写入资源目录指针", m.dataDirMax)
	}

	m.sectionAlign = binary.LittleEndian.Uint32(data[optHdr+32 : optHdr+36])
	m.fileAlign = binary.LittleEndian.Uint32(data[optHdr+36 : optHdr+40])
	m.sizeOfImageOff = optHdr + 56
	m.sizeOfHeadersOff = optHdr + 60
	m.checkSumOff = optHdr + 64

	if !isPowerOfTwo(m.sectionAlign) || !isPowerOfTwo(m.fileAlign) {
		return nil, fmt.Errorf("PE 资源注入：SectionAlignment=0x%X / FileAlignment=0x%X 不是 2 的幂，节对齐无法计算，拒绝修补", m.sectionAlign, m.fileAlign)
	}
	if m.sectionAlign < m.fileAlign {
		return nil, fmt.Errorf("PE 资源注入：SectionAlignment(0x%X) 小于 FileAlignment(0x%X)，镜像布局非法", m.sectionAlign, m.fileAlign)
	}

	m.secTableOff = optHdr + m.sizeOptHdr
	if m.secTableOff+peSectionHeaderSize*m.numSections > len(data) {
		return nil, fmt.Errorf("PE 资源注入：节表越界 —— 声明 %d 个节（需 %d 字节），但节表起点 0x%X 之后只剩 %d 字节，文件被截断",
			m.numSections, peSectionHeaderSize*m.numSections, m.secTableOff, len(data)-m.secTableOff)
	}

	for i := 0; i < m.numSections; i++ {
		off := m.secTableOff + i*peSectionHeaderSize
		sec := pePatchSection{
			name:    strings.TrimRight(string(data[off:off+peSectionNameLen]), "\x00"),
			vsize:   binary.LittleEndian.Uint32(data[off+8 : off+12]),
			rva:     binary.LittleEndian.Uint32(data[off+12 : off+16]),
			rawSize: binary.LittleEndian.Uint32(data[off+16 : off+20]),
			rawPtr:  binary.LittleEndian.Uint32(data[off+20 : off+24]),
			chars:   binary.LittleEndian.Uint32(data[off+36 : off+40]),
			hdrOff:  off,
		}
		if sec.rawSize > 0 {
			end := int64(sec.rawPtr) + int64(sec.rawSize)
			if end > int64(len(data)) {
				return nil, fmt.Errorf("PE 资源注入：节 %q 的原始数据越界（偏移 0x%X + 大小 0x%X > 文件 %d 字节）",
					sec.name, sec.rawPtr, sec.rawSize, len(data))
			}
		}
		m.sections = append(m.sections, sec)
	}

	sizeOfHeaders := binary.LittleEndian.Uint32(data[m.sizeOfHeadersOff : m.sizeOfHeadersOff+4])
	if int64(sizeOfHeaders) < int64(m.secTableOff)+int64(peSectionHeaderSize*m.numSections) {
		return nil, fmt.Errorf("PE 资源注入：SizeOfHeaders=0x%X 小于节表末尾 0x%X，头部布局非法",
			sizeOfHeaders, m.secTableOff+peSectionHeaderSize*m.numSections)
	}
	return m, nil
}

// isPowerOfTwo 判断对齐值是否为 2 的幂（0 不算）。
func isPowerOfTwo(v uint32) bool {
	return v != 0 && v&(v-1) == 0
}

// alignUp 向上对齐到 align（align 必须是 2 的幂）。
func alignUp(v, align uint32) uint32 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// dataDir 读数据目录项（返回 RVA 与 Size）。
func (m *pePatchImage) dataDir(idx int) (uint32, uint32) {
	if idx < 0 || idx >= m.dataDirMax || m.dataDirOff+idx*8+8 > len(m.data) {
		return 0, 0
	}
	off := m.dataDirOff + idx*8
	return binary.LittleEndian.Uint32(m.data[off : off+4]), binary.LittleEndian.Uint32(m.data[off+4 : off+8])
}

// rvaSection 找 rva 落在哪个节里（用 max(VirtualSize, SizeOfRawData) 作节长度）。
func (m *pePatchImage) rvaSection(rva uint32) (int, bool) {
	for i, s := range m.sections {
		if rva >= s.rva && rva < s.endRVA() {
			return i, true
		}
	}
	return -1, false
}

// maxSectionEndRVA 所有节在内存里占用的最大结束 RVA。
func (m *pePatchImage) maxSectionEndRVA() uint32 {
	var end uint32
	for _, s := range m.sections {
		if e := s.endRVA(); e > end {
			end = e
		}
	}
	return end
}

// ─── 放置方案：原地替换 or 追加新节 ─────────────────────────────────────────

// resourcePlacement 一次修补对 .rsrc 的落位方案。
type resourcePlacement struct {
	// inPlace=true：复用已有 .rsrc 节（只改内容，不动节表/头部/SizeOfImage）。
	inPlace bool
	// secIndex 原地替换时的目标节下标。
	secIndex int
	// baseRVA 资源目录的起始 RVA（原地 = 原节 RVA；追加 = 新节 RVA）。
	baseRVA uint32
	// contentLen 新内容长度（用于容量判断与 DataDirectory.Size）。
	contentLen uint32
	// 追加分支的中间结果（原地分支为零值）。
	newSection pePatchSection
	newRawPtr  uint32
	newRawSize uint32
	newSecEnd  int
	// orphanSecIndex 被"抛弃"的旧 .rsrc 节下标（-1 = 没有）。
	//
	// 为什么需要它：旧 .rsrc 装不下时要追加新节并把数据目录指过去，旧节就没人引用了。
	// 但它的**旧资源字节还留在文件里**（旧公司名/旧图标），一旦两次构建写的是不同身份，
	// 文件里就同时存在两份互相矛盾的公司名 —— 既是静态特征残留，也是取证时"被人改过"的
	// 直接证据。所以追加分支会把旧节的原始数据整段清零（内容已无引用，清零不会影响加载）。
	orphanSecIndex int
}

// planResourcePlacement 决定资源内容放哪儿，并返回需要的全部布局参数。
//
// 优先级：
//  1. DataDirectory[2] 指向一个名字是 `.rsrc`、且"资源目录正好从节首开始"的节，并且
//     新内容 ≤ min(VirtualSize, SizeOfRawData) → **原地替换**（最安全：节表一个字节不动）。
//     注意必须要求 ≤ SizeOfRawData：文件里只有 raw 数据会被加载器映射进内存，VirtualSize
//     里超出 RawSize 的部分在内存中是零填，写到那里等于数据丢失。
//  2. 否则**追加一个新 `.rsrc` 节**并把 DataDirectory[2] 指向它（旧节留着不引用）。
//     取舍写进文档：追加会改 NumberOfSections/节表/SizeOfImage/头部，必须自己算对。
func (m *pePatchImage) planResourcePlacement(types []resDirType) (resourcePlacement, error) {
	// 先按"最坏情况"算一个内容长度（构造内容时用同一个函数与同一个 baseRVA，长度不会变），
	// 这里只需要长度，故先用 0 做 baseRVA 试算一次。
	probeLen := uint32(len(buildResourceSection(types, 0)))

	orphanSec := -1
	if rva, size := m.dataDir(peDirResource); rva != 0 && size != 0 {
		if idx, ok := m.rvaSection(rva); ok {
			sec := m.sections[idx]
			if sec.name == resourceSectionName && sec.rva == rva {
				capBytes := sec.rawSize
				if sec.vsize < capBytes {
					capBytes = sec.vsize
				}
				if probeLen <= capBytes {
					return resourcePlacement{inPlace: true, secIndex: idx, baseRVA: sec.rva, contentLen: probeLen}, nil
				}
				// 装不下：这个节将被抛弃，追加新节时把它清零（见 orphanSecIndex 注释）。
				orphanSec = idx
			}
		}
	}

	// 追加分支。新节 RVA 取"所有节结束 RVA 与 SizeOfImage 的较大者"再按 SectionAlignment 对齐：
	// 这样既不会与任何已有节的内存区间重叠，也不会落进 SizeOfImage 已经覆盖的区间里。
	sizeOfImage := binary.LittleEndian.Uint32(m.data[m.sizeOfImageOff : m.sizeOfImageOff+4])
	base := m.maxSectionEndRVA()
	if sizeOfImage > base {
		base = sizeOfImage
	}
	newRVA := alignUp(base, m.sectionAlign)
	if newRVA < base {
		return resourcePlacement{}, fmt.Errorf("PE 资源注入：新节 RVA 计算溢出（base=0x%X，SectionAlignment=0x%X）", base, m.sectionAlign)
	}

	contentLen := uint32(len(buildResourceSection(types, newRVA)))
	newRawSize := alignUp(contentLen, m.fileAlign)
	newRawPtr := alignUp(uint32(len(m.data)), m.fileAlign)
	newSecEnd64 := int64(newRawPtr) + int64(newRawSize)
	if newSecEnd64 > int64(^uint32(0)) {
		return resourcePlacement{}, fmt.Errorf("PE 资源注入：追加 .rsrc 后文件大小会超过 4 GiB（0x%X 字节），拒绝修补", newSecEnd64)
	}

	// 节表要能多放一个 40 字节的节头：要么头部本来就有余量，要么能安全地扩张 SizeOfHeaders。
	secTableEnd := int64(m.secTableOff) + int64(peSectionHeaderSize)*int64(m.numSections+1)
	sizeOfHeaders := int64(binary.LittleEndian.Uint32(m.data[m.sizeOfHeadersOff : m.sizeOfHeadersOff+4]))
	firstRVA := m.sections[0].rva
	for _, s := range m.sections {
		if s.rva < firstRVA {
			firstRVA = s.rva
		}
	}
	if secTableEnd > sizeOfHeaders {
		// 头部必须扩张到能装下新节表（按 FileAlignment 对齐）。
		want := int64(alignUp(uint32(secTableEnd), m.fileAlign))
		// ① 不能与第一个节的**虚拟地址**重叠：头部映射在 RVA 0..SizeOfHeaders-1，
		//    节都从 SectionAlignment 对齐的 RVA 开始，正常 PE 绝不会冲突，冲突就是畸形文件。
		if uint32(want) > firstRVA {
			return resourcePlacement{}, fmt.Errorf("PE 资源注入：扩张后的 SizeOfHeaders=0x%X 会覆盖第一个节的 RVA 0x%X，拒绝修补", want, firstRVA)
		}
		// ② 更不能把节表写进某个节的**原始数据**里（那会直接改坏代码/数据）。头部区域
		//    [0, SizeOfHeaders) 原本必须落在所有节的 PointerToRawData 之前；一旦要扩张到
		//    某个节的 raw 数据上，就地覆写等于破坏载荷，此时只能明确报错（不做"整文件重排"
		//    这种高风险操作 —— 那要改写每个节的 PointerToRawData，收益远小于风险）。
		minRawPtr := int64(-1)
		for _, s := range m.sections {
			if s.rawSize == 0 {
				continue
			}
			if minRawPtr < 0 || int64(s.rawPtr) < minRawPtr {
				minRawPtr = int64(s.rawPtr)
			}
		}
		if minRawPtr >= 0 && secTableEnd > minRawPtr {
			return resourcePlacement{}, fmt.Errorf(
				"PE 资源注入：头部空间不足 —— 节表要从 0x%X 扩到 0x%X，而第一个节的原始数据从 0x%X 开始，"+
					"继续扩张会覆写节数据。该 PE 的节太多（%d 个）导致头部没有余量，请减少节数或改用其他方式注入资源",
				sizeOfHeaders, secTableEnd, minRawPtr, m.numSections)
		}
		sizeOfHeaders = want
	}

	newSec := pePatchSection{
		name:    resourceSectionName,
		vsize:   contentLen,
		rva:     newRVA,
		rawSize: newRawSize,
		rawPtr:  newRawPtr,
		chars:   rsrcCharacteristics,
		hdrOff:  m.secTableOff + peSectionHeaderSize*m.numSections,
	}
	return resourcePlacement{
		inPlace:        false,
		baseRVA:        newRVA,
		contentLen:     contentLen,
		newSection:     newSec,
		newRawPtr:      newRawPtr,
		newRawSize:     newRawSize,
		newSecEnd:      int(newSecEnd64),
		orphanSecIndex: orphanSec,
	}, nil
}

// applyResourcePlan 把资源内容写进 PE（原地替换或追加新节），并同步所有节表/头字段。
func (m *pePatchImage) applyResourcePlan(plan resourcePlacement, content []byte, ts uint32, setTS bool) ([]byte, error) {
	if uint32(len(content)) != plan.contentLen {
		return nil, fmt.Errorf("PE 资源注入：内部错误 —— 资源内容长度 %d 与规划长度 %d 不一致（这一条不该出现，属实现缺陷）",
			len(content), plan.contentLen)
	}

	if plan.inPlace {
		out := append([]byte(nil), m.data...)
		sec := m.sections[plan.secIndex]
		start := int(sec.rawPtr) + int(plan.baseRVA-sec.rva)
		if start < 0 || start+int(sec.rawSize) > len(out) {
			return nil, fmt.Errorf("PE 资源注入：原地替换越界（偏移 0x%X + 原始大小 0x%X 超出文件）", start, sec.rawSize)
		}
		// 先整段清零再写新内容：保证"旧资源比新资源长"时尾部不会残留上一次的字节
		// （残留的旧目录项/字符串是实打实的静态特征漏点，也解释了"补零"这条要求）。
		for i := start; i < start+int(sec.rawSize); i++ {
			out[i] = 0
		}
		copy(out[start:start+len(content)], content)

		// 数据目录指向同一个节首（RVA 没变），只更新 Size。
		m.writeDataDir(out, peDirResource, plan.baseRVA, plan.contentLen)
		// 校验和必然已失效：置 0（未签名 PE 允许为 0）。
		binary.LittleEndian.PutUint32(out[m.checkSumOff:m.checkSumOff+4], 0)
		if setTS {
			binary.LittleEndian.PutUint32(out[m.timeStampOff:m.timeStampOff+4], ts)
		}
		return out, nil
	}

	// 追加新节：先按最终大小扩容（中间用 0 填充），再依次写节头、节表计数、数据目录、
	// SizeOfImage、SizeOfHeaders、CheckSum。
	if plan.newSecEnd < len(m.data) {
		return nil, fmt.Errorf("PE 资源注入：追加节后的大小 0x%X 小于原文件 %d 字节，规划结果异常", plan.newSecEnd, len(m.data))
	}
	out := make([]byte, plan.newSecEnd)
	copy(out, m.data)

	// 节名固定 8 字节（".rsrc" + 3 个 NUL）。
	nameField := make([]byte, peSectionNameLen)
	copy(nameField, plan.newSection.name)
	copy(out[plan.newSection.hdrOff:plan.newSection.hdrOff+peSectionNameLen], nameField)

	// 被抛弃的旧 .rsrc：把它的原始数据整段清零，避免文件里同时留着两份互相矛盾的公司名
	// （旧节已无人引用，清零不影响加载；见 orphanSecIndex 注释）。
	if plan.orphanSecIndex >= 0 {
		old := m.sections[plan.orphanSecIndex]
		start, end := int(old.rawPtr), int(old.rawPtr)+int(old.rawSize)
		if old.rawSize > 0 && start >= 0 && end <= len(out) {
			for i := start; i < end; i++ {
				out[i] = 0
			}
		}
	}

	sec := plan.newSection
	writeU32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(out[off:off+4], v) }
	writeU32(sec.hdrOff+8, sec.vsize)
	writeU32(sec.hdrOff+12, sec.rva)
	writeU32(sec.hdrOff+16, sec.rawSize)
	writeU32(sec.hdrOff+20, sec.rawPtr)
	writeU32(sec.hdrOff+24, 0)                                         // PointerToRelocations
	writeU32(sec.hdrOff+28, 0)                                         // PointerToLinenumbers
	binary.LittleEndian.PutUint16(out[sec.hdrOff+32:sec.hdrOff+34], 0) // NumberOfRelocations
	binary.LittleEndian.PutUint16(out[sec.hdrOff+34:sec.hdrOff+36], 0) // NumberOfLinenumbers
	writeU32(sec.hdrOff+36, sec.chars)

	copy(out[int(sec.rawPtr):], content)

	binary.LittleEndian.PutUint16(out[m.numSectionsOff:m.numSectionsOff+2], uint16(m.numSections+1))
	m.writeDataDir(out, peDirResource, sec.rva, plan.contentLen)

	// SizeOfImage 必须覆盖新节的结束 RVA（按 SectionAlignment 对齐）。
	oldSizeOfImage := binary.LittleEndian.Uint32(out[m.sizeOfImageOff : m.sizeOfImageOff+4])
	newSizeOfImage := alignUp(sec.rva+sec.vsize, m.sectionAlign)
	if newSizeOfImage < oldSizeOfImage {
		newSizeOfImage = oldSizeOfImage
	}
	writeU32(m.sizeOfImageOff, newSizeOfImage)

	// SizeOfHeaders：只有节表越界时才需要跟着改（改过的值在 planResourcePlacement 里校验过）。
	secTableEnd := uint32(m.secTableOff + peSectionHeaderSize*(m.numSections+1))
	oldSizeOfHeaders := binary.LittleEndian.Uint32(out[m.sizeOfHeadersOff : m.sizeOfHeadersOff+4])
	if want := alignUp(secTableEnd, m.fileAlign); want > oldSizeOfHeaders {
		writeU32(m.sizeOfHeadersOff, want)
	}

	// 校验和置 0（见文件头注释：未签名 PE 允许为 0，且旧校验和已失效）。
	writeU32(m.checkSumOff, 0)
	if setTS {
		writeU32(m.timeStampOff, ts)
	}
	return out, nil
}

// writeDataDir 写一个数据目录项（RVA + Size）。越界静默忽略不可能发生（解析时已校验），
// 这里仍做一次防御性检查，避免畸形可选头导致 panic。
func (m *pePatchImage) writeDataDir(out []byte, idx int, rva, size uint32) {
	off := m.dataDirOff + idx*8
	if off < 0 || off+8 > len(out) {
		return
	}
	binary.LittleEndian.PutUint32(out[off:off+4], rva)
	binary.LittleEndian.PutUint32(out[off+4:off+8], size)
}

// ─── 资源类型表构造（版本信息 + 图标） ──────────────────────────────────────

// resDirEntryData 一个叶子资源（类型 → ID → 语言 → 数据）。
type resDirEntryData struct {
	id       uint32
	data     []byte
	codePage uint32
}

// resDirType 一层资源类型（RT_*）及其下的 ID 条目（**必须按 id 升序**，见文件头注释）。
type resDirType struct {
	id      uint32
	entries []resDirEntryData
}

// buildResourceTypes 把配置变成一个按类型升序排列的资源类型表。
// 只做版本信息与图标；图标从服务端本地 .ico 文件读（校验见 loadIconImages）。
func buildResourceTypes(cfg PEResourceConfig, isDLL bool) ([]resDirType, error) {
	types := make([]resDirType, 0, 3)

	// 图标在前（ID 小的类型排在前面，符合"目录项按 ID 升序"的约定，也符合常见 PE 的排布）。
	if cfg.hasIcon() {
		images, err := loadIconImages(cfg.IconPath)
		if err != nil {
			return nil, err
		}
		iconEntries := make([]resDirEntryData, 0, len(images))
		groupEntries := make([]byte, 0, 6+len(images)*14)
		groupEntries = append(groupEntries, 0, 0) // idReserved
		groupEntries = append(groupEntries, 1, 0) // idType = 1 (IMAGE_ICON)
		groupEntries = append(groupEntries, byte(len(images)), byte(len(images)>>8))
		// 相同图像（ICO 里两个目录项指向同一 offset/size，常见于共用调色板数据的多尺寸图标）
		// 只写一份 RT_ICON，由 nID 指过来；但 **GRPICONDIR 的条目一个不少**。
		iconIDByImage := make(map[[2]int64]uint32, len(images))
		for _, img := range images {
			key := [2]int64{img.offset, img.size}
			iconID, ok := iconIDByImage[key]
			if !ok {
				iconID = uint32(len(iconEntries) + 1)
				iconEntries = append(iconEntries, resDirEntryData{id: iconID, data: img.data})
				iconIDByImage[key] = iconID
			}
			// GRPICONDIRENTRY：14 字节，nID 指向对应的 RT_ICON。
			e := make([]byte, 14)
			e[0] = img.width
			e[1] = img.height
			e[2] = img.colorCount
			e[3] = 0 // bReserved
			binary.LittleEndian.PutUint16(e[4:6], img.planes)
			binary.LittleEndian.PutUint16(e[6:8], img.bitCount)
			binary.LittleEndian.PutUint32(e[8:12], uint32(len(img.data)))
			binary.LittleEndian.PutUint16(e[12:14], uint16(iconID))
			groupEntries = append(groupEntries, e...)
		}
		types = append(types, resDirType{id: rtIcon, entries: iconEntries})
		types = append(types, resDirType{id: rtGroupIcon, entries: []resDirEntryData{{id: 1, data: groupEntries}}})
	}

	if cfg.hasVersionInfo() {
		blob, err := buildVersionResource(cfg, isDLL)
		if err != nil {
			return nil, err
		}
		types = append(types, resDirType{id: rtVersion, entries: []resDirEntryData{{
			id: 1, data: blob, codePage: codePageUnicode,
		}}})
	}

	if len(types) == 0 {
		return nil, fmt.Errorf("PE 资源注入：没有可写入的资源（既没有版本信息也没有图标）")
	}
	return types, nil
}

// buildResourceSection 序列化整棵资源目录树。
//
// 布局（所有偏移都相对资源目录起点，因此与最终 RVA 无关）：
//
//	[根目录头 + 类型项] → [每个类型的子目录头 + ID 项] → [每个 ID 的语言目录头 + 语言项]
//	→ [数据项 IMAGE_RESOURCE_DATA_ENTRY] → [数据体（4 字节对齐）]
//
// baseRVA 只用于填 IMAGE_RESOURCE_DATA_ENTRY.OffsetToData（必须是绝对 RVA）。
func buildResourceSection(types []resDirType, baseRVA uint32) []byte {
	off := uint32(16 + 8*len(types))
	typeDirOff := make([]uint32, len(types))
	nameDirOff := make([][]uint32, len(types))
	dataEntryOff := make([][]uint32, len(types))
	dataOff := make([][]uint32, len(types))

	for i, t := range types {
		typeDirOff[i] = off
		off += uint32(16 + 8*len(t.entries))
	}
	for i, t := range types {
		nameDirOff[i] = make([]uint32, len(t.entries))
		for j := range t.entries {
			nameDirOff[i][j] = off
			off += 16 + 8 // 语言目录：一个头 + 一个语言项
		}
	}
	for i, t := range types {
		dataEntryOff[i] = make([]uint32, len(t.entries))
		for j := range t.entries {
			dataEntryOff[i][j] = off
			off += 16
		}
	}
	for i, t := range types {
		dataOff[i] = make([]uint32, len(t.entries))
		for j, e := range t.entries {
			off = alignUp(off, 4)
			dataOff[i][j] = off
			off += uint32(len(e.data))
		}
	}
	total := alignUp(off, 4)
	buf := make([]byte, total)

	// 根目录：NumberOfIdEntries = 类型数，类型项按 ID 升序（调用方保证）。
	binary.LittleEndian.PutUint16(buf[14:16], uint16(len(types)))
	for i, t := range types {
		ep := 16 + i*8
		binary.LittleEndian.PutUint32(buf[ep:ep+4], t.id)
		binary.LittleEndian.PutUint32(buf[ep+4:ep+8], typeDirOff[i]|resDirEntryIsDirectory)

		d := int(typeDirOff[i])
		binary.LittleEndian.PutUint16(buf[d+14:d+16], uint16(len(t.entries)))
		for j := range t.entries {
			e := t.entries[j]
			ep2 := d + 16 + j*8
			binary.LittleEndian.PutUint32(buf[ep2:ep2+4], e.id)
			binary.LittleEndian.PutUint32(buf[ep2+4:ep2+8], nameDirOff[i][j]|resDirEntryIsDirectory)

			ld := int(nameDirOff[i][j])
			binary.LittleEndian.PutUint16(buf[ld+14:ld+16], 1) // NumberOfIdEntries = 1（只有一个语言）
			binary.LittleEndian.PutUint32(buf[ld+16:ld+20], 0x0409)
			binary.LittleEndian.PutUint32(buf[ld+20:ld+24], dataEntryOff[i][j])

			de := int(dataEntryOff[i][j])
			binary.LittleEndian.PutUint32(buf[de:de+4], baseRVA+dataOff[i][j])
			binary.LittleEndian.PutUint32(buf[de+4:de+8], uint32(len(e.data)))
			binary.LittleEndian.PutUint32(buf[de+8:de+12], e.codePage)
			binary.LittleEndian.PutUint32(buf[de+12:de+16], 0) // Reserved
			copy(buf[int(dataOff[i][j]):], e.data)
		}
	}
	return buf
}

// ─── VS_VERSIONINFO ─────────────────────────────────────────────────────────

// buildVersionResource 构造完整 VS_VERSIONINFO：
//
//	VS_VERSION_INFO (VS_FIXEDFILEINFO + StringFileInfo/040904B0/* + VarFileInfo/Translation)
//
// 所有字符串都是 UTF-16LE，键名是 ASCII 的 UTF-16LE。
func buildVersionResource(cfg PEResourceConfig, isDLL bool) ([]byte, error) {
	fileVer := strings.TrimSpace(cfg.FileVersion)
	if fileVer == "" {
		fileVer = "1.0.0.0"
	}
	prodVer := strings.TrimSpace(cfg.ProductVersion)
	if prodVer == "" {
		prodVer = fileVer
	}
	fileMS, fileLS, err := parseVersionQuad(fileVer)
	if err != nil {
		return nil, fmt.Errorf("PE 资源注入：文件版本不合法：%w", err)
	}
	prodMS, prodLS, err := parseVersionQuad(prodVer)
	if err != nil {
		return nil, fmt.Errorf("PE 资源注入：产品版本不合法：%w", err)
	}

	fileType := uint32(vsFileTypeApp)
	if isDLL {
		fileType = vsFileTypeDLL
	}

	// VS_FIXEDFILEINFO（13 个 DWORD，MAKELONG(MS, LS) 语义）：
	//   dwFileVersionMS = (主版本 << 16) | 次版本，dwFileVersionLS = (构建号 << 16) | 修订号。
	fixed := make([]byte, vsFixedFileInfoSize)
	put := func(i int, v uint32) { binary.LittleEndian.PutUint32(fixed[i*4:i*4+4], v) }
	put(0, vsSignature)
	put(1, vsStrucVersion)
	put(2, fileMS)
	put(3, fileLS)
	put(4, prodMS)
	put(5, prodLS)
	put(6, 0x3F) // dwFileFlagsMask：我们只声明已知的 DEBUG/PRERELEASE 位
	put(7, 0)    // dwFileFlags：正式发布版
	put(8, vsFileOSWindows32)
	put(9, fileType)
	put(10, 0) // dwFileSubtype
	put(11, 0) // dwFileDateMS
	put(12, 0) // dwFileDateLS

	// StringFileInfo 下的字符串（只写非空字段；FileVersion/ProductVersion 恒有值）。
	strs := []struct{ key, val string }{
		{"CompanyName", strings.TrimSpace(cfg.CompanyName)},
		{"FileDescription", strings.TrimSpace(cfg.FileDescription)},
		{"FileVersion", fileVer},
		{"InternalName", strings.TrimSpace(cfg.InternalName)},
		{"LegalCopyright", strings.TrimSpace(cfg.LegalCopyright)},
		{"OriginalFilename", strings.TrimSpace(cfg.OriginalFilename)},
		{"ProductName", strings.TrimSpace(cfg.ProductName)},
		{"ProductVersion", prodVer},
	}
	var stringBlocks []byte
	for _, s := range strs {
		if s.val == "" {
			continue
		}
		stringBlocks = append(stringBlocks, vsBlock(s.key, len(utf16.Encode([]rune(s.val)))+1, 1, utf16z(s.val), nil)...)
	}
	stringTable := vsBlock(vsStringTableKey, 0, 1, nil, stringBlocks)
	stringFileInfo := vsBlock("StringFileInfo", 0, 1, nil, stringTable)

	// VarFileInfo\Translation = DWORD 0x040904B0（语言 0x0409 + 代码页 0x04B0）。
	trans := make([]byte, 4)
	binary.LittleEndian.PutUint32(trans, vsTranslationWord)
	varBlock := vsBlock("Translation", 4, 0, trans, nil)
	varFileInfo := vsBlock("VarFileInfo", 0, 1, nil, varBlock)

	children := append(append([]byte{}, stringFileInfo...), varFileInfo...)
	root := vsBlock("VS_VERSION_INFO", vsFixedFileInfoSize, 0, fixed, children)
	return root, nil
}

// vsBlock 构造一个 VS_VERSIONINFO 结构块：
//
//	WORD wLength, WORD wValueLength, WORD wType, WCHAR szKey\0, [padding], Value, [padding], Children
//
// 各段之间按 4 字节对齐（VS_VERSIONINFO 的硬要求），wLength 覆盖整块（含子块）。
func vsBlock(key string, valueLen int, wType uint16, value, children []byte) []byte {
	b := make([]byte, 6, 6+len(key)*2+len(value)+len(children)+8)
	b = append(b, utf16z(key)...)
	b = padTo4(b)
	b = append(b, value...)
	b = padTo4(b)
	b = append(b, children...)
	// wLength 必须是 DWORD 对齐后的整块长度（Windows 按 wLength 步进到下一个同层块）。
	b = padTo4(b)
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:4], uint16(valueLen))
	binary.LittleEndian.PutUint16(b[4:6], wType)
	return b
}

// padTo4 把切片补到 4 字节对齐（返回新切片）。
func padTo4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// utf16z 把字符串编码成以 NUL 结尾的 UTF-16LE 字节（不额外对齐）。
func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, (len(u)+1)*2)
	for _, v := range u {
		out = append(out, byte(v), byte(v>>8))
	}
	return append(out, 0, 0)
}

// parseVersionQuad 解析 a.b.c.d（1~4 段，每段 0~65535），返回 MAKELONG(MS, LS) 的两半。
func parseVersionQuad(s string) (uint32, uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("版本号为空（要求 a.b.c.d 形式，如 1.4.0.0）")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return 0, 0, fmt.Errorf("版本号 %q 有 %d 段，最多 4 段（a.b.c.d）", s, len(parts))
	}
	var v [4]uint16
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("版本号 %q 的第 %d 段 %q 不是 0~65535 的十进制整数", s, i+1, p)
		}
		v[i] = uint16(n)
	}
	ms := uint32(v[0])<<16 | uint32(v[1])
	ls := uint32(v[2])<<16 | uint32(v[3])
	return ms, ls, nil
}

// ─── ICO 解析 ───────────────────────────────────────────────────────────────

// resIconImage 一个 ICO 目录项 + 它的原始图像字节（PNG 压缩项按 IMAGE_ICON 原样搬运，不解码）。
//
// offset/size 保留 ICO 里的真实位置：多个目录项指向同一份图像时用它去重
// （去重只影响 RT_ICON 的份数，**不影响** GRPICONDIR 的条目数 —— 尺寸清单必须完整，
// 否则 Windows 按尺寸挑图标时会少一个可选尺寸）。
type resIconImage struct {
	width      byte // 0 表示 256（ICO 格式约定）
	height     byte
	colorCount byte
	planes     uint16
	bitCount   uint16
	offset     int64
	size       int64
	data       []byte
}

// loadIconImages 校验并读取操作员指定的本地 .ico 文件。四道校验（后缀 / 存在 / 大小 / 结构）
// 缺一不可，理由见 PEResourceConfig.IconPath 的注释。
func loadIconImages(path string) ([]resIconImage, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, nil
	}
	// 校验顺序：存在 → 是文件 → 后缀 → 大小。先 stat 再判后缀，是为了让"指到一个目录/
	// 不存在的路径"报出它真正的问题，而不是一律甩一句"后缀不是 .ico"。
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("PE 资源注入：图标文件不可读（%s）：%v。"+
			"图标只从**服务端本地路径**读取（配置 implant.icon_path 或请求字段 resource_icon_path），不接受客户端上传的字节", p, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("PE 资源注入：图标路径 %q 是一个目录，需要具体的 .ico 文件", p)
	}
	if !strings.EqualFold(filepath.Ext(p), ".ico") {
		return nil, fmt.Errorf("PE 资源注入：图标文件 %q 的后缀不是 .ico（只接受真正的图标文件；"+
			"把一个 EXE/DLL/脚本改后缀当图标既读不出结构，也会把任意字节塞进载荷的 .rsrc）", p)
	}
	if info.Size() <= 0 {
		return nil, fmt.Errorf("PE 资源注入：图标文件 %q 是空文件", p)
	}
	if info.Size() > maxIconFileBytes {
		return nil, fmt.Errorf("PE 资源注入：图标文件 %q 有 %d 字节，超过上限 %d 字节（1 MiB）——"+
			"图标只是外观信息，不该把产物撑大，请先裁剪多余尺寸", p, info.Size(), maxIconFileBytes)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("PE 资源注入：读取图标文件 %q 失败：%v", p, err)
	}
	return parseICOImages(raw)
}

// parseICOImages 解析 ICO 文件（ICONDIR + ICONDIRENTRY[]）。
// 不解码图像本身：PNG 压缩的项按 IMAGE_ICON 原样搬运（Windows 从 Vista 起原生支持
// PNG 压缩的图标项），BMP 项（BITMAPINFOHEADER + XOR/AND 掩码）同样原样搬运。
func parseICOImages(raw []byte) ([]resIconImage, error) {
	if len(raw) < 6 {
		return nil, fmt.Errorf("PE 资源注入：图标文件只有 %d 字节，连 ICONDIR 头（6 字节）都不完整", len(raw))
	}
	if reserved := binary.LittleEndian.Uint16(raw[0:2]); reserved != 0 {
		return nil, fmt.Errorf("PE 资源注入：图标文件头保留字段=%d（应为 0），不是标准 .ico", reserved)
	}
	switch t := binary.LittleEndian.Uint16(raw[2:4]); t {
	case 1:
		// IMAGE_ICON，正常
	case 2:
		return nil, fmt.Errorf("PE 资源注入：这是光标文件（CUR，type=2），不是图标（ICO，type=1）")
	default:
		return nil, fmt.Errorf("PE 资源注入：图标文件 type=%d（应为 1=图标），不是标准 .ico", t)
	}
	count := int(binary.LittleEndian.Uint16(raw[4:6]))
	if count <= 0 {
		return nil, fmt.Errorf("PE 资源注入：图标文件里没有任何图像（count=0）")
	}
	if count > maxIconImages {
		return nil, fmt.Errorf("PE 资源注入：图标文件里有 %d 个图像，超过上限 %d（防畸形目录项撑爆资源节）", count, maxIconImages)
	}
	dirEnd := 6 + 16*count
	if dirEnd > len(raw) {
		return nil, fmt.Errorf("PE 资源注入：图标目录被截断 —— 声明 %d 个图像需要 %d 字节，实际只有 %d 字节", count, dirEnd, len(raw))
	}

	images := make([]resIconImage, 0, count)
	for i := 0; i < count; i++ {
		e := 6 + i*16
		size := int64(binary.LittleEndian.Uint32(raw[e+8 : e+12]))
		off := int64(binary.LittleEndian.Uint32(raw[e+12 : e+16]))
		if size <= 0 {
			return nil, fmt.Errorf("PE 资源注入：图标第 %d 项的图像长度为 0，文件损坏", i+1)
		}
		if off < int64(dirEnd) || off+size > int64(len(raw)) {
			return nil, fmt.Errorf("PE 资源注入：图标第 %d 项的图像越界（偏移 %d + 长度 %d，文件 %d 字节），文件损坏",
				i+1, off, size, len(raw))
		}
		// 这里**不去重**：GRPICONDIR 必须保留完整的尺寸清单（去重只发生在 RT_ICON 那一层，
		// 见 buildResourceTypes —— 否则"16x16 与 32x32 共用一份数据"的图标会少一个尺寸）。
		images = append(images, resIconImage{
			width:      raw[e],
			height:     raw[e+1],
			colorCount: raw[e+2],
			planes:     binary.LittleEndian.Uint16(raw[e+4 : e+6]),
			bitCount:   binary.LittleEndian.Uint16(raw[e+6 : e+8]),
			offset:     off,
			size:       size,
			data:       raw[off : off+size],
		})
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("PE 资源注入：图标文件里没有可用的图像")
	}
	return images, nil
}

// ─── 时间戳策略 ─────────────────────────────────────────────────────────────

// randomInt63 随机数源（n > 0，返回 [0, n) 内的值）。
// 单独抽成包级变量是为了让时间戳策略可以在单测里注入确定性随机源。
var randomInt63 = func(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return int64(randomUint32(n))
}

// resolveResourceTimestamp 按策略算出要写进 COFF 头的 TimeDateStamp。
//
// 三种策略：
//   - ""/"keep"  不改（返回 set=false）；
//   - "fixed"    用 TimestampFixed（空则 defaultResourceTimestamp）；
//   - "random"   在固定基准之后的随机偏移（窗口 180 天），再夹到"不晚于 now"。
//
// **硬要求：无论哪种策略都不允许写出晚于构建机当前时间的时间戳** —— 未来时间戳是明显的
// 伪造信号（比时间戳为 0 更可疑）。fixed 策略配了未来时间直接报错，不静默夹取；random
// 策略天然被夹住（基准远在过去，窗口内的取值实际都早于 now）。
func resolveResourceTimestamp(mode, fixed string, now time.Time, rnd func(int64) int64) (uint32, bool, error) {
	base, err := time.Parse(time.RFC3339, defaultResourceTimestamp)
	if err != nil {
		return 0, false, fmt.Errorf("PE 资源注入：内置默认时间戳解析失败（这属于实现缺陷）：%v", err)
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "keep":
		return 0, false, nil
	case timestampModeFixed:
		t := base
		if s := strings.TrimSpace(fixed); s != "" {
			parsed, perr := parseResourceTime(s)
			if perr != nil {
				return 0, false, fmt.Errorf("PE 资源注入：时间戳 %q 无法解析：%v（支持 RFC3339，如 2024-03-15T09:00:00Z）", s, perr)
			}
			t = parsed
		}
		if t.After(now) {
			return 0, false, fmt.Errorf("PE 资源注入：配置的固定时间戳 %s 晚于构建机当前时间 %s —— "+
				"未来时间戳是明显的伪造信号（比 0 更可疑），已拒绝构建", t.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		return uint32(t.Unix()), true, nil
	case "random":
		// 窗口上界 = min(基准+180天, now)；基准远在过去，因此正常情况下窗口就是 180 天。
		upper := base.Add(randomTimestampWindow)
		if upper.After(now) {
			upper = now
		}
		if !upper.After(base) {
			// 构建机时钟早于基准（极端情况）：退化成"用当前时间"，仍然不会是未来时间。
			return uint32(now.Unix()), true, nil
		}
		span := int64(upper.Sub(base) / time.Second)
		off := int64(0)
		if span > 0 && rnd != nil {
			off = rnd(span)
			if off < 0 {
				off = 0
			}
			if off >= span {
				off = span - 1
			}
		}
		t := base.Add(time.Duration(off) * time.Second).Truncate(time.Minute) // 整分更像真实构建时间
		if t.After(now) {
			t = now.Truncate(time.Minute)
		}
		return uint32(t.Unix()), true, nil
	default:
		return 0, false, fmt.Errorf("PE 资源注入：时间戳策略 %q 不认识（只支持 keep / fixed / random，留空=keep）", mode)
	}
}

// parseResourceTime 解析操作员写的时间戳：优先 RFC3339，其次常见的 "2006-01-02 15:04:05"
// 与 "2006-01-02"（按 UTC 解释）。
func parseResourceTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("不认识的格式")
}

// ─── 自检与回读 ─────────────────────────────────────────────────────────────

// PEResourceInfo 从 PE 里回读出来的资源摘要（用于构建日志、验收脚本与单测）。
type PEResourceInfo struct {
	HasResourceDir   bool
	HasVersion       bool
	CompanyName      string
	ProductName      string
	FileDescription  string
	FileVersion      string
	ProductVersion   string
	LegalCopyright   string
	OriginalFilename string
	InternalName     string
	IconCount        int // RT_ICON 数据项个数
	GroupIconCount   int // RT_GROUP_ICON 数据项个数
	TimeDateStamp    uint32

	// VS_FIXEDFILEINFO 的关键字段（验收要核对 MAKELONG 语义与 dwFileType）。
	HasFixedFileInfo bool
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FixedFileType    uint32 // VFT_APP(1) / VFT_DLL(2)，DLL 必须是 2
}

// ReadPEResourceInfo 解析 PE 的资源目录并回读版本信息/图标数量/时间戳。
// 供 `builder.patchResources` 打日志、验收脚本与单测做"写进去的能读回来"的闭环。
func ReadPEResourceInfo(data []byte) (*PEResourceInfo, error) {
	m, err := parsePEPatchImage(data)
	if err != nil {
		return nil, err
	}
	info := &PEResourceInfo{TimeDateStamp: binary.LittleEndian.Uint32(data[m.timeStampOff : m.timeStampOff+4])}
	entries, err := m.readResourceEntries()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return info, nil
	}
	info.HasResourceDir = true

	var fixed [13]uint32
	for _, e := range entries {
		switch e.typ {
		case rtIcon:
			info.IconCount++
		case rtGroupIcon:
			info.GroupIconCount++
		case rtVersion:
			info.HasVersion = true
			strs := map[string]string{}
			if err := parseVersionInfoBlock(e.data, 0, strs, &fixed); err != nil {
				return nil, fmt.Errorf("资源里的版本信息结构损坏：%w", err)
			}
			info.CompanyName = strs["CompanyName"]
			info.ProductName = strs["ProductName"]
			info.FileDescription = strs["FileDescription"]
			info.FileVersion = strs["FileVersion"]
			info.ProductVersion = strs["ProductVersion"]
			info.LegalCopyright = strs["LegalCopyright"]
			info.OriginalFilename = strs["OriginalFilename"]
			info.InternalName = strs["InternalName"]
			info.HasFixedFileInfo = true
			info.FileVersionMS = fixed[2]
			info.FileVersionLS = fixed[3]
			info.ProductVersionMS = fixed[4]
			info.ProductVersionLS = fixed[5]
			info.FixedFileType = fixed[9]
			if fixed[0] != vsSignature {
				return nil, fmt.Errorf("版本信息的 VS_FIXEDFILEINFO 签名 = 0x%08X（应为 0x%08X）", fixed[0], vsSignature)
			}
		}
	}
	return info, nil
}

// resFoundEntry 一个"类型 + ID + 语言 + 数据"的叶子。
type resFoundEntry struct {
	typ  uint32
	name uint32
	data []byte
}

// readResourceEntries 走一遍资源目录树，返回所有叶子数据。
// 每一步都做边界检查：这段代码会被用在**自己的输出**上做自检，越界必须报错而不是 panic。
func (m *pePatchImage) readResourceEntries() ([]resFoundEntry, error) {
	rva, size := m.dataDir(peDirResource)
	if rva == 0 || size == 0 {
		return nil, nil
	}
	idx, ok := m.rvaSection(rva)
	if !ok {
		return nil, fmt.Errorf("资源目录 RVA 0x%X 不落在任何节内", rva)
	}
	sec := m.sections[idx]
	startOff := int64(sec.rawPtr) + int64(rva-sec.rva)
	if startOff < 0 || startOff+int64(size) > int64(len(m.data)) {
		return nil, fmt.Errorf("资源目录（RVA 0x%X，%d 字节）超出文件范围", rva, size)
	}
	base := int(startOff)
	dirEnd := base + int(size)

	type dirEntry struct {
		id    uint32
		isDir bool
		off   uint32
	}
	readDir := func(off int) ([]dirEntry, error) {
		if off < base || off+16 > dirEnd {
			return nil, fmt.Errorf("资源目录项偏移 0x%X 越界（资源目录 0x%X..0x%X）", off, base, dirEnd)
		}
		names := int(binary.LittleEndian.Uint16(m.data[off+12 : off+14]))
		ids := int(binary.LittleEndian.Uint16(m.data[off+14 : off+16]))
		n := names + ids
		if off+16+8*n > dirEnd {
			return nil, fmt.Errorf("资源目录项数量 %d 越出资源目录范围", n)
		}
		out := make([]dirEntry, 0, n)
		for i := 0; i < n; i++ {
			p := off + 16 + i*8
			raw := binary.LittleEndian.Uint32(m.data[p+4 : p+8])
			out = append(out, dirEntry{
				id:    binary.LittleEndian.Uint32(m.data[p : p+4]),
				isDir: raw&resDirEntryIsDirectory != 0,
				off:   raw &^ resDirEntryIsDirectory,
			})
		}
		return out, nil
	}
	// 资源数据体可能不在资源目录区间内（第三方 PE 会这样排），所以按节映射而不是按目录区间。
	readData := func(dataRVA, dataSize uint32) ([]byte, error) {
		si, ok := m.rvaSection(dataRVA)
		if !ok {
			return nil, fmt.Errorf("资源数据的 RVA 0x%X 不落在任何节内", dataRVA)
		}
		s := m.sections[si]
		start := int64(s.rawPtr) + int64(dataRVA-s.rva)
		if start < 0 || start+int64(dataSize) > int64(len(m.data)) {
			return nil, fmt.Errorf("资源数据（RVA 0x%X，%d 字节）超出文件范围", dataRVA, dataSize)
		}
		return m.data[start : start+int64(dataSize)], nil
	}

	types, err := readDir(base)
	if err != nil {
		return nil, err
	}
	var out []resFoundEntry
	for _, t := range types {
		if !t.isDir {
			return nil, fmt.Errorf("资源根目录下的类型项 0x%X 不是子目录（结构非法）", t.id)
		}
		names, err := readDir(base + int(t.off))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			langs, err := readDir(base + int(n.off))
			if err != nil {
				return nil, err
			}
			for _, l := range langs {
				if l.isDir {
					return nil, fmt.Errorf("资源语言层不应再有子目录（类型 0x%X，ID 0x%X）", t.id, n.id)
				}
				de := base + int(l.off)
				if de+16 > dirEnd {
					return nil, fmt.Errorf("资源数据项偏移 0x%X 越界", de)
				}
				dataRVA := binary.LittleEndian.Uint32(m.data[de : de+4])
				dataSize := binary.LittleEndian.Uint32(m.data[de+4 : de+8])
				blob, err := readData(dataRVA, dataSize)
				if err != nil {
					return nil, err
				}
				out = append(out, resFoundEntry{typ: t.id, name: n.id, data: blob})
			}
		}
	}
	return out, nil
}

// VerifyPELayout 对（修补后的）PE 做结构自检：
//  1. 节表可解析、每个节的原始数据不越界；
//  2. 节之间在内存里**不重叠**，且按 RVA 升序、RVA 按 SectionAlignment 对齐；
//  3. SizeOfHeaders 覆盖整个节表、按 FileAlignment 对齐，且不与第一个节的 RVA 重叠；
//  4. SizeOfImage 覆盖最后一个节的结束 RVA（并按 SectionAlignment 对齐）。
//  5. 有资源目录时：目录能走通、每个数据项都落在节内。
//
// 这是"改坏节表导致 loader 拒绝加载"最直接的护栏：每次修补后都会跑一遍，单测也直接用它。
func VerifyPELayout(data []byte) error {
	m, err := parsePEPatchImage(data)
	if err != nil {
		return err
	}
	sizeOfHeaders := binary.LittleEndian.Uint32(data[m.sizeOfHeadersOff : m.sizeOfHeadersOff+4])
	sizeOfImage := binary.LittleEndian.Uint32(data[m.sizeOfImageOff : m.sizeOfImageOff+4])

	secTableEnd := uint32(m.secTableOff + peSectionHeaderSize*m.numSections)
	if sizeOfHeaders < secTableEnd {
		return fmt.Errorf("结构自检失败：SizeOfHeaders=0x%X 小于节表末尾 0x%X（新节头没被头部覆盖）", sizeOfHeaders, secTableEnd)
	}
	if sizeOfHeaders%m.fileAlign != 0 {
		return fmt.Errorf("结构自检失败：SizeOfHeaders=0x%X 未按 FileAlignment=0x%X 对齐", sizeOfHeaders, m.fileAlign)
	}

	for i, s := range m.sections {
		if s.name == "" {
			return fmt.Errorf("结构自检失败：第 %d 个节没有节名", i)
		}
		if s.rva%m.sectionAlign != 0 {
			return fmt.Errorf("结构自检失败：节 %q 的 RVA 0x%X 未按 SectionAlignment=0x%X 对齐", s.name, s.rva, m.sectionAlign)
		}
		if s.rva < sizeOfHeaders {
			return fmt.Errorf("结构自检失败：节 %q 的 RVA 0x%X 落在头部区域（SizeOfHeaders=0x%X）内", s.name, s.rva, sizeOfHeaders)
		}
		if s.rawSize > 0 && s.rawPtr%m.fileAlign != 0 {
			return fmt.Errorf("结构自检失败：节 %q 的 PointerToRawData=0x%X 未按 FileAlignment 对齐", s.name, s.rawPtr)
		}
		if i > 0 && s.rva < m.sections[i-1].rva {
			return fmt.Errorf("结构自检失败：节 %q 的 RVA 0x%X 小于前一个节的 0x%X（节表顺序与地址顺序不一致）",
				s.name, s.rva, m.sections[i-1].rva)
		}
		for j := 0; j < i; j++ {
			prev := m.sections[j]
			if s.rva < prev.endRVA() {
				return fmt.Errorf("结构自检失败：节 %q（RVA 0x%X..0x%X）与节 %q（RVA 0x%X..0x%X）在内存里重叠",
					prev.name, prev.rva, prev.endRVA(), s.name, s.rva, s.endRVA())
			}
		}
	}

	maxEnd := m.maxSectionEndRVA()
	if sizeOfImage < maxEnd {
		return fmt.Errorf("结构自检失败：SizeOfImage=0x%X 没有覆盖最后一个节的结束 RVA 0x%X", sizeOfImage, maxEnd)
	}

	// 资源目录（如果有）必须能完整走通，且每个数据项都落在节内。
	if _, err := m.readResourceEntries(); err != nil {
		return fmt.Errorf("结构自检失败（资源目录不可解析）：%w", err)
	}
	return nil
}

// parseVersionInfoBlock 递归解析 VS_VERSIONINFO 结构块，收集 depth==3（String* 层）的
// "键 → 值"字符串，并把根块的 VS_FIXEDFILEINFO 填进 fixed。
func parseVersionInfoBlock(b []byte, depth int, out map[string]string, fixed *[13]uint32) error {
	if len(b) < 6 {
		return fmt.Errorf("版本信息块不足 6 字节头")
	}
	wLength := int(binary.LittleEndian.Uint16(b[0:2]))
	wValueLength := int(binary.LittleEndian.Uint16(b[2:4]))
	wType := binary.LittleEndian.Uint16(b[4:6])
	if wLength < 6 || wLength > len(b) {
		return fmt.Errorf("版本信息块长度 %d 越界（可用 %d 字节）", wLength, len(b))
	}
	block := b[:wLength]

	key, keyEnd, err := readUTF16Z(block, 6)
	if err != nil {
		return err
	}
	p := alignInt(keyEnd, 4)
	valueBytes := wValueLength
	if wType == 1 {
		valueBytes = wValueLength * 2
	}
	if p+valueBytes > len(block) {
		return fmt.Errorf("版本信息块 %q 的值长度 %d 越界", key, valueBytes)
	}
	if depth == 0 && key == "VS_VERSION_INFO" && valueBytes >= vsFixedFileInfoSize && fixed != nil {
		for i := 0; i < 13; i++ {
			fixed[i] = binary.LittleEndian.Uint32(block[p+i*4 : p+i*4+4])
		}
	}
	if depth == 3 {
		out[key] = decodeUTF16(block[p : p+valueBytes])
	}
	q := alignInt(p+valueBytes, 4)
	for q+6 <= len(block) {
		childLen := int(binary.LittleEndian.Uint16(block[q : q+2]))
		if childLen < 6 || q+childLen > len(block) {
			// 末尾的对齐填充会让剩余字节不足一个块，这是合法的结束条件。
			break
		}
		if err := parseVersionInfoBlock(block[q:q+childLen], depth+1, out, fixed); err != nil {
			return err
		}
		q = alignInt(q+childLen, 4)
	}
	return nil
}

// alignInt 向上对齐（int 版，align 必须是 2 的幂）。
func alignInt(v, align int) int {
	if align <= 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// readUTF16Z 从 off 开始读一个以 NUL 结尾的 UTF-16LE 字符串，返回字符串与"结束位置之后"的偏移。
func readUTF16Z(b []byte, off int) (string, int, error) {
	start := off
	for off+2 <= len(b) {
		if b[off] == 0 && b[off+1] == 0 {
			return decodeUTF16(b[start:off]), off + 2, nil
		}
		off += 2
	}
	return "", 0, fmt.Errorf("UTF-16 字符串没有以 NUL 结尾（长度 %d）", len(b))
}

// decodeUTF16 把 UTF-16LE 字节解成字符串（忽略结尾的 NUL）。
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+2 <= len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

// ─── 构建流水线接入 ─────────────────────────────────────────────────────────

// ResourcePresetNeutral 中性预设名：一键套用一套**自有品牌**的版本信息。
//
// 为什么不预置"像系统组件"的外观（例如冒充 Microsoft / 系统文件名的公司名与描述）：
// 那是品牌冒充，收益是静态特征上更像系统文件，但代价是把冒充字符串写进一个公开仓库 ——
// 这笔交易不该由默认值替操作员做。需要的话，操作员完全可以在请求里显式给公司名/描述，
// 与本预设无关。
const ResourcePresetNeutral = "neutral"

// ResourcePresetNames 返回当前支持的预设名（对外契约：GET /builders 的 resource_presets）。
func ResourcePresetNames() []string { return []string{ResourcePresetNeutral} }

// applyResourcePreset 把预设展开进 cfg（只填零值字段）；返回 false = 预设名不认识。
//
// 预设里**不猜版本号**：FileVersion/ProductVersion 留空，落到既有默认 1.0.0.0。
// 理由：版本号是发布事实，硬编码在预设里会随版本升级悄悄过期（而且"1.4.0.0 的文件描述
// 写着 ToShell"会让静态比对更容易关联到本仓库）——操作员要精确版本就显式给。
func applyResourcePreset(cfg *PEResourceConfig, preset, format string) bool {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "":
		return true // 无预设：不是错误
	case ResourcePresetNeutral:
		setIfEmpty(&cfg.CompanyName, neutralPresetCompany)
		setIfEmpty(&cfg.ProductName, neutralPresetCompany)
		setIfEmpty(&cfg.FileDescription, neutralPresetDescription)
		setIfEmpty(&cfg.LegalCopyright, neutralPresetCopyright)
		setIfEmpty(&cfg.InternalName, neutralPresetInternalName)
		if cfg.OriginalFilename == "" {
			// 原始文件名与交付格式一致（exe/bin → .exe，dll → .dll）。DLL 写成 .exe 是
			// 典型的"拼接产物"信号，且白加黑链的宿主会比对扩展名。
			if strings.EqualFold(strings.TrimSpace(format), "dll") {
				cfg.OriginalFilename = neutralPresetInternalName + ".dll"
			} else {
				cfg.OriginalFilename = neutralPresetInternalName + ".exe"
			}
		}
		// 时间戳：预设设为 fixed（确定性、可复现），比 Go 链接器默认的 0 更像一次真实发布。
		// 操作员想保留原值就显式给 resource_timestamp_mode=keep（显式优先）。
		setIfEmpty(&cfg.TimestampMode, timestampModeFixed)
		return true
	default:
		return false
	}
}

// setIfEmpty 只在目标为空时赋值（预设不覆盖操作员显式给的值）。
func setIfEmpty(dst *string, v string) {
	if strings.TrimSpace(*dst) == "" {
		*dst = v
	}
}

// ResourceConfigForOptions 是"构建选项 → 资源注入配置"的**唯一入口**（含预设展开与校验，纯数据不做 IO）。
//
// 为什么要有 error 版本：未知预设必须**让构建失败**。若这里静默返回零值配置，
// 操作员写了 resource_preset="neurtal"（拼错）就会拿到一个"构建成功但没有资源"的产物 ——
// 这类哑失败比构建失败难查得多，所以宁可明确报错。
func ResourceConfigForOptions(opts *BuildOptions) (PEResourceConfig, error) {
	if opts == nil {
		return PEResourceConfig{}, nil
	}
	cfg := PEResourceConfig{
		CompanyName:      opts.ResourceCompanyName,
		ProductName:      opts.ResourceProductName,
		FileDescription:  opts.ResourceFileDescription,
		FileVersion:      opts.ResourceFileVersion,
		ProductVersion:   opts.ResourceProductVersion,
		LegalCopyright:   opts.ResourceLegalCopyright,
		OriginalFilename: opts.ResourceOriginalFilename,
		InternalName:     opts.ResourceInternalName,
		IconPath:         opts.ResourceIconPath,
		TimestampMode:    opts.ResourceTimestampMode,
		TimestampFixed:   opts.ResourceTimestamp,
	}
	// 预设只填"操作员没显式给"的字段（显式字段永远优先：预设是便利，不是覆盖）。
	if !applyResourcePreset(&cfg, opts.ResourcePreset, opts.Format) {
		return PEResourceConfig{}, fmt.Errorf("未知的 PE 资源预设 %q（当前支持：%s）",
			opts.ResourcePreset, strings.Join(ResourcePresetNames(), " / "))
	}
	return cfg, nil
}

// shouldPatchResources 判断本次构建**是否真的**要打资源/改时间戳。
//
// 这个函数同时决定两件事，必须与真正调用 PatchPEResources 的条件完全一致：
//  1. `builder.patchResources` 要不要干活；
//  2. `finalize_order.go` 的步骤列表里要不要出现 `pe_resource_patch`
//     （"仅当本次构建真的要打资源时出现"，否则日志会报一个没发生的步骤）。
//
// 适用范围（Windows PE 交付格式、四类显式跳过及其原因）统一由
// `isWindowsPEDeliveryFormat` 判定，与 v1.4.0 S3 第三批的 `shouldNormalizeSections`
// **共用同一口径**（两处判断将来不许漂移）。
//
// 与节规范化的区别：资源修补写的是操作员选定的身份（公司名/图标），所以**默认关闭**、
// 零值不触发；节规范化只做减法，**默认执行**（见 pe_sections.go 顶部注释）。
func shouldPatchResources(opts *BuildOptions, targetOS string) bool {
	if !isWindowsPEDeliveryFormat(opts, targetOS) {
		return false
	}
	// 未知预设也必须走修补分支：只有真的进去，patchResources 才能把"预设名不认识"
	// 报成构建错误。若在这里返回 false，拼错预设名的请求会得到"构建成功但没资源"的哑结果。
	cfg, err := ResourceConfigForOptions(opts)
	if err != nil {
		return true
	}
	return !cfg.IsZero() || strings.TrimSpace(opts.ResourcePreset) != ""
}

// patchResources 在"指纹擦除之后、UPX 与签名之前"对 PE 做资源/时间戳后处理。
//
// 失败即**报错**（不静默跳过）：资源注入是操作员显式配置的动作，"配了图标却没有图标"的
// 哑失败比构建失败难查得多。成功时打一行回读摘要 —— 这是"公司名/图标版本到底写进去没有"
// 的第一现场，也顺手做了一次"写完能读回来"的闭环验证。
func (b *Builder) patchResources(bin []byte, opts *BuildOptions, targetOS string) ([]byte, error) {
	if !shouldPatchResources(opts, targetOS) {
		return bin, nil
	}
	cfg, cerr := ResourceConfigForOptions(opts)
	if cerr != nil {
		return nil, fmt.Errorf("PE 资源注入失败：%w", cerr)
	}
	if cfg.IsZero() {
		// 理论上不可达（shouldPatchResources 已经保证），但留着这层是为了"将来有人
		// 改了 shouldPatchResources 却忘了这里"时不至于打出一个空资源节。
		return bin, nil
	}
	out, err := PatchPEResources(bin, cfg)
	if err != nil {
		return nil, fmt.Errorf("PE 资源注入失败：%w", err)
	}
	before, after := len(bin), len(out)
	info, rerr := ReadPEResourceInfo(out)
	if rerr != nil {
		// 回读失败不该掩盖"已经写进去"这件事，但必须留痕（结构自检在 PatchPEResources
		// 里已经跑过一遍，这里再读不出来说明资源摘要有缺陷）。
		logging.Warn("builder", "PE 资源回读失败（资源可能已写入但无法摘要）：%v", rerr)
		return out, nil
	}
	logging.Info("builder",
		"PE 资源已写入：company=%q product=%q file_version=%q icons=%d group_icons=%d timestamp=%d size=%d->%d",
		info.CompanyName, info.ProductName, info.FileVersion, info.IconCount, info.GroupIconCount,
		info.TimeDateStamp, before, after)
	return out, nil
}

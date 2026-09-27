package builder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ─── PE 节规范化（.symtab / COFF 符号表指针）单测（v1.4.0 S3 第三批）──────────
//
// 全部自包含：在内存里手工拼 PE，**不依赖外部产物也不落盘执行**（本机安全软件会拦截
// 新生成的 PE）。真实 Windows 载荷的验证见 scripts/e2e_smoke.ps1 与 .tmp-verify 的探针。
//
// 覆盖要求（逐条对应任务书）：
//   - 最后一节删除（含“原始数据在文件末尾 → 顺带截断”）
//   - 中间节删除并前移 40 字节
//   - 无 `.symtab` 时幂等不出错（逐字节不变）
//   - 删除后 `VerifyPELayout` 通过
//   - 数据目录与节 RVA 一个字节没被改坏
//   - PointerToSymbolTable / NumberOfSymbols 被置 0

// symtabRawMarker `.symtab` 节的原始数据标记：前 4 字节是真实载荷里的 COFF 字符串表长度
// （4），其余是与“对齐填充”等长的可识别填充 —— 用来断言“截断真的把这段字节丢掉了”。
var symtabRawMarker = append([]byte{0x04, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x77}, 508)...)

// withSymtabFields 在 PE 的文件头里写 COFF 符号表指针 / 符号数（模拟 Go 链接器的遗留）。
func withSymtabFields(pe []byte, ptr, count uint32) []byte {
	out := append([]byte(nil), pe...)
	fh := int(binary.LittleEndian.Uint32(out[0x3C:0x40])) + 4
	binary.LittleEndian.PutUint32(out[fh+8:fh+12], ptr)
	binary.LittleEndian.PutUint32(out[fh+12:fh+16], count)
	return out
}

// lastSectionPEWithSymtab `.symtab` 是**最后一节**且原始数据正好在文件末尾
// （本仓库真实载荷在 compile() 阶段的形态）。
func lastSectionPEWithSymtab() []byte {
	pe := buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 600)},
		{name: ".rdata", data: bytes.Repeat([]byte{0x41}, 300)},
		{name: goSymtabSectionName, data: symtabRawMarker},
	}, false, true)
	// 指针指向文件里 .text 原始数据内部：真实载荷里它也是指向别处的一堆无关字节。
	return withSymtabFields(pe, 0x420, 0)
}

// middleSectionPEWithSymtab `.symtab` 是**中间节**（其后还有 .reloc）。
func middleSectionPEWithSymtab() []byte {
	pe := buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 600)},
		{name: goSymtabSectionName, data: symtabRawMarker},
		{name: ".reloc", data: bytes.Repeat([]byte{0x42}, 300)},
	}, false, true)
	return withSymtabFields(pe, 0x420, 0)
}

// findTestSection 在 PE 里找指定节，找不到就 Fatal。
func findTestSection(t *testing.T, data []byte, name string) (pePatchSection, *pePatchImage) {
	t.Helper()
	m, err := parsePEPatchImage(data)
	if err != nil {
		t.Fatalf("parsePEPatchImage: %v", err)
	}
	for _, s := range m.sections {
		if s.name == name {
			return s, m
		}
	}
	t.Fatalf("测试样本里找不到节 %q", name)
	return pePatchSection{}, nil
}

// hasTestSection 判断（合法）PE 里是否还有指定节。
func hasTestSection(t *testing.T, data []byte, name string) bool {
	t.Helper()
	m, err := parsePEPatchImage(data)
	if err != nil {
		t.Fatalf("parsePEPatchImage: %v", err)
	}
	for _, s := range m.sections {
		if s.name == name {
			return true
		}
	}
	return false
}

// TestNormalizePESectionsRemovesLastAndTruncates 最后一节 + 原始数据在文件末尾：
// 删节头 + 顺带截断（文件变小 rawSize 字节）+ 指针/符号数置 0 + 结构自检通过 +
// 节表其余部分与数据目录一个字节都没动。
func TestNormalizePESectionsRemovesLastAndTruncates(t *testing.T) {
	in := lastSectionPEWithSymtab()
	sym, m := findTestSection(t, in, goSymtabSectionName)
	if int64(sym.rawPtr)+int64(sym.rawSize) != int64(len(in)) {
		t.Fatalf("前置条件：.symtab 的原始数据必须在文件末尾（rawPtr=0x%X rawSize=0x%X file=%d）",
			sym.rawPtr, sym.rawSize, len(in))
	}

	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if !res.Changed {
		t.Fatal("应当报告“改了字节”")
	}
	if res.RemovedSection != goSymtabSectionName {
		t.Fatalf("RemovedSection = %q, want %q", res.RemovedSection, goSymtabSectionName)
	}
	if res.TruncatedBytes != int(sym.rawSize) {
		t.Fatalf("TruncatedBytes = %d, want %d", res.TruncatedBytes, sym.rawSize)
	}
	if res.SymTabPtr != 0x420 {
		t.Fatalf("结果里应带回原 PointerToSymbolTable=0x420，实际 0x%X", res.SymTabPtr)
	}
	if len(out) != len(in)-int(sym.rawSize) {
		t.Fatalf("文件长度 = %d, want %d", len(out), len(in)-int(sym.rawSize))
	}
	// 截断掉的那段标记字节必须真的不在文件里了。
	if bytes.Contains(out, bytes.Repeat([]byte{0x77}, 16)) {
		t.Fatal(".symtab 的原始数据没有被截断掉（文件里仍有它的填充字节）")
	}
	// 节表其余部分（前 numSections-1 项）必须逐字节一致。
	keep := peSectionHeaderSize * (m.numSections - 1)
	if !bytes.Equal(out[m.secTableOff:m.secTableOff+keep], in[m.secTableOff:m.secTableOff+keep]) {
		t.Fatal("保留的节头字节被改动了（应当只减计数 + 清零末尾 40 字节）")
	}
	// 末尾多出来的 40 字节必须清零（否则文件里留着一份“幽灵节头”）。
	tail := out[m.secTableOff+keep : m.secTableOff+keep+peSectionHeaderSize]
	if !bytes.Equal(tail, make([]byte, peSectionHeaderSize)) {
		t.Fatal("删节后节表末尾的 40 字节必须清零")
	}
	// 数据目录（16 项 × 8 字节）必须逐字节不变。
	dd := m.dataDirOff
	if !bytes.Equal(out[dd:dd+peMaxDataDirs*8], in[dd:dd+peMaxDataDirs*8]) {
		t.Fatal("数据目录被改动了")
	}
	// 其余前部（DOS/PE 头/可选头/节表起点之前）除了那两个 COFF 字段与 NumberOfSections，
	// 也必须逐字节不变。
	fh := m.fileHdrOff
	for i := 0; i < dd+peMaxDataDirs*8; i++ {
		if i >= fh+8 && i < fh+16 {
			continue // PointerToSymbolTable / NumberOfSymbols 允许（且必须）被改
		}
		if i >= fh+2 && i < fh+4 {
			continue // NumberOfSections 必须减一
		}
		if out[i] != in[i] {
			t.Fatalf("偏移 0x%X 的字节被意外改动：0x%02X → 0x%02X", i, in[i], out[i])
		}
	}
	if got := binary.LittleEndian.Uint16(out[fh+2 : fh+4]); got != uint16(m.numSections-1) {
		t.Fatalf("NumberOfSections = %d, want %d", got, m.numSections-1)
	}

	// 回读：节数 -1、`.symtab` 消失、两个 COFF 字段为 0、结构自检通过。
	m2, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatalf("处理后的 PE 解析失败：%v", err)
	}
	if m2.numSections != m.numSections-1 {
		t.Fatalf("节数 = %d, want %d", m2.numSections, m.numSections-1)
	}
	for _, s := range m2.sections {
		if s.name == goSymtabSectionName {
			t.Fatal("处理后的 PE 里不该再有 .symtab 节")
		}
	}
	if got := binary.LittleEndian.Uint32(out[m2.symTabPtrOff : m2.symTabPtrOff+4]); got != 0 {
		t.Fatalf("PointerToSymbolTable = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(out[m2.symCountOff : m2.symCountOff+4]); got != 0 {
		t.Fatalf("NumberOfSymbols = %d, want 0", got)
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("删除节后结构自检必须通过：%v", err)
	}
	// 保留节的名字/RVA/原始数据必须没动。
	for _, want := range []string{".text", ".rdata"} {
		a, _ := findTestSection(t, in, want)
		b, _ := findTestSection(t, out, want)
		if a != b {
			t.Fatalf("节 %q 的节头被改动了：%+v → %+v", want, a, b)
		}
		if !bytes.Equal(in[a.rawPtr:a.rawPtr+a.rawSize], out[b.rawPtr:b.rawPtr+b.rawSize]) {
			t.Fatalf("节 %q 的原始数据被改动了", want)
		}
	}
}

// TestNormalizePESectionsRemovesMiddleAndShifts 中间节：后续节头整体前移 40 字节，
// 文件长度不变（不可证明安全 → 不截断），结构自检通过，数据目录与保留节不受影响。
func TestNormalizePESectionsRemovesMiddleAndShifts(t *testing.T) {
	in := middleSectionPEWithSymtab()
	_, m := findTestSection(t, in, goSymtabSectionName)
	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if res.RemovedSection != goSymtabSectionName || res.SectionIndex != 1 {
		t.Fatalf("应当删掉中间的第 2 个节，实际 RemovedSection=%q index=%d", res.RemovedSection, res.SectionIndex)
	}
	if res.TruncatedBytes != 0 {
		t.Fatalf("中间节的原始数据不在文件末尾，不该截断，实际 -%d 字节", res.TruncatedBytes)
	}
	if len(out) != len(in) {
		t.Fatalf("不截断时文件长度必须不变：%d → %d", len(in), len(out))
	}
	// 后续节头前移：out 的第 1 项 == in 的第 2 项。
	newHdr := m.secTableOff + peSectionHeaderSize
	oldHdr := m.secTableOff + 2*peSectionHeaderSize
	if !bytes.Equal(out[newHdr:newHdr+peSectionHeaderSize], in[oldHdr:oldHdr+peSectionHeaderSize]) {
		t.Fatal("中间节删除后，后续节头必须整体前移 40 字节")
	}
	// 末尾 40 字节清零。
	tail := out[m.secTableOff+peSectionHeaderSize*(m.numSections-1) : m.secTableOff+peSectionHeaderSize*m.numSections]
	if !bytes.Equal(tail, make([]byte, peSectionHeaderSize)) {
		t.Fatal("前移后节表末尾的 40 字节必须清零")
	}
	// 数据目录不变。
	if !bytes.Equal(out[m.dataDirOff:m.dataDirOff+peMaxDataDirs*8], in[m.dataDirOff:m.dataDirOff+peMaxDataDirs*8]) {
		t.Fatal("数据目录被改动了")
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("中间节删除后结构自检必须通过：%v", err)
	}
	m2, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatalf("处理后的 PE 解析失败：%v", err)
	}
	if m2.numSections != m.numSections-1 {
		t.Fatalf("节数 = %d, want %d", m2.numSections, m.numSections-1)
	}
	names := make([]string, 0, len(m2.sections))
	for _, s := range m2.sections {
		names = append(names, s.name)
	}
	if len(names) != 2 || names[0] != ".text" || names[1] != ".reloc" {
		t.Fatalf("保留下来的节 = %v, want [.text .reloc]", names)
	}
	// 保留节的 RVA/原始数据位置必须一个字节没动（中间节删除不做任何数据/地址搬移）。
	for i := 0; i < m.numSections; i++ {
		if m.sections[i].name == goSymtabSectionName {
			continue
		}
		b, _ := findTestSection(t, out, m.sections[i].name)
		if b.rva != m.sections[i].rva || b.rawPtr != m.sections[i].rawPtr || b.rawSize != m.sections[i].rawSize {
			t.Fatalf("节 %q 的 RVA/原始数据位置被改动了", m.sections[i].name)
		}
	}
}

// TestNormalizePESectionsNoSymtabIsNoOp 没有 `.symtab`、两个字段本来就是 0 → 逐字节不变、
// 不报错（幂等），且 res.Changed=false。
func TestNormalizePESectionsNoSymtabIsNoOp(t *testing.T) {
	in := simplePatchPE(false)
	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("没有 .symtab 时不该报错：%v", err)
	}
	if res.Changed {
		t.Fatal("没有 .symtab 且字段为 0 时不该报告改了字节")
	}
	if !bytes.Equal(in, out) {
		t.Fatal("没有 .symtab 时产物必须逐字节一致")
	}
}

// TestNormalizePESectionsZeroesPointerOnlyWithoutSection 只有非 0 指针、没有 `.symtab`：
// 只改 8 个字节（两个字段），节表/数据目录/文件长度一律不动。
func TestNormalizePESectionsZeroesPointerOnlyWithoutSection(t *testing.T) {
	in := withSymtabFields(simplePatchPE(false), 0x1234, 7)
	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if !res.Changed || res.RemovedSection != "" || res.TruncatedBytes != 0 {
		t.Fatalf("应当只清零两个字段：res=%+v", res)
	}
	if res.SymTabPtr != 0x1234 || res.SymCount != 7 {
		t.Fatalf("结果里应带回原值 0x1234/7，实际 0x%X/%d", res.SymTabPtr, res.SymCount)
	}
	if len(out) != len(in) {
		t.Fatalf("文件长度不该变：%d → %d", len(in), len(out))
	}
	m, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatalf("处理后解析失败：%v", err)
	}
	diff := 0
	for i := range out {
		if out[i] != in[i] {
			diff++
			if i < m.fileHdrOff+8 || i >= m.fileHdrOff+16 {
				t.Fatalf("偏移 0x%X 的字节不该被改（只允许改 COFF 两个字段）", i)
			}
		}
	}
	if diff == 0 || diff > 8 {
		t.Fatalf("应当在 1~8 个字节内改完两个字段，实际改了 %d 个字节", diff)
	}
	if binary.LittleEndian.Uint32(out[m.symTabPtrOff:m.symTabPtrOff+4]) != 0 ||
		binary.LittleEndian.Uint32(out[m.symCountOff:m.symCountOff+4]) != 0 {
		t.Fatal("两个 COFF 字段必须都置 0")
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("结构自检必须通过：%v", err)
	}
}

// TestNormalizePESectionsKeepsSectionReferencedByDataDir 数据目录仍指向 `.symtab` 的 RVA 区间时
// **不删节**（只清零字段），并留下中文原因 —— 删了会让加载器解析不到那个目录。
func TestNormalizePESectionsKeepsSectionReferencedByDataDir(t *testing.T) {
	in := middleSectionPEWithSymtab()
	sym, m := findTestSection(t, in, goSymtabSectionName)
	// 用一个空闲的数据目录项（index 8）指向 .symtab 的节首。
	dir := m.dataDirOff + 8*8
	binary.LittleEndian.PutUint32(in[dir:dir+4], sym.rva)
	binary.LittleEndian.PutUint32(in[dir+4:dir+8], 4)

	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if res.RemovedSection != "" {
		t.Fatalf("数据目录仍引用时不该删节，实际删了 %q", res.RemovedSection)
	}
	if res.KeptSectionReason == "" {
		t.Fatal("保留节时必须给出原因（中文）")
	}
	if !res.Changed {
		t.Fatal("字段仍应被清零")
	}
	if len(out) != len(in) {
		t.Fatalf("不删节时文件长度必须不变：%d → %d", len(in), len(out))
	}
	if !hasTestSection(t, out, goSymtabSectionName) {
		t.Fatal("数据目录仍引用时 .symtab 节必须保留")
	}
	// 字段照样要清零（那部分与数据目录无关）。
	m2, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatalf("处理后解析失败：%v", err)
	}
	if binary.LittleEndian.Uint32(out[m2.symTabPtrOff:m2.symTabPtrOff+4]) != 0 {
		t.Fatal("PointerToSymbolTable 仍应被置 0")
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("结构自检必须通过：%v", err)
	}
}

// TestNormalizePESectionsNoTruncateWhenTrailingData 尾部还有别的数据（真实场景：exe 路径在
// compile() 之后追加的配置块）→ 只删节头、**保留文件长度**，绝不切掉有效数据。
func TestNormalizePESectionsNoTruncateWhenTrailingData(t *testing.T) {
	in := append(lastSectionPEWithSymtab(), bytes.Repeat([]byte{0xAB}, 245)...)
	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if res.RemovedSection != goSymtabSectionName {
		t.Fatalf("节头仍应被删掉，实际 %q", res.RemovedSection)
	}
	if res.TruncatedBytes != 0 {
		t.Fatalf("尾部还有数据时不该截断，实际 -%d 字节", res.TruncatedBytes)
	}
	if len(out) != len(in) {
		t.Fatalf("不截断时长度必须不变：%d → %d", len(in), len(out))
	}
	// 尾部的 245 字节（配置块）必须一个字节都没动。
	if !bytes.Equal(out[len(out)-245:], bytes.Repeat([]byte{0xAB}, 245)) {
		t.Fatal("尾部数据被改动了")
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("结构自检必须通过：%v", err)
	}
}

// TestNormalizePESectionsIdempotent 对同一个 PE 连做两次：第二次必须**逐字节一致**且
// 报告“没改字节”（幂等 —— 构建流水线重复接入/重跑构建不会漂移）。
func TestNormalizePESectionsIdempotent(t *testing.T) {
	for _, in := range [][]byte{
		lastSectionPEWithSymtab(),
		middleSectionPEWithSymtab(),
		withSymtabFields(simplePatchPE(false), 0x1234, 7),
	} {
		once, res1, err := NormalizePESections(in)
		if err != nil {
			t.Fatalf("第一次: %v", err)
		}
		if !res1.Changed {
			t.Fatal("第一次应当改动字节")
		}
		twice, res2, err := NormalizePESections(once)
		if err != nil {
			t.Fatalf("第二次: %v", err)
		}
		if res2.Changed {
			t.Fatalf("第二次不该再改动字节（幂等）：res=%+v", res2)
		}
		if !bytes.Equal(once, twice) {
			t.Fatal("第二次必须逐字节一致")
		}
	}
}

// TestNormalizePESectionsRejectsBadInput 非法输入必须**中文报错**，不许静默返回。
func TestNormalizePESectionsRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"不是 PE（无 MZ）", []byte("this is not a PE file at all")},
		{"ELF 头", append([]byte{0x7F, 'E', 'L', 'F'}, make([]byte, 200)...)},
		{"MZ 但 e_lfanew 越界", func() []byte {
			b := make([]byte, 256)
			b[0], b[1] = 'M', 'Z'
			binary.LittleEndian.PutUint32(b[0x3C:0x40], 0x4000)
			return b
		}()},
	}
	for _, c := range cases {
		if _, _, err := NormalizePESections(c.in); err == nil {
			t.Fatalf("%s：必须报错（不静默跳过）", c.name)
		}
	}
}

// TestNormalizePESectionsReportsOtherNonStandardNames 名单外的节名只**报告**、不改名不删除。
func TestNormalizePESectionsReportsOtherNonStandardNames(t *testing.T) {
	in := buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 600)},
		{name: ".gopclnt", data: bytes.Repeat([]byte{0x33}, 300)}, // 8 字节上限内被截断的 Go 节名
		{name: goSymtabSectionName, data: symtabRawMarker},
	}, false, true)
	out, res, err := NormalizePESections(in)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if len(res.OtherNonStandardSections) != 1 || res.OtherNonStandardSections[0] != ".gopclnt" {
		t.Fatalf("应当报告 .gopclnt 为非标准节名，实际 %v", res.OtherNonStandardSections)
	}
	// 只报告：那节必须还在，且字节没动。
	if !hasTestSection(t, out, ".gopclnt") {
		t.Fatal("非标准节名不该被删除（只报告）")
	}
	sym, _ := findTestSection(t, in, ".gopclnt")
	got, _ := findTestSection(t, out, ".gopclnt")
	if sym != got {
		t.Fatalf("非标准节 %q 的节头被改动了：%+v → %+v", ".gopclnt", sym, got)
	}
	for _, n := range res.OtherNonStandardSections {
		if n == ".text" || n == ".rdata" {
			t.Fatalf("标准节名被误报为非标准：%v", res.OtherNonStandardSections)
		}
	}
}

// TestNonStandardPESectionNamesRealToolchainNames 实测的 MSVC/mingw 节名不该被当成“非标准”
// （否则日志会对 DLL 产物刷无意义告警）：.bss/.tls/.edata/.eh_fram 都是合法节名。
func TestNonStandardPESectionNamesRealToolchainNames(t *testing.T) {
	pe := buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 600)},
		{name: ".bss", data: bytes.Repeat([]byte{0x00}, 300)},
		{name: ".tls", data: bytes.Repeat([]byte{0x11}, 300)},
		{name: ".edata", data: bytes.Repeat([]byte{0x22}, 300)},
		{name: ".eh_fram", data: bytes.Repeat([]byte{0x33}, 300)},
	}, true, true)
	_, res, err := NormalizePESections(pe)
	if err != nil {
		t.Fatalf("NormalizePESections: %v", err)
	}
	if len(res.OtherNonStandardSections) != 0 {
		t.Fatalf("MSVC/mingw 的合法节名不该被报告为非标准：%v", res.OtherNonStandardSections)
	}
}

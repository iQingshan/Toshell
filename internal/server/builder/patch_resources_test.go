package builder

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── PE 资源修补的单测（v1.4.0 S3 第二批）────────────────────────────────────
//
// 全部自包含：在内存里手工拼最小 PE（**不依赖任何外部产物**，也不落盘执行），
// 因为本机安全软件会拦截/删除新生成的 PE。真实 Windows 载荷的端到端验证见
// scripts/e2e_smoke.ps1 与 .tmp-verify 的探针（构建期跑，不在单测里）。

// patchTestSection 描述测试 PE 的一个节。
type patchTestSection struct {
	name string
	data []byte
}

// buildPatchTestPE 拼一个头部字段**齐全且自洽**的最小 PE32（含 SectionAlignment/
// FileAlignment/SizeOfImage/SizeOfHeaders/16 项数据目录），用于验证修补后的结构自检。
//
// 与 pecheck_test.go 的 buildTestPE 的区别：那个构造器不写对齐字段（预检不看），
// 而资源修补必须能算准对齐 —— 所以这里单独一个构造器，并支持"头部没有余量"的畸形样本。
func buildPatchTestPE(sections []patchTestSection, isDLL bool, headerRoom bool) []byte {
	const (
		secAlign  = 0x1000
		fileAlign = 0x200
		optSize   = 224
		eLfanew   = 0x80
	)
	secTableOff := eLfanew + 4 + 20 + optSize
	headerEnd := testPEAlign(secTableOff+len(sections)*peSectionHeaderSize, fileAlign)
	if headerRoom {
		// 模拟真实链接器的头部余量：Go 的 windows PE 把 SizeOfHeaders 定在 1024，
		// 节表之后留出十几项的空间（实测 6 节的 exe 与 10 节的 dll 都还有余量）。
		if headerEnd < 1024 {
			headerEnd = 1024
		}
	} else {
		// 故意把头部压到"刚好放下当前节表"：再追加一个节头就会踩到第一个节的原始数据。
		headerEnd = secTableOff + len(sections)*peSectionHeaderSize
	}

	type placed struct {
		sec    patchTestSection
		rva    uint32
		rawPtr uint32
		rawSz  uint32
	}
	placedSecs := make([]placed, 0, len(sections))
	raw := uint32(headerEnd)
	rva := uint32(secAlign)
	for _, s := range sections {
		rawSz := uint32(testPEAlign(len(s.data), fileAlign))
		placedSecs = append(placedSecs, placed{sec: s, rva: rva, rawPtr: raw, rawSz: rawSz})
		raw += rawSz
		rva += secAlign
	}
	buf := make([]byte, int(raw))

	binary.LittleEndian.PutUint16(buf[0:2], peDOSMagic)
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], eLfanew)
	binary.LittleEndian.PutUint32(buf[eLfanew:eLfanew+4], peNTSignature)

	fileHdr := eLfanew + 4
	binary.LittleEndian.PutUint16(buf[fileHdr:fileHdr+2], imageFileMachineI386)
	binary.LittleEndian.PutUint16(buf[fileHdr+2:fileHdr+4], uint16(len(sections)))
	binary.LittleEndian.PutUint16(buf[fileHdr+16:fileHdr+18], optSize)
	if isDLL {
		binary.LittleEndian.PutUint16(buf[fileHdr+18:fileHdr+20], imageFileDLL)
	}

	optHdr := fileHdr + 20
	binary.LittleEndian.PutUint16(buf[optHdr:optHdr+2], peMagic32)
	binary.LittleEndian.PutUint32(buf[optHdr+16:optHdr+20], placedSecs[0].rva) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(buf[optHdr+28:optHdr+32], 0x400000)          // ImageBase
	binary.LittleEndian.PutUint32(buf[optHdr+32:optHdr+36], secAlign)
	binary.LittleEndian.PutUint32(buf[optHdr+36:optHdr+40], fileAlign)
	binary.LittleEndian.PutUint32(buf[optHdr+56:optHdr+60], rva) // SizeOfImage（最后一个节之后的 RVA）
	binary.LittleEndian.PutUint32(buf[optHdr+60:optHdr+64], uint32(headerEnd))
	binary.LittleEndian.PutUint32(buf[optHdr+92:optHdr+96], peMaxDataDirs)

	for i, p := range placedSecs {
		off := secTableOff + i*peSectionHeaderSize
		copy(buf[off:off+peSectionNameLen], p.sec.name)
		binary.LittleEndian.PutUint32(buf[off+8:off+12], uint32(len(p.sec.data))) // VirtualSize（精确值）
		binary.LittleEndian.PutUint32(buf[off+12:off+16], p.rva)
		binary.LittleEndian.PutUint32(buf[off+16:off+20], p.rawSz)
		binary.LittleEndian.PutUint32(buf[off+20:off+24], p.rawPtr)
		binary.LittleEndian.PutUint32(buf[off+36:off+40], testScnCode)
		copy(buf[p.rawPtr:], p.sec.data)
	}
	return buf
}

// simplePatchPE 一份"两节"的常规样本（头部有余量）。
func simplePatchPE(isDLL bool) []byte {
	return buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 600)},
		{name: ".rdata", data: bytes.Repeat([]byte{0x41}, 300)},
	}, isDLL, true)
}

// fullResourceConfig 一份"八个字段全开 + 固定时间戳"的配置。
func fullResourceConfig() PEResourceConfig {
	return PEResourceConfig{
		CompanyName:      "示例科技（授权红队测试）",
		ProductName:      "示例运维助手",
		FileDescription:  "示例运维助手 主程序",
		FileVersion:      "1.4.0.0",
		ProductVersion:   "1.4.0.0",
		LegalCopyright:   "Copyright (C) 2024 示例科技",
		OriginalFilename: "svcagent.exe",
		InternalName:     "svcagent",
		TimestampMode:    "fixed",
	}
}

// TestPatchPEResourcesZeroConfigIsNoOp 零值配置必须**逐字节不动**：
// 这是"默认构建零行为变化、体积不变"这条硬要求的单测形态。
func TestPatchPEResourcesZeroConfigIsNoOp(t *testing.T) {
	in := simplePatchPE(false)
	out, err := PatchPEResources(in, PEResourceConfig{})
	if err != nil {
		t.Fatalf("零值配置不该报错：%v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatal("零值配置下产物必须逐字节一致")
	}
	// keep 策略同样不该算"要动字节"。
	out2, err := PatchPEResources(in, PEResourceConfig{TimestampMode: "keep"})
	if err != nil {
		t.Fatalf("keep 策略不该报错：%v", err)
	}
	if !bytes.Equal(in, out2) {
		t.Fatal("keep 策略下产物必须逐字节一致")
	}
}

// TestPatchPEResourcesAppendsSectionAndRoundTrips 追加 .rsrc 节 → 结构自检 → 回读字段。
func TestPatchPEResourcesAppendsSectionAndRoundTrips(t *testing.T) {
	in := simplePatchPE(false)
	cfg := fullResourceConfig()

	out, err := PatchPEResources(in, cfg)
	if err != nil {
		t.Fatalf("PatchPEResources: %v", err)
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("修补后结构自检失败：%v", err)
	}

	mIn := mustParsePE(t, in)
	m, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.numSections != 3 {
		t.Fatalf("节数 = %d, want 3", m.numSections)
	}
	last := m.sections[2]
	if last.name != ".rsrc" {
		t.Fatalf("最后一个节名 = %q, want .rsrc", last.name)
	}
	if last.chars != rsrcCharacteristics {
		t.Fatalf(".rsrc 属性 = 0x%X, want 0x%X（与 pecheck_test 的 testScnRsrc 口径一致）", last.chars, rsrcCharacteristics)
	}
	if last.vsize > last.rawSize {
		t.Fatalf(".rsrc 的 VirtualSize(0x%X) 大于 SizeOfRawData(0x%X)：超出 raw 的部分在内存里是零填，资源会读不到",
			last.vsize, last.rawSize)
	}
	if last.rawSize%m.fileAlign != 0 {
		t.Fatalf(".rsrc 的 SizeOfRawData=0x%X 未按 FileAlignment=0x%X 对齐", last.rawSize, m.fileAlign)
	}
	// 原有节的原始数据必须逐字节不变（新节追加在文件末尾）。
	for _, s := range mIn.sections {
		end := s.rawPtr + s.rawSize
		if !bytes.Equal(out[s.rawPtr:end], in[s.rawPtr:end]) {
			t.Fatalf("原有节 %q 的原始数据被改动", s.name)
		}
	}
	// 数据目录[2] 必须指向新节。
	rva, size := m.dataDir(peDirResource)
	if rva != last.rva || size == 0 {
		t.Fatalf("DataDirectory[2] = (0x%X, %d), want (0x%X, >0)", rva, size, last.rva)
	}
	// SizeOfImage 必须覆盖最后一个节。
	if got := binary.LittleEndian.Uint32(out[m.sizeOfImageOff : m.sizeOfImageOff+4]); got < last.rva+last.vsize {
		t.Fatalf("SizeOfImage=0x%X 没有覆盖 .rsrc 结束 RVA 0x%X", got, last.rva+last.vsize)
	}
	// CheckSum 必须为 0（改过字节，旧校验和已失效；未签名 PE 允许为 0）。
	if cs := binary.LittleEndian.Uint32(out[m.checkSumOff : m.checkSumOff+4]); cs != 0 {
		t.Fatalf("CheckSum=0x%X, want 0", cs)
	}

	// 回读：写进去的公司名/产品名/版本必须一模一样地读回来（UTF-16 往返）。
	info, err := ReadPEResourceInfo(out)
	if err != nil {
		t.Fatalf("ReadPEResourceInfo: %v", err)
	}
	if !info.HasVersion || !info.HasResourceDir {
		t.Fatal("回读不到资源目录或版本信息")
	}
	checks := [][3]string{
		{"CompanyName", info.CompanyName, cfg.CompanyName},
		{"ProductName", info.ProductName, cfg.ProductName},
		{"FileDescription", info.FileDescription, cfg.FileDescription},
		{"FileVersion", info.FileVersion, cfg.FileVersion},
		{"ProductVersion", info.ProductVersion, cfg.ProductVersion},
		{"LegalCopyright", info.LegalCopyright, cfg.LegalCopyright},
		{"OriginalFilename", info.OriginalFilename, cfg.OriginalFilename},
		{"InternalName", info.InternalName, cfg.InternalName},
	}
	for _, c := range checks {
		if c[1] != c[2] {
			t.Errorf("%s 回读 = %q, want %q", c[0], c[1], c[2])
		}
	}
	// MAKELONG(MS, LS)：1.4.0.0 → MS=0x00010004, LS=0x00000000。
	if info.FileVersionMS != 0x00010004 || info.FileVersionLS != 0 {
		t.Errorf("FileVersion MS/LS = 0x%08X/0x%08X, want 0x00010004/0x00000000", info.FileVersionMS, info.FileVersionLS)
	}
	if !info.HasFixedFileInfo || info.FixedFileType != vsFileTypeApp {
		t.Errorf("EXE 的 dwFileType = %d, want VFT_APP(%d)", info.FixedFileType, vsFileTypeApp)
	}
	if want := uint32(mustParseTime(t, defaultResourceTimestamp).Unix()); info.TimeDateStamp != want {
		t.Errorf("时间戳 = %d, want 固定基准 %d", info.TimeDateStamp, want)
	}
}

// TestPatchPEResourcesDLLFileType DLL 产物的 dwFileType 必须是 VFT_DLL(2)。
func TestPatchPEResourcesDLLFileType(t *testing.T) {
	out, err := PatchPEResources(simplePatchPE(true), fullResourceConfig())
	if err != nil {
		t.Fatalf("PatchPEResources: %v", err)
	}
	info, err := ReadPEResourceInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.FixedFileType != vsFileTypeDLL {
		t.Fatalf("DLL 的 dwFileType = %d, want VFT_DLL(%d)", info.FixedFileType, vsFileTypeDLL)
	}
}

// TestPatchPEResourcesIdempotent 对同一个 PE 连做两次修补：fixed 策略下必须**逐字节一致**
// （第二次走的是"已有 .rsrc 且装得下 → 原地替换"分支）。
func TestPatchPEResourcesIdempotent(t *testing.T) {
	in := simplePatchPE(false)
	cfg := fullResourceConfig()

	once, err := PatchPEResources(in, cfg)
	if err != nil {
		t.Fatalf("第一次修补：%v", err)
	}
	twice, err := PatchPEResources(once, cfg)
	if err != nil {
		t.Fatalf("第二次修补：%v", err)
	}
	if !bytes.Equal(once, twice) {
		t.Fatalf("两次修补结果不一致：len %d vs %d（幂等性被破坏）", len(once), len(twice))
	}
	if err := VerifyPELayout(twice); err != nil {
		t.Fatalf("第二次修补后结构自检失败：%v", err)
	}
	m1, _ := parsePEPatchImage(once)
	m2, _ := parsePEPatchImage(twice)
	if m1.numSections != m2.numSections {
		t.Fatalf("第二次修补把节数改了：%d → %d（说明没走原地替换分支）", m1.numSections, m2.numSections)
	}
	if len(once) != len(twice) {
		t.Fatalf("第二次修补改了文件长度：%d → %d", len(once), len(twice))
	}
}

// TestPatchPEResourcesInPlaceKeepsSectionCount 已有 .rsrc 且内容变短时，必须原地替换 + 补零，
// 而不是再追加一个节（否则每次改配置都会多一个死节）。
func TestPatchPEResourcesInPlaceKeepsSectionCount(t *testing.T) {
	in := simplePatchPE(false)
	big, err := PatchPEResources(in, fullResourceConfig())
	if err != nil {
		t.Fatal(err)
	}
	mBig, _ := parsePEPatchImage(big)
	secCount := mBig.numSections

	// 换一份字段少得多的配置（内容更短）→ 应当原地替换。
	small := PEResourceConfig{CompanyName: "A", TimestampMode: "keep"}
	out, err := PatchPEResources(big, small)
	if err != nil {
		t.Fatalf("原地替换修补：%v", err)
	}
	mOut, err := parsePEPatchImage(out)
	if err != nil {
		t.Fatal(err)
	}
	if mOut.numSections != secCount {
		t.Fatalf("内容变短后节数 = %d, want %d（应当原地替换）", mOut.numSections, secCount)
	}
	if len(out) != len(big) {
		t.Fatalf("原地替换不该改变文件长度：%d → %d", len(big), len(out))
	}
	info, err := ReadPEResourceInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.CompanyName != "A" {
		t.Fatalf("原地替换后公司名 = %q, want A", info.CompanyName)
	}
	if info.ProductName != "" {
		t.Fatalf("原地替换后不该残留旧字段：ProductName = %q", info.ProductName)
	}
	// 补零：旧内容尾部不能残留上一次的字符串（残留就是静态特征漏点）。
	if bytes.Contains(out, []byte("示例科技")) {
		t.Fatal("原地替换后残留了上一次写入的明文（没有补零）")
	}
}

// TestPatchPEResourcesGrowAppendsSecondRsrc 已有 .rsrc 但**装不下**更大的资源集时：
// 追加一个新的 `.rsrc` 并把数据目录指过去，旧节留着不引用**但内容清零**
// （否则文件里会同时留着两份互相矛盾的公司名 —— 既是静态残留，也是"被人改过"的证据）。
func TestPatchPEResourcesGrowAppendsSecondRsrc(t *testing.T) {
	dir := t.TempDir()
	icoPath := filepath.Join(dir, "app.ico")
	if err := os.WriteFile(icoPath, buildTestICO(), 0o644); err != nil {
		t.Fatal(err)
	}

	// 第一步：只写一个很短的版本信息（.rsrc 很小）。
	small := PEResourceConfig{CompanyName: "A", TimestampMode: "keep"}
	first, err := PatchPEResources(simplePatchPE(false), small)
	if err != nil {
		t.Fatal(err)
	}
	mFirst := mustParsePE(t, first)
	if mFirst.numSections != 3 {
		t.Fatalf("第一次后节数 = %d, want 3", mFirst.numSections)
	}

	// 第二步：换成"图标 + 8 个字段"的大资源集 → 装不下 → 追加第二个 .rsrc。
	big := fullResourceConfig()
	big.IconPath = icoPath
	second, err := PatchPEResources(first, big)
	if err != nil {
		t.Fatalf("追加第二个 .rsrc：%v", err)
	}
	if err := VerifyPELayout(second); err != nil {
		t.Fatalf("结构自检失败：%v", err)
	}
	mSecond := mustParsePE(t, second)
	if mSecond.numSections != 4 {
		t.Fatalf("装不下时应追加一个节：节数 = %d, want 4", mSecond.numSections)
	}
	last := mSecond.sections[3]
	if last.name != resourceSectionName {
		t.Fatalf("最后追加的节名 = %q, want %s", last.name, resourceSectionName)
	}
	// 数据目录必须指向**新**节。
	if rva, _ := mSecond.dataDir(peDirResource); rva != last.rva {
		t.Fatalf("DataDirectory[2] RVA = 0x%X, want 新节 0x%X", rva, last.rva)
	}
	// 旧的 .rsrc（下标 2）必须被清零。
	old := mSecond.sections[2]
	if old.name != resourceSectionName {
		t.Fatalf("第 3 个节名 = %q, want %s", old.name, resourceSectionName)
	}
	for i := old.rawPtr; i < old.rawPtr+old.rawSize; i++ {
		if second[i] != 0 {
			t.Fatalf("被抛弃的旧 .rsrc 没有清零（偏移 0x%X = 0x%X）", i, second[i])
		}
	}
	// 回读到的必须是新资源，且整份文件里不能再出现旧的公司名 "A" 的 UTF-16 形式。
	info, err := ReadPEResourceInfo(second)
	if err != nil {
		t.Fatal(err)
	}
	if info.CompanyName != big.CompanyName {
		t.Fatalf("回读公司名 = %q, want %q", info.CompanyName, big.CompanyName)
	}
	if info.IconCount != 2 || info.GroupIconCount != 1 {
		t.Fatalf("回读图标数 = %d/%d, want 2/1", info.IconCount, info.GroupIconCount)
	}
}

// TestPatchPEResourcesIconRoundTrip 图标：多尺寸 + 两个目录项共用一份图像（去重）。
func TestPatchPEResourcesIconRoundTrip(t *testing.T) {
	dir := t.TempDir()
	icoPath := filepath.Join(dir, "app.ico")
	if err := os.WriteFile(icoPath, buildTestICO(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := fullResourceConfig()
	cfg.IconPath = icoPath

	out, err := PatchPEResources(simplePatchPE(false), cfg)
	if err != nil {
		t.Fatalf("PatchPEResources: %v", err)
	}
	if err := VerifyPELayout(out); err != nil {
		t.Fatalf("结构自检失败：%v", err)
	}
	info, err := ReadPEResourceInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	// buildTestICO 有 3 个目录项，其中两项共用同一份图像 → 2 个 RT_ICON + 1 个 RT_GROUP_ICON。
	if info.IconCount != 2 {
		t.Fatalf("RT_ICON 个数 = %d, want 2（相同图像应去重）", info.IconCount)
	}
	if info.GroupIconCount != 1 {
		t.Fatalf("RT_GROUP_ICON 个数 = %d, want 1", info.GroupIconCount)
	}

	// GRPICONDIR 的 nID 必须都指向存在的 RT_ICON，且 dwBytesInRes 与实际一致。
	entries, err := mustParsePE(t, out).readResourceEntries()
	if err != nil {
		t.Fatal(err)
	}
	iconSizes := map[uint32]int{}
	var group []byte
	for _, e := range entries {
		switch e.typ {
		case rtIcon:
			iconSizes[e.name] = len(e.data)
		case rtGroupIcon:
			group = e.data
		}
	}
	if len(group) < 6 {
		t.Fatal("GRPICONDIR 太短")
	}
	if idType := binary.LittleEndian.Uint16(group[2:4]); idType != 1 {
		t.Fatalf("GRPICONDIR.idType = %d, want 1", idType)
	}
	n := int(binary.LittleEndian.Uint16(group[4:6]))
	if n != 3 {
		t.Fatalf("GRPICONDIR.idCount = %d, want 3（目录项数，含共用图像的两项）", n)
	}
	if len(group) != 6+n*14 {
		t.Fatalf("GRPICONDIR 长度 = %d, want %d", len(group), 6+n*14)
	}
	for i := 0; i < n; i++ {
		e := group[6+i*14 : 6+(i+1)*14]
		id := uint32(binary.LittleEndian.Uint16(e[12:14]))
		want, ok := iconSizes[id]
		if !ok {
			t.Fatalf("GRPICONDIR 第 %d 项的 nID=%d 没有对应的 RT_ICON", i, id)
		}
		if got := int(binary.LittleEndian.Uint32(e[8:12])); got != want {
			t.Fatalf("GRPICONDIR 第 %d 项的 dwBytesInRes=%d，与 RT_ICON(%d)=%d 不一致", i, got, id, want)
		}
	}
}

// TestPatchPEResourcesResourceDirSorted 资源目录项必须按 ID 升序（LdrFindResource 做二分查找）。
func TestPatchPEResourcesResourceDirSorted(t *testing.T) {
	dir := t.TempDir()
	icoPath := filepath.Join(dir, "app.ico")
	if err := os.WriteFile(icoPath, buildTestICO(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := fullResourceConfig()
	cfg.IconPath = icoPath
	out, err := PatchPEResources(simplePatchPE(false), cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := mustParsePE(t, out)
	rva, _ := m.dataDir(peDirResource)
	idx, _ := m.rvaSection(rva)
	sec := m.sections[idx]
	base := int(sec.rawPtr) + int(rva-sec.rva)
	named := int(binary.LittleEndian.Uint16(out[base+12 : base+14]))
	ids := int(binary.LittleEndian.Uint16(out[base+14 : base+16]))
	if named != 0 {
		t.Fatalf("根目录不该有按名字索引的项（NumberOfNamedEntries=%d）", named)
	}
	if ids != 3 {
		t.Fatalf("根目录类型项数 = %d, want 3（RT_ICON/RT_GROUP_ICON/RT_VERSION）", ids)
	}
	prev := uint32(0)
	for i := 0; i < ids; i++ {
		p := base + 16 + i*8
		id := binary.LittleEndian.Uint32(out[p : p+4])
		high := binary.LittleEndian.Uint32(out[p+4:p+8]) & resDirEntryIsDirectory
		if high == 0 {
			t.Fatalf("根目录第 %d 项的 OffsetToData 最高位没置位（不是子目录）", i)
		}
		if i > 0 && id <= prev {
			t.Fatalf("根目录类型项没有按 ID 升序：第 %d 项 id=0x%X ≤ 前一项 0x%X", i, id, prev)
		}
		prev = id
	}
}

// TestPatchPEResourcesTimestampPolicies 三种时间戳策略 + "绝不晚于构建机当前时间"。
func TestPatchPEResourcesTimestampPolicies(t *testing.T) {
	in := simplePatchPE(false)

	// keep：保持 Go 链接器写的 0。
	out, err := PatchPEResources(in, PEResourceConfig{CompanyName: "X", TimestampMode: "keep"})
	if err != nil {
		t.Fatal(err)
	}
	if got := readTimestamp(out); got != 0 {
		t.Fatalf("keep 策略下时间戳 = %d, want 0（保持原样）", got)
	}
	// 空策略 = keep。
	if out2, err := PatchPEResources(in, PEResourceConfig{CompanyName: "X"}); err != nil {
		t.Fatal(err)
	} else if got := readTimestamp(out2); got != 0 {
		t.Fatalf("空策略下时间戳 = %d, want 0（等同 keep）", got)
	}

	// fixed：精确写入配置值。
	fixedTime := "2023-01-02T03:04:05Z"
	out, err = PatchPEResources(in, PEResourceConfig{CompanyName: "X", TimestampMode: "fixed", TimestampFixed: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := readTimestamp(out), uint32(mustParseTime(t, fixedTime).Unix()); got != want {
		t.Fatalf("fixed 时间戳 = %d, want %d", got, want)
	}

	// fixed 配未来时间 → 必须报错（未来时间戳是明显的伪造信号）。
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := PatchPEResources(in, PEResourceConfig{CompanyName: "X", TimestampMode: "fixed", TimestampFixed: future}); err == nil {
		t.Fatal("fixed 配未来时间必须报错")
	} else if !strings.Contains(err.Error(), "晚于构建机当前时间") {
		t.Fatalf("未来时间戳的错误信息应说明原因，实际：%v", err)
	}

	// random：落在 [基准, now] 之内，且**永远不晚于 now**。
	now := time.Now()
	base := mustParseTime(t, defaultResourceTimestamp)
	for i := 0; i < 50; i++ {
		out, err = PatchPEResources(in, PEResourceConfig{CompanyName: "X", TimestampMode: "random"})
		if err != nil {
			t.Fatalf("random 策略失败：%v", err)
		}
		got := time.Unix(int64(readTimestamp(out)), 0).UTC()
		if got.Before(base) || got.After(now) {
			t.Fatalf("random 时间戳 %s 不在 [%s, %s] 区间内", got.Format(time.RFC3339), base.Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}

	// 不认识的策略 → 中文报错。
	if _, err := PatchPEResources(in, PEResourceConfig{CompanyName: "X", TimestampMode: "nonsense"}); err == nil {
		t.Fatal("未知时间戳策略必须报错")
	} else if !strings.Contains(err.Error(), "不认识") {
		t.Fatalf("未知策略的错误信息应说明原因，实际：%v", err)
	}
}

// TestPatchPEResourcesTimestampOnly 只改时间戳（不写任何资源）时不该凭空造出 .rsrc 节。
func TestPatchPEResourcesTimestampOnly(t *testing.T) {
	in := simplePatchPE(false)
	out, err := PatchPEResources(in, PEResourceConfig{TimestampMode: "fixed"})
	if err != nil {
		t.Fatal(err)
	}
	m := mustParsePE(t, out)
	if m.numSections != 2 {
		t.Fatalf("只改时间戳时节数 = %d, want 2（不该追加 .rsrc）", m.numSections)
	}
	if rva, _ := m.dataDir(peDirResource); rva != 0 {
		t.Fatalf("只改时间戳时不该设置资源数据目录，实际 RVA=0x%X", rva)
	}
	if len(out) != len(in) {
		t.Fatalf("只改时间戳不该改变文件长度：%d → %d", len(in), len(out))
	}
	if got, want := readTimestamp(out), uint32(mustParseTime(t, defaultResourceTimestamp).Unix()); got != want {
		t.Fatalf("时间戳 = %d, want 固定基准 %d", got, want)
	}
}

// TestPatchPEResourcesRejectsBadInput 非法输入必须**中文报错并说明原因**，不许静默跳过。
func TestPatchPEResourcesRejectsBadInput(t *testing.T) {
	good := simplePatchPE(false)
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	badICO := buildTestICO()
	badICO[0] = 1 // reserved != 0

	curICO := buildTestICO()
	binary.LittleEndian.PutUint16(curICO[2:4], 2) // type=2 (CUR)

	truncICO := buildTestICO()[:10] // 目录被截断

	oobICO := buildTestICO()
	binary.LittleEndian.PutUint32(oobICO[6+12:6+16], 0xFFFFFF00) // imageOffset 越界

	bigICO := writeFile("big.ico", append(buildTestICO(), bytes.Repeat([]byte{0}, maxIconFileBytes+1)...))

	// 节表被截断（文件刚好到可选头末尾，节表放不下）。
	truncPE := good[:0x178]

	// 头部没有余量：节表刚好顶到第一个节的原始数据。
	tight := buildPatchTestPE([]patchTestSection{
		{name: ".text", data: bytes.Repeat([]byte{0x90}, 0x200)},
		{name: ".rdata", data: bytes.Repeat([]byte{0x41}, 0x200)},
	}, false, false)

	zeroAlign := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(zeroAlign[0x98+32:0x98+36], 0) // SectionAlignment = 0

	cases := []struct {
		name    string
		in      []byte
		cfg     PEResourceConfig
		wantSub string
	}{
		{"不是 PE（没有 MZ）", bytes.Repeat([]byte{'x'}, 128), PEResourceConfig{CompanyName: "X"}, "MZ"},
		{"空输入", nil, PEResourceConfig{CompanyName: "X"}, "输入为空"},
		{"e_lfanew 越界", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[0x3C:0x40], 0xFF000000)
			return b
		}(), PEResourceConfig{CompanyName: "X"}, "e_lfanew"},
		{"没有 PE 签名", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[0x80:0x84], 0)
			return b
		}(), PEResourceConfig{CompanyName: "X"}, "PE\\0\\0"},
		{"可选头魔数不对", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint16(b[0x98:0x9A], 0x0107)
			return b
		}(), PEResourceConfig{CompanyName: "X"}, "迷你 PE"},
		{"节表越界", truncPE, PEResourceConfig{CompanyName: "X"}, "节表越界"},
		{"节数为 0", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint16(b[0x86:0x88], 0)
			return b
		}(), PEResourceConfig{CompanyName: "X"}, "0 个节"},
		{"对齐全为 0", zeroAlign, PEResourceConfig{CompanyName: "X"}, "2 的幂"},
		{"版本号非法", good, PEResourceConfig{FileVersion: "1.2.x"}, "版本号"},
		{"版本号超过 4 段", good, PEResourceConfig{FileVersion: "1.2.3.4.5"}, "最多 4 段"},
		{"图标后缀不是 .ico", good, PEResourceConfig{IconPath: writeFile("icon.png", buildTestICO())}, ".ico"},
		{"图标文件不存在", good, PEResourceConfig{IconPath: filepath.Join(dir, "nope.ico")}, "不可读"},
		{"图标是目录", good, PEResourceConfig{IconPath: dir}, "目录"},
		{"图标超过 1MiB", good, PEResourceConfig{IconPath: bigICO}, "超过上限"},
		{"图标空文件", good, PEResourceConfig{IconPath: writeFile("empty.ico", nil)}, "空文件"},
		{"ICO 保留字段非 0", good, PEResourceConfig{IconPath: writeFile("bad.ico", badICO)}, "保留字段"},
		{"是 CUR 不是 ICO", good, PEResourceConfig{IconPath: writeFile("cur.ico", curICO)}, "光标文件"},
		{"ICO 目录被截断", good, PEResourceConfig{IconPath: writeFile("trunc.ico", truncICO)}, "截断"},
		{"ICO 图像越界", good, PEResourceConfig{IconPath: writeFile("oob.ico", oobICO)}, "越界"},
		{"头部空间不足", tight, PEResourceConfig{CompanyName: "X"}, "头部空间不足"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.cfg.TimestampMode == "" {
				c.cfg.TimestampMode = "keep"
			}
			if c.cfg.IsZero() {
				c.cfg.CompanyName = "X"
			}
			_, err := PatchPEResources(c.in, c.cfg)
			if err == nil {
				t.Fatalf("非法输入「%s」必须报错（不许静默跳过）", c.name)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("错误信息应包含 %q，实际：%v", c.wantSub, err)
			}
			// 错误必须带中文前缀，便于定位来源。
			if !strings.Contains(err.Error(), "PE 资源注入") {
				t.Fatalf("错误信息应带中文前缀「PE 资源注入」，实际：%v", err)
			}
		})
	}
}

// TestVerifyPELayoutCatchesCorruption 自检本身要能抓到坏布局（否则它只是个装饰）。
func TestVerifyPELayoutCatchesCorruption(t *testing.T) {
	good := simplePatchPE(false)
	if err := VerifyPELayout(good); err != nil {
		t.Fatalf("干净的 PE 不该被判坏：%v", err)
	}

	// ① SizeOfImage 太小（没覆盖最后一个节）。
	bad := append([]byte(nil), good...)
	m := mustParsePE(t, bad)
	binary.LittleEndian.PutUint32(bad[m.sizeOfImageOff:m.sizeOfImageOff+4], 0x1000)
	if err := VerifyPELayout(bad); err == nil {
		t.Fatal("SizeOfImage 不够大时必须自检失败")
	}

	// ② 两个节 RVA 重叠。
	bad2 := append([]byte(nil), good...)
	m2 := mustParsePE(t, bad2)
	binary.LittleEndian.PutUint32(bad2[m2.sections[1].hdrOff+12:m2.sections[1].hdrOff+16], m2.sections[0].rva)
	if err := VerifyPELayout(bad2); err == nil {
		t.Fatal("节 RVA 重叠时必须自检失败")
	}

	// ③ SizeOfHeaders 没覆盖节表。
	bad3 := append([]byte(nil), good...)
	m3 := mustParsePE(t, bad3)
	binary.LittleEndian.PutUint32(bad3[m3.sizeOfHeadersOff:m3.sizeOfHeadersOff+4], 0x100)
	if err := VerifyPELayout(bad3); err == nil {
		t.Fatal("SizeOfHeaders 没覆盖节表时必须自检失败")
	}

	// ④ 资源目录被指向一个越界 RVA。
	patched, err := PatchPEResources(good, fullResourceConfig())
	if err != nil {
		t.Fatal(err)
	}
	bad4 := append([]byte(nil), patched...)
	m4 := mustParsePE(t, bad4)
	m4.writeDataDir(bad4, peDirResource, 0x7F000000, 0x100)
	if err := VerifyPELayout(bad4); err == nil {
		t.Fatal("资源目录 RVA 不落在任何节内时必须自检失败")
	}
}

// TestPatchPEResourcesNoNewDependency 钉住"只用标准库"：本文件不得 import 任何第三方包。
func TestPatchPEResourcesNoNewDependency(t *testing.T) {
	src, err := os.ReadFile("patch_resources.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, bad := range []string{"github.com/", "golang.org/x/", "gopkg.in/"} {
		if strings.Contains(text, `"`+bad) {
			t.Fatalf("patch_resources.go 引入了第三方依赖 %q（本项要求纯标准库实现）", bad)
		}
	}
}

// ─── 测试辅助 ───────────────────────────────────────────────────────────────

// buildTestICO 造一个"3 个目录项、其中两项共用同一份图像"的合法 ICO：
// 16x16 项、32x32 项（与前者共用字节）、48x48 PNG 项（PNG 原样搬运，不解码）。
func buildTestICO() []byte {
	shared := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 8) // 32 字节的假图像数据
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0x7F}, 40)...)

	hdr := make([]byte, 6)
	binary.LittleEndian.PutUint16(hdr[2:4], 1) // type = 1 (ICON)
	binary.LittleEndian.PutUint16(hdr[4:6], 3) // count = 3

	dir := make([]byte, 3*16)
	put := func(i int, w, h, colors byte, planes, bits uint16, size, off uint32) {
		e := dir[i*16 : (i+1)*16]
		e[0], e[1], e[2], e[3] = w, h, colors, 0
		binary.LittleEndian.PutUint16(e[4:6], planes)
		binary.LittleEndian.PutUint16(e[6:8], bits)
		binary.LittleEndian.PutUint32(e[8:12], size)
		binary.LittleEndian.PutUint32(e[12:16], off)
	}
	dataOff := uint32(6 + 3*16)
	put(0, 16, 16, 0, 1, 32, uint32(len(shared)), dataOff)                  // 16x16，共用
	put(1, 32, 32, 0, 1, 32, uint32(len(shared)), dataOff)                  // 32x32，指向同一份
	put(2, 48, 48, 0, 1, 32, uint32(len(png)), dataOff+uint32(len(shared))) // 48x48 PNG

	out := append(append(append([]byte{}, hdr...), dir...), shared...)
	return append(out, png...)
}

// readTimestamp 读 COFF 头的 TimeDateStamp。
func readTimestamp(data []byte) uint32 {
	m, err := parsePEPatchImage(data)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(data[m.timeStampOff : m.timeStampOff+4])
}

// mustParsePE 解析 PE，失败直接 Fatal（测试辅助）。
func mustParsePE(t *testing.T, data []byte) *pePatchImage {
	t.Helper()
	m, err := parsePEPatchImage(data)
	if err != nil {
		t.Fatalf("parsePEPatchImage: %v", err)
	}
	return m
}

// mustParseTime 解析 RFC3339 时间，失败直接 Fatal（测试辅助）。
func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	got, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", s, err)
	}
	return got
}

// TestResourcePresetNeutral 钉住"中性预设"的语义（v1.4.0 S3 第二批）。
//
// 为什么要单测预设而不是只测补丁本身：预设是**操作员一键套用的默认外观**，它的三条语义
// （① 只填空白字段、② 不猜版本号、③ 名字不认识就报错而不是静默跳过）一旦被改坏，
// 表现都是"构建成功但外观不对/没资源"这种哑失败，只能靠单测拦住。
func TestResourcePresetNeutral(t *testing.T) {
	t.Run("展开成自有品牌字段", func(t *testing.T) {
		opts := BuildOptions{Format: "exe", ResourcePreset: ResourcePresetNeutral}
		cfg, err := ResourceConfigForOptions(&opts)
		if err != nil {
			t.Fatalf("ResourceConfigForOptions: %v", err)
		}
		if cfg.IsZero() {
			t.Fatal("中性预设展开后配置不该是零值（否则等于没打资源）")
		}
		if cfg.CompanyName != neutralPresetCompany || cfg.ProductName != neutralPresetCompany {
			t.Fatalf("公司名/产品名应来自中性预设，得到 company=%q product=%q", cfg.CompanyName, cfg.ProductName)
		}
		if !strings.Contains(cfg.FileDescription, "ToShell") {
			t.Fatalf("文件描述应带自有品牌标识，得到 %q", cfg.FileDescription)
		}
		if cfg.OriginalFilename != "toshell-agent.exe" {
			t.Fatalf("exe 的原始文件名应为 toshell-agent.exe，得到 %q", cfg.OriginalFilename)
		}
		// 预设不猜版本号：留空 → 由 buildVersionResource 落到默认 1.0.0.0（而不是硬编码版本）。
		if cfg.FileVersion != "" || cfg.ProductVersion != "" {
			t.Fatalf("预设不该猜版本号，得到 file=%q product=%q", cfg.FileVersion, cfg.ProductVersion)
		}
		// 时间戳预设为 fixed（确定性、可复现，且比链接器默认的 0 更像一次真实发布）。
		if cfg.TimestampMode != timestampModeFixed {
			t.Fatalf("预设的时间戳策略应为 %q，得到 %q", timestampModeFixed, cfg.TimestampMode)
		}
	})

	t.Run("dll 的原始文件名跟着格式走", func(t *testing.T) {
		opts := BuildOptions{Format: "dll", ResourcePreset: ResourcePresetNeutral}
		cfg, err := ResourceConfigForOptions(&opts)
		if err != nil {
			t.Fatalf("ResourceConfigForOptions: %v", err)
		}
		if cfg.OriginalFilename != "toshell-agent.dll" {
			t.Fatalf("dll 的原始文件名应为 toshell-agent.dll，得到 %q", cfg.OriginalFilename)
		}
	})

	t.Run("显式字段永远优先", func(t *testing.T) {
		opts := BuildOptions{
			Format:                "exe",
			ResourcePreset:        ResourcePresetNeutral,
			ResourceCompanyName:   "Acme Labs",
			ResourceFileVersion:   "9.9.9.9",
			ResourceTimestampMode: "keep",
		}
		cfg, err := ResourceConfigForOptions(&opts)
		if err != nil {
			t.Fatalf("ResourceConfigForOptions: %v", err)
		}
		if cfg.CompanyName != "Acme Labs" {
			t.Fatalf("显式公司名被预设覆盖了：%q", cfg.CompanyName)
		}
		if cfg.FileVersion != "9.9.9.9" {
			t.Fatalf("显式版本号被丢弃：%q", cfg.FileVersion)
		}
		if cfg.TimestampMode != "keep" {
			t.Fatalf("显式时间戳策略被预设覆盖：%q", cfg.TimestampMode)
		}
		// 没显式给的字段仍由预设补齐（部分覆盖，而不是"有一个显式值就整体不套预设"）。
		if cfg.ProductName != neutralPresetCompany {
			t.Fatalf("未显式给的产品名应仍由预设补齐，得到 %q", cfg.ProductName)
		}
	})

	t.Run("未知预设报错且必须进入修补分支", func(t *testing.T) {
		opts := BuildOptions{Format: "exe", ResourcePreset: "neurtal"} // 故意拼错
		if _, err := ResourceConfigForOptions(&opts); err == nil {
			t.Fatal("未知预设必须报错（否则会得到「构建成功但没资源」的哑结果）")
		}
		// shouldPatchResources 必须为 true：只有真的进入修补分支，构建才会把上面这个错误抛出来。
		// 若这里返回 false，拼错预设名的请求会被静默当成"没配资源"。
		if !shouldPatchResources(&opts, "windows") {
			t.Fatal("未知预设时 shouldPatchResources 必须为 true，才能让构建报错而不是静默跳过")
		}
	})

	t.Run("零值仍然是零值", func(t *testing.T) {
		opts := BuildOptions{Format: "exe"}
		if cfg, err := ResourceConfigForOptions(&opts); err != nil || !cfg.IsZero() {
			t.Fatalf("未配置资源时必须是零值配置（默认逐字节不变），得到 err=%v cfg=%+v", err, cfg)
		}
		if shouldPatchResources(&opts, "windows") {
			t.Fatal("未配置资源时不该进入修补分支")
		}
		// 预设名空串不是错误。
		empty := BuildOptions{Format: "exe", ResourcePreset: "  "}
		if _, err := ResourceConfigForOptions(&empty); err != nil {
			t.Fatalf("空预设名不该报错：%v", err)
		}
	})

	t.Run("预设能真的写进 PE 并读回来", func(t *testing.T) {
		opts := BuildOptions{Format: "exe", ResourcePreset: ResourcePresetNeutral}
		cfg, err := ResourceConfigForOptions(&opts)
		if err != nil {
			t.Fatalf("ResourceConfigForOptions: %v", err)
		}
		pe := buildPatchTestPE([]patchTestSection{{name: ".text", data: make([]byte, 512)}}, false, true)
		out, err := PatchPEResources(pe, cfg)
		if err != nil {
			t.Fatalf("PatchPEResources: %v", err)
		}
		info, err := ReadPEResourceInfo(out)
		if err != nil {
			t.Fatalf("ReadPEResourceInfo: %v", err)
		}
		if info.CompanyName != neutralPresetCompany || info.ProductName != neutralPresetCompany {
			t.Fatalf("回读的公司名/产品名不符：company=%q product=%q", info.CompanyName, info.ProductName)
		}
		if info.FileVersion != "1.0.0.0" {
			t.Fatalf("预设留空版本时应落到默认 1.0.0.0，得到 %q", info.FileVersion)
		}
		if readTimestamp(out) == 0 {
			t.Fatal("预设的 fixed 时间戳应写进 COFF 头（不该还是 0）")
		}
	})
}

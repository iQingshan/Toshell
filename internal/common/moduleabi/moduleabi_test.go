package moduleabi

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// ─── ABI 契约的一致性单测 ─────────────────────────────────────────────────────
//
// 这组用例存在的唯一理由：ABI 是**三份副本**（本包 Go 结构 / C 头 tsh_module.h /
// 植入端 tshModuleCtx 镜像），而字段错位的后果是"加载了但读到垃圾指针"。
// 编译器管不到跨语言、跨 module 的副本，只能靠测试把它们钉在一起。
//
// 测试只做静态文本比对（不编译 C、不跑植入端），因此 CI 上不需要 gcc。

const (
	cHeaderRelPath    = "../../../internal/server/builder/implant_c/module/tsh_module.h"
	implantMirrorPath = "../../../internal/server/builder/implant/xload_windows.go"
	releaseMirrorPath = "../../../release/implant/xload_windows.go"
)

// expectedCFields 是"C 字段名 → Go 字段名"的显式映射。
//
// 刻意不用 snake→Camel 自动转换：ABIVersion / SessionIDLo / ArgsJSON / TokenFNV
// 这些缩写按通用规则会推错，自动转换只会让"字段名对不上"变成"测试自己写错"。
// 显式映射下，新增字段必须同时改两处（这正是我们想要的手续）。
var expectedCFields = []struct{ C, Go string }{
	{"struct_size", "StructSize"},
	{"abi_version", "ABIVersion"},
	{"session_id_lo", "SessionIDLo"},
	{"session_id_hi", "SessionIDHi"},
	{"args_json", "ArgsJSON"},
	{"args_len", "ArgsLen"},
	{"flags", "Flags"},
	{"out_buf", "OutBuf"},
	{"out_cap", "OutCap"},
	{"out_len", "OutLen"},
	{"token_fnv", "TokenFNV"},
	{"reserved", "Reserved"},
	{"host_reserved", "HostReserved"},
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("abs %s: %v", rel, err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("读 %s 失败：%v", abs, err)
	}
	return string(data)
}

// cStructFields 从 C 头里抽出 tsh_module_ctx 的字段名（按声明顺序）。
func cStructFields(t *testing.T, src string) []string {
	t.Helper()
	start := strings.Index(src, "typedef struct tsh_module_ctx {")
	if start < 0 {
		t.Fatal("tsh_module.h 里找不到 typedef struct tsh_module_ctx")
	}
	rest := src[start:]
	end := strings.Index(rest, "} tsh_module_ctx;")
	if end < 0 {
		t.Fatal("tsh_module_ctx 结构体没有结束标记")
	}
	body := rest[:end]
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "typedef struct") {
			continue
		}
		// 去掉行内注释后，取 `类型 名字;`
		if i := strings.Index(line, "/*"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.HasSuffix(line, ";") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSpace(line), ";")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[len(fields)-1]
		name = strings.TrimPrefix(name, "*")
		out = append(out, name)
	}
	return out
}

// goStructFields 从植入端镜像里抽出 tshModuleCtx 的字段名（按声明顺序）。
func goStructFields(t *testing.T, src string) []string {
	t.Helper()
	start := strings.Index(src, "type tshModuleCtx struct {")
	if start < 0 {
		t.Fatal("植入端镜像里找不到 type tshModuleCtx struct")
	}
	rest := src[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatal("tshModuleCtx 结构体没有结束标记")
	}
	body := rest[len("type tshModuleCtx struct {"):end]
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}

// TestCHeaderMatchesGoContract C 头与本包结构体的字段顺序/命名必须一致。
func TestCHeaderMatchesGoContract(t *testing.T) {
	src := repoFile(t, cHeaderRelPath)
	got := cStructFields(t, src)
	want := make([]string, 0, len(expectedCFields))
	for _, f := range expectedCFields {
		want = append(want, f.C)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tsh_module.h 字段顺序不符：\n got=%v\nwant=%v", got, want)
	}
	// Go 侧结构体的字段名与顺序必须与映射表一致。
	names := FieldNames()
	wantGo := make([]string, 0, len(expectedCFields))
	for _, f := range expectedCFields {
		wantGo = append(wantGo, f.Go)
	}
	if !reflect.DeepEqual(names, wantGo) {
		t.Fatalf("moduleabi.FieldNames() 与 C 头映射表不符：\n got=%v\nwant=%v", names, wantGo)
	}
	// 反向确认反射真能看到这些字段（FieldNames 是手写列表，可能和结构体漂移）。
	typ := reflect.TypeOf(Ctx{})
	if typ.NumField() != len(names) {
		t.Fatalf("Ctx 有 %d 个字段，FieldNames 有 %d 个", typ.NumField(), len(names))
	}
	for i, n := range names {
		if typ.Field(i).Name != n {
			t.Fatalf("Ctx 第 %d 个字段是 %s，FieldNames 说是 %s", i, typ.Field(i).Name, n)
		}
	}
}

// TestImplantMirrorsMatchContract 植入端镜像（两份：builder/implant 与 release/implant）
// 必须与本包契约一致，且两份逐字节一致。
func TestImplantMirrorsMatchContract(t *testing.T) {
	want := FieldNames()
	for _, rel := range []string{implantMirrorPath, releaseMirrorPath} {
		src := repoFile(t, rel)
		got := goStructFields(t, src)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s 的 tshModuleCtx 字段不符：\n got=%v\nwant=%v", rel, got, want)
		}
		// 版本常量三处一致
		if !strings.Contains(src, "moduleABIVersion uint32 = 1") {
			t.Fatalf("%s 的 moduleABIVersion 与 moduleabi.Version=%d 不一致（三处必须同步）", rel, Version)
		}
	}
	// 两份镜像逐字节一致（写文件时如果只改了一份，这里立刻炸）。
	a := repoFile(t, implantMirrorPath)
	b := repoFile(t, releaseMirrorPath)
	if a != b {
		t.Fatal("internal/server/builder/implant 与 release/implant 的 xload_windows.go 不一致（模板必须两份镜像逐字节相同）")
	}
}

// TestCHeaderVersionAndCodes C 头的版本与返回码必须与本包一致。
func TestCHeaderVersionAndCodes(t *testing.T) {
	src := repoFile(t, cHeaderRelPath)
	if !strings.Contains(src, "#define TSH_MODULE_ABI_VERSION 1u") {
		t.Fatalf("tsh_module.h 的 TSH_MODULE_ABI_VERSION 与 moduleabi.Version=%d 不一致", Version)
	}
	for _, code := range []string{"TSH_MOD_OK            0", "TSH_MOD_ERR_ABI      (-1)", "TSH_MOD_ERR_ARGS     (-2)",
		"TSH_MOD_ERR_DENIED   (-3)", "TSH_MOD_ERR_OUTPUT   (-4)", "TSH_MOD_ERR_PANIC    (-5)", "TSH_MOD_ERR_HOST     (-6)"} {
		if !strings.Contains(src, code) {
			t.Errorf("tsh_module.h 缺少返回码定义 %q（与本包 codeMessages 必须一一对应）", code)
		}
	}
	// 导出名一致
	for _, name := range []string{ExportABI, ExportMain, ExportName, ExportError} {
		if !strings.Contains(src, name) {
			t.Errorf("tsh_module.h 未提及导出名 %s", name)
		}
	}
}

// TestCtxSessionIDRoundTrip 会话 id 拆 lo/hi 后可无损拼回（32/64 位都只用到 4 字节字段）。
func TestCtxSessionIDRoundTrip(t *testing.T) {
	for _, id := range []uint64{0, 1, 0xDEADBEEF, 0x123456789ABCDEF0, ^uint64(0)} {
		c := Ctx{SessionIDLo: uint32(id), SessionIDHi: uint32(id >> 32)}
		if got := c.SessionID(); got != id {
			t.Fatalf("SessionID 往返失败：%x != %x", got, id)
		}
	}
}

// TestArgumentHeaderValidate 参数头自检（服务端与植入端共用同一口径）。
func TestArgumentHeaderValidate(t *testing.T) {
	good := ArgumentHeader{
		ModuleID: "cred_probe", Token: strings.Repeat("a", 32),
		SHA256: strings.Repeat("b", 64), Size: 4096, ABI: Version,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("合法头被拒：%v", err)
	}

	cases := []struct {
		name   string
		mutate func(h *ArgumentHeader)
		want   string // 错误文案必须包含的关键字（可判定，不依赖整句）
	}{
		{"缺 token", func(h *ArgumentHeader) { h.Token = "" }, "token"},
		{"缺 module_id", func(h *ArgumentHeader) { h.ModuleID = "" }, "module_id"},
		{"sha256 非 hex", func(h *ArgumentHeader) { h.SHA256 = strings.Repeat("z", 64) }, "non-hex"},
		{"sha256 长度错", func(h *ArgumentHeader) { h.SHA256 = "abcd" }, "64 hex"},
		{"size 非正", func(h *ArgumentHeader) { h.Size = 0 }, "positive"},
		{"size 超限", func(h *ArgumentHeader) { h.Size = MaxModuleSize + 1 }, "exceeds"},
		{"abi 版本不符", func(h *ArgumentHeader) { h.ABI = Version + 1 }, "abi mismatch"},
		{"args 超长", func(h *ArgumentHeader) { h.ArgsJSON = strings.Repeat("x", MaxArgsLen+1) }, "too large"},
	}
	for _, c := range cases {
		h := good
		c.mutate(&h)
		err := h.Validate()
		if err == nil {
			t.Fatalf("%s：期望拒绝，实际通过", c.name)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：错误文案 %q 未包含 %q（失败路径必须可判定）", c.name, err.Error(), c.want)
		}
	}
}

// TestCodeMessageCoversAllCodes 每个返回码都必须有中文说明（未知码也要有兜底文案）。
func TestCodeMessageCoversAllCodes(t *testing.T) {
	for _, code := range []int32{CodeOK, CodeErrABI, CodeErrArgs, CodeErrDenied, CodeErrOutput, CodeErrPanic, CodeErrHost} {
		if strings.TrimSpace(CodeMessage(code)) == "" {
			t.Errorf("返回码 %d 没有文案", code)
		}
	}
	if msg := CodeMessage(-999); !strings.Contains(msg, "-999") {
		t.Errorf("未知返回码文案应带码值，实际 %q", msg)
	}
}

// TestBlobFrameRoundTrip 二进制帧编解码往返 + 各种畸形帧必须被拒。
func TestBlobFrameRoundTrip(t *testing.T) {
	blob := make([]byte, 0x1234)
	for i := range blob {
		blob[i] = byte(i)
	}
	h := &ArgumentHeader{
		ModuleID: "cred_probe", Token: strings.Repeat("c", 32),
		SHA256: strings.Repeat("d", 64), Size: len(blob), ABI: Version,
	}
	frame, err := EncodeBlobFrame(h, blob)
	if err != nil {
		t.Fatalf("EncodeBlobFrame: %v", err)
	}
	gotH, gotBlob, err := DecodeBlobFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBlobFrame: %v", err)
	}
	if gotH.ModuleID != h.ModuleID || gotH.Token != h.Token || gotH.SHA256 != h.SHA256 || gotH.ABI != h.ABI || gotH.Size != h.Size {
		t.Fatalf("帧头往返不一致：%+v vs %+v", gotH, h)
	}
	if !reflect.DeepEqual(gotBlob, blob) {
		t.Fatal("帧内字节往返不一致")
	}

	// 畸形帧：太短 / 头长越界 / 头不是 JSON / 字节数与声明不符
	bad := [][]byte{
		{},
		{0, 0, 0},
		append([]byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte("{}")...),
		append([]byte{0, 0, 0, 2}, []byte("{{")...),
	}
	for i, b := range bad {
		if _, _, err := DecodeBlobFrame(b); err == nil {
			t.Errorf("畸形帧 #%d 未被拒绝", i)
		}
	}
	// 声明长度与实际不符（把 blob 截掉 1 字节）
	if _, _, err := DecodeBlobFrame(frame[:len(frame)-1]); err == nil {
		t.Error("字节数少于声明时未被拒绝")
	}
	// 空 blob / 超限 blob 不可编码
	if _, err := EncodeBlobFrame(h, nil); err == nil {
		t.Error("空 blob 未被拒绝")
	}
	huge := make([]byte, MaxModuleSize+1)
	if _, err := EncodeBlobFrame(&ArgumentHeader{ModuleID: "x", Token: "y", SHA256: strings.Repeat("e", 64), Size: len(huge), ABI: Version}, huge); err == nil {
		t.Error("超限 blob 未被拒绝")
	}
}

// TestFNV1a32Stable token 摘要在宿主与模块之间必须是同一个函数（这里锁住实现，
// 免得有人"顺手"换成别的哈希导致模块侧的审计关联失效）。
func TestFNV1a32Stable(t *testing.T) {
	cases := map[string]uint32{
		"":       2166136261,
		"a":      0xe40c292c,
		"foobar": 0xbf9cf968,
	}
	for in, want := range cases {
		if got := FNV1a32(in); got != want {
			t.Errorf("FNV1a32(%q) = 0x%08x, want 0x%08x", in, got, want)
		}
	}
}

// TestModuleIDRegexInHeaderOnly 占位：C 模块源码必须 include 本头文件（否则改了 ABI 也不会被编译期断言拦住）。
func TestExampleModuleIncludesHeader(t *testing.T) {
	src := repoFile(t, "../../../internal/server/builder/implant_c/module/cred_probe.c")
	if !regexp.MustCompile(`#include\s+"tsh_module\.h"`).MatchString(src) {
		t.Error("cred_probe.c 没有 include tsh_module.h：编译期布局断言不会生效")
	}
}

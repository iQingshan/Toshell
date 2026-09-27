package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toshell/internal/common/moduleabi"
)

// ─── 校验链纯函数单测（不联网、不需要真实植入端）────────────────────────────
//
// 覆盖：manifest 解析 / sha256 比对（硬拦）/ 架构归一与匹配 / OS 匹配 / 版本握手 /
// 一次性 token 的签发-核销-过期-复用-越权。

// blobOf 造一份"看起来像 PE"的字节（校验链里的纯函数不看内容，只看哈希/大小）。
func blobOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func validEntry(blob []byte) Entry {
	return Entry{
		ID: "cred_probe", Name: "示例模块", File: "cred_probe.dll",
		SHA256: shaOf(blob), Size: int64(len(blob)), ABI: moduleabi.Version,
		OS: "windows", Arch: "386", Entry: moduleabi.ExportMain,
	}
}

func TestParseManifestValid(t *testing.T) {
	blob := blobOf(1024)
	m := Manifest{Version: ManifestVersion, Modules: []Entry{validEntry(blob)}}
	data, _ := json.Marshal(m)
	got, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("合法清单被拒：%v", err)
	}
	if len(got.Modules) != 1 || got.Modules[0].ID != "cred_probe" {
		t.Fatalf("解析结果不对：%+v", got)
	}
}

func TestParseManifestRejects(t *testing.T) {
	blob := blobOf(64)
	good := validEntry(blob)
	base := func(mut func(e *Entry)) []byte {
		e := good
		mut(&e)
		data, _ := json.Marshal(Manifest{Version: ManifestVersion, Modules: []Entry{e}})
		return data
	}
	cases := []struct {
		name  string
		data  []byte
		want  string
		code  string
		field string
	}{
		{"非 JSON", []byte("{"), "不是合法 JSON", CodeManifestInvalid, ""},
		{"版本不认识", []byte(`{"version":99,"modules":[]}`), "不被支持", CodeManifestInvalid, ""},
		{"缺 id", base(func(e *Entry) { e.ID = "" }), "缺少 id", CodeManifestInvalid, ""},
		{"缺文件", base(func(e *Entry) { e.File = "" }), "缺少 file", CodeManifestInvalid, ""},
		{"路径穿越", base(func(e *Entry) { e.File = `..\..\windows\system32\evil.dll` }), "只能是模块目录下的文件名", CodeManifestInvalid, ""},
		{"哈希长度错", base(func(e *Entry) { e.SHA256 = "abc" }), "64 位 hex", CodeManifestInvalid, ""},
		{"哈希非 hex", base(func(e *Entry) { e.SHA256 = strings.Repeat("z", 64) }), "非 hex", CodeManifestInvalid, ""},
		{"大小非正", base(func(e *Entry) { e.Size = 0 }), "必须为正数", CodeManifestInvalid, ""},
		{"大小超限", base(func(e *Entry) { e.Size = moduleabi.MaxModuleSize + 1 }), "超过上限", CodeManifestInvalid, ""},
		{"abi 版本不符", base(func(e *Entry) { e.ABI = 99 }), "abi", CodeABIMismatch, ""},
		{"缺 arch", base(func(e *Entry) { e.Arch = "" }), "缺少 arch", CodeManifestInvalid, ""},
		{"缺 os", base(func(e *Entry) { e.OS = "" }), "缺少 os", CodeManifestInvalid, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseManifest(c.data)
			if err == nil {
				t.Fatal("期望拒绝，实际通过")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
				t.Errorf("错误文案 %q 未包含 %q", err.Error(), c.want)
			}
			if c.code != "" && ErrorCode(err) != c.code {
				t.Errorf("错误码 = %q, want %q", ErrorCode(err), c.code)
			}
		})
	}
}

func TestParseManifestRejectsDuplicateID(t *testing.T) {
	blob := blobOf(64)
	e := validEntry(blob)
	data, _ := json.Marshal(Manifest{Version: ManifestVersion, Modules: []Entry{e, e}})
	_, err := ParseManifest(data)
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复 id 未被拒：%v", err)
	}
}

// TestVerifyBytesHashMismatchIsHardReject 哈希不符必须硬拦 —— 这条是本次改动的
// 核心安全断言：绝不允许"警告后继续"。
func TestVerifyBytesHashMismatchIsHardReject(t *testing.T) {
	blob := blobOf(2048)
	e := validEntry(blob)
	if err := e.VerifyBytes(blob); err != nil {
		t.Fatalf("一致时不该报错：%v", err)
	}

	// 1) 字节被替换成同样长度的另一份 → 必须 module_hash_mismatch
	tampered := blobOf(2048)
	tampered[100] ^= 0xFF
	err := e.VerifyBytes(tampered)
	if err == nil {
		t.Fatal("哈希不符时没有拒绝！")
	}
	if ErrorCode(err) != CodeHashMismatch {
		t.Fatalf("错误码 = %q, want %q", ErrorCode(err), CodeHashMismatch)
	}
	if !strings.Contains(err.Error(), "sha256 不符") {
		t.Errorf("文案应说明是哈希不符：%q", err.Error())
	}

	// 2) 长度不同 → module_size_mismatch（先于哈希判定，文案要能区分）
	err = e.VerifyBytes(blob[:len(blob)-1])
	if ErrorCode(err) != CodeSizeMismatch {
		t.Fatalf("长度不符错误码 = %q, want %q", ErrorCode(err), CodeSizeMismatch)
	}

	// 3) 大小写不同的合法哈希仍应通过（hex 大小写不敏感，避免误拦）
	upper := Entry{}
	upper = e
	upper.SHA256 = strings.ToUpper(e.SHA256)
	if err := upper.VerifyBytes(blob); err != nil {
		t.Fatalf("大写哈希被误拦：%v", err)
	}
}

func TestNormalizeArchAndMatchArch(t *testing.T) {
	// 归一化：常见别名必须收敛到同一个值，否则会出现"x86 vs 386 被判不符"的误拦。
	same := [][]string{
		{"386", "x86", "i386", "i686", "32"},
		{"amd64", "x64", "x86_64", "64"},
		{"arm64", "aarch64"},
	}
	for _, group := range same {
		want := NormalizeArch(group[0])
		for _, a := range group {
			if got := NormalizeArch(a); got != want {
				t.Errorf("NormalizeArch(%q) = %q, want %q", a, got, want)
			}
		}
	}
	if NormalizeArch("mips") != "" {
		t.Error("未知架构必须归一成空串（fail-closed）")
	}

	if err := MatchArch("386", "386"); err != nil {
		t.Fatalf("同架构被拒：%v", err)
	}
	if err := MatchArch("x86", "386"); err != nil {
		t.Fatalf("别名应视为相同：%v", err)
	}
	err := MatchArch("amd64", "386")
	if err == nil || ErrorCode(err) != CodeArchMismatch {
		t.Fatalf("架构不符必须拒绝，实际：%v (code=%s)", err, ErrorCode(err))
	}
	if !strings.Contains(err.Error(), "指令集翻译") {
		t.Errorf("文案应解释为什么会崩宿主：%q", err.Error())
	}
	// 宿主架构未知 → 不猜，直接拒绝
	if err := MatchArch("386", ""); ErrorCode(err) != CodeArchMismatch {
		t.Fatalf("宿主架构未知时应拒绝：%v", err)
	}
	// 模块架构无法识别 → 拒绝
	if err := MatchArch("mips", "386"); ErrorCode(err) != CodeArchMismatch {
		t.Fatalf("模块架构无法识别时应拒绝：%v", err)
	}
}

func TestMatchOS(t *testing.T) {
	if err := MatchOS("windows", "Windows 10"); err != nil {
		t.Fatalf("windows 会话被拒：%v", err)
	}
	if err := MatchOS("linux", "linux"); ErrorCode(err) != CodeOSMismatch {
		t.Fatalf("非 windows 模块必须拒绝：%v", err)
	}
	if err := MatchOS("windows", "linux"); ErrorCode(err) != CodeOSMismatch {
		t.Fatalf("OS 不符必须拒绝：%v", err)
	}
}

// ─── Store：load / ReadVerified / 一次性 token ───────────────────────────────

func newTestStore(t *testing.T, blob []byte) (*Store, Entry) {
	t.Helper()
	dir := t.TempDir()
	e := validEntry(blob)
	if err := os.WriteFile(filepath.Join(dir, e.File), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifestFile(dir, &Manifest{Version: ManifestVersion, Modules: []Entry{e}}); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return s, e
}

func TestStoreReadVerified(t *testing.T) {
	blob := blobOf(4096)
	s, e := newTestStore(t, blob)

	got, raw, err := s.ReadVerified(e.ID)
	if err != nil {
		t.Fatalf("ReadVerified: %v", err)
	}
	if got.ID != e.ID || len(raw) != len(blob) {
		t.Fatalf("读出的内容不对：%+v len=%d", got, len(raw))
	}

	// 未登记 → module_not_registered
	if _, _, err := s.ReadVerified("nope"); ErrorCode(err) != CodeModuleNotRegistered {
		t.Fatalf("未登记模块错误码 = %q", ErrorCode(err))
	}

	// 文件被换掉（同样大小、不同内容）→ 必须硬拦
	tampered := blobOf(4096)
	tampered[7] ^= 0x5A
	if err := os.WriteFile(filepath.Join(s.Dir(), e.File), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadVerified(e.ID); ErrorCode(err) != CodeHashMismatch {
		t.Fatalf("文件被替换后错误码 = %q, want %q", ErrorCode(err), CodeHashMismatch)
	}

	// 文件被删 → module_file_missing（清单已登记但文件不在，是**服务端**问题）
	if err := os.Remove(filepath.Join(s.Dir(), e.File)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadVerified(e.ID); ErrorCode(err) != CodeModuleFileMissing {
		t.Fatalf("文件缺失错误码 = %q, want %q", ErrorCode(err), CodeModuleFileMissing)
	}
}

func TestStoreMissingManifestIsEmptyNotError(t *testing.T) {
	// 没有模块目录的服务端必须照常工作（只是没有可下发的模块）。
	s := NewStore(filepath.Join(t.TempDir(), "not-exist"))
	if err := s.Reload(); err != nil {
		t.Fatalf("清单缺失不应报错：%v", err)
	}
	list, err := s.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("空清单应返回空列表：%v %v", list, err)
	}
}

// TestTokenOneShot 一次性语义：同一个 token 第二次使用必须是 token_reused。
func TestTokenOneShot(t *testing.T) {
	blob := blobOf(512)
	s, e := newTestStore(t, blob)

	tok, err := s.IssueTokenFor("sess-1", e)
	if err != nil {
		t.Fatalf("IssueTokenFor: %v", err)
	}
	if len(tok.Value) != 32 {
		t.Fatalf("token 长度 %d，期望 32 位 hex（128 位随机）", len(tok.Value))
	}
	if tok.ModuleID != e.ID || tok.SHA256 != e.SHA256 || tok.Size != e.Size {
		t.Fatalf("token 未绑定模块事实：%+v", tok)
	}

	// 第一次核销：成功
	if _, err := s.ConsumeToken(tok.Value, "sess-1", e.ID); err != nil {
		t.Fatalf("首次核销应成功：%v", err)
	}
	// 第二次：token_reused（这是"重放/重试"的明确信号，必须能区分于 not_found）
	_, err = s.ConsumeToken(tok.Value, "sess-1", e.ID)
	if ErrorCode(err) != CodeTokenReused {
		t.Fatalf("重复使用错误码 = %q, want %q (err=%v)", ErrorCode(err), CodeTokenReused, err)
	}
	if !strings.Contains(err.Error(), "已被使用过") {
		t.Errorf("文案应说明被用过：%q", err.Error())
	}
}

func TestTokenExpiryAndBinding(t *testing.T) {
	blob := blobOf(512)
	s, e := newTestStore(t, blob)

	// 可控时钟：不允许靠 sleep 真实时间（测试要快且确定）。
	now := time.Unix(1700000000, 0)
	s.SetClock(func() time.Time { return now })
	s.SetTokenTTL(30 * time.Second)

	tok, err := s.IssueTokenFor("sess-A", e)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 拿 A 会话的凭据去下发到 B 会话 → token_session_mismatch
	if _, err := s.ConsumeToken(tok.Value, "sess-B", e.ID); ErrorCode(err) != CodeTokenSessionWrong {
		t.Fatalf("会话绑定错误码 = %q, want %q", ErrorCode(err), CodeTokenSessionWrong)
	}
	// 2) 拿绑定了模块 X 的 token 去下发模块 Y → token_module_mismatch。
	//    先造一个 Y 条目并通过 Lookup 走一遍清单（IssueToken 需要清单里有该 id）。
	e2 := validEntry(blobOf(600))
	e2.ID = "other"
	if err := registerEntryForTest(s, e2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeToken(tok.Value, "sess-A", "other"); ErrorCode(err) != CodeTokenModuleWrong {
		t.Fatalf("模块绑定错误码 = %q, want %q", ErrorCode(err), CodeTokenModuleWrong)
	}
	// 3) 越权尝试都不应消耗掉 token（否则一次探测就能让合法下发失败）
	now = now.Add(10 * time.Second)
	if _, err := s.ConsumeToken(tok.Value, "sess-A", e.ID); err != nil {
		t.Fatalf("被拒的尝试不该消耗 token：%v", err)
	}

	// 4) 过期：重新签发一个，时间推过期 → token_expired，且过期后从表里清掉
	tok2, err := s.IssueTokenFor("sess-A", e)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)
	if _, err := s.ConsumeToken(tok2.Value, "sess-A", e.ID); ErrorCode(err) != CodeTokenExpired {
		t.Fatalf("过期错误码 = %q, want %q (err=%v)", ErrorCode(err), CodeTokenExpired, err)
	}
	if _, ok := s.Peek(tok2.Value); ok {
		t.Error("过期 token 应从表里清除（避免内存无界增长与'过期了还留着'的歧义）")
	}
	// 5) 不存在的 token → token_not_found
	if _, err := s.ConsumeToken("deadbeef", "sess-A", e.ID); ErrorCode(err) != CodeTokenNotFound {
		t.Fatalf("不存在错误码 = %q, want %q", ErrorCode(err), CodeTokenNotFound)
	}
}

func TestIssueTokenUnregisteredModule(t *testing.T) {
	s, _ := newTestStore(t, blobOf(128))
	if _, err := s.IssueToken("sess-1", "ghost"); ErrorCode(err) != CodeModuleNotRegistered {
		t.Fatalf("未登记模块签发 token 应被拒：%v", err)
	}
}

// registerEntryForTest 往（已加载的）清单里追加一条并重新加载。
func registerEntryForTest(s *Store, e Entry) error {
	blob := blobOf(600)
	if err := os.WriteFile(filepath.Join(s.Dir(), e.File), blob, 0o644); err != nil {
		return err
	}
	e.SHA256 = shaOf(blob)
	e.Size = int64(len(blob))
	m, err := LoadManifestFile(s.Dir())
	if err != nil {
		return err
	}
	m.Modules = append(m.Modules, e)
	if err := WriteManifestFile(s.Dir(), m); err != nil {
		return err
	}
	return s.Reload()
}

func TestErrorCodesAreStable(t *testing.T) {
	// 错误码是对外契约（HTTP 响应/审计/测试断言都依赖），改名等于破坏调用方。
	want := map[string]string{
		"session": CodeSessionNotFound, "inactive": CodeSessionInactive,
		"unregistered": CodeModuleNotRegistered,
		"hash":         CodeHashMismatch, "size": CodeSizeMismatch,
		"arch": CodeArchMismatch, "os": CodeOSMismatch, "abi": CodeABIMismatch,
		"exports": CodeABIExportsAbsent, "native": CodeNotNative,
		"reused": CodeTokenReused, "expired": CodeTokenExpired,
		"notfound": CodeTokenNotFound,
	}
	for k, v := range want {
		if strings.TrimSpace(v) == "" {
			t.Errorf("%s 的错误码为空", k)
		}
	}
	if CodeHashMismatch != "module_hash_mismatch" || CodeTokenReused != "token_reused" {
		t.Fatal("关键错误码字面量被改动（对外契约）")
	}
}

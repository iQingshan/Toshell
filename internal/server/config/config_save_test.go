package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSaveKeepsUnrelatedFields 守护「读-改-写」语义：
// Save() 只允许改动传入的 key，配置文件中其余字段（未被 SetDefault 声明过的，
// 如 auth.admin_password / auth.api_keys / listener.heartbeat_timeout）必须原样保留。
// 历史 bug：Save() 用 viper.WriteConfig() 序列化合并结果，把这类字段写丢，
// 导致改端口后重启被「首次启动自动生成密码」锁在门外。
func TestSaveKeepsUnrelatedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	original := []byte(`
server:
    api_port: 18081
listener:
    port: 8080
    heartbeat_timeout: 60s
auth:
    enabled: true
    admin_username: admin
    admin_password: "$2a$10$abcdefghijklmnopqrstuv"
    api_keys: test-api-key-not-real
    jwt_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ai:
    enabled: true
    consent_mode: auto
    api_key: sk-secret-should-survive
`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 仅修改监听端口（模拟 Web 设置页保存）
	if err := Save(map[string]interface{}{"listener.port": 38080}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("written file is not valid yaml: %v\n%s", err, raw)
	}

	// 1) 改动生效
	got, _ := nestedGet(m, "listener.port")
	if toInt(got) != 38080 {
		t.Errorf("listener.port = %v, want 38080\nfile:\n%s", got, raw)
	}

	// 2) 未触碰的敏感字段必须仍在
	for _, k := range []string{
		"auth.admin_username",
		"auth.admin_password",
		"auth.api_keys",
		"auth.jwt_key",
		"listener.heartbeat_timeout",
		"ai.consent_mode",
		"ai.api_key",
		"server.api_port",
	} {
		if v, ok := nestedGet(m, k); !ok || v == nil || v == "" {
			t.Errorf("field %q lost after Save()\nfile:\n%s", k, raw)
		}
	}
}

func nestedGet(m map[string]interface{}, key string) (interface{}, bool) {
	cur := interface{}(m)
	for _, part := range strings.Split(key, ".") {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = mm[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return -1
}

// TestSavePreservesCommentsAndOrder 守护「节点树编辑」语义：
// 用户手工维护的注释与字段顺序必须保留（历史缺陷：viper 序列化会重排为字母序并抹掉注释）。
func TestSavePreservesCommentsAndOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	original := "# 顶部说明：这是运维手工维护的配置\n" +
		"server:\n" +
		"    api_port: 18081  # 管理 API 端口\n" +
		"listener:\n" +
		"    port: 8080\n" +
		"auth:\n" +
		"    admin_password: \"$2a$10$abcdefghijklmnopqrstuv\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(map[string]interface{}{"listener.port": 38080}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"# 顶部说明：这是运维手工维护的配置",
		"# 管理 API 端口",
		"admin_password",
		"38080",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("写入后丢失内容 %q\n文件内容:\n%s", want, text)
		}
	}
	// server.api_port 必须在 listener.port 之前（保持原有顺序）
	if strings.Index(text, "api_port") > strings.Index(text, "port: 38080") {
		t.Errorf("字段顺序被打乱（api_port 应在前）\n文件内容:\n%s", text)
	}
}

// TestPersistCreatesMissingFile 守护「凭据必须落盘」：
// 配置文件不存在时也必须被创建并写入内容（历史缺陷：viper.WriteConfig 要求文件已存在，
// 失败后仅打 WARNING，导致每次重启都重新生成随机密码 → 用户被锁在门外）。
func TestPersistCreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "server.yaml")
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Persist(map[string]interface{}{
		"auth.admin_password": "$2a$10$hashhashhash",
		"auth.jwt_key":        "jwt-key-value",
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("配置文件未被创建: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "$2a$10$hashhashhash") || !strings.Contains(text, "jwt-key-value") {
		t.Errorf("凭据未写入配置文件:\n%s", text)
	}
	// 不应残留临时文件
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("残留临时文件: %s", e.Name())
		}
	}
}

// TestPersistNeverWritesExampleFile 守护：绝不把真实密钥写进 *.example 模板。
func TestPersistNeverWritesExampleFile(t *testing.T) {
	dir := t.TempDir()
	example := filepath.Join(dir, "server.yaml.example")
	if err := os.WriteFile(example, []byte("auth:\n    jwt_key: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Load(example)
	if err := Persist(map[string]interface{}{"auth.jwt_key": "real-secret"}); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	raw, _ := os.ReadFile(example)
	if strings.Contains(string(raw), "real-secret") {
		t.Errorf("示例文件被写入真实密钥（不应发生）:\n%s", raw)
	}
	real, err := os.ReadFile(filepath.Join(dir, "server.yaml"))
	if err != nil || !strings.Contains(string(real), "real-secret") {
		t.Errorf("真实密钥未写入 server.yaml: err=%v content=%s", err, real)
	}
}

package listener

import (
	"os"
	"path/filepath"
	"testing"

	"toshell/internal/server/config"
)

// ─── 审计 M5：内嵌 MQTT broker 默认只绑回环 ────────────────────────────────

// TestMQTTEmbeddedBindDefaultsToLoopback 不配 listener.mqtt_embedded_bind 时，
// 内嵌 broker 必须绑 127.0.0.1（而不是历史行为里的 listener.host=0.0.0.0）。
func TestMQTTEmbeddedBindDefaultsToLoopback(t *testing.T) {
	l, err := NewMQTTListener(&config.ListenerConfig{
		EncryptionKey:      "0123456789abcdef0123456789abcdef",
		Port:               1884,
		MQTTEmbeddedBroker: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewMQTTListener: %v", err)
	}
	if got := l.embeddedBrokerBindHost(); got != "127.0.0.1" {
		t.Fatalf("内嵌 broker 默认绑定主机 = %q，want 127.0.0.1", got)
	}
	if got := l.embeddedBrokerAddr(); got != "127.0.0.1:1884" {
		t.Fatalf("内嵌 broker 默认监听地址 = %q，want 127.0.0.1:1884", got)
	}
	// 0.0.0.0 是通配地址，不能拿来连自己 → 客户端必须回落到回环。
	if got := l.embeddedBrokerClientHost(); got != "127.0.0.1" {
		t.Fatalf("客户端连接主机 = %q，want 127.0.0.1", got)
	}
}

// TestMQTTEmbeddedBindExplicit 只有显式配置成别的地址才对外监听；
// 通配地址仍然用回环作为客户端连接目标。
func TestMQTTEmbeddedBindExplicit(t *testing.T) {
	cases := []struct {
		bind       string
		wantAddr   string
		wantClient string
	}{
		{"0.0.0.0", "0.0.0.0:1884", "127.0.0.1"},
		{"192.0.2.10", "192.0.2.10:1884", "192.0.2.10"},
		{"::", "[::]:1884", "127.0.0.1"},
	}
	for _, tc := range cases {
		l, err := NewMQTTListener(&config.ListenerConfig{
			EncryptionKey:      "0123456789abcdef0123456789abcdef",
			Port:               1884,
			MQTTEmbeddedBroker: true,
			MQTTEmbeddedBind:   tc.bind,
		}, nil, nil)
		if err != nil {
			t.Fatalf("NewMQTTListener: %v", err)
		}
		if got := l.embeddedBrokerAddr(); got != tc.wantAddr {
			t.Errorf("bind=%q 监听地址 = %q，want %q", tc.bind, got, tc.wantAddr)
		}
		if got := l.embeddedBrokerClientHost(); got != tc.wantClient {
			t.Errorf("bind=%q 客户端主机 = %q，want %q", tc.bind, got, tc.wantClient)
		}
	}
}

// TestMQTTEmbeddedPortDefault 端口未配置时用 1883（保持既有行为）。
func TestMQTTEmbeddedPortDefault(t *testing.T) {
	l, err := NewMQTTListener(&config.ListenerConfig{
		EncryptionKey:      "0123456789abcdef0123456789abcdef",
		MQTTEmbeddedBroker: true,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.embeddedBrokerAddr(); got != "127.0.0.1:1883" {
		t.Fatalf("默认端口地址 = %q，want 127.0.0.1:1883", got)
	}
}

// TestMQTTEmbeddedBindConfigDefault 配置层默认值：listener.mqtt_embedded_bind
// 必须是 127.0.0.1（生产环境配置不写这一项时也不能绑 0.0.0.0）。
func TestMQTTEmbeddedBindConfigDefault(t *testing.T) {
	// viper 的 WatchConfig 是进程级状态，测试里关掉（生产路径不受影响）。
	config.DisableWatchForTests()

	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("listener:\n    port: 18777\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Listener.MQTTEmbeddedBind != "127.0.0.1" {
		t.Fatalf("listener.mqtt_embedded_bind 默认值 = %q，want 127.0.0.1",
			cfg.Listener.MQTTEmbeddedBind)
	}
	if cfg.Listener.MQTTUsername != "" || cfg.Listener.MQTTPassword != "" {
		t.Fatalf("内嵌 broker 默认不应带账号密码: user=%q pass=%q",
			cfg.Listener.MQTTUsername, cfg.Listener.MQTTPassword)
	}
}

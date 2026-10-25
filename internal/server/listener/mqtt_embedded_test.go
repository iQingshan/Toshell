package listener

import (
	"os"
	"path/filepath"
	"strings"
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

// ─── 审计 M5 fail-closed：非回环 + 缺凭据 = 拒绝启动 ─────────────────────

// TestEmbeddedBrokerBindAllowedMatrix 覆盖判定矩阵：
// 回环+无凭据 → 允许；非回环+缺用户名/口令 → 拒绝；非回环+凭据完整 → 允许；
// 回环+凭据完整 → 允许。
func TestEmbeddedBrokerBindAllowedMatrix(t *testing.T) {
	cases := []struct {
		name    string
		bind    string
		user    string
		pass    string
		wantErr bool
	}{
		{"回环+无凭据", "127.0.0.1", "", "", false},
		{"回环IPv6+无凭据", "::1", "", "", false},
		{"localhost+无凭据", "localhost", "", "", false},
		{"空bind默认回环+无凭据", "", "", "", false},
		{"非回环通配+无凭据", "0.0.0.0", "", "", true},
		{"非回环IPv6通配+无凭据", "::", "", "", true},
		{"指定网卡+无凭据", "192.0.2.10", "", "", true},
		{"非回环+只有用户名", "0.0.0.0", "operator", "", true},
		{"非回环+只有口令", "0.0.0.0", "", "secret", true},
		{"非回环+凭据完整", "0.0.0.0", "operator", "secret", false},
		{"回环+凭据完整", "127.0.0.1", "operator", "secret", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := embeddedBrokerBindAllowed(tc.bind, tc.user, tc.pass)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("bind=%q user=%q pass=%q 本应允许，实际拒绝: %v", tc.bind, tc.user, tc.pass, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("bind=%q user=%q pass=%q 本应拒绝启动", tc.bind, tc.user, tc.pass)
			}
			msg := err.Error()
			if !strings.Contains(msg, "非回环") || !strings.Contains(msg, "mqtt_username/password") {
				t.Fatalf("错误文案未说明 fail-closed 原因: %v", err)
			}
		})
	}
}

// TestMQTTEmbeddedStartRefusesNonLoopbackWithoutCredentials 直接调用 Start：
// bind=0.0.0.0 且无凭据时必须在**创建任何监听**之前失败（fail-closed）。
func TestMQTTEmbeddedStartRefusesNonLoopbackWithoutCredentials(t *testing.T) {
	l, err := NewMQTTListener(&config.ListenerConfig{
		EncryptionKey:      "0123456789abcdef0123456789abcdef",
		Port:               18770,
		MQTTEmbeddedBroker: true,
		MQTTEmbeddedBind:   "0.0.0.0",
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewMQTTListener: %v", err)
	}
	serr := l.Start()
	if serr == nil {
		_ = l.Stop()
		t.Fatal("bind=0.0.0.0 且无凭据时 Start 应拒绝启动")
	}
	if !strings.Contains(serr.Error(), "非回环") || !strings.Contains(serr.Error(), "mqtt_username/password") {
		t.Fatalf("Start 错误文案未说明 fail-closed 原因: %v", serr)
	}
	if l.brokerSrv != nil {
		_ = l.Stop()
		t.Fatal("拒绝启动后仍创建了 broker（不应有任何监听动作）")
	}
}

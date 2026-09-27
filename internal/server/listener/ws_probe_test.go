package listener

import (
	"strings"
	"testing"

	"toshell/internal/server/config"
)

// ─── WebSocket 主动探测面收敛（v1.4.0 S5 第 0 步）相关单测 ─────────────────────

// TestNewListenerWiresWSUpgradePolicy 监听器必须把 listener.ws_path /
// listener.ws_host_allowlist 真正接到传输层的升级策略上（配了不生效最难查）。
func TestNewListenerWiresWSUpgradePolicy(t *testing.T) {
	base := &config.ListenerConfig{
		EncryptionKey: "12345678901234567890123456789012",
	}

	// 默认（不配）：路径必须是默认值 —— 与现役植入端一致。
	l, err := NewListener(base, nil, nil)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	got := l.wsServer.UpgradePolicy()
	if got.Path != "/" {
		t.Fatalf("默认 ws_path=%q，want /（必须与现役植入端一致）", got.Path)
	}
	if len(got.HostAllowlist) != 0 {
		t.Fatalf("默认 Host 名单应为空（向后兼容），got %v", got.HostAllowlist)
	}

	// 显式配置：原样生效。
	cfg := &config.ListenerConfig{
		EncryptionKey:   "12345678901234567890123456789012",
		WSPath:          "/cdn-assets/v2",
		WSHostAllowlist: []string{"cdn.example.com"},
	}
	l2, err := NewListener(cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	got2 := l2.wsServer.UpgradePolicy()
	if got2.Path != "/cdn-assets/v2" {
		t.Fatalf("ws_path=%q，want /cdn-assets/v2", got2.Path)
	}
	if len(got2.HostAllowlist) != 1 || got2.HostAllowlist[0] != "cdn.example.com" {
		t.Fatalf("Host 名单未接线：%v", got2.HostAllowlist)
	}
}

// TestSanitizeLogField 拒绝日志里的可控字段必须被压成"日志安全串"：
// logging 的 json 格式是直接拼字符串的，路径/Host 里出现引号或换行就能
// 撕开日志行（日志注入）。
func TestSanitizeLogField(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/ws", "/ws"},
		{`/ws"}{"level":"error`, `/ws?}{?level?:?error`},
		{"/ws\nInjected", "/ws?Injected"},
		{"/ws\x00\x01", "/ws??"},
		{`C:\path`, `C:?path`},
	}
	for _, tc := range cases {
		if got := sanitizeLogField(tc.in); got != tc.want {
			t.Errorf("sanitizeLogField(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}

	long := sanitizeLogField(strings.Repeat("a", 1000))
	if len(long) > 256+3 {
		t.Errorf("超长字段应被截断，got %d 字节", len(long))
	}
	if !strings.HasSuffix(long, "...") {
		t.Errorf("截断应显式标注省略号，got %q", long[len(long)-8:])
	}
}

// TestSupportsRelayChannel 中继只在 TCP 通道成立；WS/HTTP/MQTT 一律 false，
// 让调用方（relayControlHandler）给出明确错误而不是"回 200 却什么都不发生"。
func TestSupportsRelayChannel(t *testing.T) {
	for _, name := range []string{"tcp", "relay", "relay2", "relay16"} {
		if !SupportsRelayChannel(name) {
			t.Errorf("通道 %q 应支持中继", name)
		}
	}
	for _, name := range []string{"", "websocket", "http", "mqtt", "relayer"} {
		if SupportsRelayChannel(name) {
			t.Errorf("通道 %q 不应被判为支持中继", name)
		}
	}
}

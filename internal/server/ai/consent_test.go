package ai

import (
	"strings"
	"testing"

	"toshell/internal/server/mcp"
)

// TestNormalizeConsentPolicy 策略归一化：三种取值 + 旧键旧值映射 + 未知值 fail-safe。
func TestNormalizeConsentPolicy(t *testing.T) {
	cases := []struct{ in, want string }{
		{"graded", consentPolicyGraded},
		{"all", consentPolicyAll},
		{"off", consentPolicyOff},
		{"", consentPolicyGraded},           // 未配置 = 默认 graded
		{"  graded  ", consentPolicyGraded}, // 首尾空白容错
		{"GRADED", consentPolicyGraded},     // 大小写容错
		{"All", consentPolicyAll},
		{"OFF", consentPolicyOff},
		// v1.3.x 旧值：老配置文件不能因为改名而失效。
		{"auto", consentPolicyOff},      // 旧 auto = 全自动 = 不询问
		{"normal", consentPolicyGraded}, // 旧 normal = 影响会话的操作需同意 = 分级
		{" auto ", consentPolicyOff},
		{"Normal", consentPolicyGraded},
		// 无法识别的值按 graded（要审批）而不是 off（放行）——拼错一个词不该让审批门失效。
		{"bogus", consentPolicyGraded},
		{"true", consentPolicyGraded},
		{"yes", consentPolicyGraded},
		{"全自动", consentPolicyGraded},
	}
	for _, tc := range cases {
		if got := normalizeConsentPolicy(tc.in); got != tc.want {
			t.Errorf("normalizeConsentPolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestKnownConsentPolicy 只有可识别的值（含空=未设置与两个旧值）才不告警。
func TestKnownConsentPolicy(t *testing.T) {
	for _, s := range []string{"", "graded", "all", "off", "auto", "normal", " ALL ", "Off"} {
		if !knownConsentPolicy(s) {
			t.Errorf("knownConsentPolicy(%q) = false，应为 true", s)
		}
	}
	for _, s := range []string{"bogus", "yolo", "graded2", "graed", "全自动"} {
		if knownConsentPolicy(s) {
			t.Errorf("knownConsentPolicy(%q) = true，应为 false（需在启动日志里告警）", s)
		}
	}
}

// TestEffectiveConsentPolicy 新旧键优先级：新键非空时以新键为准，否则回落旧键映射。
func TestEffectiveConsentPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		legacy string
		want   string
	}{
		{"新键非空时优先（即使旧键相反）", "all", "auto", consentPolicyAll},
		{"新键为空回落旧 auto", "", "auto", consentPolicyOff},
		{"新键为空回落旧 normal", "", "normal", consentPolicyGraded},
		{"两个键都空 = 默认 graded", "", "", consentPolicyGraded},
		{"新键仅空白也视为未设置", "   ", "normal", consentPolicyGraded},
		{"新键非法时按 graded", "bogus", "auto", consentPolicyGraded},
		{"旧键非法时按 graded", "", "bogus", consentPolicyGraded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveConsentPolicy(tc.policy, tc.legacy); got != tc.want {
				t.Fatalf("effectiveConsentPolicy(%q, %q) = %q, want %q", tc.policy, tc.legacy, got, tc.want)
			}
		})
	}
}

// TestNeedsConsent 分级审批的判定表：策略 × 等级 → 是否需要用户同意。
//   - graded（默认）：只读免审，confirm/danger 必问；
//   - all：连只读也要问；
//   - off：都不问（危险）；
//   - 旧值 auto/normal 与非法值分别等价 off/graded/graded。
func TestNeedsConsent(t *testing.T) {
	cases := []struct {
		policy string
		level  mcp.Level
		want   bool
	}{
		{consentPolicyGraded, mcp.LevelRead, false},
		{consentPolicyGraded, mcp.LevelConfirm, true},
		{consentPolicyGraded, mcp.LevelDanger, true},

		{consentPolicyAll, mcp.LevelRead, true},
		{consentPolicyAll, mcp.LevelConfirm, true},
		{consentPolicyAll, mcp.LevelDanger, true},

		{consentPolicyOff, mcp.LevelRead, false},
		{consentPolicyOff, mcp.LevelConfirm, false},
		{consentPolicyOff, mcp.LevelDanger, false},

		// 未配置 = 默认 graded。
		{"", mcp.LevelRead, false},
		{"", mcp.LevelConfirm, true},
		{"", mcp.LevelDanger, true},

		// 旧值映射。
		{"auto", mcp.LevelDanger, false},
		{"normal", mcp.LevelRead, false},
		{"normal", mcp.LevelDanger, true},

		// 非法值 → graded（fail-safe）。
		{"bogus", mcp.LevelRead, false},
		{"bogus", mcp.LevelDanger, true},
	}
	for _, tc := range cases {
		if got := needsConsent(tc.policy, tc.level); got != tc.want {
			t.Errorf("needsConsent(%q, %v) = %v, want %v", tc.policy, tc.level, got, tc.want)
		}
	}
}

// TestToolLevelFailClosed 工具等级统一来自注册表，且 fail-closed：
// 未注册的工具按 danger；delegate 无论注册表怎么写都按 danger（v1.3.5 的审批门绕过点）。
func TestToolLevelFailClosed(t *testing.T) {
	if got := toolLevel("session_list"); got != mcp.LevelRead {
		t.Errorf("toolLevel(session_list) = %v, want LevelRead", got)
	}
	if got := toolLevel("exec"); got != mcp.LevelDanger {
		t.Errorf("toolLevel(exec) = %v, want LevelDanger", got)
	}
	if got := toolLevel("file_list"); got != mcp.LevelConfirm {
		t.Errorf("toolLevel(file_list) = %v, want LevelConfirm", got)
	}
	// 未注册/拼错的工具名：fail-closed。
	for _, name := range []string{"some_future_tool_not_in_registry", "exec2", "", "EXEC"} {
		if got := toolLevel(name); got != mcp.LevelDanger {
			t.Errorf("未注册工具 %q 的等级 = %v, want LevelDanger（fail-closed）", name, got)
		}
	}
	// delegate 硬兜底：它驱动剧本在目标侧执行动作，不能被"只读/confirm"豁免。
	if got := toolLevel("delegate"); got != mcp.LevelDanger {
		t.Errorf("toolLevel(delegate) = %v, want LevelDanger", got)
	}
	// isRiskyTool 是 graded 策略下的等价入口（既有调用点与测试沿用）。
	for _, name := range agentToolNames {
		if want := needsConsent(consentPolicyGraded, toolLevel(name)); isRiskyTool(name) != want {
			t.Errorf("isRiskyTool(%q) = %v 与 graded needsConsent = %v 不一致", name, isRiskyTool(name), want)
		}
	}
	if !isRiskyTool("delegate") {
		t.Error("delegate 必须按危险处理（需用户同意）")
	}
	if !isRiskyTool("some_future_tool_not_in_registry") {
		t.Error("未注册的工具必须按危险处理（fail-closed）")
	}
}

// TestConsentRequestAttribution 审批请求必须带上 trace_id / call_id / 等级：
// 只有工具名不足以把"审批弹窗 → 实际执行 → 审计日志"对上（同轮可能多次同类调用）。
func TestConsentRequestAttribution(t *testing.T) {
	tc := ToolCall{ID: "call-42", Type: "function", Function: ToolCallFunc{Name: "delegate", Arguments: `{"playbook_id":"full-recon"}`}}
	args := map[string]string{"playbook_id": "full-recon"}
	req := consentRequestFor("c-token-1", "tr-123-abcd", tc, args)

	if req.Token != "c-token-1" {
		t.Errorf("Token = %q", req.Token)
	}
	if req.TraceID != "tr-123-abcd" {
		t.Errorf("TraceID = %q, want tr-123-abcd", req.TraceID)
	}
	if req.CallID != "call-42" {
		t.Errorf("CallID = %q, want call-42", req.CallID)
	}
	if req.Tool != "delegate" {
		t.Errorf("Tool = %q, want delegate", req.Tool)
	}
	if req.Level != mcp.LevelDanger.String() {
		t.Errorf("Level = %q, want %q", req.Level, mcp.LevelDanger.String())
	}
	if req.Args["playbook_id"] != "full-recon" {
		t.Errorf("Args 未透传：%+v", req.Args)
	}
	if req.Desc == "" || !strings.Contains(req.Desc, "任务流") {
		t.Errorf("delegate 的 Desc 应说明它会驱动剧本动作，得到 %q", req.Desc)
	}

	// 只读工具：等级 read（graded 下不会走到审批，但字段语义必须正确）。
	read := consentRequestFor("c-2", "tr-1-0000",
		ToolCall{ID: "call-1", Function: ToolCallFunc{Name: "session_list"}}, nil)
	if read.Level != mcp.LevelRead.String() {
		t.Errorf("session_list 的 Level = %q, want read", read.Level)
	}
}

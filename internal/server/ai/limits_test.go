package ai

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"toshell/internal/server/config"
	"toshell/internal/server/mcp"
)

// TestShouldStopRun 三处控制循环硬上限（轮次 / 工具调用数 / 墙钟）的触发语义：
// 达到上限即停、未到上限继续、同时触发时原因确定、<=0 表示该维度不设限。
func TestShouldStopRun(t *testing.T) {
	limits := runLimits{MaxTurns: 20, MaxToolCalls: 40, MaxWallclockSec: 900}
	cases := []struct {
		name   string
		usage  runUsage
		limits runLimits
		want   string // "" = 不停止
	}{
		{"全部未达上限", runUsage{Turns: 3, ToolCalls: 5, ElapsedSec: 12}, limits, ""},
		{"轮次差一轮", runUsage{Turns: 19, ToolCalls: 5, ElapsedSec: 12}, limits, ""},
		{"轮次刚好达上限", runUsage{Turns: 20, ToolCalls: 5, ElapsedSec: 12}, limits, stopReasonMaxTurns},
		{"轮次超上限", runUsage{Turns: 25, ToolCalls: 5, ElapsedSec: 12}, limits, stopReasonMaxTurns},
		{"工具调用差一次", runUsage{Turns: 3, ToolCalls: 39, ElapsedSec: 12}, limits, ""},
		{"工具调用刚好达上限", runUsage{Turns: 3, ToolCalls: 40, ElapsedSec: 12}, limits, stopReasonMaxToolCalls},
		{"墙钟差一秒", runUsage{Turns: 3, ToolCalls: 5, ElapsedSec: 899}, limits, ""},
		{"墙钟刚好达上限", runUsage{Turns: 3, ToolCalls: 5, ElapsedSec: 900}, limits, stopReasonMaxWallclock},
		{"墙钟超过上限", runUsage{Turns: 3, ToolCalls: 5, ElapsedSec: 3600}, limits, stopReasonMaxWallclock},
		// 同时触发时顺序固定：墙钟 > 工具调用数 > 轮次（原因必须可断言、可审计）。
		{"三处同时触发取墙钟", runUsage{Turns: 99, ToolCalls: 99, ElapsedSec: 901}, limits, stopReasonMaxWallclock},
		{"工具调用与轮次同时触发取工具调用", runUsage{Turns: 99, ToolCalls: 40, ElapsedSec: 1}, limits, stopReasonMaxToolCalls},
		// limits 里 <=0 = 该维度不设限（limitsFromConfig 不会产出这种值，仅供测试与临时关一项）。
		{"上限为 0 时不设限", runUsage{Turns: 999, ToolCalls: 999, ElapsedSec: 99999}, runLimits{}, ""},
		{"只关轮次上限", runUsage{Turns: 999, ToolCalls: 1, ElapsedSec: 1},
			runLimits{MaxTurns: 0, MaxToolCalls: 40, MaxWallclockSec: 900}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stop, reason := shouldStopRun(tc.usage, tc.limits)
			if tc.want == "" {
				if stop {
					t.Fatalf("不应停止，却得到 stop=true reason=%q", reason)
				}
				if reason != "" {
					t.Fatalf("不停止时 reason 应为空，得到 %q", reason)
				}
				return
			}
			if !stop {
				t.Fatalf("应停止（reason=%s），却得到 stop=false", tc.want)
			}
			if reason != tc.want {
				t.Fatalf("stop_reason = %q, want %q", reason, tc.want)
			}
		})
	}
}

// TestStopReasonConstants 停止原因字符串是写进 run.stop_reason、日志与前端契约的字面量，
// 改名会让审计/前端筛选失效，必须钉死。
func TestStopReasonConstants(t *testing.T) {
	pairs := []struct{ got, want string }{
		{stopReasonMaxTurns, "max_turns"},
		{stopReasonMaxToolCalls, "max_tool_calls"},
		{stopReasonMaxWallclock, "max_wallclock"},
		{stopReasonLoopDetected, "loop_detected"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("stop_reason 常量 = %q, want %q", p.got, p.want)
		}
	}
}

// TestLimitsFromConfig 配置 → 生效上限：缺省/非法值回落默认，run 级 MaxTurns 覆盖配置。
func TestLimitsFromConfig(t *testing.T) {
	// 1) 零值配置（配置文件里没写这三项）→ 全部取默认：20 / 40 / 900。
	if got := limitsFromConfig(config.AIConfig{}, 0); got != (runLimits{MaxTurns: 20, MaxToolCalls: 40, MaxWallclockSec: 900}) {
		t.Fatalf("零值配置解析结果 = %+v, want {20 40 900}", got)
	}
	// 2) 显式配置生效。
	cfg := config.AIConfig{MaxTurns: 7, MaxToolCalls: 11, MaxWallclockSec: 120}
	if got := limitsFromConfig(cfg, 0); got != (runLimits{MaxTurns: 7, MaxToolCalls: 11, MaxWallclockSec: 120}) {
		t.Fatalf("显式配置解析结果 = %+v", got)
	}
	// 3) 负数/0 不允许"关掉上限"，回落默认值（配置失误不能变成无限循环）。
	bad := config.AIConfig{MaxTurns: -1, MaxToolCalls: 0, MaxWallclockSec: -900}
	if got := limitsFromConfig(bad, 0); got != (runLimits{MaxTurns: 20, MaxToolCalls: 40, MaxWallclockSec: 900}) {
		t.Fatalf("非法配置解析结果 = %+v, want 默认值 {20 40 900}", got)
	}
	// 4) run 级 MaxTurns 覆盖（AgentRun.MaxTurns > 0 时优先），其余仍来自配置。
	over := limitsFromConfig(config.AIConfig{MaxTurns: 20, MaxToolCalls: 40, MaxWallclockSec: 900}, 3)
	if over.MaxTurns != 3 || over.MaxToolCalls != 40 || over.MaxWallclockSec != 900 {
		t.Fatalf("run 级覆盖结果 = %+v, want {3 40 900}", over)
	}
	// 5) run 级覆盖为 0/负数时忽略覆盖（用配置值）。
	if got := limitsFromConfig(config.AIConfig{MaxTurns: 9}, 0); got.MaxTurns != 9 {
		t.Fatalf("override=0 时应使用配置轮数，得到 %d", got.MaxTurns)
	}
	if got := limitsFromConfig(config.AIConfig{MaxTurns: 9}, -5); got.MaxTurns != 9 {
		t.Fatalf("override<0 时应使用配置轮数，得到 %d", got.MaxTurns)
	}
}

// TestStopReasonText 预算停止的中文说明必须带上具体数值（用户与模型都要知道"为什么停"）。
func TestStopReasonText(t *testing.T) {
	limits := runLimits{MaxTurns: 20, MaxToolCalls: 40, MaxWallclockSec: 900}
	usage := runUsage{Turns: 20, ToolCalls: 40, ElapsedSec: 901}
	cases := []struct {
		reason string
		needle string
	}{
		{stopReasonMaxTurns, "20"},
		{stopReasonMaxToolCalls, "40"},
		{stopReasonMaxWallclock, "900"},
		{stopReasonLoopDetected, "相同"},
		{stopReasonAwaitConsent, "审批"},
		{"", "停止"},
	}
	for _, tc := range cases {
		got := stopReasonText(tc.reason, usage, limits)
		if got == "" {
			t.Fatalf("reason=%q 的说明为空", tc.reason)
		}
		if !strings.Contains(got, tc.needle) {
			t.Errorf("reason=%q 的说明 %q 未包含 %q", tc.reason, got, tc.needle)
		}
	}
}

// TestLoopSignature 签名 = 工具名 + 规范化参数 JSON 的 sha256 前 16 hex：
// 同工具同参数必相同、任一维度不同必不同、参数书写顺序无关、nil 与空参等价。
func TestLoopSignature(t *testing.T) {
	base := loopSignature("exec", map[string]string{"session_id": "s1", "command": "whoami"})
	if base == "" {
		t.Fatal("签名不应为空")
	}
	if again := loopSignature("exec", map[string]string{"session_id": "s1", "command": "whoami"}); again != base {
		t.Fatalf("同工具同参数的签名不稳定：%q vs %q", base, again)
	}
	// 参数 key 的书写/插入顺序不影响签名（map 序列化按 key 升序）。
	reordered := map[string]string{}
	reordered["command"] = "whoami"
	reordered["session_id"] = "s1"
	if got := loopSignature("exec", reordered); got != base {
		t.Fatalf("参数顺序影响了签名：%q vs %q", base, got)
	}
	// 工具名不同 → 不同签名。
	if loopSignature("run_command", map[string]string{"session_id": "s1", "command": "whoami"}) == base {
		t.Fatal("不同工具的签名不应相同")
	}
	// 参数值不同 → 不同签名。
	if loopSignature("exec", map[string]string{"session_id": "s2", "command": "whoami"}) == base {
		t.Fatal("不同参数的签名不应相同")
	}
	// 参数个数不同 → 不同签名。
	if loopSignature("exec", map[string]string{"session_id": "s1"}) == base {
		t.Fatal("参数不同的签名不应相同")
	}
	// nil 与空参数归一为同一签名（模型可能省略/给空对象）。
	if loopSignature("session_list", nil) != loopSignature("session_list", map[string]string{}) {
		t.Fatal("nil 参数与空参数的签名应一致")
	}
	// 格式：16 位小写 hex。
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(base) {
		t.Fatalf("签名格式应为 16 位 hex，得到 %q", base)
	}
}

// TestLoopGuardAction 防死循环判定：非只读工具第 2 次提示、第 3 次停止；
// **只读工具完全豁免**（两次查同一会话列表是正常行为，不是死循环）。
func TestLoopGuardAction(t *testing.T) {
	cases := []struct {
		name  string
		seen  int
		level mcp.Level
		want  loopAction
	}{
		{"只读第 1 次", 1, mcp.LevelRead, loopOK},
		{"只读第 2 次（豁免）", 2, mcp.LevelRead, loopOK},
		{"只读第 3 次（豁免）", 3, mcp.LevelRead, loopOK},
		{"只读第 10 次（豁免）", 10, mcp.LevelRead, loopOK},
		{"confirm 第 1 次", 1, mcp.LevelConfirm, loopOK},
		{"confirm 第 2 次", 2, mcp.LevelConfirm, loopWarn},
		{"confirm 第 3 次", 3, mcp.LevelConfirm, loopStop},
		{"confirm 第 4 次", 4, mcp.LevelConfirm, loopStop},
		{"danger 第 1 次", 1, mcp.LevelDanger, loopOK},
		{"danger 第 2 次", 2, mcp.LevelDanger, loopWarn},
		{"danger 第 3 次", 3, mcp.LevelDanger, loopStop},
		{"danger 第 99 次", 99, mcp.LevelDanger, loopStop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loopGuardAction(tc.seen, tc.level); got != tc.want {
				t.Fatalf("loopGuardAction(%d, %v) = %v, want %v", tc.seen, tc.level, got, tc.want)
			}
		})
	}
	// 阈值常量与判定必须一致（提示一次不够 → 第 3 次停）。
	if loopWarnAt != 2 || loopStopAt != 3 {
		t.Fatalf("防死循环阈值被改动：warn=%d stop=%d", loopWarnAt, loopStopAt)
	}
}

// TestLoopNudgeAndStopReply 第 2 次的系统提示与第 3 次的最终回复必须点名工具与参数
// （排查"是哪把工具在打转"必须能直接从回复里读出来）。
func TestLoopNudgeAndStopReply(t *testing.T) {
	args := map[string]string{"session_id": "s1", "command": "whoami"}
	nudge := loopNudge("exec", args)
	for _, needle := range []string{"exec", "whoami", "相同输入"} {
		if !strings.Contains(nudge, needle) {
			t.Errorf("loopNudge 缺少 %q：%s", needle, nudge)
		}
	}
	reply := loopStopReply("exec", args, []ToolTrace{{Name: "session_list", Result: "共 1 个会话"}})
	for _, needle := range []string{"exec", "whoami", "防死循环", "session_list"} {
		if !strings.Contains(reply, needle) {
			t.Errorf("loopStopReply 缺少 %q：%s", needle, reply)
		}
	}
	// 无轨迹时也不能输出空回复。
	if got := loopStopReply("exec", nil, nil); got == "" {
		t.Error("无轨迹时 loopStopReply 不应为空")
	}
}

// TestArgsJSON 参数序列化用于日志/提示：空参数给 {}，不 panic。
func TestArgsJSON(t *testing.T) {
	if got := argsJSON(nil); got != "{}" {
		t.Fatalf("argsJSON(nil) = %q, want {}", got)
	}
	got := argsJSON(map[string]string{"a": "1"})
	if !strings.Contains(got, `"a":"1"`) {
		t.Fatalf("argsJSON = %q", got)
	}
}

// TestNewTraceID trace id 格式固定为 tr-<unixnano>-<4hex> 且基本唯一；
// ensureTraceID 只补空值，已有 id 原样保留（恢复审批时不能换 trace）。
func TestNewTraceID(t *testing.T) {
	re := regexp.MustCompile(`^tr-\d+-[0-9a-f]{4}$`)
	// 4 hex 只有 65536 个取值，靠"纳秒时间戳 + 随机后缀"共同保证唯一；
	// 这里只做小样本抽样，并容忍 1 次碰撞（纯随机部分的生日碰撞概率约 0.4%），
	// 避免 CI 偶发抖动——真正要钉住的是格式与"空值才补"的语义。
	seen := map[string]bool{}
	dup := 0
	for i := 0; i < 24; i++ {
		id := newTraceID()
		if !re.MatchString(id) {
			t.Fatalf("trace id 格式不符 %q", id)
		}
		if seen[id] {
			dup++
		}
		seen[id] = true
	}
	if dup > 1 {
		t.Fatalf("trace id 重复 %d 次（24 次抽样），随机性异常", dup)
	}
	if got := ensureTraceID(""); !re.MatchString(got) {
		t.Fatalf(`ensureTraceID("") 应生成新 id，得到 %q`, got)
	}
	if got := ensureTraceID("  "); !re.MatchString(got) {
		t.Fatalf("ensureTraceID 空白应生成新 id，得到 %q", got)
	}
	if got := ensureTraceID("tr-123-abc"); got != "tr-123-abc" {
		t.Fatalf("ensureTraceID 不应改动已有 id，得到 %q", got)
	}
}

// TestElapsedSec 墙钟秒数换算（上限判定用的是整秒）。
func TestElapsedSec(t *testing.T) {
	if got := elapsedSec(time.Now()); got != 0 {
		t.Fatalf("刚刚开始应为 0 秒，得到 %d", got)
	}
	if got := elapsedSec(time.Now().Add(-3 * time.Second)); got != 3 {
		t.Fatalf("3 秒前开始应为 3，得到 %d", got)
	}
}

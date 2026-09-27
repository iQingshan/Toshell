package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"toshell/internal/server/config"
)

// ═══ 常驻层稳定性（前缀缓存的基础）═══════════════════════════════════════════

// snapshotExec 假的工具执行器：只实现 session_list（返回固定在线会话清单），
// 并统计被调用了多少次——用来验证"会话快照不再每轮都取"。
type snapshotExec struct {
	mu       sync.Mutex
	calls    int
	sessions []map[string]interface{}
}

func (s *snapshotExec) InvokeTool(name string, args map[string]string) (interface{}, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if name == "session_list" {
		return map[string]interface{}{"count": len(s.sessions), "sessions": s.sessions}, nil
	}
	return map[string]interface{}{"ok": true}, nil
}

func (s *snapshotExec) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func testCopilot(exec ToolExecutor) *Copilot {
	return New(config.AIConfig{
		Enabled: true, BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "m", Timeout: 5,
	}, exec)
}

// TestResidentPrefixStableAcrossTurns 同一个 run 的多轮装配必须产出**逐字节相同**的
// 常驻层（system）前缀，且动态会话清单不许混进常驻层。
//
// 这是前缀缓存的硬前提：DeepSeek/OpenAI 的自动前缀缓存按消息前缀命中，system 前缀每轮
// 变一次，整段缓存就失效、每轮按未命中价重新计费（旧实现正是每轮往 system 里拼在线会话）。
func TestResidentPrefixStableAcrossTurns(t *testing.T) {
	exec := &snapshotExec{sessions: []map[string]interface{}{
		{"id": "sess-1", "hostname": "HOST-A", "os": "Windows Server 2019", "status": "active", "listener": "https"},
	}}
	cp := testCopilot(exec)
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "对 sess-1 做信息收集"}}, 0)
	run.SetObjective("对 sess-1 做信息收集")
	limits := limitsFromConfig(config.AIConfig{}, 0)
	budget := TokenBudgetFromConfig(config.AIConfig{})

	m1, s1 := cp.buildRunContext(run, limits, runUsage{Turns: 1}, RunTokenUsage{}, budget)
	// 第二轮：目标、计划、历史都变了（会话清单没变，但即使变也不该影响常驻层）。
	run.SetObjective("改成横向移动")
	run.SyncPlan([]GoalStep{{Index: 1, Desc: "先侦察", Status: "done"}, {Index: 2, Desc: "横向", Status: "running"}})
	run.AppendMessages([]Message{
		{Role: "assistant", Content: "【执行计划】\n1. 先侦察\n2. 横向"},
		{Role: "user", Content: "继续"},
	})
	m2, s2 := cp.buildRunContext(run, limits, runUsage{Turns: 2, ToolCalls: 1}, RunTokenUsage{}, budget)

	if len(m1) == 0 || len(m2) == 0 {
		t.Fatal("装配结果不应为空")
	}
	if m1[0].Role != "system" || m2[0].Role != "system" {
		t.Fatalf("首条必须是常驻层 system，得到 %q / %q", m1[0].Role, m2[0].Role)
	}
	if m1[0].Content != m2[0].Content {
		t.Fatalf("同一 run 多轮装配的常驻层不一致（前缀缓存必然失效）：\n第一轮 %d 字节\n第二轮 %d 字节",
			len(m1[0].Content), len(m2[0].Content))
	}
	if m1[0].Content != residentSystemPrompt {
		t.Fatal("常驻层必须就是 residentSystemPrompt（逐字节）")
	}
	if strings.Contains(m1[0].Content, "sess-1") || strings.Contains(m1[0].Content, "HOST-A") {
		t.Fatal("动态在线会话清单混进了常驻层：前缀缓存会被破坏")
	}
	if strings.Contains(m1[0].Content, "【当前在线会话】") {
		t.Fatal("常驻层不应包含【当前在线会话】段落")
	}
	// 动态信息必须落在任务层（第 2 条 system）。
	if len(m2) < 2 || m2[1].Role != "system" {
		t.Fatalf("任务层应是第 2 条 system 消息，得到 %+v", m2)
	}
	for _, needle := range []string{"sess-1", "HOST-A", "【当前在线会话】", "横向移动", "【预算】"} {
		if !strings.Contains(m2[1].Content, needle) {
			t.Errorf("任务层缺少 %q：\n%s", needle, m2[1].Content)
		}
	}
	if s1.ResidentHash != s2.ResidentHash || s1.ResidentHash != ResidentPromptHash() {
		t.Fatalf("常驻层哈希应稳定：%s / %s / %s", s1.ResidentHash, s2.ResidentHash, ResidentPromptHash())
	}
	// 在线会话快照按 run + TTL 缓存：两轮装配只允许取一次（旧实现每轮一次）。
	if got := exec.callCount(); got != 1 {
		t.Fatalf("会话快照应每 run 只取一次，实际调用 %d 次", got)
	}
}

// TestResidentPromptHasNoDynamicParts 常驻层正文本身不许含任何动态内容（回归门禁）：
// 一旦有人把在线会话/目标/时间戳拼回 system，这条用例会直接失败。
func TestResidentPromptHasNoDynamicParts(t *testing.T) {
	if strings.TrimSpace(residentSystemPrompt) == "" {
		t.Fatal("常驻层不应为空")
	}
	for _, bad := range []string{"【当前在线会话】", "【当前目标】", "【计划进度】"} {
		if strings.Contains(residentSystemPrompt, bad) {
			t.Fatalf("常驻层混入了动态段落 %q", bad)
		}
	}
	if h := ResidentPromptHash(); len(h) != 64 {
		t.Fatalf("常驻层哈希应是 64 位 hex，得到 %q", h)
	}
}

// ═══ 分层与折叠 ═════════════════════════════════════════════════════════════

// TestAssembleContextLayerOrderAndWorkingKeep 层顺序与工作层保留条数：
// resident → task → history（折叠） → working（最近 N 条原文）。
func TestAssembleContextLayerOrderAndWorkingKeep(t *testing.T) {
	history := []Message{{Role: "system", Content: "旧的常驻层副本"}}
	// 10 组「user 指令 + 长 tool 结果」+ 最后一条最新指令：足够把大部分消息推进历史层。
	for i := 1; i <= 10; i++ {
		history = append(history,
			Message{Role: "user", Content: fmt.Sprintf("指令 %d", i)},
			Message{Role: "tool", Content: fmt.Sprintf("结果 %d %s", i, strings.Repeat("x", 400))},
		)
	}
	last := Message{Role: "user", Content: "最新指令"}
	history = append(history, last)
	msgs, stats := AssembleContext(ContextInput{
		Resident: "R", Objective: "目标", Constraints: "约束", Sessions: "- s1\n", BudgetText: "轮次 0/20",
		History: history,
		Opts:    ContextOptions{WorkingKeep: 3, BudgetTokens: 32000},
	})
	if msgs[0].Content != "R" || msgs[0].Role != "system" {
		t.Fatalf("第 1 条应为常驻层，得到 %+v", msgs[0])
	}
	if msgs[1].Role != "system" || !strings.Contains(msgs[1].Content, "【当前目标】") {
		t.Fatalf("第 2 条应为任务层，得到 %+v", msgs[1])
	}
	// 旧的常驻层副本必须被丢掉（否则 system 出现两份）。
	for _, m := range msgs {
		if m.Content == "旧的常驻层副本" {
			t.Fatal("历史里开头的 system（常驻层副本）应被丢弃")
		}
	}
	if stats.WorkingKept != 3 || stats.WorkingLimit != 3 {
		t.Fatalf("工作层应保留 3 条原文，得到 kept=%d limit=%d", stats.WorkingKept, stats.WorkingLimit)
	}
	// 层顺序：resident → task → history → working。
	wantOrder := []string{LayerResident, LayerTask, LayerHistory, LayerWorking}
	for i, name := range wantOrder {
		if stats.Layers[i].Name != name {
			t.Fatalf("层顺序第 %d 位应为 %s，得到 %s", i+1, name, stats.Layers[i].Name)
		}
	}
	if stats.LayerMessages(LayerWorking) != 3 || stats.LayerMessages(LayerHistory) != 18 {
		t.Fatalf("层条数不对：working=%d history=%d", stats.LayerMessages(LayerWorking), stats.LayerMessages(LayerHistory))
	}
	// 最近 3 条原文必须原样保留；更早的长 tool 结果被折叠成一行摘要（带显式标记）。
	if got := msgs[len(msgs)-1].Content; got != "最新指令" {
		t.Fatalf("最后一条应是原文，得到 %q", got)
	}
	foldedLines := 0
	histBytes := 0
	for i := 2; i < 2+stats.LayerMessages(LayerHistory); i++ {
		if strings.HasPrefix(msgs[i].Content, foldedMarker) {
			foldedLines++
		}
		histBytes += len(msgs[i].Content)
	}
	if foldedLines != 9 {
		t.Fatalf("历史层的 9 条长 tool 结果都应被折叠，实际 %d 条", foldedLines)
	}
	if histBytes >= 9*400 {
		t.Fatalf("历史层没有被压小：%d 字节（原始工具结果约 %d 字节）", histBytes, 9*400)
	}
	if !stats.Compressed || stats.CollapsedMessages != foldedLines {
		t.Fatalf("应记录压缩与折叠条数，得到 compressed=%v collapsed=%d", stats.Compressed, stats.CollapsedMessages)
	}
	if stats.LogFields() == "" || !strings.Contains(stats.LogFields(), LayerWorking) {
		t.Fatalf("日志字段应含分层数字：%s", stats.LogFields())
	}
}

// TestFoldPreservesRealToolNameAndHandle 折叠摘要必须：① 用**真实工具名**（不再是写死的
// task_wait）；② 保留外置信封的句柄与截断说明；③ 显式标注"这是摘要不是原文"。
func TestFoldPreservesRealToolNameAndHandle(t *testing.T) {
	envelope := `{"status":"ok","data":{"summary":"（结果已外置，共 12345 字节）","handle":"r-run-1-1"},` +
		`"meta":{"call_id":"call-1","tool":"screenshot","truncated":true,` +
		`"truncation_note":"结果共 12345 字节，已外置为句柄 r-run-1-1；上下文里只给摘要，需要细节请调用 result_read 按 offset/limit 分页回读（本次未内联任何正文）。",` +
		`"total_bytes":12345,"returned_bytes":0,"handle":"r-run-1-1","untrusted":true}}`
	msgs := []Message{
		{Role: "system", Content: "resident"},
		{Role: "assistant", Content: "先截个图看看", ToolCalls: []ToolCall{{
			ID: "call-1", Type: "function",
			Function: ToolCallFunc{Name: "screenshot", Arguments: `{"session_id":"s1"}`},
		}}},
		{Role: "tool", ToolCallID: "call-1", Content: envelope},
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: "call-2", Type: "function",
			Function: ToolCallFunc{Name: "exec", Arguments: `{"session_id":"s1","command":"whoami"}`},
		}}},
		{Role: "tool", ToolCallID: "call-2", Content: `{"status":"completed","output":"nt authority\\system","exit_code":0}`},
		{Role: "user", Content: "继续"},
		{Role: "user", Content: "最新指令"},
	}
	out, stats := AssembleContext(ContextInput{
		Resident: "R", History: msgs,
		Opts: ContextOptions{WorkingKeep: 2, BudgetTokens: 32000},
	})
	if !stats.Compressed {
		t.Fatal("应触发历史层折叠")
	}
	screenshotLine, execLine := "", ""
	for _, m := range out {
		if m.Role != "tool" {
			continue
		}
		if strings.Contains(m.Content, "screenshot") {
			screenshotLine = m.Content
		}
		if strings.Contains(m.Content, "exec") {
			execLine = m.Content
		}
	}
	if screenshotLine == "" || execLine == "" {
		t.Fatalf("折叠摘要里必须保留真实工具名（screenshot / exec），得到：\n%+v", out)
	}
	for _, needle := range []string{"r-run-1-1", "12345", "非原文", "result_read", "外置"} {
		if !strings.Contains(screenshotLine, needle) {
			t.Errorf("外置信封折叠后缺少 %q：%s", needle, screenshotLine)
		}
	}
	if !strings.Contains(execLine, "exec") || !strings.Contains(execLine, "非原文") {
		t.Errorf("普通工具结果折叠后应带真实工具名与标注：%s", execLine)
	}
	for _, m := range out {
		if strings.Contains(m.Content, "task_wait") {
			t.Fatalf("折叠摘要里出现了写死的 task_wait（本次要修的 bug）：%s", m.Content)
		}
	}
	// assistant 的 ToolCalls 必须原样保留（tool 回执的配对依据）。
	foundCall := false
	for _, m := range out {
		for _, tc := range m.ToolCalls {
			if tc.ID == "call-1" {
				foundCall = true
			}
		}
	}
	if !foundCall {
		t.Fatal("折叠 assistant 时必须保留 ToolCalls（否则 tool 回执找不到配对，上游会拒绝）")
	}
}

// layerOf 依据统计判断装配结果里第 i 条消息属于哪一层。
func layerOf(stats ContextStats, i int) string {
	off := 0
	for _, l := range stats.Layers {
		if i < off+l.Messages {
			return l.Name
		}
		off += l.Messages
	}
	return ""
}

// assertToolPairsSameLayer 断言 assistant.tool_calls 与它的 tool 回执**没有被拆到两层**：
// 拆开会被上游 chat/completions 直接拒绝（tool 回执找不到声明它的 assistant）。
func assertToolPairsSameLayer(t *testing.T, msgs []Message, stats ContextStats) {
	t.Helper()
	owner := map[string]int{}
	for i, m := range msgs {
		for _, tc := range m.ToolCalls {
			if tc.ID != "" {
				owner[tc.ID] = i
			}
		}
	}
	for i, m := range msgs {
		if m.Role != "tool" || m.ToolCallID == "" {
			continue
		}
		j, ok := owner[m.ToolCallID]
		if !ok {
			continue // 孤儿回执（测试构造的历史残缺）：没有配对义务
		}
		if j > i {
			t.Fatalf("tool 回执（第 %d 条）出现在声明它的 assistant（第 %d 条）之前", i, j)
		}
		if a, b := layerOf(stats, i), layerOf(stats, j); a != b {
			t.Fatalf("tool 配对被拆到两层：回执在第 %d 条(%s)，assistant 在第 %d 条(%s)", i, a, j, b)
		}
	}
}

// TestToolCallPairsNeverSplitAcrossLayers 各种工作层条数下，成对的 assistant/tool 消息
// 都必须落在同一层（这是上游接受请求的硬要求）。
func TestToolCallPairsNeverSplitAcrossLayers(t *testing.T) {
	history := []Message{{Role: "system", Content: "resident"}}
	for i := 0; i < 8; i++ {
		callID := fmt.Sprintf("call-%d", i)
		history = append(history,
			Message{Role: "assistant", Content: fmt.Sprintf("第 %d 次调用", i), ToolCalls: []ToolCall{{
				ID: callID, Type: "function",
				Function: ToolCallFunc{Name: "exec", Arguments: fmt.Sprintf(`{"command":"cmd-%d"}`, i)},
			}}},
			Message{Role: "tool", ToolCallID: callID, Content: fmt.Sprintf(`{"status":"completed","output":"out-%d"}`, i)},
		)
	}
	for keep := 1; keep <= 18; keep++ {
		out, stats := AssembleContext(ContextInput{
			Resident: "R", History: history,
			Opts: ContextOptions{WorkingKeep: keep, BudgetTokens: 32000},
		})
		assertToolPairsSameLayer(t, out, stats)
	}
	// 激进档（预算极小）同样不能拆配对。
	out, stats := AssembleContext(ContextInput{
		Resident: "R", History: history,
		Opts: ContextOptions{WorkingKeep: 14, MinWorkingKeep: 4, BudgetTokens: 1},
	})
	assertToolPairsSameLayer(t, out, stats)
	if !stats.Aggressive {
		t.Fatal("预算极小应触发激进压缩")
	}
}

// TestAssembleEmptyHistory 空历史：只产出常驻层（+任务层），统计为 0，不 panic。
func TestAssembleEmptyHistory(t *testing.T) {
	out, stats := AssembleContext(ContextInput{
		Resident: "R", Objective: "目标",
		Opts: ContextOptions{BudgetTokens: 32000},
	})
	if len(out) != 2 {
		t.Fatalf("空历史应只有常驻层 + 任务层，得到 %d 条", len(out))
	}
	if stats.TotalMessages != 2 || stats.WorkingKept != 0 || stats.LayerMessages(LayerHistory) != 0 {
		t.Fatalf("空历史统计异常：%+v", stats)
	}
	if stats.OverBudget || stats.Aggressive {
		t.Fatalf("空历史不应触发压缩：%+v", stats)
	}
	// 完全空的输入也不能 panic。
	if out, stats := AssembleContext(ContextInput{}); len(out) != 0 || stats.TotalTokens != 0 {
		t.Fatalf("全空输入应产出空结果，得到 %d 条 / %d token", len(out), stats.TotalTokens)
	}
	if EstimateTokens("") != 0 {
		t.Fatal("空文本估算必须是 0")
	}
}

// TestAssembleLongSingleMessage 超长单条：必须被显式截断标注（绝不能静默截断或整段塞入）。
func TestAssembleLongSingleMessage(t *testing.T) {
	longUser := strings.Repeat("长", 5000)
	longTool := strings.Repeat("A", 40000)
	history := []Message{
		{Role: "system", Content: "resident"},
		{Role: "user", Content: longUser},
		{Role: "user", Content: longUser},
		{Role: "tool", Content: longTool},
		{Role: "user", Content: "最新指令"},
	}
	out, _ := AssembleContext(ContextInput{
		Resident: "R", History: history,
		Opts: ContextOptions{WorkingKeep: 2, BudgetTokens: 32000},
	})
	// 历史层的 user 指令被截断到 maxHistoryUserRunes 并带显式标注。
	histUser := out[2]
	if len([]rune(histUser.Content)) > maxHistoryUserRunes+80 {
		t.Fatalf("历史层超长 user 指令未被截断：%d 字符", len([]rune(histUser.Content)))
	}
	if !strings.Contains(histUser.Content, truncatedMarker) {
		t.Fatalf("截断必须显式标注：%s", histUser.Content)
	}
	// 工作层的超长 tool 结果同样被上限约束。
	workTool := out[len(out)-2]
	if workTool.Role != "tool" {
		t.Fatalf("工作层最后两条应是 tool + user，得到 %+v", out[len(out)-2:])
	}
	if len([]rune(workTool.Content)) > maxWorkingMessageRunes+80 {
		t.Fatalf("工作层超长消息未被截断：%d 字符", len([]rune(workTool.Content)))
	}
	if !strings.Contains(workTool.Content, truncatedMarker) {
		t.Fatalf("工作层截断必须显式标注：%s", workTool.Content[:80])
	}
}

// TestFoldIdempotent 折叠必须幂等：多轮装配不会把 [历史摘要-非原文] 前缀越叠越长。
func TestFoldIdempotent(t *testing.T) {
	history := []Message{{Role: "system", Content: "resident"}}
	for i := 0; i < 10; i++ {
		history = append(history, Message{Role: "tool", Content: strings.Repeat("x", 500)})
	}
	first, _ := CompressMessages(history, ContextOptions{WorkingKeep: 2})
	second, _ := CompressMessages(first, ContextOptions{WorkingKeep: 2})
	third, _ := CompressMessages(second, ContextOptions{WorkingKeep: 2})
	if len(first) != len(second) || len(second) != len(third) {
		t.Fatalf("重复压缩不应改变消息条数：%d / %d / %d", len(first), len(second), len(third))
	}
	for i := range first {
		if first[i].Content != third[i].Content {
			t.Fatalf("重复压缩改变了第 %d 条内容：\n%q\n%q", i, first[i].Content, third[i].Content)
		}
		if n := strings.Count(third[i].Content, foldedMarker); n > 1 {
			t.Fatalf("折叠不幂等：第 %d 条出现 %d 次折叠标记：%s", i, n, third[i].Content)
		}
	}
}

// TestCompressMessagesKeepsResidentAndTask 压缩路径必须原样保留常驻层与任务层
// （同步副驾驶每轮都要重算工作层/历史层，但不该丢掉这两层）。
func TestCompressMessagesKeepsResidentAndTask(t *testing.T) {
	taskLayer := "【当前目标】测试目标\n【预算】轮次 0/20"
	msgs := []Message{
		{Role: "system", Content: "RESIDENT"},
		{Role: "system", Content: taskLayer},
		{Role: "user", Content: "1"},
		{Role: "user", Content: "2"},
		{Role: "user", Content: "3"},
	}
	out, stats := CompressMessages(msgs, ContextOptions{WorkingKeep: 2})
	if len(out) != 5 || out[0].Content != "RESIDENT" || out[1].Content != taskLayer {
		t.Fatalf("常驻层/任务层应原样保留：%+v", out)
	}
	if stats.LayerMessages(LayerResident) != 1 || stats.LayerMessages(LayerTask) != 1 {
		t.Fatalf("层统计应识别常驻层与任务层：%+v", stats.Layers)
	}
	if out[4].Content != "3" {
		t.Fatalf("最后一条应保持原文：%q", out[4].Content)
	}
	// 对话中途的 system（如防死循环提示）不能被误当任务层搬到最前面。
	nudge := []Message{
		{Role: "system", Content: "RESIDENT"},
		{Role: "user", Content: "1"},
		{Role: "system", Content: "【系统提示】工具 exec 已用完全相同的参数调用过一次"},
		{Role: "user", Content: "2"},
	}
	out2, stats2 := CompressMessages(nudge, ContextOptions{WorkingKeep: 2})
	if stats2.LayerMessages(LayerTask) != 0 {
		t.Fatalf("对话中途的 system 不应被识别为任务层：%+v", stats2.Layers)
	}
	if out2[1].Content != "1" {
		t.Fatalf("对话中途的 system 不该被搬到常驻层之后：%+v", out2)
	}
}

// ═══ 估算与预算 ═════════════════════════════════════════════════════════════

// TestEstimateTokensCaliber 估算口径：CJK 约 1 token/字、其他约 4 字符/token、
// 单调不减、空文本为 0、含中文的估算严格大于同长度纯 ASCII。
func TestEstimateTokensCaliber(t *testing.T) {
	if got := EstimateTokens(""); got != 0 {
		t.Fatalf("空文本 = %d, want 0", got)
	}
	if got := EstimateTokens("a"); got != 1 {
		t.Fatalf("单字符应为 1（向上取整），得到 %d", got)
	}
	if got := EstimateTokens(strings.Repeat("a", 8)); got != 2 {
		t.Fatalf("8 个 ASCII 字符应为 2 token，得到 %d", got)
	}
	if got := EstimateTokens(strings.Repeat("汉", 8)); got != 8 {
		t.Fatalf("8 个汉字应为 8 token，得到 %d", got)
	}
	if EstimateTokens(strings.Repeat("汉", 4)) <= EstimateTokens(strings.Repeat("a", 4)) {
		t.Fatal("中文应按更高 token 密度估算")
	}
	// 单调性：拼接只会让估算不减。
	base := EstimateTokens(strings.Repeat("汉a", 20))
	if got := EstimateTokens(strings.Repeat("汉a", 20) + "更多内容"); got < base {
		t.Fatalf("估算不单调：%d -> %d", base, got)
	}
	if EstimateMessagesTokens(nil) != 0 {
		t.Fatal("空消息列表应为 0")
	}
	withCalls := EstimateMessageTokens(Message{Role: "assistant", ToolCalls: []ToolCall{{
		ID: "c1", Function: ToolCallFunc{Name: "exec", Arguments: `{"command":"whoami"}`},
	}}})
	plain := EstimateMessageTokens(Message{Role: "assistant", Content: "exec"})
	if withCalls <= plain {
		t.Fatalf("带 tool_calls 的消息应比同长度纯文本更贵：%d vs %d", withCalls, plain)
	}
	// 全角标点也按 CJK 口径（高估方向）。
	if EstimateTokens("，。！") != 3 {
		t.Fatalf("全角标点应按 CJK 计 3 token，得到 %d", EstimateTokens("，。！"))
	}
}

// TestTokenCalibration usage 回填校准：小样本不采信、异常值被夹紧、Apply 单调。
func TestTokenCalibration(t *testing.T) {
	c := TokenCalibration{}
	if c.EffectiveFactor() != 1.0 || c.Apply(100) != 100 {
		t.Fatalf("未校准时系数应为 1.0，得到 %v / %d", c.EffectiveFactor(), c.Apply(100))
	}
	// 估算过小（< tokenCalibMinEstimate）不采信：ceil 误差会污染系数。
	if got := c.Observe(50, 5000); got.Samples != 0 || got.EffectiveFactor() != 1.0 {
		t.Fatalf("小样本不应被采信：%+v", got)
	}
	// 有效样本：真值 2 倍 → EWMA(alpha=0.3) → 1.3。
	c1 := c.Observe(1000, 2000)
	if c1.Samples != 1 || math.Abs(c1.EffectiveFactor()-1.3) > 1e-9 {
		t.Fatalf("首次校准 = %+v, want factor 1.3", c1)
	}
	if got := c1.Apply(1000); got != 1300 {
		t.Fatalf("Apply(1000) = %d, want 1300", got)
	}
	// 连续极端样本被夹紧在 [0.5, 3.0]。
	c2 := c1
	for i := 0; i < 60; i++ {
		c2 = c2.Observe(1000, 1000000)
	}
	if f := c2.EffectiveFactor(); f > tokenCalibMaxFactor+1e-9 || f < tokenCalibMinFactor {
		t.Fatalf("系数未被夹紧：%v", f)
	}
	// 真值为 0（上游没回 usage）→ 不动系数、不计样本。
	if got := c1.Observe(1000, 0); got != c1 {
		t.Fatalf("真值为 0 不应改动校准：%+v vs %+v", got, c1)
	}
	if got := c1.Apply(0); got != 0 {
		t.Fatalf("Apply(0) 应为 0，得到 %d", got)
	}
}

// TestRunTokenUsage 累计用量：usage 真值优先、无 usage 轮次用估算回填、Total 口径正确。
func TestRunTokenUsage(t *testing.T) {
	var u RunTokenUsage
	if u.Total() != 0 {
		t.Fatal("初始用量应为 0")
	}
	u = u.ObserveUsage(1000, 100, 500)
	if u.PromptTokens != 1000 || u.CompletionTokens != 100 || u.Samples != 1 {
		t.Fatalf("usage 未被正确累加：%+v", u)
	}
	if u.Total() != 1100 {
		t.Fatalf("Total = %d, want 1100", u.Total())
	}
	// usage 缺失（字段为 0）→ 按估算回填，预算不会失效。
	u = u.ObserveEstimate(700)
	if u.EstimatedTokens != 700 || u.Total() != 1800 {
		t.Fatalf("估算回填失败：%+v total=%d", u, u.Total())
	}
	// usage 字段存在但全 0（上游缺字段/为 0 的边界）→ 不算真值、不改校准。
	before := u
	u = u.ObserveUsage(0, 0, 900)
	if u.PromptTokens != before.PromptTokens || u.CompletionTokens != before.CompletionTokens {
		t.Fatalf("全 0 usage 不应计入真值：%+v", u)
	}
	if u.Samples != before.Samples {
		t.Fatalf("全 0 usage 不应计入样本：%d -> %d", before.Samples, u.Samples)
	}
	// 负数（防御）被归零。
	u = u.ObserveUsage(-5, -5, 0)
	if u.PromptTokens != before.PromptTokens || u.CompletionTokens != before.CompletionTokens {
		t.Fatalf("负数 usage 应被归零：%+v", u)
	}
}

// TestShouldStopTokens 累计 token 预算的边界：达到即停（>=），<=0 表示不设限。
func TestShouldStopTokens(t *testing.T) {
	limit := TokenBudget{MaxRunTokens: 1000, MaxContextTokens: 32000}
	cases := []struct {
		name  string
		usage RunTokenUsage
		want  string
	}{
		{"远未达上限", RunTokenUsage{PromptTokens: 100, CompletionTokens: 10}, ""},
		{"差一点", RunTokenUsage{PromptTokens: 989, CompletionTokens: 10}, ""},
		{"刚好达上限", RunTokenUsage{PromptTokens: 990, CompletionTokens: 10}, stopReasonMaxTokens},
		{"超过上限", RunTokenUsage{PromptTokens: 5000, CompletionTokens: 10}, stopReasonMaxTokens},
		{"估算回填也计入", RunTokenUsage{EstimatedTokens: 1000}, stopReasonMaxTokens},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stop, reason := ShouldStopTokens(tc.usage, limit)
			if tc.want == "" {
				if stop {
					t.Fatalf("不应停止，却得到 %q", reason)
				}
				return
			}
			if !stop || reason != tc.want {
				t.Fatalf("stop=%v reason=%q, want %q", stop, reason, tc.want)
			}
		})
	}
	// 预算 <=0 表示不设限（仅供单测/临时关闭）。
	if stop, _ := ShouldStopTokens(RunTokenUsage{PromptTokens: 1 << 30}, TokenBudget{}); stop {
		t.Fatal("预算为 0 时不应停止")
	}
	// 常量与文案：max_tokens 与三处硬上限同风格，且文案要说明是 token 预算。
	if stopReasonMaxTokens != "max_tokens" {
		t.Fatalf("stop_reason 常量被改动：%q", stopReasonMaxTokens)
	}
	text := stopReasonText(stopReasonMaxTokens, runUsage{}, runLimits{})
	if !strings.Contains(text, "token") || !strings.Contains(text, "预算") {
		t.Fatalf("max_tokens 文案未说明原因：%q", text)
	}
	if text == stopReasonText("", runUsage{}, runLimits{}) {
		t.Fatal("max_tokens 不应落到默认文案")
	}
}

// TestTokenBudgetFromConfig 生效预算：零值/非法值回落默认，显式值生效（不允许关掉预算）。
func TestTokenBudgetFromConfig(t *testing.T) {
	def := TokenBudgetFromConfig(config.AIConfig{})
	want := TokenBudget{MaxContextTokens: config.DefaultMaxContextTokens, MaxRunTokens: config.DefaultMaxRunTokens}
	if def != want {
		t.Fatalf("零值配置 = %+v, want %+v", def, want)
	}
	if got := TokenBudgetFromConfig(config.AIConfig{MaxContextTokens: -1, MaxRunTokens: 0}); got != want {
		t.Fatalf("非法配置应回落默认：%+v", got)
	}
	got := TokenBudgetFromConfig(config.AIConfig{MaxContextTokens: 8000, MaxRunTokens: 12345})
	if got != (TokenBudget{MaxContextTokens: 8000, MaxRunTokens: 12345}) {
		t.Fatalf("显式配置未生效：%+v", got)
	}
	// 30% 余量：可用额度 = 预算 / 1.3（向上取整）。
	if u := UsableContextTokens(13000); u != 10000 {
		t.Fatalf("UsableContextTokens(13000) = %d, want 10000", u)
	}
	if u := UsableContextTokens(0); u != 0 {
		t.Fatalf("预算为 0 时可用额度应为 0，得到 %d", u)
	}
	if math.Abs(TokenSafetyFactor-1.3) > 1e-9 {
		t.Fatalf("安全余量被改动：%v", TokenSafetyFactor)
	}
	// 工作层条数配置同样回落默认。
	if got := EffectiveContextWorkingKeep(config.AIConfig{}); got != config.DefaultContextWorkingKeep {
		t.Fatalf("工作层条数默认值 = %d", got)
	}
	if got := EffectiveContextWorkingKeep(config.AIConfig{ContextWorkingKeep: 3}); got != 3 {
		t.Fatalf("工作层条数显式值未生效：%d", got)
	}
	if got := contextOptionsFromConfig(config.AIConfig{}).BudgetTokens; got != config.DefaultMaxContextTokens {
		t.Fatalf("装配选项预算 = %d", got)
	}
}

// TestBudgetTwoStageCompression 超预算的两段式处理：先激进压缩 → 仍超才算 OverBudget。
func TestBudgetTwoStageCompression(t *testing.T) {
	history := []Message{{Role: "system", Content: "resident"}}
	for i := 0; i < 20; i++ {
		history = append(history, Message{Role: "tool", Content: strings.Repeat("p", 800)})
	}
	in := ContextInput{Resident: "R", History: history}

	// ① 不做预算判定：正常装配（保留 14 条原文）。
	_, statsNormal := AssembleContext(ContextInput{
		Resident: in.Resident, History: in.History,
		Opts: ContextOptions{WorkingKeep: 14, BudgetTokens: 0},
	})
	if statsNormal.WorkingKept != 14 || statsNormal.OverBudget {
		t.Fatalf("无预算时不应触发压缩：%+v", statsNormal)
	}
	// ② 预算极小：强制走激进档，读出激进档的估算规模。
	_, statsAggr := AssembleContext(ContextInput{
		Resident: in.Resident, History: in.History,
		Opts: ContextOptions{WorkingKeep: 14, MinWorkingKeep: 4, BudgetTokens: 1},
	})
	if !statsAggr.Aggressive || !statsAggr.Compressed {
		t.Fatalf("应触发激进压缩：%+v", statsAggr)
	}
	if statsAggr.CalibratedTokens >= statsNormal.TotalTokens {
		t.Fatalf("激进压缩没有变小：aggr=%d normal=%d", statsAggr.CalibratedTokens, statsNormal.TotalTokens)
	}
	// ③ 取两者中间的预算：正常档超、激进档不超 → 压缩后继续（不是直接停）。
	mid := (statsNormal.TotalTokens + statsAggr.CalibratedTokens) / 2
	budget := int(math.Ceil(float64(mid) * TokenSafetyFactor))
	msgs, stats := AssembleContext(ContextInput{
		Resident: in.Resident, History: in.History,
		Opts: ContextOptions{WorkingKeep: 14, MinWorkingKeep: 4, BudgetTokens: budget},
	})
	if !stats.Aggressive || !stats.Compressed {
		t.Fatalf("预算 %d 应触发激进压缩：%+v", budget, stats)
	}
	if stats.OverBudget {
		t.Fatalf("激进压缩后应回到预算内（%d <= %d），不应判为超预算", stats.CalibratedTokens, stats.UsableTokens)
	}
	if len(msgs) == 0 || stats.WorkingKept != 4 {
		t.Fatalf("激进档应把工作层缩到 4 条：kept=%d", stats.WorkingKept)
	}
	// ④ 压到极限仍超预算：OverBudget=true（调用方据此停循环并记 stop_reason=max_tokens）。
	_, extreme := AssembleContext(ContextInput{
		Resident: in.Resident, History: in.History,
		Opts: ContextOptions{WorkingKeep: 14, MinWorkingKeep: 4, BudgetTokens: 200},
	})
	if !extreme.OverBudget || !extreme.Aggressive {
		t.Fatalf("极小预算应判为 OverBudget：%+v", extreme)
	}
	if extreme.UsableTokens != UsableContextTokens(200) {
		t.Fatalf("可用额度口径不一致：%d", extreme.UsableTokens)
	}
}

// TestBudgetUsesCalibration 预算判定必须用校准后的估算（否则估算长期偏低时预算形同虚设）。
func TestBudgetUsesCalibration(t *testing.T) {
	history := []Message{{Role: "system", Content: "resident"}, {Role: "user", Content: strings.Repeat("x", 4000)}}
	_, stats := AssembleContext(ContextInput{
		Resident: "R", History: history,
		Opts: ContextOptions{
			WorkingKeep: 14, BudgetTokens: 32000,
			// 校准系数 3.0（实测真值是估算的 3 倍）→ 校准后估算被放大。
			Calibration: TokenCalibration{Factor: 3.0, Samples: 5},
		},
	})
	if stats.CalibratedTokens != stats.TotalTokens*3 {
		t.Fatalf("校准未被应用：raw=%d calibrated=%d", stats.TotalTokens, stats.CalibratedTokens)
	}
	if stats.CalibrationFactor != 3.0 {
		t.Fatalf("统计里应记录校准系数：%v", stats.CalibrationFactor)
	}
}

// ═══ usage 解析与 run 可观测性 ══════════════════════════════════════════════

// TestChatResponseUsageParsing 非流式响应的 usage 解析：有、缺、为 0 三种边界。
func TestChatResponseUsageParsing(t *testing.T) {
	var withUsage chatResponse
	raw := `{"choices":[{"message":{"role":"assistant","content":"hi"}}],` +
		`"usage":{"prompt_tokens":123,"completion_tokens":45,"total_tokens":168}}`
	if err := json.Unmarshal([]byte(raw), &withUsage); err != nil {
		t.Fatal(err)
	}
	if withUsage.Usage == nil || withUsage.Usage.PromptTokens != 123 ||
		withUsage.Usage.CompletionTokens != 45 || withUsage.Usage.TotalTokens != 168 {
		t.Fatalf("usage 未解析：%+v", withUsage.Usage)
	}
	var noUsage chatResponse
	if err := json.Unmarshal([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`), &noUsage); err != nil {
		t.Fatal(err)
	}
	if noUsage.Usage != nil {
		t.Fatalf("无 usage 时应为 nil（调用方据此回退估算）：%+v", noUsage.Usage)
	}
	var zeroUsage chatResponse
	if err := json.Unmarshal([]byte(`{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`), &zeroUsage); err != nil {
		t.Fatal(err)
	}
	if zeroUsage.Usage == nil || zeroUsage.Usage.PromptTokens != 0 {
		t.Fatalf("usage 字段为 0 时应存在但为 0：%+v", zeroUsage.Usage)
	}
}

// TestStreamUsageParsing 流式响应最后一个 chunk 的 usage 必须被解析出来（不联网：本地 httptest）。
func TestStreamUsageParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n")
		// OpenAI 兼容端点常见的 usage-only 尾块（choices 为空）。
		_, _ = io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":8,\"total_tokens\":128}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	cp := New(config.AIConfig{Enabled: true, BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 5}, nil)
	ag, err := cp.completeStreamOpts(context.Background(), []Message{{Role: "user", Content: "x"}}, streamReqOpts{}, nil)
	if err != nil {
		t.Fatalf("流式调用失败：%v", err)
	}
	if ag.Content != "hi there" {
		t.Fatalf("正文拼接不对：%q", ag.Content)
	}
	if ag.Usage == nil || ag.Usage.PromptTokens != 120 || ag.Usage.CompletionTokens != 8 {
		t.Fatalf("流式 usage 未解析：%+v", ag.Usage)
	}
}

// TestStreamWithoutUsageNoDrift 上游不回 usage 时：估算回填生效、校准系数不被带偏。
func TestStreamWithoutUsageNoDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()
	cp := New(config.AIConfig{Enabled: true, BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 5}, nil)
	ag, err := cp.completeStreamOpts(context.Background(), []Message{{Role: "user", Content: "x"}}, streamReqOpts{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ag.Usage != nil {
		t.Fatalf("无 usage 时应为 nil，得到 %+v", ag.Usage)
	}
	run := NewAgentManager(1).NewRun(nil, 0)
	run.ObserveLLMUsage(0, 0, 900)
	u := run.TokenUsage()
	if u.EstimatedTokens != 900 || u.PromptTokens != 0 {
		t.Fatalf("无 usage 时应按估算回填：%+v", u)
	}
	if u.Calibration.Samples != 0 || u.Calibration.EffectiveFactor() != 1.0 {
		t.Fatalf("无 usage 不应污染校准：%+v", u.Calibration)
	}
}

// TestRunObservabilityFields run 级可观测字段：usage 累计 + 上下文统计（都是新增可选字段）。
func TestRunObservabilityFields(t *testing.T) {
	run := NewAgentManager(1).NewRun(nil, 0)
	run.ObserveLLMUsage(1000, 200, 800)
	run.ObserveLLMUsage(500, 50, 400)
	u := run.TokenUsage()
	if u.PromptTokens != 1500 || u.CompletionTokens != 250 || u.Samples != 2 {
		t.Fatalf("run 累计用量不对：%+v", u)
	}
	stats := ContextStats{
		TotalTokens: 1234, BudgetTokens: 32000, Compressed: true,
		Layers: []ContextLayerStat{{Name: LayerResident, Messages: 1, Tokens: 900}},
	}
	run.RecordContextStats(stats)
	tokens, budget, compressed := run.ContextSnapshot()
	if tokens != 1234 || budget != 32000 || !compressed {
		t.Fatalf("run 上下文观测字段不对：%d / %d / %v", tokens, budget, compressed)
	}
	// JSON 只暴露"新增可选字段"，老字段名与语义不变。
	run.SetStopReason(stopReasonMaxTokens)
	run.mu.Lock()
	run.WaitingOn = `{"kind":"consent","tool":"exec"}`
	run.mu.Unlock()
	b, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{`"prompt_tokens":1500`, `"completion_tokens":250`,
		`"context_tokens":1234`, `"context_budget_tokens":32000`, `"context_compressed":true`} {
		if !strings.Contains(string(b), needle) {
			t.Errorf("run JSON 缺少 %s：%s", needle, string(b))
		}
	}
	for _, legacy := range []string{`"id"`, `"status"`, `"stop_reason"`, `"waiting_on"`} {
		if !strings.Contains(string(b), legacy) {
			t.Errorf("既有字段 %s 不应消失", legacy)
		}
	}
}

// ═══ 与 RunAgent 循环的集成（桩 LLM，本地 httptest，不联网/不需要真实 LLM）══════

// scriptedLLM 假的 OpenAI 兼容端点：按脚本固定返回「一直要调用工具」或「一次给最终答复」，
// 并记录每次请求的 messages（用于断言常驻层前缀稳定、上下文确实被压缩过）。
type scriptedLLM struct {
	srv *httptest.Server
	mu  sync.Mutex
	// requests 每次请求的首条消息（常驻层）与全部消息条数。
	firstSystems []string
	msgCounts    []int
	bodies       [][]Message
	usage        *chatUsage
	forceTool    bool
	content      string
}

func newScriptedLLM(forceTool bool, content string, usage *chatUsage) *scriptedLLM {
	s := &scriptedLLM{forceTool: forceTool, content: content, usage: usage}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []Message `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		s.mu.Lock()
		if len(req.Messages) > 0 {
			s.firstSystems = append(s.firstSystems, req.Messages[0].Content)
		}
		s.msgCounts = append(s.msgCounts, len(req.Messages))
		s.bodies = append(s.bodies, req.Messages)
		forceTool, content, usage := s.forceTool, s.content, s.usage
		s.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		if forceTool {
			_, _ = io.WriteString(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1",`+
				`"type":"function","function":{"name":"session_list","arguments":"{}"}}]}}]}`+"\n\n")
		} else if content != "" {
			_, _ = io.WriteString(w, "data: "+mustJSON(map[string]interface{}{
				"choices": []interface{}{map[string]interface{}{
					"delta": map[string]interface{}{"content": content},
				}},
			})+"\n\n")
		}
		if usage != nil {
			_, _ = io.WriteString(w, "data: "+mustJSON(map[string]interface{}{
				"choices": []interface{}{}, "usage": usage,
			})+"\n\n")
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	return s
}

func (s *scriptedLLM) close() { s.srv.Close() }

func (s *scriptedLLM) stats() (int, []string, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.firstSystems), append([]string(nil), s.firstSystems...), append([]int(nil), s.msgCounts...)
}

// requestBodies 返回每次请求的消息副本（并发安全）。
func (s *scriptedLLM) requestBodies() [][]Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]Message, 0, len(s.bodies))
	for _, b := range s.bodies {
		out = append(out, append([]Message(nil), b...))
	}
	return out
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func agentTestCopilot(t *testing.T, url string, cfg config.AIConfig, exec ToolExecutor) *Copilot {
	t.Helper()
	cfg.Enabled = true
	cfg.BaseURL = url
	cfg.APIKey = "k"
	cfg.Model = "m"
	cfg.Timeout = 5
	return New(cfg, exec)
}

// TestRunAgentResidentPrefixStableEndToEnd 端到端：同一 run 连续多轮请求里，
// 第一条消息（常驻层）必须逐字节相同；任务层（第二条）随轮次变化。
func TestRunAgentResidentPrefixStableEndToEnd(t *testing.T) {
	srv := newScriptedLLM(true, "", nil)
	defer srv.close()
	cp := agentTestCopilot(t, srv.srv.URL, config.AIConfig{MaxTurns: 3, MaxToolCalls: 10}, &fakeToolExec{})
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "列出在线会话"}}, 0)
	run.SetObjective("列出在线会话")

	if _, err := cp.RunAgent(context.Background(), run); err == nil {
		t.Fatal("达到轮次上限应返回错误（调用方据此知道是被预算截停的）")
	}
	n, systems, _ := srv.stats()
	if n < 3 {
		t.Fatalf("应至少发出 3 次请求，实际 %d 次", n)
	}
	for i, sys := range systems {
		if sys != residentSystemPrompt {
			t.Fatalf("第 %d 次请求的常驻层不是逐字节稳定的常驻层（长度 %d）", i+1, len(sys))
		}
	}
	if run.StopReason != stopReasonMaxTurns {
		t.Fatalf("stop_reason = %q, want %q", run.StopReason, stopReasonMaxTurns)
	}
	if !strings.Contains(run.FinalReply, "轮次上限") {
		t.Fatalf("最终回复应说明因轮次上限停止：%s", run.FinalReply)
	}
	tokens, budget, _ := run.ContextSnapshot()
	if tokens <= 0 || budget != config.DefaultMaxContextTokens {
		t.Fatalf("run 应记录上下文估算与预算：tokens=%d budget=%d", tokens, budget)
	}
}

// TestRunAgentStopsOnTokenBudget 累计 token 预算：上游 usage 真值达上限后，
// 下一轮**不再**发起 LLM 调用，stop_reason=max_tokens，并照常产出最终回复（不静默中断）。
func TestRunAgentStopsOnTokenBudget(t *testing.T) {
	srv := newScriptedLLM(true, "", &chatUsage{PromptTokens: 5000, CompletionTokens: 50, TotalTokens: 5050})
	defer srv.close()
	cp := agentTestCopilot(t, srv.srv.URL, config.AIConfig{MaxTurns: 20, MaxToolCalls: 40, MaxRunTokens: 1000}, &fakeToolExec{})
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "列出在线会话"}}, 0)

	_, _ = cp.RunAgent(context.Background(), run)

	if n, _, _ := srv.stats(); n != 1 {
		t.Fatalf("预算耗尽后不应再发请求（含收尾调用），实际 %d 次", n)
	}
	if run.StopReason != stopReasonMaxTokens {
		t.Fatalf("stop_reason = %q, want %q", run.StopReason, stopReasonMaxTokens)
	}
	if run.Status != AgentDone {
		t.Fatalf("预算停止应是正常收尾（done），得到 %s", run.Status)
	}
	u := run.TokenUsage()
	if u.PromptTokens != 5000 || u.CompletionTokens != 50 || u.Samples != 1 {
		t.Fatalf("usage 真值未累计：%+v", u)
	}
	for _, needle := range []string{"token", "预算", "1000", "5000"} {
		if !strings.Contains(run.FinalReply, needle) {
			t.Errorf("预算停止的最终回复缺少 %q：\n%s", needle, run.FinalReply)
		}
	}
}

// TestRunAgentCompressesInsteadOfStopping 上下文超预算时**先压缩继续跑**（不是直接停）：
// 超长历史被折叠后仍在预算内，模型正常给出最终答复，run 上标记"压缩过"。
func TestRunAgentCompressesInsteadOfStopping(t *testing.T) {
	srv := newScriptedLLM(false, "已完成", nil)
	defer srv.close()
	// 预算 20000：正常档（工作层 14 条超大结果）会超，激进压缩后能落回预算内。
	cp := agentTestCopilot(t, srv.srv.URL, config.AIConfig{MaxTurns: 5, MaxToolCalls: 10, MaxContextTokens: 20000}, &fakeToolExec{})

	history := make([]Message, 0, 32)
	for i := 0; i < 30; i++ {
		history = append(history, Message{Role: "tool", Content: strings.Repeat("z", 20000)})
	}
	history = append(history, Message{Role: "user", Content: "汇总一下"})
	run := NewAgentManager(1).NewRun(history, 0)

	if _, err := cp.RunAgent(context.Background(), run); err != nil {
		t.Fatalf("压缩后应能正常完成：%v", err)
	}
	if run.StopReason != "" {
		t.Fatalf("压缩成功不应记 stop_reason，得到 %q", run.StopReason)
	}
	if run.FinalReply != "已完成" {
		t.Fatalf("最终答复 = %q", run.FinalReply)
	}
	tokens, budget, compressed := run.ContextSnapshot()
	if !compressed {
		t.Fatal("run 应标记本次上下文被压缩过")
	}
	if budget != 20000 || tokens > UsableContextTokens(20000) {
		t.Fatalf("压缩后仍超预算：tokens=%d budget=%d", tokens, budget)
	}
	n, systems, counts := srv.stats()
	if n == 0 {
		t.Fatal("应至少发出一次请求")
	}
	_ = counts
	// 请求里不得再出现 20000 字符的原文块，且总体积必须远小于原始历史（说明折叠生效）。
	totalBytes := 0
	for _, body := range srv.requestBodies() {
		for j, m := range body {
			totalBytes += len(m.Content)
			if j < 2 {
				continue // 前两条是常驻层与任务层，不参与"原文被压小"的判定
			}
			if len(m.Content) > maxWorkingMessageRunes+400 {
				t.Fatalf("请求里仍有 %d 字节的超长原文：上下文没有被压缩", len(m.Content))
			}
		}
	}
	if raw := len(history) * 20000; totalBytes >= raw/4 {
		t.Fatalf("请求总体积 %d 字节，远未压小（原始约 %d 字节）", totalBytes, raw)
	}
	// 常驻层依然逐字节稳定（压缩路径不得改动它）。
	for i, sys := range systems {
		if sys != residentSystemPrompt {
			t.Fatalf("第 %d 次请求的常驻层被压缩改动了", i+1)
		}
	}
}

// 且**不依赖任何 LLM 调用**（预算已耗尽，不该再发一次注定超预算的请求）。
// TestTokenBudgetStopReply 因预算停止的最终回复：必须带用量数字、不静默中断，
// 且**不依赖任何 LLM 调用**（预算已耗尽，不该再发一次注定超预算的请求）。
func TestTokenBudgetStopReply(t *testing.T) {
	stats := ContextStats{
		TotalTokens: 26000, CalibratedTokens: 26000, BudgetTokens: 32000, UsableTokens: 24616,
		Compressed: true, WorkingKept: 4, WorkingLimit: 14, CollapsedMessages: 17,
	}
	tokens := RunTokenUsage{PromptTokens: 300000, CompletionTokens: 20000, EstimatedTokens: 5000}
	budget := TokenBudget{MaxContextTokens: 32000, MaxRunTokens: 400000}
	reply := tokenBudgetStopReply("本次执行已达 token 预算上限（上下文或累计用量），工具阶段到此为止。", stats, tokens, budget, nil)
	for _, needle := range []string{"token", "32000", "400000", "压缩", "未执行任何工具调用"} {
		if !strings.Contains(reply, needle) {
			t.Errorf("预算停止回复缺少 %q：\n%s", needle, reply)
		}
	}
	withTraces := tokenBudgetStopReply("note", stats, tokens, budget,
		[]ToolTrace{{Name: "exec", Result: `{"status":"completed","output":"nt authority\\system"}`}})
	if !strings.Contains(withTraces, "exec") {
		t.Errorf("有轨迹时应附上动作清单：%s", withTraces)
	}
	if strings.Contains(withTraces, "未执行任何工具调用") {
		t.Error("有轨迹时不应出现「未执行任何工具调用」")
	}
}

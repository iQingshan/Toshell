package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"toshell/internal/server/config"
)

// ═══ 同一条 assistant 消息里的多个 tool_calls ═══════════════════════════════
//
// 用户实测事故（v1.4.0）：模型在**一条** assistant 消息里声明了 2 个工具调用，
// 自主循环只处理了 ToolCalls[0]，第二个既不执行也没有任何日志；历史里于是留下
// "声明 2 个、回执 1 条"，靠装配出口的 sanitizeToolPairs 补"未完成"回执才没被上游 400。
//
// 本文件的用例把这条不变量钉死：**一条消息声明的每个调用都必须被独立处理**——
// 要么真的执行（含去重回放/挂起），要么拿到一条明确的"未执行"回执。

// multiCallLLM 桩 LLM：第 1 次请求返回"一条 assistant 消息 + N 个 tool_call"，
// 之后每次请求返回最终答复；giveIDs=false 模拟"上游不回 tool_call id"的模型/代理。
type multiCallLLM struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  [][]Message
	giveIDs bool
	calls   []ToolCall
	final   string
}

func newMultiCallLLM(t *testing.T, calls []ToolCall, giveIDs bool, final string) *multiCallLLM {
	t.Helper()
	m := &multiCallLLM{calls: calls, giveIDs: giveIDs, final: final}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []Message `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		m.mu.Lock()
		n := len(m.bodies)
		m.bodies = append(m.bodies, req.Messages)
		m.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		if n == 0 {
			// 关键：**同一条** assistant 消息里按 index 依次产出全部 tool_call。
			for k, tc := range m.calls {
				delta := map[string]interface{}{
					"index": k, "type": "function",
					"function": map[string]interface{}{"name": tc.Function.Name, "arguments": tc.Function.Arguments},
				}
				if m.giveIDs {
					delta["id"] = tc.ID
				}
				writeSSEChunk(w, map[string]interface{}{"choices": []interface{}{map[string]interface{}{
					"delta": map[string]interface{}{"tool_calls": []interface{}{delta}},
				}}})
			}
			writeSSEChunk(w, map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{}, "finish_reason": "tool_calls",
			}}})
		} else {
			writeSSEChunk(w, map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{"content": m.final},
			}}})
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *multiCallLLM) requests() [][]Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]Message, 0, len(m.bodies))
	for _, b := range m.bodies {
		out = append(out, append([]Message(nil), b...))
	}
	return out
}

// twoReadCalls 两个**只读**工具调用（graded 策略下免审批，能直接走到执行）。
func twoReadCalls() []ToolCall {
	return []ToolCall{
		{ID: "call-p0", Type: "function", Function: ToolCallFunc{Name: "session_list", Arguments: "{}"}},
		{ID: "call-p1", Type: "function", Function: ToolCallFunc{Name: "session_context", Arguments: `{"session_id":"s1"}`}},
	}
}

// containsTool 判断执行记录里有没有某个工具。
//
// 注意：任务层装配会先用 session_list(nil) 预热一次"在线会话快照"（见 Copilot.sessionSnapshot），
// 那不是模型声明的调用，所以这里一律用 run.Traces / 具体工具名判断，而不是数调用次数。
func containsTool(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// receiptFor 找出某个 tool_call_id 的回执消息（nil=没有）。
func receiptFor(msgs []Message, callID string) *Message {
	for i := range msgs {
		if msgs[i].Role == "tool" && msgs[i].ToolCallID == callID {
			return &msgs[i]
		}
	}
	return nil
}

// assistantWithCalls 找出历史里第一条声明了 tool_calls 的 assistant 消息。
func assistantWithCalls(msgs []Message) *Message {
	for i := range msgs {
		if msgs[i].Role == "assistant" && len(msgs[i].ToolCalls) > 0 {
			return &msgs[i]
		}
	}
	return nil
}

// assertToolPairsStrict 校验历史/请求里的"声明 → 回执"严格成对：// 每个 assistant.tool_calls 后面必须**紧跟**它的全部回执，条数与顺序都与声明一致。
// （上游就是这么校验的；装配出口的 sanitizeToolPairs 只是最后的兜底，不能靠它掩盖丢执行。）
func assertToolPairsStrict(t *testing.T, msgs []Message, where string) {
	t.Helper()
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		if m.Role != "assistant" || len(m.ToolCalls) == 0 {
			continue
		}
		for k, tc := range m.ToolCalls {
			j := i + 1 + k
			if j >= len(msgs) || msgs[j].Role != "tool" {
				t.Fatalf("%s：assistant 声明的第 %d 个 tool_call(%s) 之后没有紧跟的 tool 回执", where, k+1, tc.ID)
			}
			if msgs[j].ToolCallID != tc.ID {
				t.Fatalf("%s：回执与声明错位，第 %d 个声明的 id=%s，回执 id=%s",
					where, k+1, tc.ID, msgs[j].ToolCallID)
			}
		}
	}
}

// assertAllReceiptsReal 断言"所有回执都是真结果"——只用在两次调用都该被执行的用例里：
// 一旦某个调用被静默跳过，装配出口的 sanitizeToolPairs 会补一条「未执行」占位，
// 这里就会当场抓住（而不是像以前那样被兜底掩盖过去）。
func assertAllReceiptsReal(t *testing.T, msgs []Message, where string) {
	t.Helper()
	for _, m := range msgs {
		if m.Role == "tool" && strings.Contains(m.Content, "未执行") {
			t.Fatalf("%s：出现了「未执行」占位回执，说明有调用被跳过：%s", where, m.Content)
		}
	}
}

// TestRunAgentProcessesAllToolCallsInOneMessage 核心回归：一条 assistant 消息里的
// 2 个 tool_call 必须**都被执行**（旧实现只执行第一个，第二个被静默跳过）。
func TestRunAgentProcessesAllToolCallsInOneMessage(t *testing.T) {
	llm := newMultiCallLLM(t, twoReadCalls(), true, "两个都执行完了")
	exec := &evalExec{results: map[string]string{}, errs: map[string]string{}}
	cp := agentTestCopilot(t, llm.srv.URL, config.AIConfig{MaxTurns: 5, MaxToolCalls: 40}, exec)
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "看看有哪些会话"}}, 0)

	if _, err := cp.RunAgent(context.Background(), run); err != nil {
		t.Fatalf("run 应正常结束，得到错误：%v", err)
	}
	if !containsTool(exec.toolNames(), "session_context") {
		t.Fatalf("第二个调用 session_context 必须真的被执行，实际执行序列 = %v", exec.toolNames())
	}
	if len(run.Traces) != 2 || run.Traces[0].Name != "session_list" || run.Traces[1].Name != "session_context" {
		t.Fatalf("轨迹应含两次调用且按声明顺序，实际 = %+v", run.Traces)
	}
	if run.Status != AgentDone || !strings.Contains(run.FinalReply, "两个都执行完了") {
		t.Fatalf("status=%s reply=%q", run.Status, run.FinalReply)
	}
	assertToolPairsStrict(t, run.Messages, "run.Messages")
	assertAllReceiptsReal(t, run.Messages, "run.Messages")
	// 下一轮真正发往上游的消息序列也必须严格成对（否则就是用户看到的 400）。
	reqs := llm.requests()
	if len(reqs) < 2 {
		t.Fatalf("应至少两轮 LLM 调用，实际 %d", len(reqs))
	}
	assertToolPairsStrict(t, reqs[1], "第 2 轮请求")
	assertAllReceiptsReal(t, reqs[1], "第 2 轮请求")
}

// TestRunAgentProcessesAllToolCallsWithoutUpstreamIDs 上游**不给 id** 时同样逐个执行：
// 服务端补 call_auto_<index>，两个调用都要跑，回执也要能配对。
func TestRunAgentProcessesAllToolCallsWithoutUpstreamIDs(t *testing.T) {
	llm := newMultiCallLLM(t, twoReadCalls(), false, "无 id 也跑完了")
	exec := &evalExec{results: map[string]string{}, errs: map[string]string{}}
	cp := agentTestCopilot(t, llm.srv.URL, config.AIConfig{MaxTurns: 5, MaxToolCalls: 40}, exec)
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "看看有哪些会话"}}, 0)

	if _, err := cp.RunAgent(context.Background(), run); err != nil {
		t.Fatalf("run 应正常结束，得到错误：%v", err)
	}
	if !containsTool(exec.toolNames(), "session_context") {
		t.Fatalf("无 id 时第二个调用也必须真执行，实际执行序列 = %v", exec.toolNames())
	}
	if len(run.Traces) != 2 || run.Traces[1].Name != "session_context" {
		t.Fatalf("轨迹应含两次调用且按声明顺序，实际 = %+v", run.Traces)
	}
	// 服务端补的 id 必须非空且互不相同（否则回执配不上、上游 400）。
	run.mu.Lock()
	var declared []ToolCall
	if a := assistantWithCalls(run.Messages); a != nil {
		declared = append([]ToolCall(nil), a.ToolCalls...)
	}
	run.mu.Unlock()
	if len(declared) != 2 {
		t.Fatalf("assistant 消息应声明 2 个调用，实际 %+v", declared)
	}
	if declared[0].ID == "" || declared[1].ID == "" || declared[0].ID == declared[1].ID {
		t.Fatalf("补出来的 call id 必须非空且唯一：%q / %q", declared[0].ID, declared[1].ID)
	}
	assertToolPairsStrict(t, run.Messages, "run.Messages")
	assertAllReceiptsReal(t, run.Messages, "run.Messages")
	assertToolPairsStrict(t, llm.requests()[1], "第 2 轮请求")
	assertAllReceiptsReal(t, llm.requests()[1], "第 2 轮请求")
}

// TestRunAgentToolCallBudgetFillsExplicitReceipts 提前收敛分支（工具调用数上限）：
// 没轮到的调用也**不能静默消失**——必须留下一条明确写着"未执行"的回执。
func TestRunAgentToolCallBudgetFillsExplicitReceipts(t *testing.T) {
	llm := newMultiCallLLM(t, twoReadCalls(), true, "收尾报告")
	exec := &evalExec{results: map[string]string{}, errs: map[string]string{}}
	// 上限 1：一条消息声明 2 个调用时，第 2 个必须被上限拦下并补回执。
	cp := agentTestCopilot(t, llm.srv.URL, config.AIConfig{MaxTurns: 5, MaxToolCalls: 1}, exec)
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "看看有哪些会话"}}, 0)

	_, _ = cp.RunAgent(context.Background(), run)

	if got := exec.toolNames(); containsTool(got, "session_context") {
		t.Fatalf("上限 1 时不应执行第二个调用，实际 %v", got)
	}
	if len(run.Traces) != 1 || run.Traces[0].Name != "session_list" {
		t.Fatalf("上限 1 时只应有 1 条轨迹，实际 %+v", run.Traces)
	}
	if run.stopReason() != stopReasonMaxToolCalls {
		t.Fatalf("stop_reason = %q, want %q", run.stopReason(), stopReasonMaxToolCalls)
	}
	assertToolPairsStrict(t, run.Messages, "run.Messages")
	// 被上限拦下的那个调用：回执里必须如实写"未执行"（不能既没执行又没回执）。
	run.mu.Lock()
	msgs := append([]Message(nil), run.Messages...)
	run.mu.Unlock()
	last := receiptFor(msgs, "call-p1")
	if last == nil || !strings.Contains(last.Content, "未执行") {
		t.Fatalf("被上限拦下的调用应留下明确的未执行回执，实际 = %+v", last)
	}
}

// TestRunAgentConsentPauseFillsReceiptsForRemainingCalls 挂起分支（审批）：
// 暂停在第一个调用上，同一条消息里剩下的调用在恢复时补回执，不允许"声明了却不回执"。
func TestRunAgentConsentPauseFillsReceiptsForRemainingCalls(t *testing.T) {
	llm := newMultiCallLLM(t, twoReadCalls(), true, "收尾报告")
	exec := &evalExec{results: map[string]string{}, errs: map[string]string{}}
	// all：连只读工具都要审批 → 一定停在第一个调用上（模拟"审批挂起"分支）。
	cp := agentTestCopilot(t, llm.srv.URL, config.AIConfig{MaxTurns: 5, MaxToolCalls: 40, ConsentPolicy: ConsentPolicyAll}, exec)
	run := NewAgentManager(1).NewRun([]Message{{Role: "user", Content: "看看有哪些会话"}}, 0)

	_, err := cp.RunAgent(context.Background(), run)
	if err != errAgentPaused {
		t.Fatalf("应因等待审批而挂起，得到 %v", err)
	}
	if run.Status != AgentWaitConsent {
		t.Fatalf("status = %s, want %s", run.Status, AgentWaitConsent)
	}
	if containsTool(exec.toolNames(), "session_context") {
		t.Fatalf("挂起时不应执行任何模型声明的工具，实际 %v", exec.toolNames())
	}

	if _, err := cp.ResolveAgentConsent(context.Background(), run, true); err != nil {
		t.Fatalf("审批通过后应能继续：%v", err)
	}
	if !containsTool(exec.toolNames(), "session_list") {
		t.Fatalf("审批通过后应执行第一个调用，实际 %v", exec.toolNames())
	}
	if containsTool(exec.toolNames(), "session_context") {
		t.Fatalf("审批只针对第一个调用，第二个不应被执行，实际 %v", exec.toolNames())
	}
	assertToolPairsStrict(t, run.Messages, "审批恢复后的 run.Messages")
	run.mu.Lock()
	msgs := append([]Message(nil), run.Messages...)
	run.mu.Unlock()
	last := receiptFor(msgs, "call-p1")
	if last == nil || !strings.Contains(last.Content, "未执行") {
		t.Fatalf("同批里未轮到的调用应补「未执行」回执，实际 = %+v", last)
	}
}

// TestUnexecutedToolRepliesPureFunction 纯函数层：条数/顺序/正文都要如实。
func TestUnexecutedToolRepliesPureFunction(t *testing.T) {
	calls := twoReadCalls()
	got := unexecutedToolReplies(calls, "测试原因")
	if len(got) != 2 {
		t.Fatalf("应为每个未执行的调用生成一条回执，实际 %d 条", len(got))
	}
	for i, m := range got {
		if m.Role != "tool" || m.ToolCallID != calls[i].ID {
			t.Fatalf("第 %d 条回执与声明顺序/配对不符：%+v", i+1, m)
		}
		if !strings.Contains(m.Content, "未执行") || !strings.Contains(m.Content, "测试原因") {
			t.Fatalf("回执正文必须如实写明未执行与原因，实际 %q", m.Content)
		}
	}
	if unexecutedToolReplies(nil, "x") != nil {
		t.Fatal("空调用列表不应生成回执")
	}
	// 空原因也要给出人话（不能出现空白的"未执行："）
	if n := unexecutedToolReplies(calls[:1], "  "); len(n) != 1 || !strings.Contains(n[0].Content, "收敛") {
		t.Fatalf("空原因应回落到默认说明，实际 %+v", n)
	}
}

// TestUnhandledCallsAfter 挂起快照用的"同批剩余调用"查找：从历史反推声明顺序。
func TestUnhandledCallsAfter(t *testing.T) {
	calls := twoReadCalls()
	msgs := []Message{
		{Role: "user", Content: "x"},
		{Role: "assistant", ToolCalls: calls},
	}
	if got := unhandledCallsAfter(msgs, "call-p0"); len(got) != 1 || got[0].ID != "call-p1" {
		t.Fatalf("call-p0 之后应剩 call-p1，实际 %+v", got)
	}
	if got := unhandledCallsAfter(msgs, "call-p1"); len(got) != 0 {
		t.Fatalf("最后一个调用之后不应有剩余，实际 %+v", got)
	}
	if got := unhandledCallsAfter(msgs, "不存在"); got != nil {
		t.Fatalf("找不到声明者时应返回 nil（交给装配兜底），实际 %+v", got)
	}
	if got := unhandledCallsAfter(nil, "call-p0"); got != nil {
		t.Fatalf("空历史应返回 nil，实际 %+v", got)
	}
}

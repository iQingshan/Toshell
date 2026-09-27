package ai

import (
	"testing"
)

// TestSanitizeToolPairsFillsMissingReplies 复现并锁死用户实测到的 400：
//
//	An assistant message with 'tool_calls' must be followed by tool messages responding to
//	each 'tool_call_id'. (insufficient tool messages following tool_calls message)
//
// 历史里出现"孤儿 tool_calls"的原因见 sanitizeToolPairs 的注释（agent 循环的早退分支）。
func TestSanitizeToolPairsFillsMissingReplies(t *testing.T) {
	calls := []ToolCall{
		{ID: "call_a", Type: "function", Function: ToolCallFunc{Name: "session_list", Arguments: "{}"}},
		{ID: "call_b", Type: "function", Function: ToolCallFunc{Name: "session_context", Arguments: "{}"}},
	}
	t.Run("两个调用只有一个回执：补齐缺失的那条", func(t *testing.T) {
		in := []Message{
			{Role: "user", Content: "收集信息"},
			{Role: "assistant", ToolCalls: calls},
			{Role: "tool", ToolCallID: "call_a", Content: "{\"ok\":true}"},
		}
		out := sanitizeToolPairs(in)
		if len(out) != 4 {
			t.Fatalf("输出消息数 = %d, want 4（assistant + 两条 tool 回执）: %+v", len(out), out)
		}
		if out[1].Role != "assistant" || len(out[1].ToolCalls) != 2 {
			t.Fatalf("assistant.tool_calls 不该被改写：%+v", out[1])
		}
		if out[2].Role != "tool" || out[2].ToolCallID != "call_a" {
			t.Fatalf("第一条回执应保留原内容：%+v", out[2])
		}
		if out[3].Role != "tool" || out[3].ToolCallID != "call_b" {
			t.Fatalf("缺失的 call_b 必须补一条 tool 回执：%+v", out[3])
		}
		if out[3].Content == "" {
			t.Fatal("补出来的回执必须有明确文案（说明未完成），不能是空内容")
		}
	})

	t.Run("一条回执都没有：两条都补齐", func(t *testing.T) {
		in := []Message{
			{Role: "assistant", ToolCalls: calls},
			{Role: "user", Content: "继续"},
		}
		out := sanitizeToolPairs(in)
		got := 0
		for _, m := range out {
			if m.Role == "tool" {
				got++
			}
		}
		if got != 2 {
			t.Fatalf("tool 回执数 = %d, want 2（每个 call_id 一条）: %+v", got, out)
		}
		if out[1].Role != "tool" || out[2].Role != "tool" || out[3].Role != "user" {
			t.Fatalf("回执必须紧跟 assistant，其它消息顺延：%+v", out)
		}
	})

	t.Run("回执被 system 挤在中间：并到 assistant 之后", func(t *testing.T) {
		in := []Message{
			{Role: "assistant", ToolCalls: calls[:1]},
			{Role: "system", Content: "不要重复调用"},
			{Role: "tool", ToolCallID: "call_a", Content: "result"},
		}
		out := sanitizeToolPairs(in)
		if out[1].Role != "tool" || out[1].ToolCallID != "call_a" {
			t.Fatalf("回执应紧跟 assistant（上游按'紧跟'判定）: %+v", out)
		}
		if out[2].Role != "system" {
			t.Fatalf("system 提示应顺延到回执之后：%+v", out)
		}
	})

	t.Run("孤儿回执（没有声明者）原地保留、不改写", func(t *testing.T) {
		in := []Message{
			{Role: "user", Content: "hi"},
			{Role: "tool", ToolCallID: "ghost", Content: "old result"},
		}
		out := sanitizeToolPairs(in)
		// 上游的 400 只针对"声明了 tool_calls 却没回执"；孤儿回执不在本函数职责内，
		// 真实 run 里也不会出现（循环总是先写 assistant），因此不做改写。
		if len(out) != 2 || out[1].Role != "tool" || out[1].Content != "old result" {
			t.Fatalf("孤儿 tool 回执应原样保留：%+v", out)
		}
	})

	t.Run("纯对话原样返回（零改写）", func(t *testing.T) {
		in := []Message{{Role: "system", Content: "s"}, {Role: "user", Content: "u"}}
		out := sanitizeToolPairs(in)
		if len(out) != len(in) || out[0].Content != "s" || out[1].Content != "u" {
			t.Fatalf("纯对话不该被改写：%+v", out)
		}
	})

	t.Run("不改写入参", func(t *testing.T) {
		in := []Message{
			{Role: "assistant", ToolCalls: calls},
			{Role: "tool", ToolCallID: "call_a", Content: "x"},
		}
		_ = sanitizeToolPairs(in)
		if len(in) != 2 || in[0].Role != "assistant" || in[1].ToolCallID != "call_a" {
			t.Fatalf("入参被改动了：%+v", in)
		}
	})
}

// TestAssembleContextAlwaysPairsToolCalls 装配出口必须保证成对（不管历史里存了什么）。
func TestAssembleContextAlwaysPairsToolCalls(t *testing.T) {
	history := []Message{
		{Role: "user", Content: "收集信息"},
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: "c1", Type: "function", Function: ToolCallFunc{Name: "session_list", Arguments: "{}"}},
			{ID: "c2", Type: "function", Function: ToolCallFunc{Name: "session_context", Arguments: "{}"}},
		}},
		// 故意只留一条回执（模拟早退分支留下的历史）
		{Role: "tool", ToolCallID: "c1", Content: "ok"},
	}
	msgs, _ := AssembleContext(ContextInput{History: history, Opts: ContextOptions{WorkingKeep: 14}})
	declared := 0
	answered := map[string]bool{}
	prevAssistantCalls := 0
	for _, m := range msgs {
		switch m.Role {
		case "assistant":
			prevAssistantCalls = len(m.ToolCalls)
			declared += len(m.ToolCalls)
		case "tool":
			answered[m.ToolCallID] = true
			prevAssistantCalls = 0
		}
		if prevAssistantCalls > 0 && m.Role != "tool" && m.Role != "assistant" {
			t.Fatalf("assistant.tool_calls 之后必须紧跟 tool 回执，实际跟了 %q", m.Role)
		}
	}
	if declared == 0 {
		t.Fatal("前置条件不成立：历史里应有 2 个 tool_calls")
	}
	if len(answered) != declared {
		t.Fatalf("装配结果里 tool 回执数(%d) != 声明数(%d)：上游会以 400 拒绝", len(answered), declared)
	}
}

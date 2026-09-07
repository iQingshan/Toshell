package ai

import "testing"

// TestParsePlanMarkdown 校验从助手正文解析【执行计划】步骤。
func TestParsePlanMarkdown(t *testing.T) {
	content := `收到，先列计划：
【执行计划】
1. 用 session_list 找在线会话
2. 对目标会话跑 user_info
3. 分析权限并给建议
开始执行。`
	steps := parsePlanMarkdown(content)
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d: %+v", len(steps), steps)
	}
	if steps[0].Desc != "用 session_list 找在线会话" {
		t.Fatalf("step1 desc wrong: %q", steps[0].Desc)
	}
	if steps[1].Status != "pending" {
		t.Fatalf("step2 should be pending")
	}
}

// TestParsePlanMarkdownNoPlan 无计划时应返回空。
func TestParsePlanMarkdownNoPlan(t *testing.T) {
	steps := parsePlanMarkdown("直接查一下 whoami 结果就好。")
	if len(steps) != 0 {
		t.Fatalf("expected no steps, got %d", len(steps))
	}
}

// TestCompressRunMessages 校验上下文压缩：保留 system + 最新指令、折叠较早长 tool 输出（总长显著下降）。
func TestCompressRunMessages(t *testing.T) {
	longTool := ""
	for i := 0; i < 60; i++ {
		longTool += "payload-line-0000000000-payload-0000000000\n"
	}
	msgs := []Message{{Role: "system", Content: "sys"}}
	// 30 条旧消息，每条 tool 输出都很长（模拟长任务累积）
	for i := 0; i < 30; i++ {
		msgs = append(msgs, Message{Role: "tool", Content: longTool})
	}
	msgs = append(msgs, Message{Role: "user", Content: "最新指令"})
	out := compressRunMessages(msgs)
	if out[0].Role != "system" {
		t.Fatal("first msg must stay system")
	}
	last := out[len(out)-1]
	if last.Role != "user" || last.Content != "最新指令" {
		t.Fatal("last msg must be the newest user instruction")
	}
	// 折叠后总字符应显著小于原始（早先 tool 被摘要；尾部保留区仍允许较长但整体必须下降）
	var origLen, outLen int
	for _, m := range msgs {
		origLen += len(m.Content)
	}
	for _, m := range out {
		outLen += len(m.Content)
	}
	if outLen >= origLen {
		t.Fatalf("compression did not reduce size: %d -> %d", origLen, outLen)
	}
	// 30 条长 tool（每条 2580 字符），折叠后应至少省掉大半
	if outLen > origLen/2 {
		t.Fatalf("compression too weak: orig=%d out=%d", origLen, outLen)
	}
}

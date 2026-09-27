package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"toshell/internal/server/config"
)

// ─── 离线评测门禁：黄金集 + 桩 LLM + 假工具执行器（v1.4.0 S2 / 计划 M4）──────
//
// 为什么要有这一层：Agent 的行为（工具序列、何时停、为什么停、上下文里留下什么）以前
// **没有任何回归保护**——改一行循环逻辑，只有人工在真机上试才知道有没有变坏。这里把
// "输入 → 期望工具序列 → 期望终态/停止原因 → 期望上下文痕迹"固化成可执行用例：
//
//   - 全程**不联网、不需要真实 LLM、不需要植入端**：桩 LLM 按脚本逐轮应答（httptest），
//     工具执行器是进程内的假实现，因此 CI 上可跑、结果确定；
//   - 用例写在 `testdata/golden/cases.json`（一条一块，便于加 case 而不用改 Go 代码）；
//   - 除了每条用例自己的断言，还有一条**全局不变量**：任何一次发给上游的消息序列里，
//     `tool` 回执必须能找到配对的 `assistant.tool_calls`（否则上游 chat/completions 直接
//     拒绝，压缩/折叠最容易在这里出事）。
//
// 覆盖的行为：正常收尾、单工具往返、防死循环（含只读豁免）、轮次/工具数/token 三种预算、
// 分级审批挂起（含 delegate 与未注册工具的 fail-closed）、大结果外置与句柄回读、
// 历史折叠保真（保留真实工具名与"非原文"标注）。

// goldenTurn 桩 LLM 的一轮应答：要么发起工具调用，要么给出最终文本。
type goldenTurn struct {
	Tool    string            `json:"tool,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Content string            `json:"content,omitempty"`
}

// goldenAI 该用例的 ai.* 配置（零值表示"不设置，走默认"）。
type goldenAI struct {
	ConsentPolicy      string `json:"consent_policy"`
	MaxTurns           int    `json:"max_turns"`
	MaxToolCalls       int    `json:"max_tool_calls"`
	MaxWallclockSec    int    `json:"max_wallclock_sec"`
	MaxContextTokens   int    `json:"max_context_tokens"`
	MaxRunTokens       int    `json:"max_run_tokens"`
	ContextWorkingKeep int    `json:"context_working_keep"`
	InlineLimit        int    `json:"inline_limit"`
}

// goldenExpect 期望值。
type goldenExpect struct {
	Status             string   `json:"status"`
	StopReason         string   `json:"stop_reason"`
	Tools              []string `json:"tools"`
	ReplyContains      []string `json:"reply_contains"`
	MinLLMTurns        int      `json:"min_llm_turns"`
	MaxLLMTurns        int      `json:"max_llm_turns"`
	AnyToolHasHandle   bool     `json:"any_tool_has_handle"`
	ContextContains    []string `json:"context_contains"`
	ContextNotContains []string `json:"context_not_contains"`
}

// goldenCase 一条用例。
type goldenCase struct {
	Name        string                 `json:"name"`
	Why         string                 `json:"why"`
	Objective   string                 `json:"objective"`
	Script      []goldenTurn           `json:"script"`
	ToolResults map[string]string      `json:"tool_results"`
	BigResult   map[string]interface{} `json:"big_result"` // {"tool":"tool_list","repeat":20000}
	AI          goldenAI               `json:"ai"`
	Expect      goldenExpect           `json:"expect"`
}

// ─── 桩 LLM ────────────────────────────────────────────────────────────

// evalLLM 按脚本逐轮应答的假 LLM（SSE）。第 n 次请求回 script[n]；脚本用完后**重复最后一条**，
// 这样"反复调用同一工具"的用例（防死循环/预算）不需要写很多条脚本。
type evalLLM struct {
	srv    *httptest.Server
	mu     sync.Mutex
	turns  []goldenTurn
	calls  int
	bodies [][]Message
}

func newEvalLLM(t *testing.T, turns []goldenTurn) *evalLLM {
	t.Helper()
	e := &evalLLM{turns: turns}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []Message `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)

		e.mu.Lock()
		n := e.calls
		e.calls++
		e.bodies = append(e.bodies, req.Messages)
		turn := goldenTurn{Content: "（脚本已用尽）"}
		if len(e.turns) > 0 {
			if n < len(e.turns) {
				turn = e.turns[n]
			} else {
				turn = e.turns[len(e.turns)-1]
			}
		}
		handle := ""
		for _, tr := range collectHandles(req.Messages) {
			handle = tr
		}
		e.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		if turn.Tool != "" {
			args := map[string]string{}
			for k, v := range turn.Args {
				// $LAST_HANDLE：让脚本能引用上一轮工具结果里的句柄（回读用例需要）
				if v == "$LAST_HANDLE" {
					v = handle
				}
				args[k] = v
			}
			ab, _ := json.Marshal(args)
			chunk := map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{"tool_calls": []interface{}{map[string]interface{}{
					"index": 0, "id": fmt.Sprintf("call-%d", n+1), "type": "function",
					"function": map[string]interface{}{"name": turn.Tool, "arguments": string(ab)},
				}}},
			}}}
			writeSSEChunk(w, chunk)
		} else if turn.Content != "" {
			writeSSEChunk(w, map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{"content": turn.Content},
			}}})
		}
		// usage：让 token 记账/校准走真值路径（部分兼容端点不回 usage，另有专门用例）
		writeSSEChunk(w, map[string]interface{}{
			"choices": []interface{}{},
			"usage": map[string]interface{}{
				"prompt_tokens": 120, "completion_tokens": 12, "total_tokens": 132,
			},
		})
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func writeSSEChunk(w io.Writer, chunk map[string]interface{}) {
	b, _ := json.Marshal(chunk)
	_, _ = io.WriteString(w, "data: "+string(b)+"\n\n")
}

// collectHandles 从消息里抓结果信封的句柄（形如 20260927/abcdef0123456789）。
func collectHandles(msgs []Message) []string {
	var out []string
	for _, m := range msgs {
		if m.Role != "tool" {
			continue
		}
		idx := 0
		for {
			i := strings.Index(m.Content[idx:], `"handle":"`)
			if i < 0 {
				break
			}
			start := idx + i + len(`"handle":"`)
			end := strings.Index(m.Content[start:], `"`)
			if end < 0 {
				break
			}
			out = append(out, m.Content[start:start+end])
			idx = start + end
		}
	}
	return out
}

// ─── 假工具执行器 ──────────────────────────────────────────────────────

type evalExec struct {
	mu      sync.Mutex
	calls   []string
	args    []map[string]string
	results map[string]string
	bigTool string
	bigSize int
	errs    map[string]string
}

func (e *evalExec) InvokeTool(name string, args map[string]string) (interface{}, error) {
	e.mu.Lock()
	e.calls = append(e.calls, name)
	e.args = append(e.args, args)
	big, bigSize, res, errMsg := e.bigTool, e.bigSize, e.results[name], e.errs[name]
	e.mu.Unlock()

	if errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}
	if name == big && bigSize > 0 {
		// 构造一个"很大"的结果（模拟截图/工具清单等），用于验证外置 + 句柄
		payload := strings.Repeat("A", bigSize)
		return map[string]interface{}{"image": payload, "format": "png"}, nil
	}
	if res != "" {
		var v interface{}
		if err := json.Unmarshal([]byte(res), &v); err == nil {
			return v, nil
		}
		return res, nil
	}
	return map[string]interface{}{"ok": true, "tool": name}, nil
}

func (e *evalExec) toolNames() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

// ─── 运行器 ────────────────────────────────────────────────────────────

func loadGoldenCases(t *testing.T) []goldenCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "cases.json"))
	if err != nil {
		t.Fatalf("读取黄金集失败: %v", err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("解析黄金集失败: %v", err)
	}
	if len(cases) < 10 {
		t.Fatalf("黄金集至少要有 10 例（计划 M4 的 DoD），实际 %d", len(cases))
	}
	return cases
}

// TestGoldenSet 跑完整个黄金集。一个用例一个子测试，失败时能直接看出是哪条行为变了。
func TestGoldenSet(t *testing.T) {
	for _, tc := range loadGoldenCases(t) {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			runGoldenCase(t, tc)
		})
	}
}

func runGoldenCase(t *testing.T, tc goldenCase) {
	t.Helper()
	llm := newEvalLLM(t, tc.Script)

	exec := &evalExec{results: tc.ToolResults, errs: map[string]string{}}
	if tc.BigResult != nil {
		exec.bigTool, _ = tc.BigResult["tool"].(string)
		if v, ok := tc.BigResult["repeat"].(float64); ok {
			exec.bigSize = int(v)
		}
	}

	cfg := config.AIConfig{
		Enabled: true, BaseURL: llm.srv.URL, APIKey: "k", Model: "m", Timeout: 10,
		ConsentPolicy:      tc.AI.ConsentPolicy,
		MaxTurns:           tc.AI.MaxTurns,
		MaxToolCalls:       tc.AI.MaxToolCalls,
		MaxWallclockSec:    tc.AI.MaxWallclockSec,
		MaxContextTokens:   tc.AI.MaxContextTokens,
		MaxRunTokens:       tc.AI.MaxRunTokens,
		ContextWorkingKeep: tc.AI.ContextWorkingKeep,
	}
	cp := New(cfg, exec)
	// 结果外置：小内联上限 + 内存版存储，专门用来验证"超限 → 句柄 → 回读"
	inlineLimit := tc.AI.InlineLimit
	if inlineLimit <= 0 {
		inlineLimit = 8192
	}
	cp.SetResultStore(newFakeResultWriter(), inlineLimit)

	mgr := NewAgentManager(1)
	run := mgr.NewRun([]Message{{Role: "user", Content: tc.Objective}}, 0)
	run.SetObjective(tc.Objective)

	_, _ = cp.RunAgent(context.Background(), run)

	// ── 全局不变量：每次发往上游的消息里，tool 回执必须能配到 assistant.tool_calls ──
	llm.mu.Lock()
	bodies := append([][]Message(nil), llm.bodies...)
	turns := llm.calls
	llm.mu.Unlock()
	for i, msgs := range bodies {
		if bad := firstUnpairedToolMessage(msgs); bad != "" {
			t.Fatalf("第 %d 轮请求的消息序列里有配不上 assistant.tool_calls 的 tool 回执（上游会直接拒绝）：%s",
				i+1, bad)
		}
	}

	// ── 用例自身断言 ──
	gotTools := make([]string, 0, len(run.Traces))
	for _, tr := range run.Traces {
		gotTools = append(gotTools, tr.Name)
	}
	if tc.Expect.Tools != nil {
		if strings.Join(gotTools, ",") != strings.Join(tc.Expect.Tools, ",") {
			t.Errorf("工具序列 = %v, want %v", gotTools, tc.Expect.Tools)
		}
	}
	if tc.Expect.Status != "" {
		if st, _ := run.WaitState(); string(st) != tc.Expect.Status {
			t.Errorf("status = %s, want %s（stop_reason=%s）", st, tc.Expect.Status, run.stopReason())
		}
	}
	if tc.Expect.StopReason != "" && run.stopReason() != tc.Expect.StopReason {
		t.Errorf("stop_reason = %q, want %q", run.stopReason(), tc.Expect.StopReason)
	}
	if tc.Expect.StopReason == "" && run.stopReason() != "" {
		t.Errorf("不该有 stop_reason，实际 %q", run.stopReason())
	}
	for _, want := range tc.Expect.ReplyContains {
		if !strings.Contains(run.FinalReply, want) {
			t.Errorf("最终答复缺少 %q：%s", want, truncate(run.FinalReply, 300))
		}
	}
	if tc.Expect.MinLLMTurns > 0 && turns < tc.Expect.MinLLMTurns {
		t.Errorf("LLM 往返 = %d, want ≥ %d", turns, tc.Expect.MinLLMTurns)
	}
	if tc.Expect.MaxLLMTurns > 0 && turns > tc.Expect.MaxLLMTurns {
		t.Errorf("LLM 往返 = %d, want ≤ %d（预算/上限没生效？）", turns, tc.Expect.MaxLLMTurns)
	}
	if tc.Expect.AnyToolHasHandle {
		found := false
		for _, tr := range run.Traces {
			if tr.Handle != "" && tr.Truncated {
				found = true
			}
		}
		if !found {
			t.Errorf("应有工具结果被外置成句柄（traces=%+v）", run.Traces)
		}
	}
	if len(tc.Expect.ContextContains) > 0 || len(tc.Expect.ContextNotContains) > 0 {
		if len(bodies) == 0 {
			t.Fatal("没有任何请求体可供上下文断言")
		}
		last := flattenMessages(bodies[len(bodies)-1])
		for _, want := range tc.Expect.ContextContains {
			if !strings.Contains(last, want) {
				t.Errorf("最后一轮上下文里缺少 %q", want)
			}
		}
		for _, bad := range tc.Expect.ContextNotContains {
			if strings.Contains(last, bad) {
				t.Errorf("最后一轮上下文里不该出现 %q", bad)
			}
		}
	}
}

// firstUnpairedToolMessage 校验 tool 回执是否都能配到 assistant.tool_calls；返回人话说明（空=通过）。
func firstUnpairedToolMessage(msgs []Message) string {
	declared := map[string]bool{}
	for _, m := range msgs {
		for _, tc := range m.ToolCalls {
			if tc.ID != "" {
				declared[tc.ID] = true
			}
		}
		if m.Role == "tool" {
			if m.ToolCallID == "" {
				return "有 tool 回执没有 tool_call_id"
			}
			if !declared[m.ToolCallID] {
				return fmt.Sprintf("tool 回执 %s 之前没有声明它的 assistant.tool_calls", m.ToolCallID)
			}
		}
	}
	return ""
}

func flattenMessages(msgs []Message) string {
	var sb strings.Builder
	for _, m := range msgs {
		sb.WriteString(m.Content)
		sb.WriteString("\n")
		for _, tc := range m.ToolCalls {
			sb.WriteString(tc.Function.Name)
			sb.WriteString(" ")
			sb.WriteString(tc.Function.Arguments)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

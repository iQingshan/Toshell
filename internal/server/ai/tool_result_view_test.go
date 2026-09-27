package ai

import (
	"encoding/json"
	"strings"
	"testing"

	"toshell/internal/server/config"
	"toshell/internal/server/mcp"
)

// ─── 工具结果 → 模型可见文本：转换点与元信息传递（v1.4.0 S2）───────────────
//
// 这里全部是纯函数/接口级用例：不联网、不需要 LLM、不需要真实会话，可在 CI 直接跑。
// 覆盖三件事：
//  1. toolResultView 的判定（超限外置、句柄/截断元信息回传、索引记录）；
//  2. ToolTrace / SSE tool_result 事件确实带上了 handle/truncated（前端与审计都依赖它）；
//  3. 摘要函数对"已外置结果"给出的是句柄说明，而不是信息量为零的 "任务状态: ok"。

// fakeResultWriter 内存版 ResultWriter（ai 包自己的实现：mcp 包里的 memStore 不导出）。
type fakeResultWriter struct {
	data  map[string]string
	fail  bool
	putID string
}

func newFakeResultWriter() *fakeResultWriter {
	return &fakeResultWriter{data: map[string]string{}, putID: "20260101/0123456789abcdef"}
}

func (f *fakeResultWriter) Put(_ string, raw []byte) (string, int, error) {
	if f.fail {
		return "", 0, mcp.ErrBadHandle
	}
	f.data[f.putID] = string(raw)
	return f.putID, len(raw), nil
}

func (f *fakeResultWriter) Get(handle string, offset, limit int) ([]byte, int, error) {
	d, ok := f.data[handle]
	if !ok {
		return nil, 0, mcp.ErrHandleNotFound
	}
	if offset > len(d) {
		offset = len(d)
	}
	end := offset + limit
	if limit <= 0 || end > len(d) {
		end = len(d)
	}
	return []byte(d[offset:end]), len(d), nil
}

// recordingIndexer 记录写入索引的记录（验证句柄/sha256 真的传到了索引层）。
type recordingIndexer struct {
	recs []IndexedResult
	err  error
}

func (r *recordingIndexer) IndexToolResult(rec IndexedResult) error {
	r.recs = append(r.recs, rec)
	return r.err
}

// TestToolResultViewSmallIsRaw 小结果：原样进上下文，轨迹上不带句柄/截断标记。
func TestToolResultViewSmallIsRaw(t *testing.T) {
	c := New(config.AIConfig{}, nil)
	c.SetResultStore(newFakeResultWriter(), 4096)

	raw := `{"count":0,"sessions":[]}`
	view := c.toolResultView(resultRef{Tool: "session_list", CallID: "call-1", TraceID: "tr-1"}, raw)
	if view.Text != raw {
		t.Fatalf("小结果应原样交给模型，实际 %q", view.Text)
	}
	if view.Truncated || view.Handle != "" {
		t.Fatalf("小结果不该带截断元信息: truncated=%v handle=%q", view.Truncated, view.Handle)
	}
	tr := ToolTrace{Name: "session_list"}.withResultMeta(view)
	if tr.Handle != "" || tr.Truncated || tr.TotalBytes != len(raw) {
		t.Fatalf("轨迹元信息不对: %+v", tr)
	}
}

// TestToolResultViewLargeExternalizesAndReports 大结果：模型只看到摘要 + 句柄，
// 轨迹与 SSE 事件都带上 handle/truncated，索引里也能查到 sha256 与字节数。
func TestToolResultViewLargeExternalizesAndReports(t *testing.T) {
	store := newFakeResultWriter()
	idx := &recordingIndexer{}
	c := New(config.AIConfig{}, nil)
	c.SetResultStore(store, 512)
	c.SetResultIndexer(idx)

	raw := `{"image":"` + strings.Repeat("iVBORw0KGgo", 500) + `","format":"png"}`
	ref := resultRef{Tool: "screenshot", CallID: "call-shot", RunID: "ag-1", TraceID: "tr-9"}
	view := c.toolResultView(ref, raw)

	if !view.Truncated || view.Handle == "" {
		t.Fatalf("超限结果必须外置并给出句柄: truncated=%v handle=%q", view.Truncated, view.Handle)
	}
	// 模型可见文本必须是合法 JSON（否则就退化成"坏 JSON"这个历史 bug）。
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(view.Text), &env); err != nil {
		t.Fatalf("模型可见文本不是合法 JSON: %v", err)
	}
	if strings.Contains(view.Text, "iVBORw0KGgoiVBORw0KGgo") {
		t.Fatal("外置后不应把原图 base64 塞进上下文")
	}

	// ToolTrace（前端轨迹）
	tr := ToolTrace{Name: ref.Tool, Args: map[string]string{"session_id": "s1"}}.withResultMeta(view)
	if tr.Handle != view.Handle || !tr.Truncated || tr.TruncationNote == "" || tr.TotalBytes != len(raw) {
		t.Fatalf("ToolTrace 未带上外置元信息: %+v", tr)
	}
	if tr.Result != view.Text {
		t.Fatal("ToolTrace.Result 应是模型可见文本（摘要 + 句柄），不是被截断的原文")
	}

	// SSE tool_result 事件（老字段名不变，新字段可选）
	ev := toolResultEvent(ref.Tool, ref.TraceID, view, "")
	if ev.Name != ref.Tool || ev.TraceID != ref.TraceID {
		t.Fatalf("既有字段被改动: %+v", ev)
	}
	if ev.Handle != view.Handle || !ev.Truncated || ev.TruncationNote == "" {
		t.Fatalf("tool_result 事件未带上外置元信息: %+v", ev)
	}
	// 事件序列化后新字段必须真的出现在 JSON 里（老前端忽略未知字段即可）。
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("事件序列化失败: %v", err)
	}
	for _, k := range []string{`"handle"`, `"truncated"`, `"truncation_note"`, `"total_bytes"`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("事件 JSON 缺少 %s: %s", k, string(b))
		}
	}

	// 结果索引：句柄 + sha256 + 字节数 + 配对键都要落进去。
	if len(idx.recs) != 1 {
		t.Fatalf("应有 1 条索引记录，实际 %d", len(idx.recs))
	}
	rec := idx.recs[0]
	if rec.Handle != view.Handle || rec.SHA256 != view.SHA256 || len(rec.SHA256) != 64 {
		t.Fatalf("索引记录缺少句柄/sha256: %+v", rec)
	}
	if rec.BytesTotal != int64(len(raw)) || !rec.Truncated {
		t.Fatalf("索引记录的字节数/截断标记不对: %+v", rec)
	}
	if rec.RunID != "ag-1" || rec.Tool != "screenshot" {
		t.Fatalf("索引记录缺少归因字段: %+v", rec)
	}
	if rec.CorrelationID != "tr-9:call-shot" {
		t.Fatalf("配对键 = %q, want tr-9:call-shot", rec.CorrelationID)
	}
}

// TestToolResultViewDegradesExplicitly 外置失败 / 未配置存储：必须显式标注，绝不静默截断。
func TestToolResultViewDegradesExplicitly(t *testing.T) {
	raw := `{"image":"` + strings.Repeat("QUJDRA", 400) + `"`
	// 无存储的那条要用**超过默认内联上限**（mcp.DefaultInlineLimit = 8 KiB）的结果：
	// 上限之内本就不该截断，用 2.4 KB 的样本会误判成"没标注"。
	bigRaw := `{"image":"` + strings.Repeat("QUJDRA", 2000) + `"}`
	if len(bigRaw) <= mcp.DefaultInlineLimit {
		t.Fatalf("样本 %d 字节必须超过默认内联上限 %d，否则这条用例验不到降级路径", len(bigRaw), mcp.DefaultInlineLimit)
	}
	// ① 有存储但写失败
	failing := newFakeResultWriter()
	failing.fail = true
	c := New(config.AIConfig{}, nil)
	c.SetResultStore(failing, 256)
	view := c.toolResultView(resultRef{Tool: "screenshot", CallID: "c"}, raw)
	if !view.Truncated || view.Handle != "" || view.TruncationNote == "" {
		t.Fatalf("外置失败也必须显式标注且不给句柄: %+v", view)
	}
	if err := json.Unmarshal([]byte(view.Text), &map[string]interface{}{}); err != nil {
		t.Fatalf("外置失败时模型可见文本仍须是合法 JSON: %v", err)
	}

	// ② 完全没有存储（Copilot 未注入 store）：超过默认上限时仍必须显式标注（无句柄）
	c2 := New(config.AIConfig{}, nil)
	view2 := c2.toolResultView(resultRef{Tool: "exec", CallID: "c"}, bigRaw)
	if !view2.Truncated || view2.Handle != "" {
		t.Fatalf("无存储时也必须标注截断: %+v", view2)
	}
	if !strings.Contains(view2.TruncationNote, "未启用结果外置存储") {
		t.Fatalf("应说明未配置存储：%s", view2.TruncationNote)
	}
	if err := json.Unmarshal([]byte(view2.Text), &map[string]interface{}{}); err != nil {
		t.Fatalf("无存储时模型可见文本仍须是合法 JSON: %v", err)
	}
}

// TestResultRefCorrelationID 配对键的兜底：call_id 为空时用工具名，避免空键写进索引。
func TestResultRefCorrelationID(t *testing.T) {
	cases := []struct {
		ref  resultRef
		want string
	}{
		{resultRef{Tool: "exec", CallID: "call-1", TraceID: "tr-1"}, "tr-1:call-1"},
		{resultRef{Tool: "exec", CallID: "", TraceID: "tr-1"}, "tr-1:exec"},
		{resultRef{Tool: "exec", CallID: "call-1"}, "call-1"},
		{resultRef{Tool: "exec"}, "exec"},
	}
	for _, c := range cases {
		if got := c.ref.correlationID(); got != c.want {
			t.Errorf("correlationID(%+v) = %q, want %q", c.ref, got, c.want)
		}
	}
}

// TestSummarizeExternalizedResult 摘要函数对"已外置结果"必须给句柄说明，
// 而不是把信封当成普通 JSON 猜字段（历史表现是 "任务状态: ok"）。
func TestSummarizeExternalizedResult(t *testing.T) {
	view := mcp.InlineForModel("exec", "c", strings.Repeat("x", 4096), newFakeResultWriter(), 256)
	if view.Handle == "" {
		t.Fatal("应已外置")
	}
	got := summarizeToolResult("exec", view.Text)
	if !strings.Contains(got, view.Handle) {
		t.Fatalf("摘要里应出现句柄，实际: %s", got)
	}
	if !strings.Contains(got, "result_read") {
		t.Fatalf("摘要里应指明回读工具，实际: %s", got)
	}
	if strings.Contains(got, "任务状态") {
		t.Fatalf("摘要不应退化成「任务状态: ok」: %s", got)
	}
}

// TestAgentToolNamesIncludesResultRead 回读元工具必须在 Agent 工具面里，
// 否则"超限结果外置"等于把结果丢掉（模型拿不到句柄里的内容）。
func TestAgentToolNamesIncludesResultRead(t *testing.T) {
	found := false
	for _, n := range agentToolNames {
		if n == "result_read" {
			found = true
		}
	}
	if !found {
		t.Fatal("agentToolNames 缺少 result_read：外置结果将无法回读")
	}
	if toolLevel("result_read") != mcp.LevelRead {
		t.Fatalf("result_read 应是 LevelRead（免审批），实际 %v", toolLevel("result_read"))
	}
	// 只读工具在防死循环判定里豁免：反复按不同 offset 分页回读是正常行为。
	if loopGuardAction(9, toolLevel("result_read")) != loopOK {
		t.Fatal("result_read 作为只读工具不应被防死循环误伤")
	}
}

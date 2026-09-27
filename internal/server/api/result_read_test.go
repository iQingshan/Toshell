package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/ai"
	"toshell/internal/server/config"
	"toshell/internal/server/mcp"
)

// newReadTestServer 构造一个"只接了结果外置存储"的最小 Server：
// result_read 只依赖 agentResults + cfg（不碰会话/任务/监听器），因此不需要起真实服务端。
func newReadTestServer(t *testing.T, inlineLimit int) (*Server, *mcp.ResultStore) {
	t.Helper()
	store, err := mcp.NewResultStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewResultStore: %v", err)
	}
	if store == nil {
		t.Fatal("store 为 nil")
	}
	cfg := &config.Config{}
	cfg.MCP.InlineLimit = inlineLimit
	cfg.MCP.ResultTTL = "1h"
	return &Server{cfg: cfg, agentResults: store}, store
}

// TestReadResultPagesFitInlineLimit 回读页必须"塞得进内联上限"。
//
// 这是回读闭环能成立的前提：如果一页超过内联上限，转换层会把它再次外置，
// 模型拿到的是指向"某页的某页"的新句柄 —— 再读又超限，形成句柄套句柄。
func TestReadResultPagesFitInlineLimit(t *testing.T) {
	const inlineLimit = 2048
	s, store := newReadTestServer(t, inlineLimit)
	raw := strings.Repeat("0123456789abcdef", 4096) // 64 KiB
	handle, _, err := store.Put("call-1", []byte(raw))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.readResult(map[string]string{"handle": handle})
	if err != nil {
		t.Fatalf("readResult: %v", err)
	}
	payload, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("返回类型 = %T, want map", got)
	}
	b, merr := json.Marshal(payload)
	if merr != nil {
		t.Fatalf("回读响应不是合法 JSON: %v", merr)
	}
	if len(b) > inlineLimit {
		t.Fatalf("回读页 %d 字节超过了内联上限 %d：这一页会被再次外置，形成句柄套句柄", len(b), inlineLimit)
	}
	if payload["has_more"] != true {
		t.Fatal("还有剩余内容时必须 has_more=true")
	}
	if _, ok := payload["next_offset"]; !ok {
		t.Fatal("还有剩余内容时必须给出 next_offset")
	}
	if payload["total"] != len(raw) {
		t.Fatalf("total = %v, want %d", payload["total"], len(raw))
	}
	if payload["untrusted"] != true {
		t.Fatal("工具结果必须标记为不可信数据")
	}
}

// TestReadResultPagingRoundTrip 分页回读往返：按 next_offset 反复翻页，拼回的内容必须与原文一致。
func TestReadResultPagingRoundTrip(t *testing.T) {
	const inlineLimit = 1024
	s, store := newReadTestServer(t, inlineLimit)
	raw := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 400) // 10400 字节
	handle, _, err := store.Put("call-2", []byte(raw))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	var got strings.Builder
	params := map[string]string{"handle": handle}
	pages := 0
	for {
		pages++
		if pages > 200 {
			t.Fatal("翻页次数异常（可能有页不前进的死循环）")
		}
		out, err := s.readResult(params)
		if err != nil {
			t.Fatalf("第 %d 页失败: %v", pages, err)
		}
		p := out.(map[string]interface{})
		got.WriteString(p["content"].(string))
		if p["has_more"] != true {
			break
		}
		next, _ := p["next_offset"].(int)
		if next <= 0 {
			t.Fatal("next_offset 必须为正数")
		}
		params["offset"] = strconv.Itoa(next)
	}
	if got.String() != raw {
		t.Fatalf("分页回读拼接结果与原文不一致（got %d 字节, want %d）", got.Len(), len(raw))
	}
	if pages < 2 {
		t.Fatalf("10400 字节内容在 1024 内联上限下不可能一页读完，实际 %d 页", pages)
	}
}

// TestReadResultTailMode tail 模式取末尾，且同样要满足"塞得进内联上限"。
func TestReadResultTailMode(t *testing.T) {
	const inlineLimit = 1024
	s, store := newReadTestServer(t, inlineLimit)
	raw := strings.Repeat("x", 8000) + "TAIL-MARKER"
	handle, _, err := store.Put("call-3", []byte(raw))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	out, err := s.readResult(map[string]string{"handle": handle, "mode": "tail"})
	if err != nil {
		t.Fatalf("readResult(tail): %v", err)
	}
	p := out.(map[string]interface{})
	content, _ := p["content"].(string)
	if !strings.HasSuffix(content, "TAIL-MARKER") {
		t.Fatalf("tail 模式应给结果末尾，实际结尾: %q", lastN(content, 40))
	}
	if p["total"] != len(raw) {
		t.Fatalf("total = %v, want %d", p["total"], len(raw))
	}
	b, _ := json.Marshal(p)
	if len(b) > inlineLimit {
		t.Fatalf("tail 页 %d 字节超过内联上限 %d", len(b), inlineLimit)
	}
}

// TestReadResultExplicitLimitStillFits 显式给一个很大的 limit 也不能突破内联上限
// （否则"模型一次要 256 KiB"又会把这一页推去外置）。
func TestReadResultExplicitLimitStillFits(t *testing.T) {
	const inlineLimit = 1536
	s, store := newReadTestServer(t, inlineLimit)
	raw := strings.Repeat("y", 30000)
	handle, _, err := store.Put("call-4", []byte(raw))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	out, err := s.readResult(map[string]string{"handle": handle, "limit": "262144"})
	if err != nil {
		t.Fatalf("readResult: %v", err)
	}
	b, _ := json.Marshal(out)
	if len(b) > inlineLimit {
		t.Fatalf("显式大 limit 时回读页 %d 字节仍不得超过内联上限 %d", len(b), inlineLimit)
	}
}

// TestReadResultRejectsTraversal 句柄来自模型/客户端，属不可信输入：穿越型句柄必须被拒。
func TestReadResultRejectsTraversal(t *testing.T) {
	s, _ := newReadTestServer(t, 8192)
	for _, bad := range []string{
		"../../configs/server.yaml",
		"20260927/../../../../configs/server.yaml",
		"../../../etc/passwd",
		`C:\Windows\win.ini`,
		"20260927/DEADBEEFDEADBEEF", // 大写 hex 不接受
		"2026092/deadbeefdeadbeef",  // 日期位数不对
	} {
		_, err := s.readResult(map[string]string{"handle": bad})
		if err == nil {
			t.Fatalf("穿越/非法句柄 %q 竟被接受", bad)
		}
		if !strings.Contains(err.Error(), "非法") && !strings.Contains(err.Error(), "不存在") {
			t.Fatalf("句柄 %q 的错误信息应说明原因，实际: %v", bad, err)
		}
	}
}

// TestReadResultMissingHandleAndStore 缺句柄 / 未启用存储都要给可读错误，而不是 panic。
func TestReadResultMissingHandleAndStore(t *testing.T) {
	s, _ := newReadTestServer(t, 8192)
	if _, err := s.readResult(map[string]string{}); err == nil {
		t.Fatal("缺 handle 必须报错")
	}
	empty := &Server{cfg: s.cfg} // agentResults 为 nil（mcp.result_dir 不可用）
	if _, err := empty.readResult(map[string]string{"handle": "20260927/0011223344556677"}); err == nil {
		t.Fatal("未启用外置存储时必须报错")
	} else if !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("错误信息应说明存储未启用，实际: %v", err)
	}
}

// TestReadResultNotFound 合法但不存在的句柄：明确说"不存在或已被回收"，避免模型反复重试。
func TestReadResultNotFound(t *testing.T) {
	s, _ := newReadTestServer(t, 8192)
	_, err := s.readResult(map[string]string{"handle": "20260927/0011223344556677"})
	if err == nil {
		t.Fatal("不存在的句柄必须报错")
	}
	if !strings.Contains(err.Error(), "不存在") && !strings.Contains(err.Error(), "回收") {
		t.Fatalf("错误信息应指出句柄不存在/过期，实际: %v", err)
	}
}

// TestTaskOutputIsNotTruncated 工具层不得再做字符串截断。
//
// 历史 bug：pushAndAwait 用 truncateStr(t.Output, 8000) 切 JSON 正文，截图结果
// `{"image":"<base64>",...}` 被切在中间 → 模型/前端拿到的是坏 JSON、坏 base64。
// 截断决策只允许发生在上下文层（mcp.InlineForModel / Envelope.FinalizeInline）。
func TestTaskOutputIsNotTruncated(t *testing.T) {
	big := `{"image":"` + strings.Repeat("iVBORw0KGgo", 6000) + `","format":"png","width":1920,"height":1080}`
	info := &types.TaskInfo{ID: 1, TaskType: "screenshot", Status: "completed", Output: big}
	if got := taskOutput(info); got != big {
		t.Fatalf("工具层截断了任务输出：got %d 字节, want %d 字节", len(got), len(big))
	}
	if taskOutput(nil) != "" {
		t.Fatal("nil 任务应返回空串而不是 panic")
	}
}

// TestAgentResultIndexerSkipsWithoutDB 没有 DB 时索引整条跳过
// （不允许因为审计缺失而影响执行）；配对键为空则必须报错（无法幂等，不写脏数据）。
func TestAgentResultIndexerSkipsWithoutDB(t *testing.T) {
	idx := agentResultIndexer{}
	if err := idx.IndexToolResult(ai.IndexedResult{CorrelationID: "tr-1:call-1"}); err != nil {
		t.Fatalf("无 DB 时索引应静默跳过: %v", err)
	}
	if err := idx.IndexToolResult(ai.IndexedResult{}); err == nil {
		t.Fatal("空 correlation_id 必须报错（表上 UNIQUE(correlation_id)，不能写脏数据）")
	}
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

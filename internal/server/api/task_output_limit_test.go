package api

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/mcp"
	"toshell/internal/server/task"
)

// ─── 任务结果上限：截断阈值可配 + 超限外置 + truncated 标注 ──────────────
//
// 用户反馈"凭据获取没有完善"的直接原因之一：结果落库/回读阈值写死在 500 字节。
// 这里钉住修复后的策略：
//   - 未超限：结果原样（不标 truncated）；
//   - 超限且外置可用：truncated=true + output_bytes_original + handle，
//     正文只留前 inline 上限字节，完整内容能按句柄 result_read 回读（逐页拼回原文）；
//   - 外置不可用：显式截断（truncated + 说明），绝不静默。

// resetTaskOutputLimit 用例前后复位全局入库上限。
func resetTaskOutputLimit(t *testing.T) int {
	t.Helper()
	prev := database.TaskContentMaxBytes()
	database.SetTaskContentMaxBytes(database.DefaultTaskContentMaxBytes)
	t.Cleanup(func() { database.SetTaskContentMaxBytes(prev) })
	return prev
}

// TestAnnotateTaskOutputSmallUnchanged 未超限：不标 truncated，不改正文。
func TestAnnotateTaskOutputSmallUnchanged(t *testing.T) {
	resetTaskOutputLimit(t)
	s, _ := newReadTestServer(t, 2048)
	s.cfg.Task.OutputMaxBytes = 4096

	ti := &types.TaskInfo{ID: 11, Output: "small output"}
	env := map[string]interface{}{"output": ti.Output, "status": "completed"}
	s.annotateTaskOutput(env, ti)

	if _, ok := env["truncated"]; ok {
		t.Fatalf("未超限不应出现 truncated 字段：%v", env["truncated"])
	}
	if env["output"] != "small output" {
		t.Fatalf("未超限正文被改写：%v", env["output"])
	}
	if env["output_bytes"] != len(ti.Output) {
		t.Fatalf("output_bytes = %v, want %d", env["output_bytes"], len(ti.Output))
	}
}

// TestAnnotateTaskOutputExternalizesLarge 超限：外置成句柄 + 显式 truncated/原始字节数，
// 并且句柄能通过 result_read 逐页回读出**完整原文**（不丢内容）。
func TestAnnotateTaskOutputExternalizesLarge(t *testing.T) {
	resetTaskOutputLimit(t)
	const inlineLimit = 2048
	s, _ := newReadTestServer(t, inlineLimit)
	s.cfg.Task.OutputMaxBytes = 4096 // 小阈值：构造超限

	raw := strings.Repeat("0123456789abcdef", 1024) // 16 KiB
	ti := &types.TaskInfo{ID: 42, Output: raw}
	env := map[string]interface{}{"output": raw}
	s.annotateTaskOutput(env, ti)

	if env["truncated"] != true {
		t.Fatalf("超限结果必须显式 truncated=true，实际 %v", env["truncated"])
	}
	if env["output_bytes_original"] != len(raw) {
		t.Fatalf("output_bytes_original = %v, want %d", env["output_bytes_original"], len(raw))
	}
	handle, _ := env["handle"].(string)
	if handle == "" {
		t.Fatal("外置可用时必须给出句柄")
	}
	note, _ := env["truncation_note"].(string)
	if !strings.Contains(note, "result_read") {
		t.Fatalf("截断说明必须指引 result_read 回读，实际 %q", note)
	}
	view, _ := env["output"].(string)
	if len(view) >= len(raw) {
		t.Fatalf("超限正文仍把全文塞回信封（%d 字节）", len(view))
	}
	if !strings.HasPrefix(raw, strings.TrimSuffix(view, "\n...[已截断 truncated=true：完整结果见外置句柄 result_read]")) {
		t.Fatal("信封里的正文必须是原文前缀（不能替换成摘要）")
	}

	// 端到端回读：按 next_offset 逐页取回，拼起来必须与原文逐字节相等。
	var got strings.Builder
	offset := 0
	for i := 0; i < 64; i++ {
		res, err := s.readResult(map[string]string{
			"handle": handle, "offset": strconv.Itoa(offset), "limit": "262144",
		})
		if err != nil {
			t.Fatalf("result_read 第 %d 页失败：%v", i, err)
		}
		page, ok := res.(map[string]interface{})
		if !ok {
			t.Fatalf("result_read 返回类型异常：%T", res)
		}
		content, _ := page["content"].(string)
		got.WriteString(content)
		if more, _ := page["has_more"].(bool); !more {
			break
		}
		next, ok := page["next_offset"].(int)
		if !ok || next <= offset {
			t.Fatalf("分页游标不前进：next=%v offset=%d", page["next_offset"], offset)
		}
		offset = next
	}
	if got.String() != raw {
		t.Fatalf("回读内容与原文不一致：回读 %d 字节，原文 %d 字节", got.Len(), len(raw))
	}
}

// TestAnnotateTaskOutputDegradesWithoutStore 外置不可用：必须显式截断（不静默）。
func TestAnnotateTaskOutputDegradesWithoutStore(t *testing.T) {
	resetTaskOutputLimit(t)
	s, _ := newReadTestServer(t, 2048)
	s.agentResults = nil // 模拟 mcp.result_dir 未配置/不可用
	s.cfg.Task.OutputMaxBytes = 1024

	raw := strings.Repeat("Z", 8192)
	ti := &types.TaskInfo{ID: 7, Output: raw}
	env := map[string]interface{}{"output": raw}
	s.annotateTaskOutput(env, ti)

	if env["truncated"] != true {
		t.Fatalf("外置不可用时也必须 truncated=true，实际 %v", env["truncated"])
	}
	if _, ok := env["handle"]; ok {
		t.Fatal("外置不可用时不应给出句柄")
	}
	note, _ := env["truncation_note"].(string)
	if !strings.Contains(note, "不可用") {
		t.Fatalf("降级说明必须写清外置不可用，实际 %q", note)
	}
	view, _ := env["output"].(string)
	if len(view) >= len(raw) {
		t.Fatalf("降级后正文未被截断（%d 字节）", len(view))
	}
}

// TestLongTaskResultMarksTruncated 走完整 LongTaskResult 路径：任务输出超限时
// 返回的信封带 truncated / output_bytes_original / handle（挂起恢复不再静默丢内容）。
func TestLongTaskResultMarksTruncated(t *testing.T) {
	resetTaskOutputLimit(t)
	env := newAgentTaskTestEnv(t, false)
	store, err := mcp.NewResultStore(t.TempDir(), time.Hour)
	if err != nil || store == nil {
		t.Fatalf("NewResultStore: %v", err)
	}
	env.s.agentResults = store
	env.s.cfg.Task.OutputMaxBytes = 1024

	ti, err := env.tm.Create(env.sid, task.TaskParams{TaskType: "credentials", Data: `{"action":"all"}`})
	if err != nil {
		t.Fatalf("task.Create: %v", err)
	}
	raw := strings.Repeat("y", 8192)
	if err := env.tm.Complete(ti.ID, 0, raw, ""); err != nil {
		t.Fatalf("task.Complete: %v", err)
	}

	got, done, err := env.s.LongTaskResult(ti.ID)
	if err != nil || !done {
		t.Fatalf("LongTaskResult: done=%v err=%v", done, err)
	}
	if got["truncated"] != true {
		t.Fatalf("超限任务结果信封必须 truncated=true，实际 %v", got["truncated"])
	}
	if got["output_bytes_original"] != len(raw) {
		t.Fatalf("output_bytes_original = %v, want %d", got["output_bytes_original"], len(raw))
	}
	if h, _ := got["handle"].(string); h == "" {
		t.Fatal("超限任务结果信封必须带外置句柄")
	}
}

// TestApplyTaskOutputLimit 配置 → database 层的接线：显式值生效，零值回落默认。
func TestApplyTaskOutputLimit(t *testing.T) {
	resetTaskOutputLimit(t)

	applyTaskOutputLimit(&config.Config{Task: config.TaskConfig{OutputMaxBytes: 1024}})
	if got := database.TaskContentMaxBytes(); got != 1024 {
		t.Fatalf("applyTaskOutputLimit(1024) 后 database 上限 = %d", got)
	}
	applyTaskOutputLimit(&config.Config{})
	if got := database.TaskContentMaxBytes(); got != database.DefaultTaskContentMaxBytes {
		t.Fatalf("applyTaskOutputLimit(0) 应回落默认 %d，实际 %d", database.DefaultTaskContentMaxBytes, got)
	}
}

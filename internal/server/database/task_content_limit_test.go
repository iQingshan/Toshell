package database

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"toshell/internal/common/types"
)

// ─── 任务输出入库上限（task.output_max_bytes）──────────────────────────────
//
// 历史缺陷：这里把上限写死成 500 字节。凭据分段 JSON 正常几十 KB，入库后只剩
// 开头几百字节 —— 重启/回读时界面看着"凭据根本没有拿到"。本文件钉住三件事：
//  1. 上限**可配**（不是常量 500）；
//  2. 超限时**显式**标注（truncated + 原始字节数，可解析）；
//  3. 默认值下 4 KiB 的任务结果能完整入库（500 字节回归守卫）。

// resetTaskContentLimit 每个用例前后都把全局上限复位（避免用例间串味）。
func resetTaskContentLimit(t *testing.T) {
	t.Helper()
	SetTaskContentMaxBytes(DefaultTaskContentMaxBytes)
	t.Cleanup(func() { SetTaskContentMaxBytes(DefaultTaskContentMaxBytes) })
}

// TestTaskContentLimitConfigurable 阈值可配：改小后生效，<=0 回落默认（不是"不限制"）。
func TestTaskContentLimitConfigurable(t *testing.T) {
	resetTaskContentLimit(t)

	if got := TaskContentMaxBytes(); got != DefaultTaskContentMaxBytes {
		t.Fatalf("默认上限 = %d, want %d", got, DefaultTaskContentMaxBytes)
	}
	SetTaskContentMaxBytes(100)
	if got := TaskContentMaxBytes(); got != 100 {
		t.Fatalf("SetTaskContentMaxBytes(100) 后上限 = %d", got)
	}
	// <=0 一律回落默认：不允许"配置成 0 就无上限"把数据库撑爆。
	SetTaskContentMaxBytes(0)
	if got := TaskContentMaxBytes(); got != DefaultTaskContentMaxBytes {
		t.Fatalf("SetTaskContentMaxBytes(0) 后上限 = %d, want 默认 %d", got, DefaultTaskContentMaxBytes)
	}
}

// TestTaskContentTruncateMarksTruncated 超限时保留前 maxLen 字节 + 显式标注，
// 且能从标注里反解出**原始字节数**（前端/Agent 靠它显示 truncated 与原始大小）。
func TestTaskContentTruncateMarksTruncated(t *testing.T) {
	resetTaskContentLimit(t)
	SetTaskContentMaxBytes(100)

	raw := strings.Repeat("A", 1000)
	got := truncateTaskContent(raw, TaskContentMaxBytes())
	if !strings.HasPrefix(got, strings.Repeat("A", 100)) {
		t.Fatalf("截断后应保留前 100 字节原文，实际前 40 字节 = %q", got[:40])
	}
	truncated, original := TaskContentTruncated(got)
	if !truncated {
		t.Fatal("超限结果必须能被识别为 truncated")
	}
	if original != len(raw) {
		t.Fatalf("原始字节数 = %d, want %d", original, len(raw))
	}
	// 未超限的内容不得被标成截断（否则界面会长期挂一个假 truncated）。
	if ok, n := TaskContentTruncated("normal output"); ok || n != 0 {
		t.Fatalf("普通输出被误判为截断：ok=%v n=%d", ok, n)
	}
	// 短内容原样返回。
	if got := truncateTaskContent("short", TaskContentMaxBytes()); got != "short" {
		t.Fatalf("未超限内容被改写：%q", got)
	}
}

// TestTaskContentTruncateKeepsUTF8Boundary 截断点必须落在 UTF-8 字符边界上，
// 否则界面/JSON 里会出现 U+FFFD 乱码（历史上中文回显"�"就是这个原因）。
func TestTaskContentTruncateKeepsUTF8Boundary(t *testing.T) {
	resetTaskContentLimit(t)
	SetTaskContentMaxBytes(100)

	raw := strings.Repeat("中", 100) // 300 字节，100 落在第二个字符中间
	got := truncateTaskContent(raw, TaskContentMaxBytes())
	idx := strings.Index(got, "\n...[输出已截断")
	if idx < 0 {
		t.Fatalf("缺少截断标注：%q", got)
	}
	body := got[:idx]
	if !utf8.ValidString(body) {
		t.Fatalf("截断点切在多字节字符中间，产生非法 UTF-8（%d 字节）", len(body))
	}
	if len(body) != 99 {
		t.Fatalf("100 字节切点应回退到字符边界 99 字节，实际 %d", len(body))
	}
}

// TestTaskOutputSurvivesBeyondLegacy500Bytes 回归守卫：默认配置下 4 KiB 结果
// 必须完整入库；把上限改小后必须显式截断（而不是静默丢内容）。
func TestTaskOutputSurvivesBeyondLegacy500Bytes(t *testing.T) {
	resetTaskContentLimit(t)

	db, err := New("sqlite", filepath.Join(t.TempDir(), "task-limit.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	big := strings.Repeat("X", 4096)
	task := &types.TaskInfo{
		SessionID: "sess-limit", TaskType: "credentials", Status: "completed",
		Output: big, CreatedAt: time.Now(),
	}
	if err := db.CreateTask(task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	// 直接读列（不用 ListTasks/GetTask：它们把可空的 sent_at/completed_at 扫进 int64，
	// 未发送任务会扫失败并 continue —— 那是既有行为，与本用例无关）。
	readOutput := func() string {
		t.Helper()
		var stored string
		if err := db.SQL().QueryRow("SELECT output FROM tasks ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil {
			t.Fatalf("读取入库 output 失败：%v", err)
		}
		return stored
	}
	if stored := readOutput(); stored != big {
		t.Fatalf("默认上限下 4 KiB 结果被截断成 %d 字节（旧 500 字节回归）", len(stored))
	}

	// 小阈值：入库内容被显式截断，且能解析出原始字节数。
	SetTaskContentMaxBytes(256)
	// CreateTask 不填 task.ID（自增列），UpdateTask 按 id 更新，所以先取回自增 id。
	if err := db.SQL().QueryRow("SELECT id FROM tasks ORDER BY id DESC LIMIT 1").Scan(&task.ID); err != nil {
		t.Fatalf("读取自增 id 失败：%v", err)
	}
	task.Output = big
	if err := db.UpdateTask(task); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
	stored := readOutput()
	truncated, original := TaskContentTruncated(stored)
	if !truncated || original != len(big) {
		t.Fatalf("小阈值入库未显式标注 truncated：truncated=%v original=%d want %d",
			truncated, original, len(big))
	}
	if len(stored) <= 256 {
		t.Fatalf("标注太短（%d 字节），应保留 256 字节原文 + 标注", len(stored))
	}
}

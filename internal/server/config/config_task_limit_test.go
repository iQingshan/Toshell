package config

import "testing"

// ─── 任务结果入库上限（task.output_max_bytes）──────────────────────────────
//
// 背景：旧实现把任务输出入库上限写死成 500 字节（database.truncateTaskContent），
// 凭据分段结果（几十 KB）入库后只剩开头几百字节。这里钉住"默认 256 KiB + 可配"，
// 防止默认值又被打回小数字。

// TestTaskOutputMaxBytesDefault 未配置 task 段时取默认 256 KiB。
func TestTaskOutputMaxBytesDefault(t *testing.T) {
	if DefaultTaskOutputMaxBytes != 256<<10 {
		t.Fatalf("DefaultTaskOutputMaxBytes = %d, want %d（256 KiB）", DefaultTaskOutputMaxBytes, 256<<10)
	}
	cfg := loadFromYAML(t, "server:\n    api_port: 18081\n")
	if cfg.Task.OutputMaxBytes != DefaultTaskOutputMaxBytes {
		t.Fatalf("默认 task.output_max_bytes = %d, want %d（旧实现写死 500 字节，属回归）",
			cfg.Task.OutputMaxBytes, DefaultTaskOutputMaxBytes)
	}
}

// TestTaskOutputMaxBytesOverride 显式配置可覆盖默认值（阈值必须真的可配）。
func TestTaskOutputMaxBytesOverride(t *testing.T) {
	cfg := loadFromYAML(t, "task:\n    output_max_bytes: 1024\n")
	if cfg.Task.OutputMaxBytes != 1024 {
		t.Fatalf("task.output_max_bytes = %d, want 1024", cfg.Task.OutputMaxBytes)
	}
}

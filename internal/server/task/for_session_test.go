package task

import (
	"encoding/json"
	"errors"
	"testing"
)

// ─── ForSession 归属校验（审计 H1）────────────────────────────────────────────
//
// 任务 id 是进程内全局递增、可预测；这组用例钉住“只有任务所属会话才能终结它”，
// 归属不符时任务必须保持原状态。

func TestCompleteForSessionRejectsForeignSession(t *testing.T) {
	m := NewIsolated(nil)
	tk, err := m.Create("sess-owner", TaskParams{TaskType: TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = m.CompleteForSession(tk.ID, "sess-attacker", 0, "FORGED")
	if !errors.Is(err, ErrTaskNotOwnedBySession) {
		t.Fatalf("跨会话完成应返回 ErrTaskNotOwnedBySession，实际 %v", err)
	}

	got, _ := m.Get(tk.ID)
	if got.Status != StatusPending {
		t.Errorf("归属不符时任务必须保持 pending，实际 %q", got.Status)
	}
	if got.Output != "" {
		t.Errorf("归属不符时不得写入 output，实际 %q", got.Output)
	}
}

func TestCompleteForSessionAllowsOwner(t *testing.T) {
	m := NewIsolated(nil)
	tk, _ := m.Create("sess-owner", TaskParams{TaskType: TaskTypeCommand})

	if err := m.CompleteForSession(tk.ID, "sess-owner", 0, "ok"); err != nil {
		t.Fatalf("归属正确应允许完成：%v", err)
	}
	got, _ := m.Get(tk.ID)
	if got.Status != StatusCompleted || got.Output != "ok" {
		t.Fatalf("任务未完成：status=%q output=%q", got.Status, got.Output)
	}
}

func TestFailForSessionRejectsForeignSession(t *testing.T) {
	m := NewIsolated(nil)
	tk, _ := m.Create("sess-owner", TaskParams{TaskType: TaskTypeCommand})

	err := m.FailForSession(tk.ID, "sess-attacker", "forged fail")
	if !errors.Is(err, ErrTaskNotOwnedBySession) {
		t.Fatalf("跨会话失败应返回 ErrTaskNotOwnedBySession，实际 %v", err)
	}
	got, _ := m.Get(tk.ID)
	if got.Status != StatusPending {
		t.Errorf("归属不符时任务必须保持 pending，实际 %q", got.Status)
	}
}

// FailWithResultForSession 是 handler 失败路径的落点：归属校验 + 保留 output/exit。
func TestFailWithResultForSessionKeepsOutputAndExit(t *testing.T) {
	m := NewIsolated(nil)
	tk, _ := m.Create("sess-owner", TaskParams{TaskType: TaskTypeCommand})

	if err := m.FailWithResultForSession(tk.ID, "sess-owner", 7, "probe output", "exit code 7"); err != nil {
		t.Fatalf("FailWithResultForSession: %v", err)
	}
	got, _ := m.Get(tk.ID)
	if got.Status != StatusFailed || got.ExitCode != 7 || got.Output != "probe output" {
		t.Fatalf("失败结果丢了 output/exit：status=%q exit=%d output=%q", got.Status, got.ExitCode, got.Output)
	}
}

func TestForSessionUnknownTaskIsNotFound(t *testing.T) {
	m := NewIsolated(nil)
	err := m.CompleteForSession(uint64(999999), "sess-owner", 0, "x")
	if !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("未知任务应返回 ErrTaskNotFound，实际 %v", err)
	}
}

// normalizeTaskID 兼容历史调用形态，但拒绝 0/负数/小数/垃圾字符串。
func TestNormalizeTaskID(t *testing.T) {
	ok := []interface{}{uint64(5), uint(5), uint32(5), int(5), int64(5), int32(5), float64(5), json.Number("5"), "5"}
	for _, v := range ok {
		if id, err := normalizeTaskID(v); err != nil || id != 5 {
			t.Errorf("normalizeTaskID(%T %v) = %d, %v; want 5", v, v, id, err)
		}
	}
	bad := []interface{}{uint64(0), int(0), int(-1), float64(1.5), "", "abc", nil, struct{}{}}
	for _, v := range bad {
		if _, err := normalizeTaskID(v); err == nil {
			t.Errorf("normalizeTaskID(%T %v) 应报错", v, v)
		}
	}
}

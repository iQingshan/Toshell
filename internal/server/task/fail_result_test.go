package task

import "testing"

// 守护 v1.4.0 S6 P0-2 的连带修复：**失败任务也要保住植入端回传的输出**。
//
// 背景：任务失败（非 0 退出码）时，植入端常常同时回了 stdout —— 例如内存执行的工具
// 退出码 1，而输出里写着失败原因。旧路径只调 Fail(errMsg)，把 result.Output 丢掉，
// 结果界面上只剩一句 "exit code 7"，与"截断/丢失必须显式可见"的口径相悖。
func TestFailWithResultKeepsOutputAndExitCode(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "fileless_exec")

	if err := m.FailWithResult(id, 7, "probe_exit: before explicit ExitProcess(7)\n", "exit code 7"); err != nil {
		t.Fatalf("FailWithResult: %v", err)
	}

	ti, err := m.Get(id)
	if err != nil || ti == nil {
		t.Fatalf("Get: %v", err)
	}
	if ti.Status != StatusFailed {
		t.Errorf("status = %q, want failed", ti.Status)
	}
	if ti.ExitCode != 7 {
		t.Errorf("exit_code = %d, want 7（失败任务的真实退出码必须留下）", ti.ExitCode)
	}
	if ti.Output == "" {
		t.Error("output 为空：失败任务把植入端回传的输出丢了（本次修复的核心）")
	}
	if ti.Error != "exit code 7" {
		t.Errorf("error = %q, want exit code 7", ti.Error)
	}
}

// 旧的 Fail 语义不变：不传输出时不会凭空写入，也不会改 ExitCode。
func TestFailWithoutResultKeepsLegacySemantics(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	if err := m.Fail(id, "boom"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	ti, err := m.Get(id)
	if err != nil || ti == nil {
		t.Fatalf("Get: %v", err)
	}
	if ti.Status != StatusFailed || ti.Error != "boom" {
		t.Errorf("status/error = %q/%q, want failed/boom", ti.Status, ti.Error)
	}
	if ti.Output != "" {
		t.Errorf("旧 Fail 路径不应写入 output，实际 %q", ti.Output)
	}
	// 旧路径不碰 ExitCode，任务创建时的默认值 -1（= 没有真实退出码）保持不变。
	if ti.ExitCode != -1 {
		t.Errorf("旧 Fail 路径不应改动 exit_code，期望保持默认 -1，实际 %d", ti.ExitCode)
	}
}

package ai

import "testing"

// TestResumeKeepsEventBufferSize 恢复（审批挂起 / 长任务挂起 / 续接指令）后的 run
// 必须与新 run 有**同样大的事件缓冲**。
//
// 历史坑：NewRun 用 8192，而 ResetForResume 单独写死 256 —— 于是"恢复过的 run"事件缓冲
// 只有新 run 的 1/32，恢复后一旦 thinking/message 事件密集，最先被丢掉的恰恰是
// final/done 这类**终态事件**，前端表现为收不到最终答复（network error）。
// 这类问题在单测里只能靠"两侧容量必须一致"来钉住。
func TestResumeKeepsEventBufferSize(t *testing.T) {
	mgr := NewAgentManager(1)
	fresh := mgr.NewRun([]Message{{Role: "user", Content: "hi"}}, 0)
	want := cap(fresh.events)
	if want != agentEventBuffer {
		t.Fatalf("新 run 事件缓冲 = %d, want %d", want, agentEventBuffer)
	}

	// 模拟挂起后恢复（ResetForResume 会重建事件通道）
	fresh.ResetForResume()
	got := cap(fresh.events)
	if got != want {
		t.Fatalf("恢复后事件缓冲 = %d, want %d（恢复过的 run 会更容易丢 final/done 事件）", got, want)
	}
}

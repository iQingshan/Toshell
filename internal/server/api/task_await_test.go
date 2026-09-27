package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/task"
)

// ─── 等待原语：事件驱动 + 契约不变 ────────────────────────────────────

// TestAwaitTaskSettledWakesOnNotification 任务完成即唤醒，且**没有 500ms 轮询粒度**。
// 时间断言是这条改造的核心证据：旧实现最快也要等一次 time.Sleep(500ms) 才看到结果。
func TestAwaitTaskSettledWakesOnNotification(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	tk, err := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = env.tm.Complete(tk.ID, 0, "hello", "")
	}()

	start := time.Now()
	res := env.s.awaitTaskSettled(tk, 5)
	elapsed := time.Since(start)
	if res.Timeout || res.Gone || res.Task == nil {
		t.Fatalf("结局不对：%+v", res)
	}
	if res.Task.Status != task.StatusCompleted || res.Task.Output != "hello" {
		t.Fatalf("任务快照不对：%+v", res.Task)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("唤醒耗时 %v：仍带 500ms 轮询粒度，通知没有挂在状态变更点上", elapsed)
	}
}

// TestAwaitTaskSettledLateWaiter 任务已完成时后到的等待者立即返回（不丢通知）。
func TestAwaitTaskSettledLateWaiter(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	tk, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	_ = env.tm.Complete(tk.ID, 0, "done", "")

	start := time.Now()
	res := env.s.awaitTaskSettled(tk, 5)
	if res.Task == nil || res.Task.Status != task.StatusCompleted {
		t.Fatalf("结局不对：%+v", res)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("终态任务上的等待应立即返回")
	}
}

// TestAwaitTaskSettledTimeoutAndVanished 超时返回"仍在跑"（不是错误），任务消失单独成一种结局。
func TestAwaitTaskSettledTimeoutAndVanished(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	tk, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})

	start := time.Now()
	res := env.s.awaitTaskSettled(tk, 1)
	if !res.Timeout || res.Task == nil || res.Task.Status != task.StatusPending {
		t.Fatalf("超时结局不对：%+v", res)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("超时等待过短：%v（应接近 1s）", elapsed)
	}

	if err := env.tm.Delete(tk.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if res := env.s.awaitTaskSettled(tk, 1); !res.Gone {
		t.Fatalf("被删除的任务应判为 Gone：%+v", res)
	}
	if res := env.s.awaitTaskSettled(nil, 1); !res.Gone {
		t.Fatal("nil 任务应判为 Gone")
	}
}

// TestAwaitTaskSettledSessionOffline 会话掉线熔断语义保留：
// 不能因为改成事件驱动就丢掉"会话离线立即中止等待"（否则会白等满整个超时）。
func TestAwaitTaskSettledSessionOffline(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	tk, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})

	// 把会话的心跳时间倒拨到很久以前 → 判活结论为 asleep。
	sess, err := env.s.sessionMgr.Get(env.sid)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	sess.LastSeen = time.Now().Add(-24 * time.Hour)
	sess.BusyUntil = time.Time{}

	start := time.Now()
	res := env.s.awaitTaskSettled(tk, 30)
	if res.SessionOffline != env.sid {
		t.Fatalf("应判定会话离线，实际 %+v", res)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("会话离线应立即返回，实际耗时 %v（说明又退化成按间隔轮询了）", elapsed)
	}
	// 复原，避免影响同包其它用例（全局会话管理器是单例）。
	sess.LastSeen = time.Now()
}

// TestPushAndAwaitEnvelopeUnchanged pushAndAwait 的返回结构必须与改造前逐字段一致
// （字段名、超时语义、错误文案都是对外契约）。
func TestPushAndAwaitEnvelopeUnchanged(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)

	// ① 完成。
	tk, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand, Command: "whoami"})
	go func() { time.Sleep(20 * time.Millisecond); _ = env.tm.Complete(tk.ID, 0, "nt authority\\system", "") }()
	out, err := env.s.pushAndAwait(env.sid, tk, 5)
	if err != nil {
		t.Fatalf("pushAndAwait: %v", err)
	}
	assertKeys(t, out, []string{"session_id", "task_id", "task_type", "command", "status",
		"output", "output_bytes", "error", "exit_code", "completed_at"})
	if out["status"] != "completed" || out["output"] != "nt authority\\system" {
		t.Fatalf("完成信封内容不对：%+v", out)
	}

	// ② 失败：没有 completed_at，status 透传。
	tk2, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	go func() { time.Sleep(20 * time.Millisecond); _ = env.tm.Fail(tk2.ID, "boom") }()
	out2, err := env.s.pushAndAwait(env.sid, tk2, 5)
	if err != nil {
		t.Fatalf("pushAndAwait(失败): %v", err)
	}
	assertKeys(t, out2, []string{"session_id", "task_id", "task_type", "command", "status",
		"output", "output_bytes", "error", "exit_code"})
	if out2["status"] != "failed" || out2["error"] != "boom" {
		t.Fatalf("失败信封内容不对：%+v", out2)
	}

	// ③ 超时：带 timeout 标记与中文说明（不是错误）。
	tk3, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	out3, err := env.s.pushAndAwait(env.sid, tk3, 1)
	if err != nil {
		t.Fatalf("pushAndAwait(超时): %v", err)
	}
	if out3["timeout"] != true || out3["status"] != task.StatusPending {
		t.Fatalf("超时信封不对：%+v", out3)
	}
	if out3["message"] != "任务超时仍在执行" {
		t.Fatalf("超时文案变了：%v", out3["message"])
	}
}

// TestPushAndAwaitOfflineSession 会话不活跃时必须在**创建任务之前**就失败：
// 不能因为改造而多落一条永远没人执行的任务记录。
func TestPushAndAwaitOfflineSession(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	before := env.tm.Count()
	_, err := env.s.pushAndAwait("sess-not-exist", &types.TaskInfo{ID: 1}, 1)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("离线会话应返回 not active 错误，实际 %v", err)
	}
	if env.tm.Count() != before {
		t.Fatal("离线时不应创建新任务")
	}
}

// TestTaskWaitToolEnvelopeAndErrors task_wait 工具的返回结构与错误码保持兼容。
func TestTaskWaitToolEnvelopeAndErrors(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	tk, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand, Command: "whoami"})

	// 超时（timeout_sec=1）。
	out, err := env.s.invokeTool("task_wait", map[string]string{
		"task_id": taskIDStr(tk.ID), "timeout_sec": "1",
	})
	if err != nil {
		t.Fatalf("task_wait: %v", err)
	}
	m := out.(map[string]interface{})
	if m["timeout"] != true || m["message"] != "等待超时，任务仍在执行" {
		t.Fatalf("超时信封不对：%+v", m)
	}

	// 完成。
	go func() { time.Sleep(20 * time.Millisecond); _ = env.tm.Complete(tk.ID, 0, "ok", "") }()
	out2, err := env.s.invokeTool("task_wait", map[string]string{"task_id": taskIDStr(tk.ID), "timeout_sec": "5"})
	if err != nil {
		t.Fatalf("task_wait: %v", err)
	}
	assertKeys(t, out2.(map[string]interface{}), []string{"task_id", "task_type", "command",
		"session_id", "status", "output", "output_bytes", "error", "exit_code", "completed_at"})

	// 不存在的任务：立即报错，不空转到超时。
	start := time.Now()
	if _, err := env.s.invokeTool("task_wait", map[string]string{"task_id": "987654321"}); err == nil {
		t.Fatal("不存在的任务必须报错")
	} else if !strings.Contains(err.Error(), "task not found") {
		t.Fatalf("错误码变了：%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("不存在的任务必须立即返回")
	}

	// 非法 task_id。
	if _, err := env.s.invokeTool("task_wait", map[string]string{"task_id": "abc"}); err == nil {
		t.Fatal("非法 task_id 必须报错")
	}
}

// TestExecAndAwaitEnvelope exec 的同步语义（对外契约）不变。
func TestExecAndAwaitEnvelope(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	done := make(chan map[string]interface{}, 1)
	go func() {
		out, err := env.s.execAndAwait(env.sid, "whoami", 5)
		if err != nil {
			done <- map[string]interface{}{"error": err.Error()}
			return
		}
		done <- out
	}()
	// 等任务落到内存里再回结果。
	var tid uint64
	waitFor(t, 2*time.Second, "execAndAwait 下发任务", func() bool {
		for _, t2 := range env.tm.ListBySession(env.sid) {
			if t2.TaskType == task.TaskTypeCommand && t2.Command == "whoami" {
				tid = t2.ID
				return true
			}
		}
		return false
	})
	_ = env.tm.Complete(tid, 0, "user", "")
	select {
	case out := <-done:
		if out["status"] != "completed" || out["output"] != "user" {
			t.Fatalf("exec 信封不对：%+v", out)
		}
		if env.pusher.count() != 1 {
			t.Fatalf("下发次数 = %d, want 1", env.pusher.count())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("execAndAwait 未返回")
	}
}

// assertKeys 断言 map 的 key 集合与期望**完全一致**（多一个少一个都算契约变化）。
func assertKeys(t *testing.T, m map[string]interface{}, want []string) {
	t.Helper()
	if len(m) != len(want) {
		b, _ := json.Marshal(m)
		t.Fatalf("字段数 = %d, want %d；实际 %s", len(m), len(want), b)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			b, _ := json.Marshal(m)
			t.Fatalf("缺少字段 %q；实际 %s", k, b)
		}
	}
}

// taskIDStr 十进制任务 id（测试里拼参数用）。
func taskIDStr(id uint64) string {
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[i:])
}

package task

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newWaitTestManager 建一个不共享全局单例的 Manager（无 sessionMgr、无 DB）。
// Create 在 sessionMgr==nil 时跳过会话校验，Complete 在 output=="" 时不会触发情报提取，
// 因此这些用例完全不依赖植入端/数据库。
func newWaitTestManager(t *testing.T) *Manager {
	t.Helper()
	return NewIsolated(nil)
}

func mustCreate(t *testing.T, m *Manager, typ string) uint64 {
	t.Helper()
	task, err := m.Create("sess-wait", TaskParams{TaskType: typ})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return task.ID
}

// TestSubscribeWakesOnComplete 完成即唤醒：等待者不需要任何 sleep 轮询。
// 同时钉住"唤醒延迟远小于旧实现的 500ms 轮询粒度"。
func TestSubscribeWakesOnComplete(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	ch, cancel := m.Subscribe(id)
	defer cancel()

	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := m.Complete(id, 0, "done", ""); err != nil {
			t.Errorf("Complete: %v", err)
		}
	}()

	start := time.Now()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("完成通知未到达（等待者被卡住）")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("唤醒耗时 %v：接近 500ms 轮询粒度，说明通知没有挂在状态变更点上", elapsed)
	}
	task, err := m.Get(id)
	if err != nil || task.Status != StatusCompleted {
		t.Fatalf("任务状态 = %+v err=%v, want completed", task, err)
	}
	if n := m.WaiterCount(id); n != 0 {
		t.Fatalf("任务终结后仍残留 %d 个等待者（泄漏）", n)
	}
}

// TestSubscribeAfterTerminalReturnsImmediately 后到的等待者不丢通知：
// 任务已是终态时 Subscribe 必须立即返回已关闭的通道（否则调用方会白等到超时）。
func TestSubscribeAfterTerminalReturnsImmediately(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")
	if err := m.Fail(id, "boom"); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	ch, cancel := m.Subscribe(id)
	defer cancel()
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("终态任务上 Subscribe 应立即返回（可能丢通知）")
	}

	// 不存在的任务同理：立即返回，等待者据此按 vanished 处理而不空等。
	ch2, cancel2 := m.Subscribe(id + 9999)
	defer cancel2()
	select {
	case <-ch2:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("不存在任务的 Subscribe 应立即返回")
	}
}

// TestWaitSettledOutcomes 三种结局：终结 / 超时仍在跑 / 任务消失。
// 超时**不是错误**（返回 WaitTimeout + 当前状态），与既有 REST/MCP 语义一致。
func TestWaitSettledOutcomes(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	// 超时：任务仍 pending。
	task, outcome := m.WaitSettled(id, 60*time.Millisecond)
	if outcome != WaitTimeout {
		t.Fatalf("outcome = %v, want WaitTimeout", outcome)
	}
	if task == nil || task.Status != StatusPending {
		t.Fatalf("超时应返回「仍在跑」的任务快照，得到 %+v", task)
	}

	// 终结。
	go func() { time.Sleep(10 * time.Millisecond); _ = m.Complete(id, 0, "out", "") }()
	task, outcome = m.WaitSettled(id, 2*time.Second)
	if outcome != WaitTerminal || task.Status != StatusCompleted || task.Output != "out" {
		t.Fatalf("outcome=%v task=%+v, want WaitTerminal/completed/out", outcome, task)
	}

	// 消失：未创建的 id。
	if _, outcome := m.WaitSettled(id+9999, time.Second); outcome != WaitVanished {
		t.Fatalf("未知任务 outcome = %v, want WaitVanished", outcome)
	}
	// timeout<=0 = 只做即时判定，不阻塞。
	if _, outcome := m.WaitSettled(id, 0); outcome != WaitTerminal {
		t.Fatalf("终态任务在 timeout=0 时 outcome = %v, want WaitTerminal", outcome)
	}
}

// TestWaitSettledManyWaiters 并发多等待者：一次 Complete 唤醒全部，且无泄漏。
func TestWaitSettledManyWaiters(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	const n = 32
	var done atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task, outcome := m.WaitSettled(id, 3*time.Second)
			if outcome != WaitTerminal || task == nil || task.Status != StatusCompleted {
				t.Errorf("outcome=%v task=%+v, want WaitTerminal/completed", outcome, task)
				return
			}
			done.Add(1)
		}()
	}
	time.Sleep(30 * time.Millisecond) // 让等待者都完成注册
	if got := m.WaiterCount(id); got != n {
		t.Fatalf("注册的等待者 = %d, want %d", got, n)
	}
	if err := m.Complete(id, 0, "ok", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	wg.Wait()
	if done.Load() != n {
		t.Fatalf("被唤醒的等待者 = %d, want %d", done.Load(), n)
	}
	if got := m.WaiterCount(id); got != 0 {
		t.Fatalf("任务终结后残留 %d 个等待者", got)
	}
}

// TestUnsubscribeRemovesWaiter 等待者提前离开必须摘除注册（否则就是内存泄漏）。
func TestUnsubscribeRemovesWaiter(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	ch, cancel := m.Subscribe(id)
	if got := m.WaiterCount(id); got != 1 {
		t.Fatalf("注册后等待者 = %d, want 1", got)
	}
	cancel()
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("unsubscribe 应关闭通道，让调用方的 select 立刻返回")
	}
	if got := m.WaiterCount(id); got != 0 {
		t.Fatalf("unsubscribe 后等待者 = %d, want 0（泄漏）", got)
	}
	// 幂等：重复调用 unsubscribe 不应 panic（sync.Once 关闭）。
	cancel()
	cancel()

	// 任务随后终结也不应再唤醒任何东西。
	if err := m.Complete(id, 0, "late", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := m.WaiterCount(id); got != 0 {
		t.Fatalf("终结后等待者 = %d, want 0", got)
	}
}

// TestWaitSettledWakesOnDelete 任务被删除（= 对等待者而言"消失"）时必须唤醒：
// 否则等待者会一直挂到超时。
func TestWaitSettledWakesOnDelete(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	ch, cancel := m.Subscribe(id)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := m.Delete(id); err != nil {
			t.Errorf("Delete: %v", err)
		}
	}()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("任务删除未唤醒等待者")
	}
	if _, outcome := m.WaitSettled(id, time.Second); outcome != WaitVanished {
		t.Fatalf("已删除任务 outcome = %v, want WaitVanished", outcome)
	}
}

// TestWaitSettledWakesOnCancelAndCleanup 其余两个终结/消失路径也要通知：
// Cancel（operator 取消 → failed）与 CleanupOldTasks（僵尸任务回收）。
func TestWaitSettledWakesOnCancelAndCleanup(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	ch, cancel := m.Subscribe(id)
	defer cancel()
	if err := m.Cancel(id); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("Cancel 未唤醒等待者")
	}
	task, _ := m.Get(id)
	if task.Status != StatusFailed {
		t.Fatalf("Cancel 后状态 = %s, want failed", task.Status)
	}

	// 僵尸任务回收：把创建时间倒拨到 24h 前，再用 maxAge=1s 回收。
	stale := mustCreate(t, m, "command")
	m.mu.Lock()
	m.tasks[stale].CreatedAt = time.Now().Add(-48 * time.Hour)
	m.mu.Unlock()
	staleCh, staleCancel := m.Subscribe(stale)
	defer staleCancel()
	if n := m.CleanupOldTasks(time.Second); n == 0 {
		t.Fatal("应回收到过期的 pending 任务")
	}
	select {
	case <-staleCh:
	case <-time.After(time.Second):
		t.Fatal("僵尸任务回收未唤醒等待者")
	}
	if _, outcome := m.WaitSettled(stale, 0); outcome != WaitVanished {
		t.Fatalf("被回收任务 outcome = %v, want WaitVanished", outcome)
	}
}

// TestCompleteNotifiesOnlyOnce 重复结果帧（终态去重）不得产生额外副作用：
// 第二次 Complete 是空操作，等待者早已被唤醒且表已清空。
func TestCompleteNotifiesOnlyOnce(t *testing.T) {
	m := newWaitTestManager(t)
	id := mustCreate(t, m, "command")

	got := make(chan string, 4)
	ch, cancel := m.Subscribe(id)
	defer cancel()
	go func() {
		<-ch
		got <- "woke"
	}()

	if err := m.Complete(id, 0, "first", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := m.Complete(id, 1, "second", "dup"); err != nil {
		t.Fatalf("重复 Complete 应幂等返回 nil: %v", err)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("等待者未被唤醒")
	}
	task, _ := m.Get(id)
	if task.Output != "first" || task.ExitCode != 0 {
		t.Fatalf("重复结果帧覆盖了终态：%+v", task)
	}
}

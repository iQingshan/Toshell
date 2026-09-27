package task

import (
	"sync"
	"time"

	"toshell/internal/common/types"
)

// ─── 任务终结通知（事件驱动等待）────────────────────────────────────────
//
// 为什么需要这个原语：`internal/server/api` 的三处「下发任务后等结果」
// （pushAndAwait / task_wait / execAndAwait）此前都是 `time.Sleep(500ms)` 轮询到超时——
// 一次 300s 的文件下载要空转 600 次，且每个等待者都多出最多 500ms 的固定延迟；
// 更要紧的是 Agent 侧：工具调用是同步阻塞的，一个 credentials(180s) 就把
// AgentConcurrency（默认 2）的一个槽位占满三分钟。
//
// 任务状态的真实变更点只有一个（本包的 Complete/Fail/Cancel/Delete/CleanupOldTasks），
// 因此把「通知」挂在状态变更上：等待者注册后阻塞在 channel 上，被唤醒即返回，
// 不再周期性醒来查状态。**通知必须挂在真正的状态变更点**——挂在读取侧只会退化成轮询。
//
// 语义约定（调用方必须知道的边界）：
//   - 只有**终态**（completed/failed/timeout）与**任务消失**（删除/回收）才通知；
//     pending→sent 这类中间变更不通知（只会带来无意义的唤醒）。
//   - 注册时任务已是终态、或任务不存在 → 通道立即关闭：后到的等待者不会丢通知，
//     也不需要额外的「先查一次状态」竞态窗口。
//   - 等待超时**不报错**：超时表示「仍在跑」，与既有 REST/MCP 语义一致
//     （返回 timeout 标记 + 当前状态），不是失败。

// WaitOutcome 一次等待的结局。
type WaitOutcome int

const (
	// WaitTerminal 任务已进入终态（completed/failed/timeout）。
	WaitTerminal WaitOutcome = iota
	// WaitTimeout 超时仍未终结：任务仍在执行（不是错误，调用方返回"仍在跑"）。
	WaitTimeout
	// WaitVanished 任务不存在：从未创建，或等待期间被删除/回收。
	WaitVanished
)

// waiter 一个等待者的广播通道。
//
// 用 sync.Once 关闭：通知路径（任务终结）与取消路径（等待者提前离开）都可能关它，
// 双关会 panic；once 保证无论谁先到都只关一次。
type waiter struct {
	ch   chan struct{}
	once sync.Once
}

func (w *waiter) close() { w.once.Do(func() { close(w.ch) }) }

// IsTerminalStatus 判定任务状态是否为终态（此后不再变化）。
func IsTerminalStatus(status string) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusTimeout:
		return true
	}
	return false
}

// Subscribe 订阅指定任务的终结通知。
//
// 返回的通道在任务进入终态、或任务被删除/回收时关闭；unsubscribe 供等待者提前离开
// （关闭通道并摘除注册，避免 waiters 泄漏——等待者离开而不摘除，就是一次内存泄漏，
// 长跑进程里会随超时/断线不断累积）。
//
// 注册与状态判定都在 m.mu 下完成，这是**正确性关键**：通知路径（Complete 等）在持有
// m.mu 时改状态并唤醒，若注册侧分两次取锁（先判状态再注册），就会出现
// 「判定为非终态 → 任务在此刻终结并通知（此时还没有我）→ 我注册完成 → 永远收不到通知」
// 的丢通知窗口。与状态用同一把锁，注册与状态变更互为原子点。
func (m *Manager) Subscribe(id uint64) (<-chan struct{}, func()) {
	w := &waiter{ch: make(chan struct{})}
	if m == nil {
		w.close()
		return w.ch, func() {}
	}
	m.mu.Lock()
	t, ok := m.tasks[id]
	if !ok || t == nil || IsTerminalStatus(t.Status) {
		m.mu.Unlock()
		w.close()
		return w.ch, func() {}
	}
	if m.waiters == nil {
		m.waiters = make(map[uint64][]*waiter)
	}
	m.waiters[id] = append(m.waiters[id], w)
	m.mu.Unlock()
	return w.ch, func() {
		m.mu.Lock()
		m.removeWaiterLocked(id, w)
		m.mu.Unlock()
		w.close()
	}
}

// removeWaiterLocked 摘除一个等待者（需持有 m.mu）。
func (m *Manager) removeWaiterLocked(id uint64, w *waiter) {
	list := m.waiters[id]
	for i, x := range list {
		if x == w {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(m.waiters, id)
		return
	}
	m.waiters[id] = list
}

// notifyLocked 唤醒某任务的全部等待者（需持有 m.mu）。
//
// 关闭 channel 是非阻塞的，因此可以在锁内做；放到锁外反而会引入两个窗口：
// ① 等待者已判定"还在跑"、通知却还没发出去；② 任务被回收后等待者仍挂在表上。
func (m *Manager) notifyLocked(id uint64) {
	list := m.waiters[id]
	if len(list) == 0 {
		return
	}
	delete(m.waiters, id)
	for _, w := range list {
		w.close()
	}
}

// WaiterCount 当前注册在该任务上的等待者数量。
// 供测试断言「任务结束/等待者离开后 waiters 不泄漏」——泄漏在这类原语里是最隐蔽的 bug。
func (m *Manager) WaiterCount(id uint64) int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.waiters[id])
}

// WaitSettled 事件驱动地等待任务进入终态。
//
// timeout <= 0 表示只做一次即时判定（不阻塞）。返回的 TaskInfo 在内存里就是同一个对象，
// 因此读到的是最新状态（任务消失时返回 nil）。
func (m *Manager) WaitSettled(id uint64, timeout time.Duration) (*types.TaskInfo, WaitOutcome) {
	ch, unsubscribe := m.Subscribe(id)
	defer unsubscribe()

	// 注册后立刻复核一次：任务可能刚刚终结（通道已关闭，select 会立即命中），
	// 但显式判定能让「任务不存在」与「超时=0」这两种情形有确定结论。
	if t, outcome, decided := m.settledOrVanish(id); decided {
		return t, outcome
	}
	if timeout <= 0 {
		t, _ := m.Get(id)
		return t, WaitTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		if t, outcome, decided := m.settledOrVanish(id); decided {
			return t, outcome
		}
		// 被唤醒但既非终态也未消失：只可能是本等待者被 unsubscribe（不会走到这里）。
		// 保守返回"仍在跑"，绝不谎报终态。
		t, _ := m.Get(id)
		return t, WaitTimeout
	case <-timer.C:
		t, err := m.Get(id)
		if err != nil || t == nil {
			return nil, WaitVanished
		}
		return t, WaitTimeout
	}
}

// settledOrVanish 即时判定：终态 / 消失 / 仍在跑（decided=false 表示仍在跑）。
func (m *Manager) settledOrVanish(id uint64) (*types.TaskInfo, WaitOutcome, bool) {
	t, err := m.Get(id)
	if err != nil || t == nil {
		return nil, WaitVanished, true
	}
	if IsTerminalStatus(t.Status) {
		return t, WaitTerminal, true
	}
	return t, WaitTimeout, false
}

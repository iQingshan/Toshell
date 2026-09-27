package api

import (
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/task"
)

// ─── 等任务终结：事件驱动（v1.4.0 S2）──────────────────────────────────
//
// 这里是 pushAndAwait / task_wait / execAndAwait 三处阻塞点的**唯一**等待实现。
// 改造前它们是 `for time.Now().Before(deadline) { 查状态; time.Sleep(500ms) }`：
//   - 300s 的文件下载要空转 600 次；
//   - 每个等待者都多出最多 500ms 的固定延迟（任务 1ms 就完成也要等到下一次睡醒）；
//   - 并发等待者越多，周期性查状态的次数线性增长，而这些查询 99% 是"状态没变"。
//
// 改造后等待者只会在**真正有事发生**时醒来，共三类事件：
//  1. 任务进入终态 / 任务消失 —— 由 task.Manager 在状态变更点广播（task.Subscribe）；
//  2. 等待超时 —— 一次性的 deadline 定时器；
//  3. 会话判活结论可能翻转的时刻 —— session.NextLivenessFlip 算出的**语义时刻**，
//     用来保留既有的"会话掉线立即熔断"语义（不靠固定间隔轮询：在那一刻之前，
//     GetStatus 的结论不可能改变，提前醒来毫无意义）。
//
// 对外契约完全不变：字段名、超时语义（超时返回"仍在跑"而不是报错）、错误文案都不动；
// 变的只是"怎么等到结果"。

// agentTaskSource 任务侧「读取 + 终结通知」的最小依赖。
//
// 生产环境就是 *task.Manager。抽成接口有两个理由：
//  1. 等待/挂起/恢复的**编排**（分类、落库、订阅、唤醒）需要能在不依赖真实植入端与
//     真实会话的情况下被单测覆盖；
//  2. 让 api 层明确只依赖"能查状态、能订阅终结"这两件事，而不是整个任务管理器。
type agentTaskSource interface {
	Get(id uint64) (*types.TaskInfo, error)
	Subscribe(id uint64) (<-chan struct{}, func())
}

// taskWaiter 返回生效的任务通知源（默认 = taskMgr）。
func (s *Server) taskWaiter() agentTaskSource {
	if s.taskWait != nil {
		return s.taskWait
	}
	if s.taskMgr == nil {
		return nil
	}
	return s.taskMgr
}

// taskAwaitResult 一次"等任务终结"的结局。
type taskAwaitResult struct { // Task 终结时/超时时/掉线时的任务快照（Gone 时为 nil）。
	Task *types.TaskInfo
	// Timeout 超时仍未终结：任务仍在执行（不是错误）。
	Timeout bool
	// Gone 任务已不存在（从未创建，或等待期间被删除/回收）。
	Gone bool
	// SessionOffline 非空 = 该会话在等待期间被判离线（asleep 或已不存在），值为会话 id。
	// 只回传会话 id 而不直接回传错误：pushAndAwait 与 task_wait 的历史错误文案不同，
	// 属于既有对外契约，由各自组装。
	SessionOffline string
}

// awaitTaskSettled 事件驱动地等待任务进入终态。
//
// 循环结构是"顶部复核 + 一次性定时器"：任何唤醒（任务通知/定时器）都回到顶部重新判定，
// 因此判定逻辑只有一份，不会出现"定时器分支与通知分支各自判一半"的偏差。
// 定时器的时长取 min(deadline, 下一次判活翻转)，保证不会心跳式空转：
// 判活翻转点由会话自己算（见 session.NextLivenessFlip），没有配置间隔、也不是固定轮询。
func (s *Server) awaitTaskSettled(t *types.TaskInfo, timeoutSec int) taskAwaitResult {
	if t == nil {
		return taskAwaitResult{Gone: true}
	}
	mgr := s.taskWaiter()
	if mgr == nil {
		return taskAwaitResult{Gone: true}
	}
	ch, unsubscribe := mgr.Subscribe(t.ID)
	defer unsubscribe()

	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	// waitCh 指向一次性通知通道（任务终结/消失时关闭）。触发一次后必须置 nil，理由见下方 select。
	var waitCh <-chan struct{} = ch

	for {
		cur, err := mgr.Get(t.ID)
		if err != nil || cur == nil {
			return taskAwaitResult{Gone: true}
		}
		if task.IsTerminalStatus(cur.Status) {
			return taskAwaitResult{Task: cur}
		}
		if off := s.sessionAwaitAbort(cur.SessionID); off != "" {
			return taskAwaitResult{Task: cur, SessionOffline: off}
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return taskAwaitResult{Task: cur, Timeout: true}
		}
		// 下一次判活复核点：只可能把唤醒**提前**，绝不会晚于 deadline。
		if flip, ok := s.nextLivenessFlip(cur.SessionID); ok {
			if d := time.Until(flip); d > 0 && d < wait {
				wait = d
			} else if d <= 0 {
				// 理论上到不了这里（上面 GetStatus 已判定为存活，而翻转时刻只会被心跳推后）。
				// 万一因为时钟回拨等原因落到这里，用一个很小的下限避免自旋；这不是轮询间隔。
				if wait > 10*time.Millisecond {
					wait = 10 * time.Millisecond
				}
			}
		}
		resetTimer(timer, wait)
		select {
		case <-waitCh:
			// 任务状态变了（或任务消失）：通知是**一次性**的，摘掉后回顶部复核。
			// 不摘掉的话，已关闭的通道会让 select 每轮都立刻就绪——变成自旋，
			// 而且每轮都 reset 定时器，连超时都永远到不了。
			waitCh = nil
		case <-timer.C:
			// 到 deadline 或判活翻转点：同样回顶部复核（顶部会给出确定结论）。
		}
	}
}

// resetTimer 安全地重置一个已停止/已触发的定时器（避免 drain 竞态）。
func resetTimer(t *time.Timer, d time.Duration) {
	if d <= 0 {
		d = time.Millisecond
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// sessionAwaitAbort 判定"等待期间会话是否已不可用"（沿用既有熔断语义）。
// 返回会话 id，空串表示仍可用。
//
// 与历史实现逐字对齐：会话不存在（查询报错）或状态为 asleep 即视为掉线；
// SessionID 为空（如本地/无会话任务）不做判定。
func (s *Server) sessionAwaitAbort(sessionID string) string {
	if s.sessionMgr == nil || sessionID == "" {
		return ""
	}
	st, err := s.sessionMgr.GetStatus(sessionID)
	if err != nil || st == "asleep" {
		return sessionID
	}
	return ""
}

// nextLivenessFlip 会话判活结论的下一次翻转时刻（会话不存在时 ok=false，
// 此时等待方会在顶部复核里按掉线熔断处理）。
func (s *Server) nextLivenessFlip(sessionID string) (time.Time, bool) {
	if s.sessionMgr == nil || sessionID == "" {
		return time.Time{}, false
	}
	return s.sessionMgr.NextLivenessFlip(sessionID, time.Now())
}

// ─── 结果信封（同步路径与挂起恢复路径**共用**）─────────────────────────
//
// 抽出来是为了让"挂起后由任务完成事件恢复"的 Agent 拿到与同步调用**完全一致**的
// 返回结构：字段名、字段集合、超时语义、错误码都由这里唯一决定。
// 否则两条路径各写一份 map，迟早出现"同步有 completed_at、恢复没有"这类偏差。

// taskCompletedResult 任务成功完成的结果信封。
func taskCompletedResult(sid string, t *types.TaskInfo) map[string]interface{} {
	return map[string]interface{}{
		"session_id": sid, "task_id": t.ID, "task_type": t.TaskType,
		"command": t.Command, "status": "completed",
		"output": taskOutput(t), "output_bytes": len(t.Output), "error": t.Error,
		"exit_code": t.ExitCode, "completed_at": t.CompletedAt,
	}
}

// taskFailedResult 任务失败/超时终结的结果信封。
func taskFailedResult(sid string, t *types.TaskInfo) map[string]interface{} {
	return map[string]interface{}{
		"session_id": sid, "task_id": t.ID, "task_type": t.TaskType,
		"command": t.Command, "status": t.Status,
		"output": taskOutput(t), "output_bytes": len(t.Output), "error": t.Error,
		"exit_code": t.ExitCode,
	}
}

// taskTimeoutResult 等待超时（任务仍在跑）的结果信封：与失败不同，这里带 timeout 标记，
// 明确告诉调用方"不是任务失败，是我们不等了"。
func taskTimeoutResult(sid string, t *types.TaskInfo) map[string]interface{} {
	return map[string]interface{}{
		"session_id": sid, "task_id": t.ID, "command": t.Command,
		"status": t.Status, "output": taskOutput(t), "output_bytes": len(t.Output),
		"error": t.Error, "exit_code": t.ExitCode, "timeout": true,
		"message": "任务超时仍在执行",
	}
}

// taskEnvelopeByStatus 按任务状态给出同步路径的结果信封
// （completed → 完成信封；failed/timeout → 失败信封；仍在跑 → 超时信封）。
func taskEnvelopeByStatus(sid string, t *types.TaskInfo) map[string]interface{} {
	switch t.Status {
	case task.StatusCompleted:
		return taskCompletedResult(sid, t)
	case task.StatusFailed, task.StatusTimeout:
		return taskFailedResult(sid, t)
	default:
		return taskTimeoutResult(sid, t)
	}
}

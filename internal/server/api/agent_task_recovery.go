package api

import (
	"encoding/json"
	"time"

	"toshell/internal/server/agentstore"
	"toshell/internal/server/logging"
)

// ─── 重启恢复：把"等待任务"的 run 接回来（v1.4.0 S2）────────────────────
//
// 场景：进程重启后，内存里的 run 全没了，但库里的 agent_runs 还停在
// status=awaiting_task（waiting_on 记着在等哪个 internal_task_id）。此时必须对账：
//
//	① 任务已完成 → 把结果接回 run 并继续/收尾；
//	② 任务仍在跑 → 重新订阅，等它完成（恢复时按持久化信息重建最小上下文）；
//	③ 任务已丢失 → 给 run 一个**明确的终态与中文说明**（绝不静默卡在等待态）。
//
// 接线位置：cmd/server 在建库、SeedTaskCounter、api.New、SetAgentStore 之后调用一次。

// waitingTaskOutcome 恢复扫描对"等待中的任务"的分类结论。
type waitingTaskOutcome int

const (
	// waitingTaskResume 任务已终结：结果可直接接回，run 继续/收尾。
	waitingTaskResume waitingTaskOutcome = iota
	// waitingTaskResubscribe 任务仍在跑：重新订阅，等它完成。
	waitingTaskResubscribe
	// waitingTaskLost 任务已丢失（库与内存都查不到）：给 run 明确终态。
	waitingTaskLost
	// waitingTaskUnparsable waiting_on 无法解析：给 run 明确终态。
	waitingTaskUnparsable
)

// classifyWaitingTask 纯函数分类（表驱动单测覆盖三种任务状态）。
//   - refOK=false：waiting_on 解析失败（旧的/被截断的记录）；
//   - exists=false：tasks 表查不到该任务；
//   - terminal=true：任务已进入终态。
func classifyWaitingTask(refOK, exists, terminal bool) waitingTaskOutcome {
	if !refOK {
		return waitingTaskUnparsable
	}
	if !exists {
		return waitingTaskLost
	}
	if terminal {
		return waitingTaskResume
	}
	return waitingTaskResubscribe
}

// RecoverWaitingAgentRuns 扫描库里所有"等待任务"的 run 并对账处理。
//
// 无数据库 / 未接线时是空操作（Nothing to do），绝不 panic。
func (s *Server) RecoverWaitingAgentRuns() {
	if s == nil || s.agentStore == nil {
		return
	}
	runs, err := s.agentStore.ListRunsAwaitingTask(0)
	if err != nil {
		logging.Warn("api", "重启恢复：读取等待任务的 run 失败：%v", err)
		return
	}
	if len(runs) == 0 {
		return
	}
	logging.Info("api", "重启恢复：发现 %d 个处于「等待任务」态的 Agent run，开始对齐 tasks 表", len(runs))
	var resumed, resubscribed, lost int
	for _, r := range runs {
		switch s.recoverWaitingRun(r) {
		case waitingTaskResume:
			resumed++
		case waitingTaskResubscribe:
			resubscribed++
		default:
			lost++
		}
	}
	logging.Info("api", "重启恢复完成：接回 %d 个已完成任务、重新订阅 %d 个仍在跑的任务、终结 %d 个无法恢复的 run",
		resumed, resubscribed, lost)
}

// recoverWaitingRun 处理单个 run，返回分类结论（便于调用方统计与测试断言）。
func (s *Server) recoverWaitingRun(r *agentstore.Run) waitingTaskOutcome {
	ref, refOK := agentstore.ParseWaitingOn(r.WaitingOn)
	exists, terminal := false, false
	var taskID uint64
	if refOK {
		taskID = ref.InternalTaskID
		if t, terr := s.taskMgr.Get(taskID); terr == nil && t != nil {
			exists = true
			terminal = isTerminalTaskStatus(t.Status)
		}
	}
	outcome := classifyWaitingTask(refOK, exists, terminal)
	entry := s.entryFromStoredRun(r, ref)

	switch outcome {
	case waitingTaskResume:
		logging.Info("api", "重启恢复：run=%s 等待的任务 #%d 已完成，接回结果继续", r.ID, taskID)
		s.resumeEntry(entry, false)
	case waitingTaskResubscribe:
		logging.Info("api", "重启恢复：run=%s 等待的任务 #%d 仍在执行，重新订阅等它完成", r.ID, taskID)
		// 重新订阅：恢复出来的等待项由 watchTask 在任务终结时唤醒。
		s.agentTasks.register(entry)
		go s.watchTask(entry)
	case waitingTaskLost:
		s.failWaitingRun(entry,
			"等待中的内部任务 #"+u64str(taskID)+" 已丢失（tasks 表查不到，可能已被清理或数据库被更换）："+
				"无法取得结果，该 run 已终止；请重新下发该操作。",
			"task_lost")
	case waitingTaskUnparsable:
		s.failWaitingRun(entry,
			"该 run 的 waiting_on 记录无法解析（缺少 internal_task_id）：无法确定在等哪个任务，已终止以免静默卡住；"+
				"请重新下发该操作。",
			"waiting_on_unparsable")
	}
	return outcome
}

// entryFromStoredRun 用持久化信息重建一个等待项（重启恢复用）。
//
// 注意 run 为 nil：恢复项只有在真正要恢复时才重建内存 run（见 restoreRunForEntry），
// 这样"仍在跑"的分支不会凭空造出一个永远不会被恢复的 run 对象。
func (s *Server) entryFromStoredRun(r *agentstore.Run, ref *agentstore.WaitingTaskRef) *taskWaitEntry {
	e := &taskWaitEntry{
		recovered: true, runID: r.ID, objective: r.Objective,
		traceID: r.TraceID, timeoutSec: DefaultLongTaskTimeoutFromStore(),
	}
	if ref == nil {
		return e
	}
	e.tool = ref.Tool
	e.callID = ref.CallID
	e.stepNo = ref.StepNo
	e.correlation = ref.CorrelationID
	e.internalTaskID = ref.InternalTaskID
	if ref.TraceID != "" {
		e.traceID = ref.TraceID
	}
	if ref.TimeoutSec > 0 {
		e.timeoutSec = ref.TimeoutSec
	}
	// 等待预算：优先用落盘的截止时刻；已经过期时给一次完整的新预算——进程停机的
	// 那段时间我们并没有"在等"，直接判超时会让重启刚好卡在边界的任务被误判。
	if ref.DeadlineTS > 0 {
		e.deadline = time.Unix(ref.DeadlineTS, 0)
	}
	if e.deadline.IsZero() || e.deadline.Before(time.Now()) {
		e.deadline = time.Now().Add(time.Duration(e.timeoutSec) * time.Second)
	}
	// 回查工具调用记录补齐工具名/参数/call_id（waiting_on 之外的权威来源）。
	if s.agentStore != nil && ref.CorrelationID != "" {
		if call, err := s.agentStore.GetToolCall(ref.CorrelationID); err == nil && call != nil {
			if e.tool == "" {
				e.tool = call.Tool
			}
			if e.callID == "" {
				e.callID = call.ID
			}
			if e.stepNo == 0 {
				e.stepNo = call.StepNo
			}
			if call.ArgsJSON != "" {
				var args map[string]string
				if json.Unmarshal([]byte(call.ArgsJSON), &args) == nil {
					e.args = args
				}
			}
		}
	}
	// call_id 为空时用 correlation_id 兜底：恢复时要构造"assistant.tool_calls ↔ tool"
	// 的配对消息，两侧用同一个值即可（空 id 会让上游直接拒绝这段消息序列）。
	if e.callID == "" {
		e.callID = e.correlation
	}
	return e
}

// DefaultLongTaskTimeoutFromStore 恢复时若库里没记超时预算，用同步路径的默认等待上限兜底。
func DefaultLongTaskTimeoutFromStore() int { return taskWaitMaxSec }

// u64str 十进制输出（避免为一行转换引入 strconv 依赖）。
func u64str(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

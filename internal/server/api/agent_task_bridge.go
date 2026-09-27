package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"toshell/internal/server/agentstore"
	"toshell/internal/server/ai"
	"toshell/internal/server/logging"
)

// ─── Agent 长任务：提交 → 挂起 → 事件驱动恢复（v1.4.0 S2）──────────────
//
// 本文件是"执行层（ai）"与"任务/持久化层（task + agentstore）"之间的接线：
//   - 实现 ai.LongTaskExecutor（LongTaskPlan / SubmitLongTask / LongTaskResult）；
//   - 任务完成通知的订阅桥：任务终结 → 取结果 → 接回 run → 走 resumeRun 恢复循环；
//   - 重启恢复扫描：把库里处于 awaiting_task 的 run 按 internal_task_id 对齐 tasks 表。
//
// 三件事都刻意做成"可注入依赖"（s.taskWait / s.agentStore / s.resumeRun），
// 因此可以在没有真实植入端、没有真实 LLM 的测试里验证完整流转。

// agentTaskBridge 内部任务 → Agent run 的唤醒桥。
type agentTaskBridge struct {
	s  *Server
	mu sync.Mutex
	// byTask internal_task_id → 等待项。同一任务只会有一条（幂等：重复通知/重复
	// 恢复都从表里取走，取不到即视为已被处理过）。
	byTask map[uint64]*taskWaitEntry
}

// taskWaitEntry 一个"run 正在等这个任务"的等待项。
type taskWaitEntry struct {
	// run 进程内挂起的活 run。重启恢复出来的等待项为 nil（恢复时才重建）。
	run *ai.AgentRun
	// recovered=true 表示这是重启后恢复出来的等待项：run 需要按持久化信息重建。
	recovered bool

	runID          string
	tool           string
	callID         string
	stepNo         int
	traceID        string
	objective      string
	args           map[string]string
	internalTaskID uint64
	timeoutSec     int
	deadline       time.Time
	// correlation 工具调用的幂等键（run_id:step_no:attempt）。显式保存而不是每次拼：
	// 重启恢复时它以 waiting_on / agent_tool_calls 里的记录为准，拼错了就对不上账。
	correlation string
}

func newAgentTaskBridge(s *Server) *agentTaskBridge {
	return &agentTaskBridge{s: s, byTask: map[uint64]*taskWaitEntry{}}
}

// register 登记一个等待项（幂等：同一任务重复登记只保留第一条）。
func (b *agentTaskBridge) register(e *taskWaitEntry) {
	if b == nil || e == nil || e.internalTaskID == 0 {
		return
	}
	b.mu.Lock()
	if _, exists := b.byTask[e.internalTaskID]; !exists {
		b.byTask[e.internalTaskID] = e
	}
	b.mu.Unlock()
}

// take 取走等待项（取到的人负责恢复；重复通知取不到 → 幂等跳过）。
func (b *agentTaskBridge) take(taskID uint64) *taskWaitEntry {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.byTask[taskID]
	delete(b.byTask, taskID)
	return e
}

// pending 当前等待项数量（测试用）。
func (b *agentTaskBridge) pending() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.byTask)
}

// watchTask 订阅任务终结通知并在完成时恢复 run（每个挂起任务一个 goroutine，
// 阻塞在通知 channel 上——**不轮询**，也不占用 Agent 并发槽位）。
//
// 两条唤醒路径：
//   - 任务终结通知（task.Subscribe）：正常路径，唤醒即恢复；
//   - deadline 定时器：waiting_on 里记录的等待预算到点仍未终结时按"仍在跑"收尾
//     （与同步路径的超时信封语义一致：不是错误，明确告诉模型"任务超时仍在执行"）。
func (s *Server) watchTask(e *taskWaitEntry) {
	if e == nil {
		return
	}
	src := s.taskWaiter()
	if src == nil {
		return
	}
	ch, unsubscribe := src.Subscribe(e.internalTaskID)
	defer unsubscribe()

	timeout := time.Until(e.deadline)
	if e.deadline.IsZero() || timeout <= 0 {
		// 没有 deadline 的等待项（理论上不该出现）：只等通知，不再设兜底定时器。
		<-ch
		s.resumeFromTask(e, false)
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	timedOut := false
	select {
	case <-ch:
	case <-timer.C:
		timedOut = true
	}
	s.resumeFromTask(e, timedOut)
}

// resumeFromTask 任务有结论（或等待超时）后恢复对应的 run。
func (s *Server) resumeFromTask(e *taskWaitEntry, timedOut bool) {
	// 幂等：同一任务可能同时被"通知"与"重启恢复扫描"两条路径唤醒，
	// take 不到就说明已经有人处理过（或已被取消），直接退出。
	if s.agentTasks.take(e.internalTaskID) == nil {
		logging.Debug("api", "任务 #%d 的等待项已被处理，跳过重复恢复（幂等）", e.internalTaskID)
		return
	}
	s.resumeEntry(e, timedOut)
}

// resumeEntry 恢复一个等待项（不做幂等摘除；调用方负责"谁处理谁摘除"）。
func (s *Server) resumeEntry(e *taskWaitEntry, timedOut bool) {
	if e == nil {
		return
	}
	result, done, err := s.LongTaskResult(e.internalTaskID)
	var resultErr error
	switch {
	case err != nil:
		resultErr = err
	case !done:
		// 超时或"仍在跑"：给出与同步路径一致的 timeout 信封，而不是把 run 判失败。
		result = s.snapshotTimeoutResult(e.internalTaskID, e.timeoutSec)
	}

	run := e.run
	if run == nil || e.recovered {
		run = s.restoreRunForEntry(e)
	}
	if run == nil {
		// 连 run 都重建不出来（库里也没有）：只能把等待项丢掉并记账，
		// 绝不静默卡在等待态。
		s.failWaitingRun(e, "无法重建等待任务的 Agent run（缺少持久化上下文）", "run_restore_failed")
		return
	}

	rctx := ai.TaskResumeContext{
		Tool: e.tool, Args: e.args, CallID: e.callID, TraceID: e.traceID,
		Rebuild: e.recovered, Objective: e.objective,
	}
	if e.recovered {
		rctx.Note = "服务端在本次工具调用执行期间重启：内存中的对话历史已丢失，" +
			"工具结果取自数据库副本（超长输出可能已被截断到 500 字节）。"
	}
	if s.copilot != nil {
		s.copilot.CompleteTaskResume(run, rctx, result, resultErr)
	}

	// 落库收口：步骤与工具调用进入终态、run 回到 running（不再是等待态）。
	s.finishTaskWaitRecords(e, resultErr)

	logging.Info("api", "恢复等待中的 Agent run=%s（task #%d，tool=%s，timed_out=%v，rebuild=%v）",
		run.ID, e.internalTaskID, e.tool, timedOut, e.recovered)
	if s.resumeRun != nil {
		s.resumeRun(run)
	}
}

// restoreRunForEntry 为重启恢复出来的等待项重建内存 run。
func (s *Server) restoreRunForEntry(e *taskWaitEntry) *ai.AgentRun {
	if s.agentMgr == nil {
		return nil
	}
	if run := s.agentMgr.Get(e.runID); run != nil {
		return run
	}
	if s.agentStore == nil {
		return nil
	}
	stored, err := s.agentStore.GetRun(e.runID)
	if err != nil {
		return nil
	}
	objective := e.objective
	if objective == "" {
		objective = stored.Objective
	}
	run := s.agentMgr.RestoreRun(e.runID, stored.TraceID, nil, stored.MaxTurns)
	if run == nil {
		return nil
	}
	// 步骤序号续号：correlation_id = run_id:step_no:attempt，续号才能保证不撞已有记录。
	if n, nerr := s.agentStore.NextStepNo(e.runID); nerr == nil {
		run.SetStepSeq(n - 1)
	}
	if objective != "" {
		run.SetObjective(objective)
	}
	return run
}

// failWaitingRun 给等待中的 run 一个明确终态（中文说明），绝不静默卡住。
func (s *Server) failWaitingRun(e *taskWaitEntry, reason, stopReason string) {
	logging.Error("api", "等待任务 #%d 的 Agent run %s 无法恢复：%s", e.internalTaskID, e.runID, reason)
	if s.agentStore != nil && e.runID != "" {
		if err := s.agentStore.SetRunStatus(e.runID, agentstore.RunFailed, stopReason, "", true); err != nil {
			logging.Warn("api", "写入 run %s 终态失败：%v", e.runID, err)
		}
		// 明确的中文说明必须落盘：只写 status=failed 的话，事后没人知道为什么失败。
		_ = s.agentStore.AppendStep(&agentstore.Step{
			RunID: e.runID, StepNo: e.stepNo, Turn: 0, Kind: "error",
			Status: agentstore.StepFailed, Summary: reason, Error: reason,
			ErrorClass: stopReason, StartedAt: time.Now().Unix(), EndedAt: time.Now().Unix(),
		})
		if cid := e.correlationID(); cid != "" {
			_ = s.agentStore.FinishToolCall(cid, agentstore.CallFailed, reason)
		}
	}
	// 内存里如果有活 run，也把它推进终态并把说明回给模型/前端。
	if s.agentMgr != nil {
		if run := s.agentMgr.Get(e.runID); run != nil {
			run.SetReply("❌ " + reason)
			run.SetStopReason(stopReason)
			run.Cancel()
		}
	}
}

// correlationID 该等待项的工具调用幂等键（优先用落盘的原值，缺失时按规则推导）。
func (e *taskWaitEntry) correlationID() string {
	if e == nil {
		return ""
	}
	if e.correlation != "" {
		return e.correlation
	}
	if e.runID == "" || e.stepNo <= 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d:1", e.runID, e.stepNo)
}

// snapshotTimeoutResult 构造"等待超时/任务仍在跑"的结果信封（字段与同步路径一致）。
func (s *Server) snapshotTimeoutResult(taskID uint64, timeoutSec int) map[string]interface{} {
	t, err := s.taskMgr.Get(taskID)
	if err != nil || t == nil {
		return map[string]interface{}{
			"task_id": taskID, "status": "unknown", "timeout": true,
			"message": "等待超时，且任务已不在库中（可能已被清理）",
		}
	}
	env := taskTimeoutResult(t.SessionID, t)
	env["timeout_sec"] = timeoutSec
	return env
}

// finishTaskWaitRecords 落库收口：step / tool_call 终态 + run 回到 running。
func (s *Server) finishTaskWaitRecords(e *taskWaitEntry, resultErr error) {
	if s.agentStore == nil || e.runID == "" {
		return
	}
	status := agentstore.StepSucceeded
	callStatus := agentstore.CallSucceeded
	errMsg := ""
	if resultErr != nil {
		status = agentstore.StepFailed
		callStatus = agentstore.CallFailed
		errMsg = resultErr.Error()
	}
	if e.stepNo > 0 {
		if err := s.agentStore.FinishStep(e.runID, e.stepNo, status, "", errMsg, "", 0); err != nil {
			logging.Warn("api", "收口 step 失败 run=%s step=%d: %v", e.runID, e.stepNo, err)
		}
	}
	if cid := e.correlationID(); cid != "" {
		if err := s.agentStore.FinishToolCall(cid, callStatus, errMsg); err != nil {
			logging.Warn("api", "收口 tool_call 失败 %s: %v", cid, err)
		}
	}
	// run 回到 running 并清空 waiting_on：它已经不在等任何东西了。
	if err := s.agentStore.SetRunStatus(e.runID, agentstore.RunRunning, "", "", false); err != nil {
		logging.Warn("api", "更新 run %s 状态失败：%v", e.runID, err)
	}
}

// ─── ai.LongTaskExecutor 实现 ─────────────────────────────────────────

// LongTaskPlan 实现 ai.LongTaskExecutor：返回该工具是否为任务类工具与预估超时（无副作用）。
func (s *Server) LongTaskPlan(tool string, args map[string]string) (int, bool) {
	return s.toolTaskTimeout(tool, args)
}

// SubmitLongTask 实现 ai.LongTaskExecutor：创建并下发内部任务，返回句柄（不等待结果）。
//
// 幂等保证：correlation_id = run_id:step_no:attempt 是 agent_tool_calls 上的 UNIQUE 键。
// 先按它回查：已存在且已关联 internal_task_id 时**直接复用**，绝不重复创建/下发
// （at-least-once 语义下重复提交是常态：恢复重放、通知重复都会走到这里）。
func (s *Server) SubmitLongTask(req ai.LongTaskRequest) (ai.LongTaskHandle, bool, error) {
	if _, ok := s.toolTaskTimeout(req.Tool, req.Args); !ok {
		return ai.LongTaskHandle{}, false, nil
	}
	run := s.currentRun(req.RunID)
	stepNo := s.nextStepNo(req.RunID, run)
	h, ok, err := s.submitLongTaskWithStep(req, run, stepNo)
	if err != nil || !ok {
		return h, ok, err
	}
	// 提交成功后才登记等待项并起订阅 goroutine：挂起流程不会再失败（下一步只是把
	// 快照写进 run），因此"有等待项"与"run 真的挂起了"是一致的。
	s.registerLongTaskWait(run, h, req)
	return h, true, nil
}

// submitLongTaskWithCorrelation 提交核心（按 correlation_id 幂等）。
// 单独暴露出来是为了让"同 correlation_id 两次提交只下发一次"这条不变量可被直接单测。
func (s *Server) submitLongTaskWithStep(req ai.LongTaskRequest, run *ai.AgentRun, stepNo int) (ai.LongTaskHandle, bool, error) {
	plan, ok, err := s.planToolTask(req.Tool, req.Args)
	if !ok {
		return ai.LongTaskHandle{}, false, nil
	}
	if err != nil {
		return ai.LongTaskHandle{}, true, err
	}
	correlationID := fmt.Sprintf("%s:%d:1", req.RunID, stepNo)

	// ① 幂等：同一 correlation_id 已经提交过 → 复用已有任务，不重复下发。
	if s.agentStore != nil {
		if prev, perr := s.agentStore.GetToolCall(correlationID); perr == nil && prev.InternalTaskID > 0 {
			logging.Info("api", "长任务提交幂等命中：run=%s correlation=%s 复用 task #%d（不重复下发）",
				req.RunID, correlationID, prev.InternalTaskID)
			h := s.buildHandle(req, plan, prev.InternalTaskID, correlationID, stepNo)
			return h, true, nil
		}
	}

	// ② 下发（与同步路径共用同一套推送逻辑：失败只告警，任务已入队，心跳/重连会补发）。
	sid := req.Args["session_id"]
	if sid == "" {
		sid = plan.Task.SessionID
	}
	if s.listener != nil {
		if perr := s.listener.PushTask(sid, plan.Task); perr != nil {
			logging.Warn("api", "长任务推送到 %s 失败（任务已入队，等待轮询补发）：%v", sid, perr)
		}
	}

	// ③ 落库：run 状态 → awaiting_task（waiting_on 描述在等谁），tool_call 关联任务 id，
	//    并写一条 step 作为恢复游标（step_no 同时是 correlation_id 的组成部分）。
	if s.agentStore != nil {
		s.persistSubmit(req, plan, correlationID, stepNo)
	}

	h := s.buildHandle(req, plan, plan.Task.ID, correlationID, stepNo)
	logging.Info("api", "长任务已提交：run=%s tool=%s task_id=%d correlation=%s timeout=%ds",
		req.RunID, req.Tool, plan.Task.ID, correlationID, plan.TimeoutSec)
	return h, true, nil
}

// buildHandle 组装句柄（waiting_on 由持久化层构造，执行层只透传）。
func (s *Server) buildHandle(req ai.LongTaskRequest, plan toolTaskPlan, taskID uint64, correlationID string, stepNo int) ai.LongTaskHandle {
	deadline := time.Now().Add(time.Duration(plan.TimeoutSec) * time.Second)
	waitingOn := agentstore.WaitingOnTask(agentstore.WaitingTaskRef{
		Tool:           req.Tool,
		CorrelationID:  correlationID,
		InternalTaskID: taskID,
		DeadlineTS:     deadline.Unix(),
		CallID:         req.CallID,
		StepNo:         stepNo,
		TraceID:        req.TraceID,
		TimeoutSec:     plan.TimeoutSec,
	})
	return ai.LongTaskHandle{
		TaskID:        taskID,
		CorrelationID: correlationID,
		StepNo:        stepNo,
		TimeoutSec:    plan.TimeoutSec,
		WaitingOn:     waitingOn,
		DeadlineAt:    deadline,
	}
}

// persistSubmit 把"在等哪个任务"落盘（低风险接线：写失败只告警，不影响执行）。
func (s *Server) persistSubmit(req ai.LongTaskRequest, plan toolTaskPlan, correlationID string, stepNo int) {
	sid := req.Args["session_id"]
	if sid == "" {
		sid = plan.Task.SessionID
	}
	run := s.currentRun(req.RunID)
	objective := ""
	maxTurns := 0
	if run != nil {
		objective = run.Objective
		maxTurns = run.MaxTurns
	}
	// run 行可能还不存在（本增量之前 agent_runs 没有任何写入点）：先 upsert 一次，
	// 再推进到等待态。UpsertRun 按 id 幂等，重复调用安全。
	if err := s.agentStore.UpsertRun(&agentstore.Run{
		ID: req.RunID, SessionID: sid, Objective: objective,
		Status: agentstore.RunRunning, MaxTurns: maxTurns,
		TraceID: req.TraceID, WaitingOn: "",
	}); err != nil {
		logging.Warn("api", "落盘 run %s 失败：%v", req.RunID, err)
	}
	if err := s.agentStore.SaveToolCall(&agentstore.ToolCall{
		ID: req.CallID, CorrelationID: correlationID, RunID: req.RunID, StepNo: stepNo,
		Tool: req.Tool, ArgsJSON: argsJSONOf(req.Args), ArgsHash: argsHashOf(req.Args),
		Status: agentstore.CallDispatched, InternalTaskID: plan.Task.ID,
		TraceID: req.TraceID, DispatchedAt: time.Now().Unix(),
	}); err != nil {
		logging.Warn("api", "落盘 tool_call 失败 %s: %v", correlationID, err)
	}
	if err := s.agentStore.AppendStep(&agentstore.Step{
		RunID: req.RunID, StepNo: stepNo, Turn: req.Turn, Kind: "tool_call",
		Status: agentstore.StepRunning, Summary: req.Tool,
		StartedAt: time.Now().Unix(),
	}); err != nil {
		logging.Warn("api", "落盘 step 失败 run=%s step=%d: %v", req.RunID, stepNo, err)
	}
	// waiting_on 必须在 UpsertRun 之后写（Upsert 会整行覆盖，包含 waiting_on）。
	if h := s.buildHandle(req, plan, plan.Task.ID, correlationID, stepNo); h.WaitingOn != "" {
		if err := s.agentStore.SetRunStatus(req.RunID, agentstore.RunAwaitingTask, stopReasonAwaitTaskPersist, h.WaitingOn, false); err != nil {
			logging.Warn("api", "落盘 waiting_on 失败 run=%s: %v", req.RunID, err)
		}
	}
}

// LongTaskResult 实现 ai.LongTaskExecutor：读取任务最终结果信封。
//
// done=false 表示任务仍在跑（不是错误）；err!=nil 表示任务已丢失（库与内存都没有）。
// 结果信封与同步路径完全一致（同一个 taskEnvelopeByStatus），因此"挂起恢复"拿到的
// 工具结果与"同步等待"逐字段相同。
func (s *Server) LongTaskResult(taskID uint64) (map[string]interface{}, bool, error) {
	t, err := s.taskMgr.Get(taskID)
	if err != nil || t == nil {
		return nil, false, fmt.Errorf("内部任务 #%d 已丢失（tasks 表查不到，可能已被清理或从未落库）", taskID)
	}
	if !isTerminalTaskStatus(t.Status) {
		return nil, false, nil
	}
	return taskEnvelopeByStatus(t.SessionID, t), true, nil
}

// isTerminalTaskStatus 任务终态判定（与 task.IsTerminalStatus 同义，这里避免多引一层）。
func isTerminalTaskStatus(status string) bool {
	switch status {
	case "completed", "failed", "timeout":
		return true
	}
	return false
}

// ─── 挂起登记与恢复注册 ───────────────────────────────────────────────

// registerLongTaskWait 在提交成功后登记等待项并起订阅 goroutine（由 ai 侧挂起流程触发）。
//
// 注意：这里不是"提交的一部分"，而是"挂起成功之后"的动作——挂起失败（run 没能进入
// 等待态）时不应该有等待项，否则会出现"任务完成去恢复一个并没有挂起的 run"。
func (s *Server) registerLongTaskWait(run *ai.AgentRun, h ai.LongTaskHandle, req ai.LongTaskRequest) {
	if s.agentTasks == nil || h.TaskID == 0 {
		return
	}
	e := &taskWaitEntry{
		run: run, runID: req.RunID, tool: req.Tool, callID: req.CallID,
		stepNo: h.StepNo, traceID: req.TraceID, args: req.Args,
		internalTaskID: h.TaskID, timeoutSec: h.TimeoutSec, deadline: h.DeadlineAt,
		correlation: h.CorrelationID,
	}
	s.agentTasks.register(e)
	go s.watchTask(e)
}

// currentRun 取内存中的 run（没有则 nil）。
func (s *Server) currentRun(runID string) *ai.AgentRun {
	if s.agentMgr == nil || runID == "" {
		return nil
	}
	return s.agentMgr.Get(runID)
}

// nextStepNo 分配本次长任务的步骤序号：内存 run 自增；没有 run（重启恢复路径）时
// 用库里 agent_steps 的 MAX(step_no)+1 续号。
func (s *Server) nextStepNo(runID string, run *ai.AgentRun) int {
	if run != nil {
		return run.NextStep()
	}
	if s.agentStore != nil {
		if n, err := s.agentStore.NextStepNo(runID); err == nil {
			return n
		}
	}
	return 1
}

// applyLongTaskExecutor 把长任务通道注入 Copilot（构造与热更新后都要调）。
func (s *Server) applyLongTaskExecutor(cp *ai.Copilot) {
	if cp == nil {
		return
	}
	cp.SetLongTaskExecutor(s)
}

// stopReasonAwaitTaskPersist 落库时 run 的 stop_reason（与 ai.stopReasonAwaitTask 同值）。
const stopReasonAwaitTaskPersist = "awaiting_task"

// argsJSONOf 序列化工具参数（与 ai 侧的签名口径一致：json.Marshal 按 key 升序）。
func argsJSONOf(args map[string]string) string {
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// argsHashOf 参数哈希（防死循环与"同参重复"统计用）。
func argsHashOf(args map[string]string) string {
	sum := sha256.Sum256([]byte(argsJSONOf(args)))
	return fmt.Sprintf("%x", sum)[:16]
}

// longTaskDebugString 供日志/测试阅读等待项（避免在日志里打印整份参数）。
func (e *taskWaitEntry) String() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("run=%s tool=%s task=%d step=%d timeout=%ds",
		e.runID, e.tool, e.internalTaskID, e.stepNo, e.timeoutSec)
}

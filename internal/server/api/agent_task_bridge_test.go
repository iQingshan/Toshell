package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toshell/internal/server/agentstore"
	"toshell/internal/server/ai"
	"toshell/internal/server/config"
	"toshell/internal/server/task"
)

// ─── 长任务：提交幂等 / 挂起恢复 / 重启恢复 ────────────────────────────

// TestClassifyWaitingTask 重启恢复的分类判定（表驱动）：任务已终结/仍在跑/已丢失/记录不可解析。
func TestClassifyWaitingTask(t *testing.T) {
	cases := []struct {
		name     string
		refOK    bool
		exists   bool
		terminal bool
		want     waitingTaskOutcome
	}{
		{"waiting_on 不可解析", false, false, false, waitingTaskUnparsable},
		{"任务查不到（已丢失）", true, false, false, waitingTaskLost},
		{"任务仍在跑", true, true, false, waitingTaskResubscribe},
		{"任务已终结", true, true, true, waitingTaskResume},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyWaitingTask(tc.refOK, tc.exists, tc.terminal); got != tc.want {
				t.Fatalf("classifyWaitingTask(%v,%v,%v) = %v, want %v",
					tc.refOK, tc.exists, tc.terminal, got, tc.want)
			}
		})
	}
}

// TestWaitingOnTaskRoundTrip waiting_on 的构造与解析必须成对（跨重启的唯一契约）。
func TestWaitingOnTaskRoundTrip(t *testing.T) {
	ref := agentstore.WaitingTaskRef{
		Tool: "credentials", CorrelationID: "ag-1:3:1", InternalTaskID: 42,
		DeadlineTS: 1234567, CallID: "call-9", StepNo: 3, TraceID: "tr-1", TimeoutSec: 180,
	}
	got, ok := agentstore.ParseWaitingOn(agentstore.WaitingOnTask(ref))
	if !ok {
		t.Fatal("自己构造的 waiting_on 必须能解析回来")
	}
	if got.Tool != ref.Tool || got.CorrelationID != ref.CorrelationID || got.InternalTaskID != 42 ||
		got.CallID != ref.CallID || got.StepNo != 3 || got.TimeoutSec != 180 {
		t.Fatalf("往返后字段丢失：%+v", got)
	}
	// 审批挂起的 waiting_on（kind=consent）不能被当成任务等待；空串同理。
	if _, ok := agentstore.ParseWaitingOn(agentstore.WaitingOnConsent("exec", "ag-1:1:1")); ok {
		t.Fatal("kind=consent 不应被解析成任务等待")
	}
	if _, ok := agentstore.ParseWaitingOn(""); ok {
		t.Fatal("空 waiting_on 不应被解析成任务等待")
	}
	if _, ok := agentstore.ParseWaitingOn(`{"kind":"task"}`); ok {
		t.Fatal("缺少 internal_task_id 的记录不应被解析成任务等待")
	}
}

// TestSubmitLongTaskIdempotent 同一个 correlation_id 两次提交**只下发一次**：
// 这是 at-least-once 语义下的硬要求（恢复重放、通知重复都会走到同一条提交路径）。
func TestSubmitLongTaskIdempotent(t *testing.T) {
	env := newAgentTaskTestEnv(t, true)
	run := env.newRun(t)
	req := ai.LongTaskRequest{
		RunID: run.ID, Tool: "credentials",
		Args:   map[string]string{"session_id": env.sid, "action": "all"},
		CallID: "call-1", TraceID: "tr-1", Turn: 1,
	}

	h1, ok, err := env.s.submitLongTaskWithStep(req, run, 1)
	if err != nil || !ok {
		t.Fatalf("首次提交失败：ok=%v err=%v", ok, err)
	}
	if h1.CorrelationID != run.ID+":1:1" {
		t.Fatalf("correlation_id = %q, want %q", h1.CorrelationID, run.ID+":1:1")
	}
	if h1.TimeoutSec != 180 {
		t.Fatalf("credentials 的等待超时 = %d, want 180", h1.TimeoutSec)
	}
	if env.pusher.count() != 1 {
		t.Fatalf("下发次数 = %d, want 1", env.pusher.count())
	}
	tk, err := env.tm.Get(h1.TaskID)
	if err != nil || tk == nil {
		t.Fatalf("任务未创建：%v", err)
	}
	if tk.TaskType != "credentials" || !strings.Contains(tk.Data, `"action":"all"`) {
		t.Fatalf("任务参数与同步路径不一致：type=%s data=%s", tk.TaskType, tk.Data)
	}

	// 第二次同 correlation 提交：复用同一任务，不重复下发、不重复落库。
	h2, ok2, err2 := env.s.submitLongTaskWithStep(req, run, 1)
	if err2 != nil || !ok2 {
		t.Fatalf("重复提交失败：ok=%v err=%v", ok2, err2)
	}
	if h2.TaskID != h1.TaskID {
		t.Fatalf("重复提交创建了新任务：%d vs %d（幂等失效）", h2.TaskID, h1.TaskID)
	}
	if env.pusher.count() != 1 {
		t.Fatalf("重复提交导致重复下发：%d 次", env.pusher.count())
	}
	calls, err := env.store.ListToolCalls(run.ID)
	if err != nil {
		t.Fatalf("ListToolCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("重复提交产生 %d 条 tool_call，应只有 1 条", len(calls))
	}
	if calls[0].InternalTaskID != h1.TaskID || calls[0].Status != agentstore.CallDispatched {
		t.Fatalf("tool_call 未正确关联任务：%+v", calls[0])
	}
	// run 已进入等待态并带上等待描述。
	stored, err := env.store.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if stored.Status != agentstore.RunAwaitingTask {
		t.Fatalf("run 状态 = %q, want %q", stored.Status, agentstore.RunAwaitingTask)
	}
	ref, ok := agentstore.ParseWaitingOn(stored.WaitingOn)
	if !ok || ref.InternalTaskID != h1.TaskID || ref.CorrelationID != h1.CorrelationID {
		t.Fatalf("waiting_on 未正确落盘：%q", stored.WaitingOn)
	}
	if n, err := env.store.NextStepNo(run.ID); err != nil || n != 2 {
		t.Fatalf("步骤游标 = %d err=%v, want 2（step 1 已被本次挂起占用）", n, err)
	}
}

// TestSubmitLongTaskRejectsNonTaskTool 只读工具不产生内部任务 → ok=false（调用方走同步路径）。
func TestSubmitLongTaskRejectsNonTaskTool(t *testing.T) {
	env := newAgentTaskTestEnv(t, true)
	run := env.newRun(t)
	_, ok, err := env.s.SubmitLongTask(ai.LongTaskRequest{RunID: run.ID, Tool: "session_list"})
	if ok || err != nil {
		t.Fatalf("session_list 不该产生长任务：ok=%v err=%v", ok, err)
	}
	if env.pusher.count() != 0 {
		t.Fatal("不该下发任何任务")
	}
}

// TestRecoverWaitingAgentRuns 重启恢复的三种情形：
//
//	① 任务已完成 → 接回结果并恢复 run；
//	② 任务仍在跑 → 重新订阅，任务完成时自动恢复；
//	③ 任务已丢失 → run 得到明确终态与中文说明（不静默卡在等待态）。
func TestRecoverWaitingAgentRuns(t *testing.T) {
	env := newAgentTaskTestEnv(t, true)

	// ① 已完成的内部任务。
	doneTask, err := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand, Command: "whoami"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := env.tm.Complete(doneTask.ID, 0, "secret-output", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	env.seedWaitingRun(t, "ag-done", doneTask.ID, "ag-done:1:1", 1)

	// ② 仍在跑的内部任务。
	runningTask, _ := env.tm.Create(env.sid, task.TaskParams{TaskType: task.TaskTypeCommand, Command: "ping"})
	env.seedWaitingRun(t, "ag-running", runningTask.ID, "ag-running:2:1", 2)

	// ③ 已丢失的内部任务（库与内存都没有）。
	env.seedWaitingRun(t, "ag-lost", 987654321, "ag-lost:1:1", 1)

	var mu sync.Mutex
	resumed := map[string]*ai.AgentRun{}
	env.s.resumeRun = func(run *ai.AgentRun) {
		mu.Lock()
		resumed[run.ID] = run
		mu.Unlock()
	}

	env.s.RecoverWaitingAgentRuns()

	// ① 已被接回并交给恢复入口。
	waitFor(t, 2*time.Second, "ag-done 被恢复", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return resumed["ag-done"] != nil
	})
	mu.Lock()
	doneRun := resumed["ag-done"]
	mu.Unlock()
	msgs := doneRun.SnapshotMessages()
	if len(msgs) == 0 || !strings.Contains(msgs[len(msgs)-1].Content, "secret-output") {
		t.Fatalf("恢复后的上下文必须带任务真实结果：%+v", msgs)
	}
	if len(doneRun.Traces) == 0 || doneRun.Traces[0].Name != "credentials" {
		t.Fatalf("恢复后应有该次工具调用的轨迹：%+v", doneRun.Traces)
	}
	stored, _ := env.store.GetRun("ag-done")
	if stored.Status != agentstore.RunRunning || stored.WaitingOn != "" {
		t.Fatalf("接回结果后 run 应回到 running 且清空 waiting_on：status=%s waiting_on=%q",
			stored.Status, stored.WaitingOn)
	}
	if calls, _ := env.store.ListToolCalls("ag-done"); len(calls) != 1 || calls[0].Status != agentstore.CallSucceeded {
		t.Fatalf("tool_call 应收口为 succeeded：%+v", calls)
	}

	// ② 仍在跑：不恢复，但已重新订阅（等待项在桥上）。
	mu.Lock()
	_, resumedRunning := resumed["ag-running"]
	mu.Unlock()
	if resumedRunning {
		t.Fatal("任务仍在跑时不该提前恢复 run")
	}
	if n := env.s.agentTasks.pending(); n != 1 {
		t.Fatalf("桥上等待项 = %d, want 1（仍在跑的那个）", n)
	}
	storedRunning, _ := env.store.GetRun("ag-running")
	if storedRunning.Status != agentstore.RunAwaitingTask || storedRunning.WaitingOn == "" {
		t.Fatalf("仍在跑时 run 应保持等待态：%+v", storedRunning)
	}

	// 任务完成后自动恢复（事件驱动，无轮询）。
	if err := env.tm.Complete(runningTask.ID, 0, "pong", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	waitFor(t, 3*time.Second, "任务完成后自动恢复 ag-running", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return resumed["ag-running"] != nil
	})

	// ③ 已丢失：明确终态 + 中文说明。
	storedLost, err := env.store.GetRun("ag-lost")
	if err != nil {
		t.Fatalf("GetRun(ag-lost): %v", err)
	}
	if storedLost.Status != agentstore.RunFailed {
		t.Fatalf("丢失任务的 run 应为 failed，实际 %q", storedLost.Status)
	}
	if storedLost.StopReason != "task_lost" {
		t.Fatalf("stop_reason = %q, want task_lost", storedLost.StopReason)
	}
	if storedLost.FinishedAt == 0 {
		t.Fatal("失败终态必须写 finished_at")
	}
	steps, err := env.store.ListSteps("ag-lost", 0, 10)
	if err != nil || len(steps) == 0 {
		t.Fatalf("必须落一条说明步骤：%v %+v", err, steps)
	}
	last := steps[len(steps)-1]
	if !strings.Contains(last.Error, "已丢失") || !strings.Contains(last.Summary, "重新下发") {
		t.Fatalf("失败说明必须是可读中文且给出下一步：%+v", last)
	}
	// 且绝不静默卡在等待态。
	if agentstore.IsTerminalRun(storedLost.Status) == false {
		t.Fatal("failed 必须是终态")
	}
}

// TestRecoverUnparsableWaitingOn 无法解析的 waiting_on 也要给出明确终态，而不是留在等待态。
func TestRecoverUnparsableWaitingOn(t *testing.T) {
	env := newAgentTaskTestEnv(t, true)
	if err := env.store.UpsertRun(&agentstore.Run{
		ID: "ag-bad", SessionID: env.sid, Status: agentstore.RunAwaitingTask,
		WaitingOn: `{"kind":"consent"}`, MaxTurns: 4, TraceID: "tr-bad",
	}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}
	env.s.resumeRun = func(*ai.AgentRun) { t.Error("无法解析的等待项不该被恢复") }
	env.s.RecoverWaitingAgentRuns()

	stored, _ := env.store.GetRun("ag-bad")
	if stored.Status != agentstore.RunFailed || stored.StopReason != "waiting_on_unparsable" {
		t.Fatalf("应给出明确终态：%+v", stored)
	}
}

// TestAgentLongTaskSuspendAndResumeEndToEnd 完整流转（假 LLM + 假推送 + 真实任务管理器）：
//
//	模型请求 credentials → 判定为长任务 → 提交（下发 1 次）→ run 挂起、并发槽位释放
//	→ 内部任务完成事件 → 结果接回上下文与轨迹 → 自动恢复循环 → 产出最终答复。
//
// 这条用例是"事件驱动恢复"端到端的证据：全程没有轮询等待任务（run 的挂起与恢复都由
// 通知触发），且恢复后模型确实又跑了一轮（LLM 请求次数 ≥ 2）。
func TestAgentLongTaskSuspendAndResumeEndToEnd(t *testing.T) {
	env := newAgentTaskTestEnv(t, true)
	llm, calls := newMockSSELLM(t, "credentials", map[string]string{"session_id": env.sid}, "凭据收集完成")

	// consent_policy=off：本用例验证的是"长任务挂起"，审批挂起由 consent_test.go 覆盖。
	aiCfg := config.AIConfig{
		Enabled: true, BaseURL: llm.URL, APIKey: "k", Model: "m",
		ConsentPolicy: "off", LongTaskThresholdSec: ai.DefaultLongTaskThresholdSec,
	}
	env.s.cfg.AI = aiCfg
	cp := ai.New(aiCfg, env.s)
	env.s.copilot = cp
	env.s.applyLongTaskExecutor(cp)

	run := env.s.agentMgr.NewRun([]ai.Message{{Role: "user", Content: "收集凭据"}}, 0)
	go func() { _, _ = cp.RunAgent(context.Background(), run) }()

	// ① 挂起：run 进入 awaiting_task，槽位由 runAgentAsync 的 defer 释放。
	waitFor(t, 5*time.Second, "run 进入 awaiting_task", func() bool {
		st, _ := run.WaitState()
		return st == ai.AgentWaitTask
	})
	if env.pusher.count() != 1 {
		t.Fatalf("长任务应只下发一次，实际 %d", env.pusher.count())
	}
	taskID, timeoutSec := run.PendingTaskInfo()
	if taskID == 0 || timeoutSec != 180 {
		t.Fatalf("挂起目标不对：task_id=%d timeout=%d", taskID, timeoutSec)
	}
	_, waitingOn := run.WaitState()
	if !strings.Contains(waitingOn, fmt.Sprintf(`"internal_task_id":%d`, taskID)) {
		t.Fatalf("run.waiting_on 必须能看出在等哪个任务：%q", waitingOn)
	}
	// 桥上有等待项（任务完成时会唤醒它）。
	if n := env.s.agentTasks.pending(); n != 1 {
		t.Fatalf("桥上等待项 = %d, want 1", n)
	}

	// ② 任务完成 → 事件唤醒 → 结果接回 → 自动恢复循环。
	if err := env.tm.Complete(taskID, 0, "Administrator:500:aad3b435b51404ee", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	waitFor(t, 8*time.Second, "run 恢复并产出最终答复", func() bool {
		st, _ := run.WaitState()
		return st == ai.AgentDone
	})
	if !strings.Contains(run.FinalReply, "凭据") {
		t.Fatalf("最终答复未使用恢复后的结果：%q", run.FinalReply)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("恢复后必须重新进入循环（LLM 往返次数 = %d, want ≥2）", got)
	}
	found := false
	for _, tr := range run.Traces {
		if tr.Name == "credentials" && strings.Contains(tr.Result, "aad3b435b51404ee") {
			found = true
		}
	}
	if !found {
		t.Fatalf("轨迹里应有 credentials 的真实结果：%+v", run.Traces)
	}
	if n := env.s.agentTasks.pending(); n != 0 {
		t.Fatalf("恢复后等待项应清空：%d", n)
	}
	stored, err := env.store.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if stored.Status == agentstore.RunAwaitingTask {
		t.Fatalf("run 不该还停在等待态：%+v", stored)
	}
}

// newMockSSELLM 起一个 OpenAI 兼容的假流式服务：第一次请求返回一个工具调用，
// 之后返回最终文本。用于在不联网、不用真实模型的情况下驱动完整 Agent 循环。
func newMockSSELLM(t *testing.T, toolName string, toolArgs map[string]string, finalText string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		var chunk map[string]interface{}
		if n == 1 {
			args, _ := json.Marshal(toolArgs)
			chunk = map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{
					"tool_calls": []interface{}{map[string]interface{}{
						"index": 0, "id": "call-1", "type": "function",
						"function": map[string]interface{}{"name": toolName, "arguments": string(args)},
					}},
				},
			}}}
		} else {
			chunk = map[string]interface{}{"choices": []interface{}{map[string]interface{}{
				"delta": map[string]interface{}{"content": finalText},
			}}}
		}
		b, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", b)
		fmt.Fprint(w, "data: [DONE]\n\n")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

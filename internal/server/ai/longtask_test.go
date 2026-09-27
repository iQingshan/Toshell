package ai

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"toshell/internal/server/config"
)

// fakeLongTaskExec 假的长任务通道：记录提交请求，返回预设句柄。
// 用它可以在不创建任何真实任务、不依赖植入端的情况下验证挂起/恢复流转。
type fakeLongTaskExec struct {
	submitted   []LongTaskRequest
	planTimeout int
	planIsTask  bool
	handle      LongTaskHandle
	submitErr   error
	result      map[string]interface{}
	done        bool
	resultErr   error
}

func (f *fakeLongTaskExec) LongTaskPlan(tool string, args map[string]string) (int, bool) {
	return f.planTimeout, f.planIsTask
}

func (f *fakeLongTaskExec) SubmitLongTask(req LongTaskRequest) (LongTaskHandle, bool, error) {
	if !f.planIsTask {
		return LongTaskHandle{}, false, nil
	}
	if f.submitErr != nil {
		return LongTaskHandle{}, true, f.submitErr
	}
	f.submitted = append(f.submitted, req)
	return f.handle, true, nil
}

func (f *fakeLongTaskExec) LongTaskResult(taskID uint64) (map[string]interface{}, bool, error) {
	return f.result, f.done, f.resultErr
}

// fakeToolExec 假的同步工具执行器（记录调用次数，便于断言"没有走同步路径"）。
type fakeToolExec struct{ calls int }

func (f *fakeToolExec) InvokeTool(name string, args map[string]string) (interface{}, error) {
	f.calls++
	return map[string]interface{}{"sync": name}, nil
}

// TestShouldSuspendLongTask 长任务判定的表驱动用例。
//
// 这张表就是"什么情况挂起、什么情况继续同步等"的规格：阈值边界（== 阈值即挂起）、
// 非法阈值回落默认、非任务类工具不挂起、超时未知时不冒险挂起、运维禁挂名单优先。
func TestShouldSuspendLongTask(t *testing.T) {
	def := LongTaskPolicy{} // 阈值 0 → 回落 DefaultLongTaskThresholdSec(150)
	cases := []struct {
		name        string
		policy      LongTaskPolicy
		tool        string
		isTaskTool  bool
		timeoutSec  int
		wantSuspend bool
		wantReason  string // 只需包含该子串
	}{
		{"凭据收集 180s ≥ 150 → 挂起", def, "credentials", true, 180, true, "timeout_sec=180"},
		{"文件下载 300s → 挂起", def, "file_download", true, 300, true, ">=150"},
		{"插件加载 180s → 挂起", def, "plugin_load", true, 180, true, ""},
		{"内存执行 180s → 挂起", def, "fileless_exec", true, 180, true, ""},
		{"exec 默认 120s < 150 → 同步等", def, "exec", true, 120, false, "timeout_sec=120<150"},
		{"file_list 60s → 同步等", def, "file_list", true, 60, false, ""},
		{"截图 90s → 同步等", def, "screenshot", true, 90, false, ""},
		{"恰好等于阈值 → 挂起（≥ 判定）", def, "exec", true, 150, true, ""},
		{"比阈值小一秒 → 同步等", def, "exec", true, 149, false, ""},
		{"显式 timeout_sec 调大后挂起", def, "exec", true, 200, true, ""},
		{"非任务类工具永不挂起", def, "session_list", false, 600, false, "not_task_tool"},
		{"只读工具即使超时很大也不挂起", def, "intel_query", false, 0, false, "not_task_tool"},
		{"超时未知（0）不冒险挂起", def, "exec", true, 0, false, "unknown_timeout"},
		{"负数超时同样不挂起", def, "exec", true, -5, false, "unknown_timeout"},
		{"自定义阈值 60：file_list 60s 挂起", LongTaskPolicy{ThresholdSec: 60}, "file_list", true, 60, true, ""},
		{"自定义阈值 400：credentials 不挂起", LongTaskPolicy{ThresholdSec: 400}, "credentials", true, 180, false, ""},
		{"非法阈值（负数）回落默认 150", LongTaskPolicy{ThresholdSec: -1}, "exec", true, 149, false, ""},
		{"禁挂名单优先于一切", LongTaskPolicy{NeverSuspend: []string{"credentials"}}, "credentials", true, 180, false, "never_suspend"},
		{"禁挂名单不影响其它工具", LongTaskPolicy{NeverSuspend: []string{"credentials"}}, "file_download", true, 300, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := ShouldSuspendLongTask(tc.policy, tc.tool, tc.isTaskTool, tc.timeoutSec)
			if got != tc.wantSuspend {
				t.Fatalf("ShouldSuspendLongTask = %v (%s), want %v", got, reason, tc.wantSuspend)
			}
			if tc.wantReason != "" && !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason = %q，应包含 %q（挂起/不挂起的原因必须能直接读出来）", reason, tc.wantReason)
			}
			if reason == "" {
				t.Fatal("reason 不应为空（审计与排查要能知道为什么）")
			}
		})
	}
	// 默认阈值与配置常量必须一致：viper 默认值与运行时兜底是同一个数。
	if DefaultLongTaskThresholdSec != config.DefaultLongTaskThresholdSec {
		t.Fatalf("默认阈值漂移：ai=%d config=%d", DefaultLongTaskThresholdSec, config.DefaultLongTaskThresholdSec)
	}
	if (LongTaskPolicy{}).effectiveThreshold() != DefaultLongTaskThresholdSec {
		t.Fatal("空策略应回落默认阈值")
	}
}

// TestLongTaskPolicyFromConfig 配置 → 策略：显式配置生效，非法值回落默认。
func TestLongTaskPolicyFromConfig(t *testing.T) {
	if got := longTaskPolicyFromConfig(config.AIConfig{LongTaskThresholdSec: 42}).effectiveThreshold(); got != 42 {
		t.Fatalf("显式阈值未生效：%d", got)
	}
	if got := longTaskPolicyFromConfig(config.AIConfig{}).effectiveThreshold(); got != DefaultLongTaskThresholdSec {
		t.Fatalf("零值配置应回落默认阈值：%d", got)
	}
}

// newLongTaskTestCopilot 构造一个只接了假执行器的 Copilot（不联网、不起服务端）。
func newLongTaskTestCopilot(t *testing.T, ex LongTaskExecutor) (*Copilot, *fakeToolExec) {
	t.Helper()
	tools := &fakeToolExec{}
	cp := New(config.AIConfig{
		Enabled: true, BaseURL: "http://127.0.0.1:1", APIKey: "k", Model: "m",
	}, tools)
	cp.SetLongTaskExecutor(ex)
	return cp, tools
}

// assistantToolCallRun 造一个"模型刚发起工具调用"的 run（循环里挂起前就是这个状态）。
func assistantToolCallRun(t *testing.T, tool, argsJSON, callID string) (*AgentRun, ToolCall) {
	t.Helper()
	mgr := NewAgentManager(1)
	run := mgr.NewRun([]Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "收集凭据"},
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: callID, Type: "function",
			Function: ToolCallFunc{Name: tool, Arguments: argsJSON},
		}}},
	}, 0)
	return run, run.Messages[len(run.Messages)-1].ToolCalls[0]
}

// TestSuspendForTaskSetsWaitState 挂起流转的关键不变量：
// run 进入 awaiting_task、waiting_on 落上等待描述、挂起快照被保存、事件里有 task_wait、
// 且**没有**走同步执行路径（否则并发槽位根本没被释放）。
func TestSuspendForTaskSetsWaitState(t *testing.T) {
	handle := LongTaskHandle{
		TaskID: 42, CorrelationID: "ag-1:1:1", StepNo: 1, TimeoutSec: 180,
		WaitingOn:  `{"kind":"task","internal_task_id":42,"tool":"credentials"}`,
		DeadlineAt: time.Now().Add(180 * time.Second),
	}
	ex := &fakeLongTaskExec{planIsTask: true, planTimeout: 180, handle: handle}
	cp, tools := newLongTaskTestCopilot(t, ex)
	run, tc := assistantToolCallRun(t, "credentials", `{"session_id":"s1"}`, "call-1")
	args := map[string]string{"session_id": "s1"}

	got, ok := cp.suspendForTask(context.Background(), run, tc, args, "tr-1-abcd", 2)
	if !ok {
		t.Fatal("挂起失败（提交应当成功）")
	}
	if got.TaskID != 42 {
		t.Fatalf("挂起句柄 task_id = %d, want 42", got.TaskID)
	}
	status, waitingOn := run.WaitState()
	if status != AgentWaitTask {
		t.Fatalf("run 状态 = %q, want %q", status, AgentWaitTask)
	}
	if waitingOn != handle.WaitingOn {
		t.Fatalf("run.waiting_on = %q，应与落库的等待描述一致", waitingOn)
	}
	run.mu.Lock()
	p := run.PendingTask
	run.mu.Unlock()
	if p == nil {
		t.Fatal("挂起必须保存 PendingTask（恢复要用它接续消息序列）")
	}
	if len(p.messages) != len(run.SnapshotMessages()) {
		t.Fatal("挂起快照应包含挂起那一刻的完整消息序列")
	}
	if tools.calls != 0 {
		t.Fatalf("挂起路径不得同步执行工具（实际调用 %d 次）——并发槽位正是靠这一步释放的", tools.calls)
	}
	if len(ex.submitted) != 1 {
		t.Fatalf("提交次数 = %d, want 1", len(ex.submitted))
	}
	req := ex.submitted[0]
	if req.RunID != run.ID || req.Tool != "credentials" || req.CallID != "call-1" ||
		req.TraceID != "tr-1-abcd" || req.Args["session_id"] != "s1" {
		t.Fatalf("提交请求字段不完整：%+v", req)
	}
	if reason := run.StopReason; reason != stopReasonAwaitTask {
		t.Fatalf("stop_reason = %q, want %q（可观测性要求等待态能被看出来）", reason, stopReasonAwaitTask)
	}

	// 事件：tool_start + task_wait（后者带 task_id，前端据此显示"等待任务 #N"）。
	var kinds []AgentEventKind
	var waitInfo TaskWaitInfo
	for {
		select {
		case ev, okc := <-run.Events():
			if !okc {
				break
			}
			kinds = append(kinds, ev.Kind)
			if ev.Kind == AgentEventTaskWait {
				_ = json.Unmarshal(ev.Data, &waitInfo)
			}
			continue
		default:
		}
		break
	}
	if len(kinds) < 2 || kinds[len(kinds)-1] != AgentEventTaskWait {
		t.Fatalf("事件序列 = %v，末尾应是 task_wait", kinds)
	}
	if waitInfo.TaskID != 42 || waitInfo.Status != string(AgentWaitTask) || waitInfo.Tool != "credentials" {
		t.Fatalf("task_wait 载荷不完整：%+v", waitInfo)
	}
}

// TestSuspendForTaskSubmitFailureFallsBack 提交失败必须退回同步路径（不挂起）：
// 否则会出现"判定要挂起、任务却没提交成功"的静默死等。
func TestSuspendForTaskSubmitFailureFallsBack(t *testing.T) {
	ex := &fakeLongTaskExec{planIsTask: true, planTimeout: 180, submitErr: errors.New("session offline")}
	cp, _ := newLongTaskTestCopilot(t, ex)
	run, tc := assistantToolCallRun(t, "credentials", `{"session_id":"s1"}`, "call-1")

	if _, ok := cp.suspendForTask(context.Background(), run, tc, map[string]string{"session_id": "s1"}, "tr-1", 0); ok {
		t.Fatal("提交失败时不应判定为挂起成功")
	}
	if status, _ := run.WaitState(); status == AgentWaitTask {
		t.Fatal("提交失败时 run 不应进入等待态")
	}
	// 非任务类工具同理（ok=false）。
	ex2 := &fakeLongTaskExec{planIsTask: false}
	cp.SetLongTaskExecutor(ex2)
	if _, ok := cp.suspendForTask(context.Background(), run, tc, nil, "tr-1", 0); ok {
		t.Fatal("非任务类工具不应挂起")
	}
}

// TestCompleteTaskResumeAppendsToolMessage 恢复流转：结果按同一套转换点接回上下文与轨迹，
// 等待态被清空、run 回到 running（此后由 resumeAgentAsync 重新进入循环）。
func TestCompleteTaskResumeAppendsToolMessage(t *testing.T) {
	cp, _ := newLongTaskTestCopilot(t, &fakeLongTaskExec{})
	run, tc := assistantToolCallRun(t, "credentials", `{"session_id":"s1"}`, "call-1")
	args := map[string]string{"session_id": "s1"}

	run.mu.Lock()
	run.Status = AgentWaitTask
	run.WaitingOn = `{"kind":"task"}`
	run.StopReason = stopReasonAwaitTask
	run.PendingTask = &pendingTaskState{
		messages: append([]Message(nil), run.Messages...),
		tool:     tc, args: args,
		traces:  []ToolTrace{{Name: "session_list", Result: "共 1 个会话"}},
		traceID: "tr-1-abcd",
		handle:  LongTaskHandle{TaskID: 7, TimeoutSec: 180},
	}
	run.mu.Unlock()

	result := map[string]interface{}{
		"task_id": 7, "status": "completed", "output": "Administrator:500:aad3b435", "exit_code": 0,
	}
	cp.CompleteTaskResume(run, TaskResumeContext{
		Tool: "credentials", Args: args, CallID: "call-1", TraceID: "tr-1-abcd",
	}, result, nil)

	status, waitingOn := run.WaitState()
	if status != AgentRunning || waitingOn != "" {
		t.Fatalf("恢复后状态 = %q waiting_on=%q，want running/空", status, waitingOn)
	}
	run.mu.Lock()
	pending := run.PendingTask
	stopReason := run.StopReason
	msgs := append([]Message(nil), run.Messages...)
	traces := append([]ToolTrace(nil), run.Traces...)
	run.mu.Unlock()
	if pending != nil {
		t.Fatal("恢复后 PendingTask 必须清空")
	}
	if stopReason != "" {
		t.Fatalf("恢复后 stop_reason 必须清空（否则最终 done 会带过期的 awaiting_task），实际 %q", stopReason)
	}
	last := msgs[len(msgs)-1]
	if last.Role != "tool" || last.ToolCallID != "call-1" {
		t.Fatalf("最后一条消息应是配对的 tool 消息：%+v", last)
	}
	if !strings.Contains(last.Content, "aad3b435") {
		t.Fatalf("tool 消息必须带任务真实结果：%q", last.Content)
	}
	if len(traces) != 2 || traces[0].Name != "session_list" {
		t.Fatalf("轨迹应保留挂起前的记录并追加本次：%+v", traces)
	}
	if traces[1].Name != "credentials" || !strings.Contains(traces[1].Result, "aad3b435") {
		t.Fatalf("本次工具轨迹不对：%+v", traces[1])
	}
}

// TestCompleteTaskResumeRebuildPairsToolCall 重启恢复：消息历史丢失后用最小上下文重建，
// 且 assistant.tool_calls 与 tool 消息**必须配对**（否则上游 chat/completions 会直接报错）。
func TestCompleteTaskResumeRebuildPairsToolCall(t *testing.T) {
	cp, _ := newLongTaskTestCopilot(t, &fakeLongTaskExec{})
	run := NewAgentManager(1).NewRun(nil, 0)
	cp.CompleteTaskResume(run, TaskResumeContext{
		Tool: "file_download", Args: map[string]string{"session_id": "s1", "path": "C:\\a.zip"},
		CallID: "ag-9:1:1", TraceID: "tr-restart", Rebuild: true, Objective: "把 a.zip 拉回来",
	}, map[string]interface{}{"task_id": 9, "status": "completed", "output": "ok"}, nil)

	msgs := run.SnapshotMessages()
	if len(msgs) != 4 {
		t.Fatalf("重建上下文应有 4 条消息（system/user/assistant/tool），实际 %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[1].Role != "user" || msgs[2].Role != "assistant" || msgs[3].Role != "tool" {
		t.Fatalf("重建消息角色顺序不对：%v/%v/%v/%v", msgs[0].Role, msgs[1].Role, msgs[2].Role, msgs[3].Role)
	}
	if !strings.Contains(msgs[1].Content, "把 a.zip 拉回来") {
		t.Fatalf("重建上下文必须带原目标：%q", msgs[1].Content)
	}
	if !strings.Contains(msgs[1].Content, "重启") {
		t.Fatalf("重建上下文必须诚实标注「历史已重建」：%q", msgs[1].Content)
	}
	if len(msgs[2].ToolCalls) != 1 {
		t.Fatalf("重建的 assistant 消息必须带 tool_calls：%+v", msgs[2])
	}
	if msgs[2].ToolCalls[0].ID != msgs[3].ToolCallID {
		t.Fatalf("tool_calls[0].id=%q 与 tool.tool_call_id=%q 必须配对",
			msgs[2].ToolCalls[0].ID, msgs[3].ToolCallID)
	}
	if msgs[2].ToolCalls[0].Function.Name != "file_download" {
		t.Fatalf("重建的 tool_calls 名称不对：%+v", msgs[2].ToolCalls[0])
	}
}

// TestCompleteTaskResumeError 任务结果获取失败时按"工具失败"处理：
// 轨迹带 Error、上下文里写明 error（模型据此换策略），而不是静默丢弃。
func TestCompleteTaskResumeError(t *testing.T) {
	cp, _ := newLongTaskTestCopilot(t, &fakeLongTaskExec{})
	run, _ := assistantToolCallRun(t, "file_download", `{"session_id":"s1"}`, "call-1")
	cp.CompleteTaskResume(run, TaskResumeContext{Tool: "file_download", CallID: "call-1", TraceID: "tr-1"},
		nil, errors.New("内部任务 #9 已丢失"))

	run.mu.Lock()
	traces := append([]ToolTrace(nil), run.Traces...)
	msgs := append([]Message(nil), run.Messages...)
	run.mu.Unlock()
	if len(traces) != 1 || traces[0].Error == "" {
		t.Fatalf("失败结果必须写进轨迹 Error：%+v", traces)
	}
	if !strings.Contains(msgs[len(msgs)-1].Content, "已丢失") {
		t.Fatalf("失败说明必须进上下文：%q", msgs[len(msgs)-1].Content)
	}
}

// TestResetForResumeClearsTaskWait 复用 run 续接新指令时必须清掉等待态残留
// （否则新一轮会带着上一轮的 waiting_on/PendingTask，前端显示"还在等任务"）。
func TestResetForResumeClearsTaskWait(t *testing.T) {
	run := NewAgentManager(1).NewRun(nil, 0)
	run.mu.Lock()
	run.Status = AgentWaitTask
	run.WaitingOn = `{"kind":"task"}`
	run.PendingTask = &pendingTaskState{traceID: "old"}
	run.mu.Unlock()
	run.ResetForResume()
	status, waitingOn := run.WaitState()
	if status != AgentQueued || waitingOn != "" {
		t.Fatalf("ResetForResume 后 status=%q waiting_on=%q", status, waitingOn)
	}
	if _, timeout := run.PendingTaskInfo(); timeout != 0 {
		t.Fatal("ResetForResume 应清空 PendingTask")
	}
}

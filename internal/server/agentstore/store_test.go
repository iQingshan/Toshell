package agentstore

import (
	"path/filepath"
	"testing"

	"toshell/internal/server/database"
)

// newTestStore 用真实 schema（database.AgentSchemaStatements）建一个临时库。
// 这样测试同时验证了 DDL 本身可用——schema 只有一处定义，不会与生产漂移。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "agentstore.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	s, err := New(d.SQL())
	if err != nil {
		t.Fatalf("agentstore.New: %v", err)
	}
	return s
}

func TestSchemaCreatesAgentTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "schema.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	want := []string{"agent_runs", "agent_steps", "agent_tool_calls", "tool_results"}
	for _, tbl := range want {
		var name string
		err := d.SQL().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		if err != nil {
			t.Fatalf("表 %s 未创建：%v", tbl, err)
		}
	}
	// 幂等：对同一个库再初始化一次不应报错（老库升级路径，全部 IF NOT EXISTS）
	if _, err := database.New("sqlite", dbPath); err != nil {
		t.Fatalf("重复初始化应幂等（老库升级路径）: %v", err)
	}
}

func TestRunLifecycleAndResume(t *testing.T) {
	s := newTestStore(t)

	r := &Run{
		ID: "ag-1", SessionID: "sess-1", Objective: "收集信息",
		Status: RunQueued, MaxTurns: 8, MaxToolCalls: 20, MaxWallclockSec: 600,
		Model: "deepseek-chat", ConsentPolicy: "graded", Initiator: "admin",
		TraceID: "tr-1",
	}
	if err := s.UpsertRun(r); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}
	if err := s.StartRun(r.ID); err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if err := s.BumpRunUsage(r.ID, 1, 2, 100, 50); err != nil {
		t.Fatalf("BumpRunUsage: %v", err)
	}
	// 进入"等工具结果"状态
	if err := s.SetRunStatus(r.ID, RunRunning, "", WaitingOnTool("exec", "ag-1:3:1", 0), false); err != nil {
		t.Fatalf("SetRunStatus: %v", err)
	}

	got, err := s.GetRun(r.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Status != RunRunning || got.TotalTurns != 1 || got.TotalToolCalls != 2 {
		t.Fatalf("run 状态不对: %s turns=%d calls=%d", got.Status, got.TotalTurns, got.TotalToolCalls)
	}
	if got.StartedAt == 0 {
		t.Fatal("StartRun 应写入 started_at")
	}
	if got.WaitingOn == "" {
		t.Fatal("waiting_on 应被保存（恢复时要据此知道在等谁）")
	}

	// 未终态 → 出现在可恢复列表里
	resumable, err := s.ListResumableRuns(10)
	if err != nil {
		t.Fatalf("ListResumableRuns: %v", err)
	}
	if len(resumable) != 1 || resumable[0].ID != "ag-1" {
		t.Fatalf("可恢复列表不对: %+v", resumable)
	}

	// 终态后不再出现在可恢复列表
	if err := s.SetRunStatus(r.ID, RunSucceeded, "max_turns", "", true); err != nil {
		t.Fatalf("SetRunStatus(final): %v", err)
	}
	resumable, _ = s.ListResumableRuns(10)
	if len(resumable) != 0 {
		t.Fatalf("终态 run 不该出现在可恢复列表: %+v", resumable)
	}
	final, _ := s.GetRun(r.ID)
	if final.FinishedAt == 0 {
		t.Fatal("终态应写 finished_at")
	}
	if !IsTerminalRun(final.Status) {
		t.Fatalf("IsTerminalRun(%s) 应为 true", final.Status)
	}
	// 会话维度能查到
	bySess, err := s.ListRunsBySession("sess-1", 10)
	if err != nil || len(bySess) != 1 {
		t.Fatalf("ListRunsBySession: %v %d", err, len(bySess))
	}
	// 不存在的 run 返回 ErrNotFound
	if _, err := s.GetRun("nope"); err != ErrNotFound {
		t.Fatalf("GetRun(不存在) = %v, want ErrNotFound", err)
	}
}

func TestStepCursorAndIdempotency(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertRun(&Run{ID: "ag-2", SessionID: "s", Status: RunRunning, MaxTurns: 4, MaxToolCalls: 8, MaxWallclockSec: 60}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}

	n, err := s.NextStepNo("ag-2")
	if err != nil || n != 1 {
		t.Fatalf("NextStepNo 空表应为 1，实际 %d err=%v", n, err)
	}
	st := &Step{RunID: "ag-2", StepNo: 1, Turn: 1, Kind: "tool_call", Status: StepRunning, PlanJSON: `{"steps":["a"]}`}
	if err := s.AppendStep(st); err != nil {
		t.Fatalf("AppendStep: %v", err)
	}
	// 同一 step_no 重复写入（恢复重放）不应报错、不应产生第二行
	dup := &Step{RunID: "ag-2", StepNo: 1, Turn: 1, Kind: "tool_call", Status: StepSucceeded, Summary: "重放"}
	if err := s.AppendStep(dup); err != nil {
		t.Fatalf("AppendStep(dup): %v", err)
	}
	steps, err := s.ListSteps("ag-2", 0, 10)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("重复 step_no 产生了 %d 行，应只有 1 行", len(steps))
	}
	if steps[0].Status != StepSucceeded || steps[0].Summary != "重放" {
		t.Fatalf("upsert 未生效: %+v", steps[0])
	}

	if err := s.AppendStep(&Step{RunID: "ag-2", Turn: 1, Kind: "final", Status: StepRunning}); err != nil {
		t.Fatalf("AppendStep(auto step_no): %v", err)
	}
	n, _ = s.NextStepNo("ag-2")
	if n != 3 {
		t.Fatalf("NextStepNo 应为 3，实际 %d", n)
	}

	if err := s.FinishStep("ag-2", 1, StepFailed, "摘要", "会话离线", "session_offline", 1234); err != nil {
		t.Fatalf("FinishStep: %v", err)
	}
	steps, _ = s.ListSteps("ag-2", 1, 10)
	if steps[0].LatencyMS != 1234 || steps[0].ErrorClass != "session_offline" || steps[0].EndedAt == 0 {
		t.Fatalf("FinishStep 未生效: %+v", steps[0])
	}
	// fromStepNo 过滤（SSE 断点续传）
	from2, _ := s.ListSteps("ag-2", 2, 10)
	if len(from2) != 1 || from2[0].StepNo != 2 {
		t.Fatalf("fromStepNo=2 应只返回 step 2: %+v", from2)
	}
}

func TestToolCallIdempotencyAndLoopDetection(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertRun(&Run{ID: "ag-3", SessionID: "s", Status: RunRunning, MaxTurns: 4, MaxToolCalls: 8, MaxWallclockSec: 60}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}

	tc := &ToolCall{
		ID: "call_1", CorrelationID: "ag-3:1:1", RunID: "ag-3", StepNo: 1,
		Tool: "exec", ArgsJSON: `{"session_id":"s","command":"whoami"}`, ArgsHash: "h1",
		Risk: "L3", ConsentRequired: true, TraceID: "tr",
	}
	if err := s.SaveToolCall(tc); err != nil {
		t.Fatalf("SaveToolCall: %v", err)
	}
	// at-least-once：同 correlation_id 再投一次（状态推进 + 关联任务 id）
	again := *tc
	again.Status = CallDispatched
	again.InternalTaskID = 42
	again.Attempt = 2
	if err := s.SaveToolCall(&again); err != nil {
		t.Fatalf("SaveToolCall(again): %v", err)
	}
	calls, err := s.ListToolCalls("ag-3")
	if err != nil {
		t.Fatalf("ListToolCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("重复投递产生了 %d 行，应只有 1 行（按 correlation_id 幂等）", len(calls))
	}
	if calls[0].InternalTaskID != 42 || calls[0].Status != CallDispatched {
		t.Fatalf("upsert 未推进状态: %+v", calls[0])
	}

	// 同工具同参数重复 → 计数（防死循环）
	n, err := s.CountArgsHash("ag-3", "h1")
	if err != nil || n != 1 {
		t.Fatalf("CountArgsHash = %d err=%v, want 1", n, err)
	}
	// SetInternalTaskID / FinishToolCall / SetConsent 路径
	if err := s.SetConsent(tc.CorrelationID, "allow"); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	if err := s.FinishToolCall(tc.CorrelationID, CallSucceeded, ""); err != nil {
		t.Fatalf("FinishToolCall: %v", err)
	}
	got, err := s.GetToolCall(tc.CorrelationID)
	if err != nil {
		t.Fatalf("GetToolCall: %v", err)
	}
	if got.ConsentDecision != "allow" || got.Status != CallSucceeded || got.FinishedAt == 0 {
		t.Fatalf("审批/收口字段不对: %+v", got)
	}
	// 未决列表应空（已终态）
	pending, _ := s.ListPendingToolCalls("ag-3")
	if len(pending) != 0 {
		t.Fatalf("已终态调用不该出现在待决列表: %+v", pending)
	}
	// 仍在跑的调用会出现在待决列表
	if err := s.SaveToolCall(&ToolCall{ID: "call_2", CorrelationID: "ag-3:2:1", RunID: "ag-3", StepNo: 2, Tool: "file_list", ArgsJSON: "{}", ArgsHash: "h2", Status: CallRunning}); err != nil {
		t.Fatalf("SaveToolCall(pending): %v", err)
	}
	pending, _ = s.ListPendingToolCalls("ag-3")
	if len(pending) != 1 || pending[0].CorrelationID != "ag-3:2:1" {
		t.Fatalf("待决列表不对: %+v", pending)
	}
}

func TestResultIndexAndTTLPurge(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertRun(&Run{ID: "ag-4", SessionID: "s", Status: RunRunning, MaxTurns: 2, MaxToolCalls: 4, MaxWallclockSec: 60}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}
	res := &Result{
		ID: "r-ag4-1-1", CorrelationID: "ag-4:1:1", RunID: "ag-4", Tool: "screenshot",
		Status: "ok", MediaType: "image/png", BytesTotal: 900000, SHA256: "abc",
		InlineSummary: "截图 1 张", ExternalPath: "data/agent-results/ag-4/r-ag4-1-1.png",
		Truncated: true, TruncatedFields: `["image"]`, PageCount: 3, TTLExpiresAt: 1,
	}
	if err := s.SaveResult(res); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	got, err := s.GetResultByCorrelation(res.CorrelationID)
	if err != nil {
		t.Fatalf("GetResultByCorrelation: %v", err)
	}
	if !got.Truncated || got.TruncatedFields != `["image"]` || got.PageCount != 3 {
		t.Fatalf("截断标注字段丢失: %+v", got)
	}
	// TTL 过期 → 清理并回传外置路径（供调用方删文件）
	paths, err := s.PurgeExpiredResults(0)
	if err != nil {
		t.Fatalf("PurgeExpiredResults: %v", err)
	}
	if len(paths) != 1 || paths[0] != res.ExternalPath {
		t.Fatalf("应回传待删外置路径: %+v", paths)
	}
	if _, err := s.GetResultByCorrelation(res.CorrelationID); err != ErrNotFound {
		t.Fatalf("清理后应查不到: %v", err)
	}
}

func TestMaxTaskID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "maxtask.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	s, _ := New(d.SQL())
	if n, err := s.MaxTaskID(); err != nil || n != 0 {
		t.Fatalf("空表 MaxTaskID = %d err=%v, want 0", n, err)
	}
}

func TestNewRejectsNilDB(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil 连接应报错而不是 panic")
	}
}

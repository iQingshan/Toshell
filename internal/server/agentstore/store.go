// Package agentstore 持久化「Agent 长任务」的状态：run / step / tool_call / result 四类记录。
//
// 为什么需要它（见 ROADMAP 的 v1.4.0 迭代计划 S2）：
//   - 现状是 run 与任务句柄**全在内存**（`ai.AgentManager.runs` map、run ID 内存自增），
//     进程重启或前端断线 = 任务凭空消失；等待外部工具结果的状态也不落盘；
//   - 因此把「状态机 + checkpoint + 幂等工具调用 + 结果外置索引」落到 sqlite：
//     断线/重启后能按 run 恢复，工具调用按 correlation_id 幂等（at-least-once 重复投递安全），
//     大结果外置后这里只留句柄与摘要。
//
// 表结构由 `internal/server/database` 的 AgentSchemaStatements 统一创建（单一来源），
// 本包只做 CRUD，不建表、不做迁移。时间戳统一用 **Unix 秒**，与 database.go 既有做法一致。
package agentstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// 状态常量：run 与 tool_call 的状态机取值（写盘的是字符串，便于人工排查）。
const (
	RunQueued          = "queued"
	RunRunning         = "running"
	RunAwaitingConsent = "awaiting_consent"
	// RunAwaitingTask run 正在等一个内部任务（tasks 表）的结果（v1.4.0 S2 新增）。
	//
	// 与 RunAwaitingConsent 的区别：审批挂起等的是"人"，本态等的是"任务完成事件"。
	// 两者都是**非终态**：run 的循环已退出（并发槽位已释放），由外部事件唤醒后恢复。
	// 恢复所需的全部信息在 waiting_on（kind="task"）+ agent_tool_calls（internal_task_id）
	// 里，重启后据此重新对齐 tasks 表。
	RunAwaitingTask = "awaiting_task"
	RunSucceeded    = "succeeded"
	RunFailed       = "failed"
	RunTimeout      = "timeout"
	RunCancelled    = "cancelled"

	CallSubmitted  = "submitted"
	CallDispatched = "dispatched"
	CallRunning    = "running"
	CallSucceeded  = "succeeded"
	CallFailed     = "failed"
	CallTimeout    = "timeout"
	CallDenied     = "denied"
	CallCancelled  = "cancelled"

	StepRunning   = "running"
	StepSucceeded = "succeeded"
	StepFailed    = "failed"
	StepSkipped   = "skipped"
	StepDenied    = "denied"
)

// ErrNotFound 目标记录不存在。
var ErrNotFound = errors.New("agentstore: record not found")

// Store 是 sqlite 上的一层薄 CRUD。
type Store struct {
	db *sql.DB
}

// New 包装一个已初始化的连接（来自 database.Get().SQL()）。
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("agentstore: nil database handle")
	}
	return &Store{db: db}, nil
}

// Run 一次 Agent 运行（run 级状态机与预算）。
type Run struct {
	ID               string
	SessionID        string
	Objective        string
	Status           string
	StopReason       string // 见 ROADMAP：max_turns|max_tool_calls|max_wallclock|loop_detected|session_offline|llm_error|user_cancel|consent_denied...
	WaitingOn        string // JSON：{"kind":"tool"|"consent", ...}；空闲为空串
	MaxTurns         int
	MaxToolCalls     int
	MaxWallclockSec  int
	Model            string
	ConsentPolicy    string
	Initiator        string
	TraceID          string
	PromptHash       string
	ToolsHash        string
	TotalTurns       int
	TotalToolCalls   int
	PromptTokens     int
	CompletionTokens int
	CreatedAt        int64
	StartedAt        int64 // 0 = 未开始
	UpdatedAt        int64
	FinishedAt       int64 // 0 = 未结束
}

// WaitingOnTool 构造"在等某个工具结果"的 waiting_on JSON。
func WaitingOnTool(tool, correlationID string, deadline int64) string {
	b, _ := json.Marshal(map[string]interface{}{
		"kind": "tool", "tool": tool, "correlation_id": correlationID, "deadline_ts": deadline,
	})
	return string(b)
}

// WaitingOnConsent 构造"在等人工审批"的 waiting_on JSON。
func WaitingOnConsent(tool, correlationID string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"kind": "consent", "tool": tool, "correlation_id": correlationID,
	})
	return string(b)
}

// WaitingTaskRef waiting_on 里 kind="task" 的语义：谁在等、等哪个内部任务、等到什么时候。
//
// 定义在持久化层而不是执行层：这份 JSON 是**写进库、重启后要读回来**的契约，
// 构造（WaitingOnTask）与解析（ParseWaitingOn）必须成对演进，放一起才不会漂移。
type WaitingTaskRef struct {
	Kind string `json:"kind"`
	// Tool 发起本次工具调用的工具名（恢复时要按它构造 tool 消息/轨迹）。
	Tool string `json:"tool"`
	// CorrelationID 工具调用的幂等键（run_id:step_no:attempt），用于回查 agent_tool_calls。
	CorrelationID string `json:"correlation_id"`
	// InternalTaskID tasks 表里的任务 id（重启后按它对账）。
	InternalTaskID uint64 `json:"internal_task_id"`
	// DeadlineTS 等待截止时刻（Unix 秒，0 = 不限）。超过它就不再等，按"仍在跑"继续。
	DeadlineTS int64 `json:"deadline_ts,omitempty"`
	// CallID LLM 给出的 tool_call id：恢复时追加的 tool 消息必须与它配对，
	// 否则上游 chat/completions 会因"tool 消息没有对应的 assistant.tool_calls"直接报错。
	CallID string `json:"call_id,omitempty"`
	// StepNo 步骤游标（与 agent_steps 的 step_no 一致）。
	StepNo int `json:"step_no,omitempty"`
	// TraceID 贯穿本次执行的 trace id（恢复后仍要能串起审计）。
	TraceID string `json:"trace_id,omitempty"`
	// TimeoutSec 本次等待的超时预算（秒）。
	TimeoutSec int `json:"timeout_sec,omitempty"`
}

// WaitingOnTask 构造"在等某个内部任务结果"的 waiting_on JSON。
func WaitingOnTask(ref WaitingTaskRef) string {
	ref.Kind = "task"
	b, _ := json.Marshal(ref)
	return string(b)
}

// ParseWaitingOn 解析 waiting_on；仅当 kind="task" 且带 internal_task_id 时返回 ok=true。
// 解析失败按"无法恢复的等待"处理（调用方给 run 一个明确终态，而不是静默卡住）。
func ParseWaitingOn(raw string) (*WaitingTaskRef, bool) {
	if raw == "" {
		return nil, false
	}
	var ref WaitingTaskRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil {
		return nil, false
	}
	if ref.Kind != "task" || ref.InternalTaskID == 0 {
		return nil, false
	}
	return &ref, true
}

// IsTerminalRun 判断 run 是否已进入终态（终态不再恢复）。
func IsTerminalRun(status string) bool {
	switch status {
	case RunSucceeded, RunFailed, RunTimeout, RunCancelled:
		return true
	}
	return false
}

func nowSec() int64 { return time.Now().Unix() }

// UpsertRun 写入或整体更新一条 run（幂等）。
func (s *Store) UpsertRun(r *Run) error {
	if r == nil || r.ID == "" {
		return errors.New("agentstore: run.id required")
	}
	if r.Status == "" {
		r.Status = RunQueued
	}
	if r.ConsentPolicy == "" {
		r.ConsentPolicy = "graded"
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = nowSec()
	}
	r.UpdatedAt = nowSec()
	_, err := s.db.Exec(`
		INSERT INTO agent_runs (id, session_id, objective, status, stop_reason, waiting_on,
			max_turns, max_tool_calls, max_wallclock_sec, model, consent_policy, initiator,
			trace_id, prompt_hash, tools_hash, total_turns, total_tool_calls,
			prompt_tokens, completion_tokens, created_at, started_at, updated_at, finished_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			session_id=excluded.session_id, objective=excluded.objective, status=excluded.status,
			stop_reason=excluded.stop_reason, waiting_on=excluded.waiting_on,
			max_turns=excluded.max_turns, max_tool_calls=excluded.max_tool_calls,
			max_wallclock_sec=excluded.max_wallclock_sec, model=excluded.model,
			consent_policy=excluded.consent_policy, initiator=excluded.initiator,
			trace_id=excluded.trace_id, prompt_hash=excluded.prompt_hash, tools_hash=excluded.tools_hash,
			total_turns=excluded.total_turns, total_tool_calls=excluded.total_tool_calls,
			prompt_tokens=excluded.prompt_tokens, completion_tokens=excluded.completion_tokens,
			started_at=excluded.started_at, updated_at=excluded.updated_at, finished_at=excluded.finished_at`,
		r.ID, r.SessionID, r.Objective, r.Status, r.StopReason, nullIfEmpty(r.WaitingOn),
		r.MaxTurns, r.MaxToolCalls, r.MaxWallclockSec, r.Model, r.ConsentPolicy, nullIfEmpty(r.Initiator),
		r.TraceID, nullIfEmpty(r.PromptHash), nullIfEmpty(r.ToolsHash),
		r.TotalTurns, r.TotalToolCalls, r.PromptTokens, r.CompletionTokens,
		r.CreatedAt, nullable(r.StartedAt), r.UpdatedAt, nullable(r.FinishedAt))
	return err
}

// SetRunStatus 更新状态机字段（并可写 waiting_on / stop_reason）。
// finished=true 时同时落 finished_at（终态）。
func (s *Store) SetRunStatus(id, status, stopReason, waitingOn string, finished bool) error {
	var fin interface{}
	if finished {
		fin = nowSec()
	}
	_, err := s.db.Exec(`UPDATE agent_runs SET status=?, stop_reason=?, waiting_on=?, updated_at=?, finished_at=COALESCE(?, finished_at) WHERE id=?`,
		status, nullIfEmpty(stopReason), nullIfEmpty(waitingOn), nowSec(), fin, id)
	return err
}

// StartRun 标记 run 已开始（queued → running）。
func (s *Store) StartRun(id string) error {
	_, err := s.db.Exec(`UPDATE agent_runs SET status=?, started_at=COALESCE(started_at, ?), updated_at=? WHERE id=?`,
		RunRunning, nowSec(), nowSec(), id)
	return err
}

// BumpRunUsage 累加预算用量（轮次/工具调用/token）。写盘用增量，避免读改写竞态。
func (s *Store) BumpRunUsage(id string, turns, toolCalls, promptTokens, completionTokens int) error {
	_, err := s.db.Exec(`UPDATE agent_runs SET
			total_turns=total_turns+?, total_tool_calls=total_tool_calls+?,
			prompt_tokens=prompt_tokens+?, completion_tokens=completion_tokens+?, updated_at=?
		WHERE id=?`, turns, toolCalls, promptTokens, completionTokens, nowSec(), id)
	return err
}

const runCols = `id, session_id, COALESCE(objective,''), status, COALESCE(stop_reason,''), COALESCE(waiting_on,''),
	max_turns, max_tool_calls, max_wallclock_sec, model, consent_policy, COALESCE(initiator,''),
	trace_id, COALESCE(prompt_hash,''), COALESCE(tools_hash,''), total_turns, total_tool_calls,
	prompt_tokens, completion_tokens, created_at, COALESCE(started_at,0), updated_at, COALESCE(finished_at,0)`

func scanRun(row interface{ Scan(...interface{}) error }) (*Run, error) {
	r := &Run{}
	err := row.Scan(&r.ID, &r.SessionID, &r.Objective, &r.Status, &r.StopReason, &r.WaitingOn,
		&r.MaxTurns, &r.MaxToolCalls, &r.MaxWallclockSec, &r.Model, &r.ConsentPolicy, &r.Initiator,
		&r.TraceID, &r.PromptHash, &r.ToolsHash, &r.TotalTurns, &r.TotalToolCalls,
		&r.PromptTokens, &r.CompletionTokens, &r.CreatedAt, &r.StartedAt, &r.UpdatedAt, &r.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// GetRun 按 id 取 run。
func (s *Store) GetRun(id string) (*Run, error) {
	return scanRun(s.db.QueryRow(`SELECT `+runCols+` FROM agent_runs WHERE id=?`, id))
}

// ListResumableRuns 列出"还没进终态"的 run（进程重启后的恢复入口）。
// 含 awaiting_task：它同样是"循环已退出、等外部事件唤醒"的非终态。
func (s *Store) ListResumableRuns(limit int) ([]*Run, error) {
	return s.queryRuns(`SELECT `+runCols+` FROM agent_runs
		WHERE status IN (?,?,?,?) ORDER BY created_at ASC LIMIT ?`,
		RunQueued, RunRunning, RunAwaitingConsent, RunAwaitingTask, limitOrDefault(limit, 50))
}

// ListRunsAwaitingTask 列出所有"正在等内部任务结果"的 run（重启恢复扫描用）。
// 单独一个查询而不是复用 ListResumableRuns：恢复要按下标对齐 tasks 表，
// 混进 queued/running 的 run 会让扫描逻辑被迫做无意义的过滤。
func (s *Store) ListRunsAwaitingTask(limit int) ([]*Run, error) {
	return s.queryRuns(`SELECT `+runCols+` FROM agent_runs
		WHERE status=? ORDER BY created_at ASC LIMIT ?`, RunAwaitingTask, limitOrDefault(limit, 200))
}

// ListRunsBySession 按会话列出历史 run（前端"该会话跑过哪些 run"）。
func (s *Store) ListRunsBySession(sessionID string, limit int) ([]*Run, error) {
	return s.queryRuns(`SELECT `+runCols+` FROM agent_runs WHERE session_id=? ORDER BY created_at DESC LIMIT ?`,
		sessionID, limitOrDefault(limit, 50))
}

func (s *Store) queryRuns(q string, args ...interface{}) ([]*Run, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Step 步骤级 checkpoint。
type Step struct {
	RunID             string
	StepNo            int
	Turn              int
	Kind              string // plan|think|assistant|tool_call|tool_result|final|error|consent
	Status            string
	ObjectiveSnapshot string
	PlanJSON          string
	Summary           string // ≤2KB，进上下文的那份
	Error             string
	ErrorClass        string
	PromptTokens      int
	CompletionTokens  int
	LatencyMS         int64
	RetryCount        int
	StartedAt         int64
	EndedAt           int64
}

// NextStepNo 返回该 run 的下一个 step_no（恢复游标）。
func (s *Store) NextStepNo(runID string) (int, error) {
	var maxNo sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(step_no) FROM agent_steps WHERE run_id=?`, runID).Scan(&maxNo); err != nil {
		return 0, err
	}
	if !maxNo.Valid {
		return 1, nil
	}
	return int(maxNo.Int64) + 1, nil
}

// AppendStep 追加一个步骤。同一 (run_id, step_no) 重复写入会被忽略（幂等，恢复时重放安全）。
func (s *Store) AppendStep(st *Step) error {
	if st == nil || st.RunID == "" {
		return errors.New("agentstore: step.run_id required")
	}
	if st.StepNo == 0 {
		n, err := s.NextStepNo(st.RunID)
		if err != nil {
			return err
		}
		st.StepNo = n
	}
	if st.StartedAt == 0 {
		st.StartedAt = nowSec()
	}
	_, err := s.db.Exec(`INSERT INTO agent_steps (run_id, step_no, turn, kind, status,
			objective_snapshot, plan_json, summary, error, error_class,
			prompt_tokens, completion_tokens, latency_ms, retry_count, started_at, ended_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(run_id, step_no) DO UPDATE SET
			turn=excluded.turn, kind=excluded.kind, status=excluded.status,
			objective_snapshot=excluded.objective_snapshot, plan_json=excluded.plan_json,
			summary=excluded.summary, error=excluded.error, error_class=excluded.error_class,
			prompt_tokens=excluded.prompt_tokens, completion_tokens=excluded.completion_tokens,
			latency_ms=excluded.latency_ms, retry_count=excluded.retry_count,
			started_at=excluded.started_at, ended_at=excluded.ended_at`,
		st.RunID, st.StepNo, st.Turn, st.Kind, st.Status,
		nullIfEmpty(st.ObjectiveSnapshot), nullIfEmpty(st.PlanJSON), nullIfEmpty(st.Summary),
		nullIfEmpty(st.Error), nullIfEmpty(st.ErrorClass),
		st.PromptTokens, st.CompletionTokens, st.LatencyMS, st.RetryCount,
		st.StartedAt, nullable(st.EndedAt))
	return err
}

// FinishStep 收口一个步骤（状态 + 摘要 + 错误归类 + 耗时）。
func (s *Store) FinishStep(runID string, stepNo int, status, summary, errMsg, errClass string, latencyMS int64) error {
	_, err := s.db.Exec(`UPDATE agent_steps SET status=?, summary=COALESCE(NULLIF(?,''), summary),
			error=?, error_class=?, latency_ms=?, ended_at=? WHERE run_id=? AND step_no=?`,
		status, summary, nullIfEmpty(errMsg), nullIfEmpty(errClass), latencyMS, nowSec(), runID, stepNo)
	return err
}

// ListSteps 按 step_no 升序取步骤（fromStepNo 用于 SSE 断点续传/恢复）。
func (s *Store) ListSteps(runID string, fromStepNo, limit int) ([]*Step, error) {
	rows, err := s.db.Query(`SELECT run_id, step_no, turn, kind, status,
			COALESCE(objective_snapshot,''), COALESCE(plan_json,''), COALESCE(summary,''),
			COALESCE(error,''), COALESCE(error_class,''),
			prompt_tokens, completion_tokens, latency_ms, retry_count, started_at, COALESCE(ended_at,0)
		FROM agent_steps WHERE run_id=? AND step_no>=? ORDER BY step_no ASC LIMIT ?`,
		runID, fromStepNo, limitOrDefault(limit, 200))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Step{}
	for rows.Next() {
		st := &Step{}
		if err := rows.Scan(&st.RunID, &st.StepNo, &st.Turn, &st.Kind, &st.Status,
			&st.ObjectiveSnapshot, &st.PlanJSON, &st.Summary, &st.Error, &st.ErrorClass,
			&st.PromptTokens, &st.CompletionTokens, &st.LatencyMS, &st.RetryCount, &st.StartedAt, &st.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ToolCall 一次工具调用记录。
type ToolCall struct {
	ID              string
	CorrelationID   string // run_id:step_no:attempt —— 配对键（乱序/重复投递都按它对齐）
	RunID           string
	StepNo          int
	Tool            string
	ArgsJSON        string
	ArgsHash        string
	Risk            string // L0|L1|L2|L3
	Status          string
	ConsentRequired bool
	ConsentDecision string // allow|deny|""(未决)
	Attempt         int
	InternalTaskID  uint64 // 0 = 未关联
	TraceID         string
	SubmittedAt     int64
	DispatchedAt    int64
	FinishedAt      int64
	Error           string
}

// SaveToolCall 落一条工具调用（按 correlation_id 幂等 upsert，重复投递安全）。
func (s *Store) SaveToolCall(tc *ToolCall) error {
	if tc == nil || tc.CorrelationID == "" {
		return errors.New("agentstore: tool_call.correlation_id required")
	}
	if tc.Risk == "" {
		tc.Risk = "L1"
	}
	if tc.Status == "" {
		tc.Status = CallSubmitted
	}
	if tc.Attempt == 0 {
		tc.Attempt = 1
	}
	if tc.SubmittedAt == 0 {
		tc.SubmittedAt = nowSec()
	}
	_, err := s.db.Exec(`INSERT INTO agent_tool_calls (id, correlation_id, run_id, step_no, tool, args_json, args_hash,
			risk, status, consent_required, consent_decision, attempt, internal_task_id, trace_id,
			submitted_at, dispatched_at, finished_at, error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(correlation_id) DO UPDATE SET
			status=excluded.status, consent_required=excluded.consent_required,
			consent_decision=COALESCE(excluded.consent_decision, agent_tool_calls.consent_decision),
			attempt=excluded.attempt,
			internal_task_id=COALESCE(excluded.internal_task_id, agent_tool_calls.internal_task_id),
			dispatched_at=COALESCE(excluded.dispatched_at, agent_tool_calls.dispatched_at),
			finished_at=COALESCE(excluded.finished_at, agent_tool_calls.finished_at),
			error=excluded.error`,
		nullIfEmpty(tc.ID), tc.CorrelationID, tc.RunID, tc.StepNo, tc.Tool, tc.ArgsJSON, tc.ArgsHash,
		tc.Risk, tc.Status, boolToInt(tc.ConsentRequired), nullIfEmpty(tc.ConsentDecision), tc.Attempt,
		nullableUint(tc.InternalTaskID), tc.TraceID,
		tc.SubmittedAt, nullable(tc.DispatchedAt), nullable(tc.FinishedAt), nullIfEmpty(tc.Error))
	return err
}

const callCols = `COALESCE(id,''), correlation_id, run_id, step_no, tool, args_json, args_hash, risk, status,
	consent_required, COALESCE(consent_decision,''), attempt, COALESCE(internal_task_id,0), trace_id,
	submitted_at, COALESCE(dispatched_at,0), COALESCE(finished_at,0), COALESCE(error,'')`

func scanCall(row interface{ Scan(...interface{}) error }) (*ToolCall, error) {
	tc := &ToolCall{}
	var consent int
	var taskID int64
	err := row.Scan(&tc.ID, &tc.CorrelationID, &tc.RunID, &tc.StepNo, &tc.Tool, &tc.ArgsJSON, &tc.ArgsHash,
		&tc.Risk, &tc.Status, &consent, &tc.ConsentDecision, &tc.Attempt, &taskID, &tc.TraceID,
		&tc.SubmittedAt, &tc.DispatchedAt, &tc.FinishedAt, &tc.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	tc.ConsentRequired = consent != 0
	if taskID > 0 {
		tc.InternalTaskID = uint64(taskID)
	}
	return tc, nil
}

// GetToolCall 按 correlation_id 取调用记录。
func (s *Store) GetToolCall(correlationID string) (*ToolCall, error) {
	return scanCall(s.db.QueryRow(`SELECT `+callCols+` FROM agent_tool_calls WHERE correlation_id=?`, correlationID))
}

// ListToolCalls 列出某 run 的工具调用（按 step_no 升序）。
func (s *Store) ListToolCalls(runID string) ([]*ToolCall, error) {
	rows, err := s.db.Query(`SELECT `+callCols+` FROM agent_tool_calls WHERE run_id=? ORDER BY step_no ASC, attempt ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ToolCall{}
	for rows.Next() {
		tc, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}

// ListPendingToolCalls 列出"还没结束"的调用（恢复时据此判断在等谁）。
func (s *Store) ListPendingToolCalls(runID string) ([]*ToolCall, error) {
	rows, err := s.db.Query(`SELECT `+callCols+` FROM agent_tool_calls
		WHERE run_id=? AND status IN (?,?,?) ORDER BY step_no ASC`,
		runID, CallSubmitted, CallDispatched, CallRunning)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ToolCall{}
	for rows.Next() {
		tc, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}

// SetConsent 记录审批结论（allow|deny）。
func (s *Store) SetConsent(correlationID, decision string) error {
	_, err := s.db.Exec(`UPDATE agent_tool_calls SET consent_decision=?, consent_required=1 WHERE correlation_id=?`,
		decision, correlationID)
	return err
}

// FinishToolCall 收口一次调用。
func (s *Store) FinishToolCall(correlationID, status, errMsg string) error {
	_, err := s.db.Exec(`UPDATE agent_tool_calls SET status=?, error=?, finished_at=? WHERE correlation_id=?`,
		status, nullIfEmpty(errMsg), nowSec(), correlationID)
	return err
}

// SetInternalTaskID 关联内部任务 id（恢复时据此对齐 tasks 表）。
func (s *Store) SetInternalTaskID(correlationID string, taskID uint64) error {
	_, err := s.db.Exec(`UPDATE agent_tool_calls SET internal_task_id=?, status=?, dispatched_at=COALESCE(dispatched_at,?) WHERE correlation_id=?`,
		int64(taskID), CallDispatched, nowSec(), correlationID)
	return err
}

// CountArgsHash 统计同一 run 里"同工具同参数"已出现的次数（防死循环：同参重复调用要换策略/中断）。
func (s *Store) CountArgsHash(runID, argsHash string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_tool_calls WHERE run_id=? AND args_hash=?`, runID, argsHash).Scan(&n)
	return n, err
}

// Result 结果外置索引。
type Result struct {
	ID              string
	CorrelationID   string
	RunID           string
	Tool            string
	Status          string // ok|error|timeout|partial
	MediaType       string
	BytesTotal      int64
	SHA256          string
	InlineJSON      string
	InlineSummary   string
	ExternalPath    string
	Truncated       bool
	TruncatedFields string // JSON 数组，例如 ["image"]
	PageCount       int
	PageSize        int
	Redacted        bool
	TTLExpiresAt    int64
	CreatedAt       int64
}

// SaveResult 落一条结果索引（按 correlation_id 幂等）。
func (s *Store) SaveResult(r *Result) error {
	if r == nil || r.ID == "" || r.CorrelationID == "" {
		return errors.New("agentstore: result.id/correlation_id required")
	}
	if r.MediaType == "" {
		r.MediaType = "application/json"
	}
	if r.PageSize == 0 {
		r.PageSize = 8192
	}
	if r.PageCount == 0 {
		r.PageCount = 1
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = nowSec()
	}
	_, err := s.db.Exec(`INSERT INTO tool_results (id, correlation_id, run_id, tool, status, media_type,
			bytes_total, sha256, inline_json, inline_summary, external_path, truncated, truncated_fields,
			page_count, page_size, redacted, ttl_expires_at, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(correlation_id) DO UPDATE SET
			status=excluded.status, media_type=excluded.media_type, bytes_total=excluded.bytes_total,
			sha256=excluded.sha256, inline_json=excluded.inline_json, inline_summary=excluded.inline_summary,
			external_path=excluded.external_path, truncated=excluded.truncated,
			truncated_fields=excluded.truncated_fields, page_count=excluded.page_count,
			page_size=excluded.page_size, redacted=excluded.redacted, ttl_expires_at=excluded.ttl_expires_at`,
		r.ID, r.CorrelationID, r.RunID, r.Tool, r.Status, r.MediaType,
		r.BytesTotal, r.SHA256, nullIfEmpty(r.InlineJSON), nullIfEmpty(r.InlineSummary), nullIfEmpty(r.ExternalPath),
		boolToInt(r.Truncated), nullIfEmpty(r.TruncatedFields), r.PageCount, r.PageSize,
		boolToInt(r.Redacted), nullable(r.TTLExpiresAt), r.CreatedAt)
	return err
}

// GetResultByCorrelation 按配对键取结果。
func (s *Store) GetResultByCorrelation(correlationID string) (*Result, error) {
	r := &Result{}
	var truncated, redacted int
	err := s.db.QueryRow(`SELECT id, correlation_id, run_id, tool, status, media_type, bytes_total, sha256,
			COALESCE(inline_json,''), COALESCE(inline_summary,''), COALESCE(external_path,''),
			truncated, COALESCE(truncated_fields,''), page_count, page_size, redacted,
			COALESCE(ttl_expires_at,0), created_at
		FROM tool_results WHERE correlation_id=?`, correlationID).
		Scan(&r.ID, &r.CorrelationID, &r.RunID, &r.Tool, &r.Status, &r.MediaType, &r.BytesTotal, &r.SHA256,
			&r.InlineJSON, &r.InlineSummary, &r.ExternalPath, &truncated, &r.TruncatedFields,
			&r.PageCount, &r.PageSize, &redacted, &r.TTLExpiresAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Truncated = truncated != 0
	r.Redacted = redacted != 0
	return r, nil
}

// PurgeExpiredResults 删除已过 TTL 的结果索引，返回删除行数（外置文件由调用方按返回的路径删）。
func (s *Store) PurgeExpiredResults(now int64) ([]string, error) {
	if now == 0 {
		now = nowSec()
	}
	rows, err := s.db.Query(`SELECT COALESCE(external_path,'') FROM tool_results
		WHERE ttl_expires_at IS NOT NULL AND ttl_expires_at > 0 AND ttl_expires_at <= ?`, now)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		if p != "" {
			paths = append(paths, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`DELETE FROM tool_results WHERE ttl_expires_at IS NOT NULL AND ttl_expires_at > 0 AND ttl_expires_at <= ?`, now); err != nil {
		return nil, err
	}
	return paths, nil
}

// MaxTaskID 返回 tasks 表里最大的 id（用于把内存计数器 taskCounter 初始化到历史值之上，
// 避免进程重启后从 0 开始生成与历史任务撞号的 id）。
func (s *Store) MaxTaskID() (uint64, error) {
	var maxID sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(id) FROM tasks`).Scan(&maxID); err != nil {
		return 0, err
	}
	if !maxID.Valid || maxID.Int64 < 0 {
		return 0, nil
	}
	return uint64(maxID.Int64), nil
}

// ── 小工具 ──────────────────────────────────────────────────────────

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullable(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableUint(v uint64) interface{} {
	if v == 0 {
		return nil
	}
	return int64(v)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func limitOrDefault(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

// String 便于日志/调试。
func (r *Run) String() string {
	return fmt.Sprintf("run %s session=%s status=%s turns=%d/%d calls=%d/%d",
		r.ID, r.SessionID, r.Status, r.TotalTurns, r.MaxTurns, r.TotalToolCalls, r.MaxToolCalls)
}

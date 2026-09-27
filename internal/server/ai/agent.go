package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"toshell/internal/server/logging"
	"toshell/internal/server/mcp"
)

// ─── 异步自主 Agent───────────────────────────────────────────────────
// 一次「交代任务」对应一个 AgentRun：后台 goroutine 自主运行 ReAct 循环，
// 事件经 channel 以 SSE 形式推给前端（可见推理与每步工具），不再同步阻塞
// 一次 HTTP 请求。支持取消、并发上限、跨消息保持执行计划。

// AgentEventKind 事件类型（SSE event）。
type AgentEventKind string

const (
	AgentEventThinking   AgentEventKind = "thinking"    // 模型推理增量（reasoning_content）
	AgentEventMessage    AgentEventKind = "message"     // 模型正文增量（content）
	AgentEventToolStart  AgentEventKind = "tool_start"  // 开始执行工具
	AgentEventToolResult AgentEventKind = "tool_result" // 工具执行结果
	AgentEventFinal      AgentEventKind = "final"       // 最终答复（完整）
	AgentEventConsent    AgentEventKind = "consent"     // 需要审批（需同意的工具）
	AgentEventDone       AgentEventKind = "done"        // 全部完成
	AgentEventError      AgentEventKind = "error"       // 出错（会话级）
	// AgentEventTrace 本次执行的 trace/预算/策略（v1.4.0 S2 新增）。
	// 单独发一条而不是塞进 thinking/message：那两个事件的 data 是**字符串**，
	// 加字段会变成对象，老前端解析会退化；独立事件名老前端不认识会直接忽略。
	AgentEventTrace AgentEventKind = "trace"
	// AgentEventTaskWait run 因等待内部任务（长任务）结果而挂起（v1.4.0 S2 新增）。
	// 老前端不认识该事件名会走 SSE 默认分支忽略；新前端可据此显示"等待任务 #N 结果"
	// 而不是把"没有事件"误当成卡死。run 的 status 也会同时变成 awaiting_task。
	AgentEventTaskWait AgentEventKind = "task_wait"
)

// AgentEvent 一次 Agent 事件。
type AgentEvent struct {
	Kind AgentEventKind `json:"kind"`
	// 载荷：thinking/message 为字符串；tool_start 为 ToolStart；
	// tool_result 为 ToolResult；final 为 string；consent 为 ConsentRequest；
	// trace 为 TraceInfo；done 为 DoneInfo；error 见 Error。
	Data json.RawMessage `json:"data,omitempty"`
	// Error 仅 kind=error 时携带。
	Error string `json:"error,omitempty"`
	// TraceID 本次执行的 trace id（v1.4.0 S2 新增，老前端忽略即可）。
	// ⚠️ HTTP 层（internal/server/api）只把 Data 透传成 SSE 的 data 字段，
	// 所以 trace_id 同时也写进了 tool_start/tool_result/consent/done 的载荷结构里。
	TraceID string `json:"trace_id,omitempty"`
}

// TraceInfo 事件 kind=trace 的载荷：本次执行的 trace id 与生效预算/审批策略，
// 便于前端与审计把一次 run 的日志、审批、工具调用串成一条线。
type TraceInfo struct {
	TraceID         string `json:"trace_id"`
	RunID           string `json:"run_id"`
	ConsentPolicy   string `json:"consent_policy"`
	MaxTurns        int    `json:"max_turns"`
	MaxToolCalls    int    `json:"max_tool_calls"`
	MaxWallclockSec int    `json:"max_wallclock_sec"`
	// MaxContextTokens / MaxRunTokens / ContextWorkingKeep 为 v1.4.0 S2 新增可选字段：
	// 生效的上下文预算（近似 token）、累计 token 预算与工作层保留条数。
	// 老前端不认识这些字段，忽略即可（同一个 JSON 对象里多几个键）。
	MaxContextTokens   int `json:"max_context_tokens,omitempty"`
	MaxRunTokens       int `json:"max_run_tokens,omitempty"`
	ContextWorkingKeep int `json:"context_working_keep,omitempty"`
}

// DoneInfo 事件 kind=done 的载荷（v1.4.0 S2 新增）：trace id 与停止原因。
// 老前端把 done 的 data 当空对象忽略，新增字段不影响。
type DoneInfo struct {
	TraceID    string `json:"trace_id,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

// TaskWaitInfo 事件 kind=task_wait 的载荷（v1.4.0 S2 新增）：
// run 已释放并发槽位、正在等某个内部任务的结果；任务完成时会被自动唤醒恢复。
type TaskWaitInfo struct {
	RunID         string `json:"run_id"`
	TaskID        uint64 `json:"task_id"`
	Tool          string `json:"tool"`
	CorrelationID string `json:"correlation_id,omitempty"`
	TimeoutSec    int    `json:"timeout_sec,omitempty"`
	Status        string `json:"status"` // awaiting_task
	TraceID       string `json:"trace_id,omitempty"`
}

// ToolStart 工具开始执行事件。
type ToolStart struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args,omitempty"`
	// TraceID v1.4.0 S2 新增：本次执行的 trace id（SSE 载荷里可见）。
	TraceID string `json:"trace_id,omitempty"`
}

// ToolResult 工具结果事件。
type ToolResult struct {
	Name   string `json:"name"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	// TraceID v1.4.0 S2 新增：本次执行的 trace id（SSE 载荷里可见）。
	TraceID string `json:"trace_id,omitempty"`
	// Handle/Truncated/TruncationNote/TotalBytes 为 v1.4.0 S2 新增可选字段：
	// 超过内联上限的结果已外置，Result 里只有摘要；前端可据此显示"结果已外置，
	// 共 N 字节，可用句柄回读"，而不是展示一段被截断的正文。老前端忽略即可。
	Handle         string `json:"handle,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
	TruncationNote string `json:"truncation_note,omitempty"`
	TotalBytes     int    `json:"total_bytes,omitempty"`
}

// AgentStatus run 生命周期状态。
type AgentStatus string

const (
	AgentQueued      AgentStatus = "queued"
	AgentRunning     AgentStatus = "running"
	AgentDone        AgentStatus = "done"
	AgentError       AgentStatus = "error"
	AgentWaitConsent AgentStatus = "awaiting_consent"
	// AgentWaitTask 等待内部任务（长任务）结果（v1.4.0 S2 新增）。
	//
	// 与 AgentWaitConsent 一样是**非终态**：run 的循环已退出（并发槽位已释放），
	// 由"任务完成通知"驱动恢复。命名刻意与 agentstore.RunAwaitingTask 对齐——
	// 同一个状态在内存与库里的字符串必须是同一个，否则恢复扫描对不上。
	AgentWaitTask AgentStatus = "awaiting_task"
)

// RunEvent run 的结构化时间线事件（供前端展示 goal→step→tool→result 及失败原因）。
type RunEvent struct {
	Ts   int64  `json:"ts"`             // unix ms
	Kind string `json:"kind"`           // thinking/tool_start/tool_result/final/error
	Text string `json:"text,omitempty"` // 摘要文本（thinking 片段/工具名/结果摘要/错误）
}

// GoalStep 目标分解后的一个执行步骤（agent 自主维护进度）。
type GoalStep struct {
	Index  int    `json:"index"`
	Desc   string `json:"desc"`   // 步骤描述
	Status string `json:"status"` // pending / running / done / skipped / failed
	Result string `json:"result,omitempty"`
}

// AgentRun 一次自主任务运行实例。
type AgentRun struct {
	ID     string      `json:"id"`
	Status AgentStatus `json:"status"`
	// Objective 当前被交代的目标（用户最新指令摘要，供展示/续接）。
	Objective string `json:"objective,omitempty"`
	// Plan 目标驱动执行计划（LLM 输出【执行计划】后由服务端解析维护，跨消息保持）。
	Plan []GoalStep `json:"plan,omitempty"`
	// Messages 保存本 run 的完整消息序列（system+history+tool）。后续「继续」可追加。
	Messages []Message `json:"-"`
	// Traces 已完成的工具轨迹（最终汇总展示用）。
	Traces []ToolTrace `json:"traces,omitempty"`
	// FinalReply 最终答复（done 后填充）。
	FinalReply string `json:"reply,omitempty"`
	// Timeline 结构化时间线（goal→thinking→tool→result/error，供前端回放/失败定位）。
	Timeline []RunEvent `json:"timeline,omitempty"`
	// CreatedAt / UpdatedAt。
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// MaxTurns 本轮上限（0=用配置默认）。
	MaxTurns int `json:"-"`
	// TraceID 本次执行的 trace id（tr-<unixnano>-<4hex>，v1.4.0 S2 新增）：
	// 同一次 run 的所有事件、工具调用、审批请求与日志都带同一个 id。
	TraceID string `json:"trace_id,omitempty"`
	// StopReason 循环停止原因（v1.4.0 S2 新增）：
	// max_turns / max_tool_calls / max_wallclock / loop_detected，空=正常产出最终答复。
	StopReason string `json:"stop_reason,omitempty"`
	// WaitingOn 当前挂起在等什么（v1.4.0 S2 新增，JSON 字符串；空闲为空串）。
	// 语义与 agentstore.Run.WaitingOn 一致（kind=consent 或 kind=task），
	// 由持久化层构造、执行层透传，保证内存与库里是同一份描述。
	// GET /api/v1/agent/runs/{id} 会回传它：新等待态必须"看得见"。
	WaitingOn string `json:"waiting_on,omitempty"`

	// ── v1.4.0 S2 上下文/token 可观测性（全部是**新增可选字段**，既有字段名与语义不变）──
	//
	// PromptTokens / CompletionTokens 是上游 usage 真值累计（无 usage 的轮次不计入，
	// 那部分记在 tokenUsage.EstimatedTokens 里）；ContextTokens 是最近一次四层装配的
	// 估算上下文 token（含 30% 余量口径之外的原始估算），ContextCompressed 表示那次装配
	// 是否做过压缩。前端/脚本据此回答"这次 run 的上下文有多大、有没有被压过"。
	PromptTokens        int  `json:"prompt_tokens,omitempty"`
	CompletionTokens    int  `json:"completion_tokens,omitempty"`
	ContextTokens       int  `json:"context_tokens,omitempty"`
	ContextBudgetTokens int  `json:"context_budget_tokens,omitempty"`
	ContextCompressed   bool `json:"context_compressed,omitempty"`

	// tokenUsage 累计 token 用量（真值优先、估算兜底）+ 估算校准系数。
	tokenUsage RunTokenUsage
	// sessionsSnapshot 在线会话快照（任务层用）。缓存在 run 上的理由见 cachedSessions 注释。
	sessionsSnapshot string
	sessionsAt       time.Time

	// events 缓冲事件通道（有缓冲，避免阻塞循环）。
	events chan AgentEvent
	// once 保证 events 只关闭一次。
	once sync.Once
	// cancel 取消当前循环。
	cancel context.CancelFunc
	// Pending 待审批（awaiting_consent 时的挂起状态）。
	Pending *pendingState `json:"-"`
	// PendingTask 长任务挂起状态（awaiting_task 时非 nil）。
	PendingTask *pendingTaskState `json:"-"`
	// stepSeq 本 run 已分配的步骤序号（挂起/恢复的 correlation_id 靠它保证唯一）。
	// 从 0 开始自增；重启恢复时由持久化层按 agent_steps 的 MAX(step_no) 校准。
	stepSeq int

	// execSeen 本 run 已执行过的命令缓存（规范键 → 结果），用于命令级去重：
	// 相同命令只下发一次，重复调用直接回放上次结果，杜绝信息收集反复重跑同一命令。
	execSeen map[string]cachedExec
	// execStall 连续命中去重的次数：≥2 说明模型在无新信息地空转，强制收敛出报告。
	execStall int

	mu sync.Mutex
}

// cachedExec 一次已执行命令的缓存结果。
type cachedExec struct {
	OK    bool   // 上次是否成功（exit 0 / status completed）
	Brief string // 上次结果摘要（截断），供去重回放
	Full  string // 上次完整输出（截断），供去重回放
	// View 上次的"模型可见文本"（v1.4.0 S2）：去重复用时连同句柄/截断标注一起回放，
	// 否则被外置的大结果在回放时会退化成一段被截断的正文（模型会把它当全部）。
	View mcp.ModelView
}

// seenExecKey 返回某次 exec 类调用的规范键；非 exec 类返回 ""。
// 规范键忽略空白差异与尾部 2>&1（同一条命令的等价写法视为重复）。
func seenExecKey(tool string, args map[string]string) string {
	switch tool {
	case "exec":
		cmd := args["command"]
		if cmd == "" {
			cmd = args["kind"]
		}
		if cmd == "" {
			return ""
		}
		return "exec|" + normExecKey(cmd)
	case "run_command":
		cmd := args["command"]
		if cmd == "" {
			return ""
		}
		return "exec|" + normExecKey(cmd)
	case "user_info", "system_info", "service_list", "check_av",
		"net_info", "net_connections", "env_vars", "scheduled_tasks":
		// 语义工具映射为固定内置命令，按工具名去重即可（避免空 command 相互碰撞）
		return "tool:" + tool
	default:
		return ""
	}
}

// normExecKey 规范化命令文本用于去重比较（折叠空白/大小写，去掉尾部重定向）。
func normExecKey(cmd string) string {
	s := strings.TrimSpace(cmd)
	s = strings.ReplaceAll(s, "2>&1", "")
	s = strings.ReplaceAll(s, "2>nul", "")
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ToLower(s)
	return s
}

// isReconRequest 判断当前 run 是否属于「信息收集/侦察」类请求。
// 只有这类请求启用命令级去重（同一条命令只下发一次）；
// 提权/横向/利用等需要事后复验状态的任务不去重，避免误挡合法重跑。
func isReconRequest(run *AgentRun) bool {
	run.mu.Lock()
	obj := run.Objective
	msgs := append([]Message(nil), run.Messages...)
	run.mu.Unlock()
	text := obj
	// 取最近一条用户消息兜底（objective 可能尚未生成）
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" && strings.TrimSpace(msgs[i].Content) != "" {
			text = msgs[i].Content
			break
		}
	}
	keys := []string{
		"信息收集", "信息搜集", "侦察", "枚举", "盘点", "态势", "信息采集",
		"收集", "recon", "collect", "enumerate", "gather", "informati",
		"看看", "查看", "了解", "情况", "信息",
	}
	t := strings.ToLower(text)
	for _, k := range keys {
		if strings.Contains(t, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// reconExecKey 返回信息收集请求下某次 exec 类调用的去重键；非收集任务返回 ""（不去重）。
func reconExecKey(run *AgentRun, tool string, args map[string]string) string {
	if !isReconRequest(run) {
		return ""
	}
	return seenExecKey(tool, args)
}

// getCachedExec 查询本 run 是否执行过该规范键。
func (r *AgentRun) getCachedExec(key string) (cachedExec, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.execSeen == nil {
		r.execSeen = map[string]cachedExec{}
	}
	c, ok := r.execSeen[key]
	return c, ok
}

// rememberExec 记录一次已执行命令；若该键此前已存在则返回 true（本次为重复调用）。
func (r *AgentRun) rememberExec(key string, c cachedExec) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.execSeen == nil {
		r.execSeen = map[string]cachedExec{}
	}
	_, dup := r.execSeen[key]
	r.execSeen[key] = c
	return dup
}

// SetObjective 记录当前目标（线程安全）。
func (r *AgentRun) SetObjective(o string) {
	r.mu.Lock()
	if o != "" {
		r.Objective = o
	}
	r.mu.Unlock()
}

// appendTimeline 记录一条时间线事件（线程安全，按时间序追加，上限 400 条防膨胀）。
func (r *AgentRun) appendTimeline(kind, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Timeline = append(r.Timeline, RunEvent{Ts: time.Now().UnixMilli(), Kind: kind, Text: truncate(text, 300)})
	if len(r.Timeline) > 400 {
		r.Timeline = r.Timeline[len(r.Timeline)-400:]
	}
}

// SyncPlan 用 LLM 输出的最新计划同步 run.Plan（线程安全）。
func (r *AgentRun) SyncPlan(steps []GoalStep) {
	if len(steps) == 0 {
		return
	}
	r.mu.Lock()
	r.Plan = steps
	r.mu.Unlock()
}

// pendingState 挂起时的上下文（用于恢复）。
type pendingState struct {
	messages []Message
	tool     ToolCall
	args     map[string]string
	traces   []ToolTrace
	// traceID 挂起前的 trace id：审批通过后恢复循环仍用同一条，审计可串起来。
	traceID string
}

// AgentManager 管理所有 run（并发上限 + 取消）。
type AgentManager struct {
	mu   sync.Mutex
	runs map[string]*AgentRun
	// sem 并发信号量（容量 = MaxConcurrent）。Acquire 阻塞直到有空位。
	sem chan struct{}
	// MaxConcurrent 并发上限；0=不限制。
	MaxConcurrent int
}

// NewAgentManager 创建管理器。
func NewAgentManager(maxConcurrent int) *AgentManager {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	return &AgentManager{
		runs:          map[string]*AgentRun{},
		MaxConcurrent: maxConcurrent,
		sem:           make(chan struct{}, maxConcurrent),
	}
}

// Acquire 获取一个并发槽位（阻塞直到有空位）。
func (m *AgentManager) Acquire(ctx context.Context) bool {
	select {
	case m.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// Release 释放一个并发槽位。
func (m *AgentManager) Release() {
	select {
	case <-m.sem:
	default:
	}
}

// agentEventBuffer 事件通道容量（**唯一出处**，NewRun 与 ResetForResume 都用它）。
//
// 为什么是 8192：SSE 流式 thinking/message 事件密集，通道过小会让 final/done 这类
// **终态事件**被丢弃，前端表现为 network error（收不到最终答复）。
//
// ⚠️ 曾经的坑：`ResetForResume`（审批/长任务挂起后恢复、续接指令）单独写死 256，
// 于是"恢复过的 run"事件缓冲只有新 run 的 1/32 —— 恢复后一旦 thinking 密集，最先被丢的
// 恰恰是 final/done。同一个坑的另一种形态，只是更难复现，所以收敛成一个常量。
const agentEventBuffer = 8192

// NewRun 创建一个 run（不启动；由调用方 Start）。
func (m *AgentManager) NewRun(history []Message, maxTurns int) *AgentRun {
	run := &AgentRun{
		ID:        newAgentID(),
		Status:    AgentQueued,
		Messages:  append([]Message(nil), history...),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		MaxTurns:  maxTurns,
		TraceID:   newTraceID(),
		events:    make(chan AgentEvent, agentEventBuffer),
		Traces:    []ToolTrace{},
	}
	m.mu.Lock()
	m.runs[run.ID] = run
	m.mu.Unlock()
	return run
}

// Get 取 run。
func (m *AgentManager) Get(id string) *AgentRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id]
}

// Remove 移除 run（done/error 后可清理内存）。
func (m *AgentManager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runs, id)
}

// Events 提供事件通道（供 SSE handler 读取）。
func (r *AgentRun) Events() <-chan AgentEvent {
	return r.events
}

// emit 推事件到通道（非阻塞，通道满则丢弃——SSE 慢时保循环前进不卡）。
// v1.4.0 S2：所有事件自动带上本 run 的 trace_id。
func (r *AgentRun) emit(kind AgentEventKind, data interface{}, errMsg string) {
	var raw json.RawMessage
	if data != nil {
		b, _ := json.Marshal(data)
		raw = b
	}
	ev := AgentEvent{Kind: kind, Data: raw, Error: errMsg, TraceID: r.traceID()}
	select {
	case r.events <- ev:
	default:
		logging.Warn("ai", "agent %s trace=%s: event channel full, dropping %s event", r.ID, ev.TraceID, kind)
	}
}

// emitRaw 直接推一个已构造事件（缺 trace_id 时补上）。
func (r *AgentRun) emitRaw(ev AgentEvent) {
	if ev.TraceID == "" {
		ev.TraceID = r.traceID()
	}
	select {
	case r.events <- ev:
	default:
		logging.Warn("ai", "agent %s trace=%s: event channel full, dropping %s event", r.ID, ev.TraceID, ev.Kind)
	}
}

// emitDone 发送终态 done 事件：载荷带 trace_id 与 stop_reason。
// 老前端收到 done 的 data 是空对象时也是"忽略"，新增字段向后兼容。
func (r *AgentRun) emitDone() {
	r.emit(AgentEventDone, DoneInfo{TraceID: r.traceID(), StopReason: r.stopReason()}, "")
}

// traceID 读本 run 的 trace id（线程安全）。
func (r *AgentRun) traceID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.TraceID
}

// setTraceID 设置/刷新本 run 的 trace id（空值忽略）。
func (r *AgentRun) setTraceID(id string) {
	if id == "" {
		return
	}
	r.mu.Lock()
	r.TraceID = id
	r.mu.Unlock()
}

// stopReason 读循环停止原因（线程安全）。
func (r *AgentRun) stopReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.StopReason
}

// setStopReason 记录循环停止原因（max_turns/max_tool_calls/max_wallclock/loop_detected）。
func (r *AgentRun) setStopReason(reason string) {
	r.mu.Lock()
	r.StopReason = reason
	r.UpdatedAt = time.Now()
	r.mu.Unlock()
}

// SetStopReason 记录停止原因（导出给恢复编排使用；与 setStopReason 同一份状态）。
func (r *AgentRun) SetStopReason(reason string) { r.setStopReason(reason) }

// ─── 上下文/token 可观测性（v1.4.0 S2）─────────────────────────────────────

// ObserveLLMUsage 记录一次 LLM 往返的 token 用量（线程安全）。
//
// 真值优先：上游给了 usage 就累加真值并用它回填估算校准；没给（prompt/completion 均为 0）
// 就按估算回填，保证 token 预算不会因为"上游不回 usage"而失效。
func (r *AgentRun) ObserveLLMUsage(prompt, completion, estimatedPrompt int) {
	r.mu.Lock()
	if prompt > 0 || completion > 0 {
		r.tokenUsage = r.tokenUsage.ObserveUsage(prompt, completion, estimatedPrompt)
	} else {
		r.tokenUsage = r.tokenUsage.ObserveEstimate(estimatedPrompt)
	}
	r.PromptTokens = r.tokenUsage.PromptTokens
	r.CompletionTokens = r.tokenUsage.CompletionTokens
	r.UpdatedAt = time.Now()
	r.mu.Unlock()
}

// TokenUsage 读取累计 token 用量快照（线程安全；纯值对象，供预算判定使用）。
func (r *AgentRun) TokenUsage() RunTokenUsage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tokenUsage
}

// SetTokenUsage 直接写入累计用量（重启恢复路径用：从持久化的 agent_runs 恢复计数）。
func (r *AgentRun) SetTokenUsage(u RunTokenUsage) {
	r.mu.Lock()
	r.tokenUsage = u
	r.PromptTokens = u.PromptTokens
	r.CompletionTokens = u.CompletionTokens
	r.mu.Unlock()
}

// RecordContextStats 把一次四层装配的统计挂到 run 上（线程安全）。
// 只记录"当前上下文有多大 / 是否压缩过 / 预算多少"，不改动任何既有字段。
func (r *AgentRun) RecordContextStats(s ContextStats) {
	r.mu.Lock()
	r.ContextTokens = s.TotalTokens
	r.ContextBudgetTokens = s.BudgetTokens
	r.ContextCompressed = s.Compressed
	r.UpdatedAt = time.Now()
	r.mu.Unlock()
}

// ContextSnapshot 读取最近一次装配的上下文可观测信息（线程安全）。
func (r *AgentRun) ContextSnapshot() (tokens, budget int, compressed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ContextTokens, r.ContextBudgetTokens, r.ContextCompressed
}

// cachedSessions 读取在线会话快照；超过 ttl 视为过期（返回 ok=false）。
//
// 为什么把快照缓存在 run 上而不是每轮重新取：取快照的实现（Copilot.currentSessions）
// 内部是一次真实的 session_list 工具调用——每轮都调既慢，又会在审计之外多出大量工具调用；
// 而它只影响**任务层**（不参与前缀缓存稳定性），因此按 run + TTL 缓存即可。
func (r *AgentRun) cachedSessions(ttl time.Duration) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessionsAt.IsZero() {
		return "", false
	}
	if ttl > 0 && time.Since(r.sessionsAt) > ttl {
		return "", false
	}
	return r.sessionsSnapshot, true
}

// setSessionsSnapshot 记录在线会话快照（失败取空也要记时间，避免每轮都重试一次工具调用）。
func (r *AgentRun) setSessionsSnapshot(s string) {
	r.mu.Lock()
	r.sessionsSnapshot = s
	r.sessionsAt = time.Now()
	r.mu.Unlock()
}

// SetReply 写入最终答复（导出给恢复编排使用，线程安全）。
func (r *AgentRun) SetReply(reply string) { r.setReply(reply) }

func (r *AgentRun) setStatus(s AgentStatus) {
	r.mu.Lock()
	r.Status = s
	r.UpdatedAt = time.Now()
	r.mu.Unlock()
}

func (r *AgentRun) setReply(reply string) {
	r.mu.Lock()
	r.FinalReply = reply
	r.UpdatedAt = time.Now()
	r.mu.Unlock()
}

// closeEvents 关闭事件通道（run 到达终态后调用），让 SSE handler 的阻塞读能退出。
// 幂等：用 sync.Once 保证只关一次。
func (r *AgentRun) closeEvents() {
	r.once.Do(func() { close(r.events) })
}

// Cancel 取消当前 run 的循环。
func (r *AgentRun) Cancel() {
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
}

// NextStep 取下一个步骤序号（挂起/恢复的 correlation_id 用它保证唯一；线程安全）。
//
// 为什么必须在 run 上维护而不是每次从库里查：一次 run 可能连续挂起多次，
// 而 agent_steps 只有在挂起点才写一行；只用 MAX(step_no)+1 会让同一 run 的第二次
// 挂起拿到重复的 step_no → correlation_id 冲突 → 幂等 upsert 把两次调用合并成一条。
func (r *AgentRun) NextStep() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stepSeq++
	return r.stepSeq
}

// SetStepSeq 校准步骤序号（重启恢复时按持久化的 MAX(step_no) 续号）。
func (r *AgentRun) SetStepSeq(n int) {
	r.mu.Lock()
	if n > r.stepSeq {
		r.stepSeq = n
	}
	r.mu.Unlock()
}

// WaitState 读取当前状态与等待描述（线程安全）。
func (r *AgentRun) WaitState() (AgentStatus, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Status, r.WaitingOn
}

// SetMessages 整体替换消息序列（重启恢复重建最小上下文时使用；线程安全）。
func (r *AgentRun) SetMessages(msgs []Message) {
	r.mu.Lock()
	r.Messages = msgs
	r.mu.Unlock()
}

// PendingTaskInfo 返回当前长任务等待的目标：任务 id 与等待超时（秒）。
// 无等待时返回 (0, 0)。供可观测性（GET /agent/runs/{id} 展示"在等哪个任务"）。
func (r *AgentRun) PendingTaskInfo() (uint64, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.PendingTask == nil {
		return 0, 0
	}
	return r.PendingTask.handle.TaskID, r.PendingTask.handle.TimeoutSec
}

// SnapshotMessages 复制一份消息序列（供恢复路径构造上下文快照）。
func (r *AgentRun) SnapshotMessages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message(nil), r.Messages...)
}

// AppendMessages 往 run 的长期记忆追加消息（跨指令续接，保持完整上下文）。
func (r *AgentRun) AppendMessages(msgs []Message) {
	r.mu.Lock()
	r.Messages = append(r.Messages, msgs...)
	r.mu.Unlock()
}

// ResetForResume 在复用同一个 run 继续下一轮指令前，重置事件通道与循环状态
// （保留 Messages/Traces，即保留完整上下文memory）。
// v1.4.0 S2：同时换一条新的 trace_id——trace 归因的单位是「一次指令 → 一次执行」，
// 复用 run 续接新指令若沿用旧 id，两次独立执行会在审计日志里混成一条。
//
// 四处预算（轮次/工具调用数/墙钟/token）在循环里都是"本次执行"的口径（局部计数器），
// 所以这里同步清零 token 累计与上下文统计：否则一条长指令花光 token 预算后，用户续接的
// 下一条指令会立刻被 max_tokens 掐断。在线会话快照也一并作废（新指令要看最新的清单）。
func (r *AgentRun) ResetForResume() {
	r.mu.Lock()
	r.Status = AgentQueued
	r.FinalReply = ""
	r.Pending = nil
	r.PendingTask = nil
	r.WaitingOn = ""
	r.cancel = nil
	r.StopReason = ""
	r.TraceID = newTraceID()
	r.events = make(chan AgentEvent, agentEventBuffer)
	r.once = sync.Once{}
	r.tokenUsage = RunTokenUsage{}
	r.PromptTokens = 0
	r.CompletionTokens = 0
	r.ContextTokens = 0
	r.ContextCompressed = false
	r.sessionsSnapshot = ""
	r.sessionsAt = time.Time{}
	r.mu.Unlock()
}

// RestoreRun 用持久化的 id / trace 重建一个内存 run（重启恢复用；不覆盖已存在的同类 run）。
//
// 为什么需要它：run id 与 trace id 是**对外可见的引用**（GET /agent/runs/{id}、审计日志、
// 前端续接都按它索引）。重启恢复若新生成一个 id，恢复出来的 run 在外部看来就是"另一个任务"，
// 原来的 id 永远停在等待态。
func (m *AgentManager) RestoreRun(id, traceID string, history []Message, maxTurns int) *AgentRun {
	if id == "" {
		return m.NewRun(history, maxTurns)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.runs[id]; ok && existing != nil {
		return existing
	}
	run := &AgentRun{
		ID:        id,
		Status:    AgentQueued,
		Messages:  append([]Message(nil), history...),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		MaxTurns:  maxTurns,
		TraceID:   ensureTraceID(traceID),
		events:    make(chan AgentEvent, 8192),
		Traces:    []ToolTrace{},
	}
	m.runs[run.ID] = run
	return run
}

// ResetTaskView 清空任务视图状态（目标/计划/时间线/轨迹）——纯聊短回复等
// 非执行轮次使用，避免前端展示上一轮任务的残留目标与计划。
func (r *AgentRun) ResetTaskView() {
	r.mu.Lock()
	r.Objective = ""
	r.Plan = nil
	r.Timeline = nil
	r.Traces = nil
	r.mu.Unlock()
}

var agentIDSeq uint64

func newAgentID() string {
	agentIDSeq++
	return fmt.Sprintf("ag-%d-%d", time.Now().UnixNano(), agentIDSeq)
}

var (
	errAgentCancelled = errors.New("agent cancelled")
	errAgentPaused    = errors.New("agent paused for consent")
	// errAgentAwaitTask run 已挂起等内部任务结果：**不是失败**，循环退出是为了释放并发槽位，
	// 任务完成通知会把它唤醒（见 api 的任务桥与 ai.CompleteTaskResume）。
	errAgentAwaitTask = errors.New("agent awaiting internal task")
)

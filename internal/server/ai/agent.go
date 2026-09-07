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
)

// ─── 异步自主 Agent───────────────────────────────────────────────────
// 一次「交代任务」对应一个 AgentRun：后台 goroutine 自主运行 ReAct 循环，
// 事件经 channel 以 SSE 形式推给前端（可见推理与每步工具），不再同步阻塞
// 一次 HTTP 请求。支持取消、并发上限、跨消息保持执行计划。

// AgentEventKind 事件类型（SSE event）。
type AgentEventKind string

const (
	AgentEventThinking   AgentEventKind = "thinking"      // 模型推理增量（reasoning_content）
	AgentEventMessage    AgentEventKind = "message"       // 模型正文增量（content）
	AgentEventToolStart  AgentEventKind = "tool_start"    // 开始执行工具
	AgentEventToolResult AgentEventKind = "tool_result"   // 工具执行结果
	AgentEventFinal      AgentEventKind = "final"         // 最终答复（完整）
	AgentEventConsent    AgentEventKind = "consent"       // 需要审批（normal 模式）
	AgentEventDone       AgentEventKind = "done"          // 全部完成
	AgentEventError      AgentEventKind = "error"         // 出错（会话级）
)

// AgentEvent 一次 Agent 事件。
type AgentEvent struct {
	Kind AgentEventKind `json:"kind"`
	// 载荷：thinking/message 为字符串；tool_start 为 ToolStart；
	// tool_result 为 ToolResult；final 为 string；consent 为 ConsentRequest；done/error 见 Error。
	Data json.RawMessage `json:"data,omitempty"`
	// Error 仅 kind=error 时携带。
	Error string `json:"error,omitempty"`
}

// ToolStart 工具开始执行事件。
type ToolStart struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args,omitempty"`
}

// ToolResult 工具结果事件。
type ToolResult struct {
	Name   string `json:"name"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// AgentStatus run 生命周期状态。
type AgentStatus string

const (
	AgentQueued  AgentStatus = "queued"
	AgentRunning AgentStatus = "running"
	AgentDone    AgentStatus = "done"
	AgentError   AgentStatus = "error"
	AgentWaitConsent AgentStatus = "awaiting_consent"
)

// RunEvent run 的结构化时间线事件（供前端展示 goal→step→tool→result 及失败原因）。
type RunEvent struct {
	Ts   int64  `json:"ts"`   // unix ms
	Kind string `json:"kind"` // thinking/tool_start/tool_result/final/error
	Text string `json:"text,omitempty"` // 摘要文本（thinking 片段/工具名/结果摘要/错误）
}

// GoalStep 目标分解后的一个执行步骤（agent 自主维护进度）。
type GoalStep struct {
	Index    int    `json:"index"`
	Desc     string `json:"desc"`     // 步骤描述
	Status   string `json:"status"`   // pending / running / done / skipped / failed
	Result   string `json:"result,omitempty"`
}

// AgentRun 一次自主任务运行实例。
type AgentRun struct {
	ID     string `json:"id"`
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

	// events 缓冲事件通道（有缓冲，避免阻塞循环）。
	events chan AgentEvent
	// once 保证 events 只关闭一次。
	once sync.Once
	// cancel 取消当前循环。
	cancel context.CancelFunc
	// Pending 待审批（awaiting_consent 时的挂起状态）。
	Pending *pendingState `json:"-"`

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

// NewRun 创建一个 run（不启动；由调用方 Start）。
func (m *AgentManager) NewRun(history []Message, maxTurns int) *AgentRun {
	run := &AgentRun{
		ID:        newAgentID(),
		Status:    AgentQueued,
		Messages:  append([]Message(nil), history...),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		MaxTurns:  maxTurns,
		// 事件通道缓冲放大到 8192：SSE 流式 thinking/message 事件密集，
		// 通道过小会导致 final/done 等终态事件被丢弃，前端收不到最终答复（表现 network error）。
		events:    make(chan AgentEvent, 8192),
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
func (r *AgentRun) emit(kind AgentEventKind, data interface{}, errMsg string) {
	var raw json.RawMessage
	if data != nil {
		b, _ := json.Marshal(data)
		raw = b
	}
	ev := AgentEvent{Kind: kind, Data: raw, Error: errMsg}
	select {
	case r.events <- ev:
	default:
		logging.Warn("ai", "agent %s: event channel full, dropping %s event", r.ID, kind)
	}
}

// emitRaw 直接推一个已构造事件。
func (r *AgentRun) emitRaw(ev AgentEvent) {
	select {
	case r.events <- ev:
	default:
		logging.Warn("ai", "agent %s: event channel full, dropping %s event", r.ID, ev.Kind)
	}
}

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

// AppendMessages 往 run 的长期记忆追加消息（跨指令续接，保持完整上下文）。
func (r *AgentRun) AppendMessages(msgs []Message) {
	r.mu.Lock()
	r.Messages = append(r.Messages, msgs...)
	r.mu.Unlock()
}

// ResetForResume 在复用同一个 run 继续下一轮指令前，重置事件通道与循环状态
// （保留 Messages/Traces，即保留完整上下文memory）。
func (r *AgentRun) ResetForResume() {
	r.mu.Lock()
	r.Status = AgentQueued
	r.FinalReply = ""
	r.Pending = nil
	r.cancel = nil
	r.events = make(chan AgentEvent, 256)
	r.once = sync.Once{}
	r.mu.Unlock()
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
)

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// AgentRun 一次自主任务运行实例。
type AgentRun struct {
	ID     string `json:"id"`
	Status AgentStatus `json:"status"`
	// Plan 跨消息保持的执行计划/上下文（由 run 自己管理，可被后续 turn 延续）。
	// Messages 保存本 run 的完整消息序列（system+history+tool）。后续「继续」可追加。
	Messages []Message `json:"-"`
	// Traces 已完成的工具轨迹（最终汇总展示用）。
	Traces []ToolTrace `json:"traces,omitempty"`
	// FinalReply 最终答复（done 后填充）。
	FinalReply string `json:"reply,omitempty"`
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

	mu sync.Mutex
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

var agentIDSeq uint64

func newAgentID() string {
	agentIDSeq++
	return fmt.Sprintf("ag-%d-%d", time.Now().UnixNano(), agentIDSeq)
}

var (
	errAgentCancelled = errors.New("agent cancelled")
	errAgentPaused    = errors.New("agent paused for consent")
)

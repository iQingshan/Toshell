package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"toshell/internal/server/config"
	"toshell/internal/server/logging"
)

// ─── Agent 长任务：提交 → 挂起 → 事件驱动恢复（v1.4.0 S2）───────────────
//
// 要解决的问题：Agent 循环里的工具调用原本是**同步阻塞**的（一次 InvokeTool 一直等到
// 任务出结果）。而 Agent 的并发槽位只有 AgentConcurrency（默认 2）个——一把 credentials
// （180s）就能把整个 Agent 卡住三分钟，期间其它指令只能排队。
//
// 改造方式不是"把 REST 改成返回句柄"（对外契约必须是"一次调用返回最终结果"），而是
// **只在 Agent 内部**把长工具拆成两步：
//  1. 提交：创建并下发内部任务，拿到句柄（task_id / correlation_id），立即返回；
//  2. 挂起：把"在等哪个任务"落库，run 进入 await_task 态，RunAgent 返回 → 并发槽位释放；
//  3. 恢复：任务完成通知到达后，取结果按上一轮的流程（同一套结果外置/截断语义）接回
//     上下文与轨迹，再重新进入循环（与审批恢复 resumeAgentAsync 完全同构）。
//
// 为什么复用"审批挂起"的模式而不是新造一套：审批挂起已经证明了这条路的正确性
// （消息序列在 run.Messages 里、恢复即重入循环、trace 不变），任务挂起只是把
// "等用户点确认"换成"等任务完成事件"。两套状态、一条恢复路径，语义更好推理。

// DefaultLongTaskThresholdSec 长任务挂起的默认阈值（秒）：预估超时 ≥ 该值才走挂起路径。
// 取值来自 config.DefaultLongTaskThresholdSec（viper 默认值与运行时兜底必须是同一个数）。
//
// 为什么是 150 而不是"全部挂起"或"只看工具名"：
//   - 短工具挂起只会更慢——它本来几百毫秒就回来了，却要付出"落库 + 退出循环 +
//     等通知 + 重新进入循环（重新发一次 LLM 请求）"的代价；
//   - 150s 落在两档之间：credentials/fileless_exec/plugin_load（180s）与
//     file_download（300s）属于**分钟级**操作，是真正会长时间占住槽位的那一类；
//     而 file_list/process_list/screenshot（60~90s）与 exec 默认 120s 是"秒级命令 + 安全余量"，
//     超时给得宽不代表真会跑那么久，同步等它是划算的。
//
// 阈值可配置（ai.long_task_threshold_sec），但不允许用它关掉：<=0 一律回落默认值
// （与 max_turns/max_tool_calls 同一个口径——配置失误不该让长任务重新占满槽位）。
const DefaultLongTaskThresholdSec = config.DefaultLongTaskThresholdSec

// LongTaskPolicy 长任务挂起策略（纯值对象，便于单测）。
type LongTaskPolicy struct {
	// ThresholdSec 预估超时阈值（秒）；<=0 用 DefaultLongTaskThresholdSec。
	ThresholdSec int
	// NeverSuspend 永不挂起的工具名（运维/测试用的紧急开关：例如某个工具挂起后恢复
	// 依赖的上游不可用时，可以临时把它按同步路径跑）。
	NeverSuspend []string
}

// effectiveThreshold 生效阈值（非法值回落默认）。
func (p LongTaskPolicy) effectiveThreshold() int {
	if p.ThresholdSec > 0 {
		return p.ThresholdSec
	}
	return DefaultLongTaskThresholdSec
}

// ShouldSuspendLongTask 判定一次工具调用是否走"提交 → 挂起 → 恢复"路径（纯函数）。
//
// isTaskTool 与 timeoutSec 由执行层（api）给出——它们必须来自**创建任务的同一份映射**，
// 否则会出现"判定要挂起、却提交不出任务"的错位。这里的判定只做策略层的事：
//  1. NeverSuspend 名单优先（运维开关）；
//  2. 不是任务类工具 → 不挂起（本地工具/只读工具没有"内部任务"可等）；
//  3. 预估超时 <=0 → 不挂起（信息不足时保守走同步，避免把本该同步的工具挂起来）；
//  4. 预估超时 ≥ 阈值 → 挂起。
//
// 返回的 reason 用于日志与审计（"为什么这次挂起了"必须能直接读出来）。
func ShouldSuspendLongTask(p LongTaskPolicy, tool string, isTaskTool bool, timeoutSec int) (bool, string) {
	for _, n := range p.NeverSuspend {
		if n == tool {
			return false, "never_suspend"
		}
	}
	if !isTaskTool {
		return false, "not_task_tool"
	}
	if timeoutSec <= 0 {
		return false, "unknown_timeout"
	}
	threshold := p.effectiveThreshold()
	if timeoutSec >= threshold {
		return true, fmt.Sprintf("timeout_sec=%d>=%d", timeoutSec, threshold)
	}
	return false, fmt.Sprintf("timeout_sec=%d<%d", timeoutSec, threshold)
}

// longTaskPolicyFromConfig 由配置得到生效策略。
func longTaskPolicyFromConfig(cfg config.AIConfig) LongTaskPolicy {
	return LongTaskPolicy{ThresholdSec: cfg.LongTaskThresholdSec}
}

// LongTaskThresholdFromConfig 返回配置里**生效**的长任务阈值（非法值按默认处理）。
// 供设置页/自动化读取"循环里真正会用到的数"，避免各自猜默认值。
func LongTaskThresholdFromConfig(cfg config.AIConfig) int {
	return longTaskPolicyFromConfig(cfg).effectiveThreshold()
}

// ─── 执行层接口（由 api.Server 实现）────────────────────────────────────

// LongTaskRequest 一次长任务提交请求。
type LongTaskRequest struct {
	RunID   string
	Tool    string
	Args    map[string]string
	CallID  string // LLM 给出的 tool_call id（恢复时构造配对的 tool 消息用）
	TraceID string
	Turn    int
}

// LongTaskHandle 一次已提交的长任务句柄（挂起与恢复都靠它）。
type LongTaskHandle struct {
	TaskID        uint64
	CorrelationID string
	StepNo        int
	TimeoutSec    int
	// WaitingOn 落库用的 waiting_on JSON：由持久化层构造、执行层只透传。
	// 这样"run 上展示的等待描述"与"库里落盘的等待描述"必然是同一份。
	WaitingOn string
	// DeadlineAt 本次等待的截止时刻（由提交方按 TimeoutSec 算好，恢复桥据此兜底超时）。
	DeadlineAt time.Time
}

// LongTaskExecutor Agent 循环与"内部任务"之间的通道（v1.4.0 S2 新增）。
//
// 为什么把这三件事抽成接口而不是让 ai 直接依赖 api：ai 是执行层，不该知道 sqlite、
// tasks 表、会话推送与 MCP 工具的参数映射。接口只表达"能不能挂起 / 提交拿句柄 / 取最终结果"。
type LongTaskExecutor interface {
	// LongTaskPlan 返回该工具是否为任务类工具、及其预估超时（秒）。**不得有副作用**。
	LongTaskPlan(tool string, args map[string]string) (timeoutSec int, isTaskTool bool)
	// SubmitLongTask 创建并下发内部任务，返回句柄；按 correlation_id 幂等
	// （同一 correlation_id 重复提交必须复用同一个任务，绝不重复下发）。
	// ok=false 表示该工具不产生内部任务（调用方应退回同步 InvokeTool）。
	SubmitLongTask(req LongTaskRequest) (LongTaskHandle, bool, error)
	// LongTaskResult 读取任务的**最终结果信封**（与同步路径同一份字段）。
	// done=true 表示任务已终结；done=false 表示仍在跑（result 为 nil）。
	// err != nil 表示任务已丢失（查不到），调用方据此给 run 一个明确结论。
	LongTaskResult(taskID uint64) (result map[string]interface{}, done bool, err error)
}

// SetLongTaskExecutor 注入长任务通道（api.Server 在构造与热更新后调用）。
// 传 nil 表示不启用长任务挂起：所有工具都走同步路径（等价于改造前的行为）。
func (c *Copilot) SetLongTaskExecutor(ex LongTaskExecutor) { c.longTasks = ex }

// LongTaskEnabled 是否已注入长任务通道。
//
// 存在意义：热更新会**重建** Copilot（s.copilot == nil 那条分支），重建后忘了重新注入
// 不会有任何报错 —— 表现只是"长工具又变成同步等待"。有了这个访问器，接线错误可以在
// 单测里被钉住（api 包的 TestReconfigureCopilotReinjectsLongTask），也能用于诊断输出。
func (c *Copilot) LongTaskEnabled() bool { return c != nil && c.longTasks != nil }

// pendingTaskState 长任务挂起时的上下文（与审批挂起的 pendingState 同构）。
//
// 为什么要快照 messages/traces 而不是恢复时直接读 run 上的值：恢复发生在另一个
// goroutine（任务完成通知的处理器）里，快照能保证"挂起那一刻的对话状态"被原样接续，
// 即便期间有别的路径改动了 run。
type pendingTaskState struct {
	messages []Message
	tool     ToolCall
	args     map[string]string
	traces   []ToolTrace
	traceID  string
	handle   LongTaskHandle
}

// suspendForTask 提交长任务并把 run 置为等待态（不设终态、不关事件通道）。
//
// 返回值：提交成功时 ok=true，调用方应立即结束本轮 RunAgent（释放并发槽位）。
// 提交失败（会话离线/参数错/任务类工具但创建失败）时 ok=false，调用方**退回同步路径**：
// 让同步 InvokeTool 产生同样的错误，避免出现"挂起路径与同步路径错误语义不一致"。
func (c *Copilot) suspendForTask(ctx context.Context, run *AgentRun, tc ToolCall, args map[string]string, traceID string, turn int) (LongTaskHandle, bool) {
	if c.longTasks == nil {
		return LongTaskHandle{}, false
	}
	h, ok, err := c.longTasks.SubmitLongTask(LongTaskRequest{
		RunID: run.ID, Tool: tc.Function.Name, Args: args,
		CallID: tc.ID, TraceID: traceID, Turn: turn,
	})
	if err != nil {
		// 提交失败不致命：回退同步路径，由它给出与改造前一致的错误结果。
		logging.Warn("ai", "run=%s trace=%s 长任务提交失败，回退同步等待 tool=%s: %v",
			run.ID, traceID, tc.Function.Name, err)
		return LongTaskHandle{}, false
	}
	if !ok {
		return LongTaskHandle{}, false
	}

	run.mu.Lock()
	run.PendingTask = &pendingTaskState{
		messages: append([]Message(nil), run.Messages...),
		tool:     tc,
		args:     args,
		traces:   append([]ToolTrace(nil), run.Traces...),
		traceID:  traceID,
		handle:   h,
	}
	run.WaitingOn = h.WaitingOn
	run.Status = AgentWaitTask
	run.StopReason = stopReasonAwaitTask
	run.UpdatedAt = time.Now()
	run.mu.Unlock()

	// 事件顺序：先 tool_start（前端已经看到"开始执行"），再 task_wait（说明它变成了等待）。
	run.emit(AgentEventToolStart, ToolStart{Name: tc.Function.Name, Args: args, TraceID: traceID}, "")
	run.emit(AgentEventTaskWait, TaskWaitInfo{
		RunID: run.ID, TaskID: h.TaskID, Tool: tc.Function.Name,
		CorrelationID: h.CorrelationID, TimeoutSec: h.TimeoutSec,
		Status: string(AgentWaitTask), TraceID: traceID,
	}, "")
	run.appendTimeline("task_wait", fmt.Sprintf("⏳ %s 转为长任务等待（task #%d，超时 %ds，槽位已释放）",
		tc.Function.Name, h.TaskID, h.TimeoutSec))
	logging.Info("agent-audit", "run=%s trace=%s long_task_suspended tool=%s call_id=%s task_id=%d correlation=%s timeout_sec=%d",
		run.ID, traceID, tc.Function.Name, tc.ID, h.TaskID, h.CorrelationID, h.TimeoutSec)
	return h, true
}

// TaskResumeContext 恢复一次长任务所需的全部信息（进程内挂起态与重启重建态共用）。
type TaskResumeContext struct {
	Tool    string
	Args    map[string]string
	CallID  string
	TraceID string
	// Rebuild=true 表示这是**重启后**的恢复：内存里的消息历史已丢失，
	// 需要用最小上下文重建（系统提示 + 续接说明 + 该次工具调用/结果）。
	Rebuild bool
	// Objective 重启恢复时的原任务目标（写进重建上下文）。
	Objective string
	// Note 重启恢复时给模型的额外说明（例如"结果来自数据库副本，可能已被截断"）。
	Note string
}

// CompleteTaskResume 把长任务的结果接回 run：追加 tool 消息与轨迹，清空等待态。
//
// 与 ResolveAgentConsent 同构：这里只负责"把结果变成上下文"，真正的循环恢复由调用方
// （api 的 resumeAgentAsync）发起。结果 → 模型可见文本的转换走**同一个** toolResultView，
// 因此挂起恢复路径不会出现"同步路径有截断标注、恢复路径没有"的偏差。
func (c *Copilot) CompleteTaskResume(run *AgentRun, rctx TaskResumeContext, result interface{}, resultErr error) {
	var out string
	if resultErr != nil {
		out = "error: " + resultErr.Error()
	} else if b, jerr := json.Marshal(result); jerr == nil {
		out = string(b)
	} else {
		out = fmt.Sprintf("%v", result)
	}

	view := c.toolResultView(resultRef{
		Tool: rctx.Tool, CallID: rctx.CallID, RunID: run.ID, TraceID: rctx.TraceID,
	}, out)
	trace := ToolTrace{Name: rctx.Tool, Args: rctx.Args, Result: view.Text}.withResultMeta(view)
	if resultErr != nil {
		trace.Error = resultErr.Error()
	}

	// 重启恢复：消息历史随进程丢失，先重建最小上下文（必须包含与 tool 消息配对的
	// assistant.tool_calls，否则上游 chat/completions 会直接拒绝这段消息序列）。
	if rctx.Rebuild {
		run.SetMessages(c.rebuildRunMessages(rctx))
	}

	run.mu.Lock()
	p := run.PendingTask
	run.PendingTask = nil
	run.WaitingOn = ""
	// 等待态已结束：stop_reason 必须清掉，否则最终 done 事件会带一个已经过期的
	// "awaiting_task"（run 已经不在等待了）。
	run.StopReason = ""
	run.Status = AgentRunning
	run.UpdatedAt = time.Now()
	if p != nil {
		// 用挂起时的消息快照作为基础（与审批恢复同一做法）：避免恢复期间对 run.Messages
		// 的其它追加导致同一批消息被写两遍。
		run.Traces = append(run.Traces, p.traces...)
		run.Messages = append(append([]Message(nil), p.messages...),
			Message{Role: "tool", ToolCallID: rctx.CallID, Content: view.Text})
	} else {
		run.Messages = append(run.Messages, Message{Role: "tool", ToolCallID: rctx.CallID, Content: view.Text})
	}
	run.Traces = append(run.Traces, trace)
	run.mu.Unlock()

	status := "✅ 任务已返回"
	if resultErr != nil {
		status = "❌ 任务结果获取失败"
	}
	run.appendTimeline("tool_result", fmt.Sprintf("%s %s → %s", status, rctx.Tool,
		truncate(summarizeToolResult(rctx.Tool, out), 220)))
	run.emit(AgentEventToolResult, toolResultEvent(rctx.Tool, rctx.TraceID, view, trace.Error), "")
	logging.Info("agent-audit", "run=%s trace=%s long_task_resumed tool=%s call_id=%s rebuild=%v handle=%s truncated=%v err=%v",
		run.ID, rctx.TraceID, rctx.Tool, rctx.CallID, rctx.Rebuild, view.Handle, view.Truncated, trace.Error)
}

// rebuildRunMessages 重启恢复用的最小上下文。
//
// 为什么是"最小重建"而不是完整回放：完整的对话历史只在内存里（run.Messages 标了
// json:"-"），落盘的只有 run/step/tool_call（ArgsJSON/结果索引）。要做到逐字回放需要
// 新增"消息快照"的持久化设计，属于本增量之外；这里重建出**足以继续推理**的三件东西：
// 系统提示、原目标 + 续接说明、该次工具调用与其真实结果。诚实标注"这是重建的上下文"，
// 避免模型把它当成完整历史。
func (c *Copilot) rebuildRunMessages(rctx TaskResumeContext) []Message {
	argsJSON := "{}"
	if b, err := json.Marshal(rctx.Args); err == nil {
		argsJSON = string(b)
	}
	note := strings.TrimSpace(rctx.Note)
	if note == "" {
		note = "服务端在本次工具调用执行期间重启，内存中的对话历史已丢失；以下是按持久化状态重建的最小上下文。"
	}
	var sb strings.Builder
	sb.WriteString("【续接上下文】")
	sb.WriteString(note)
	if obj := strings.TrimSpace(rctx.Objective); obj != "" {
		sb.WriteString("\n原任务目标：")
		sb.WriteString(obj)
	}
	sb.WriteString("\n下面这条工具调用的结果来自目标主机的真实执行记录，请基于它继续完成任务；若信息已足够，直接给出最终结论，不要再重复下发同一条命令。")
	return []Message{
		{Role: "system", Content: c.systemPrompt()},
		{Role: "user", Content: sb.String()},
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: rctx.CallID, Type: "function",
			Function: ToolCallFunc{Name: rctx.Tool, Arguments: argsJSON},
		}}},
	}
}

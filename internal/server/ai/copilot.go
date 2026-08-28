// Package ai 实现 AI 副驾驶：OpenAI 兼容的 LLM 聊天 + 工具调用循环。
// 工具即 internal/server/api 暴露的 MCP 工具（intel_query/session_list/
// session_context/task_submit/attack_suggest），LLM 决策调用、执行结果
// 回喂后继续对话，直至模型产出最终回复或达到轮数上限。
package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/server/config"
	"toshell/internal/server/logging"
)

// consentSeq 审批令牌序号（atomic 保证唯一）。
var consentSeq atomic.Uint64

// ─── 消息与请求结构（OpenAI chat/completions 兼容） ─────────────────────

type Message struct {
	Role       string     `json:"role"` // system / user / assistant / tool
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function ToolCallFunc   `json:"function"`
}

type ToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolSchema OpenAI function calling 工具描述。
type ToolSchema struct {
	Type     string              `json:"type"`
	Function ToolSchemaFunction  `json:"function"`
}

type ToolSchemaFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type chatRequest struct {
	Model       string       `json:"model"`
	Messages    []Message    `json:"messages"`
	Tools       []ToolSchema `json:"tools,omitempty"`
	ToolChoice  string       `json:"tool_choice,omitempty"`
	Temperature float64      `json:"temperature,omitempty"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Stream      bool         `json:"stream,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// ToolExecutor 执行一次 MCP 工具调用（由 api.Server 实现）。
type ToolExecutor interface {
	InvokeTool(name string, args map[string]string) (interface{}, error)
}

// ─── Copilot ──────────────────────────────────────────────────────────

type Copilot struct {
	cfg      config.AIConfig
	executor ToolExecutor
	client   *http.Client

	// pending 挂起的审批会话：normal 模式下，影响会话的操作不自动执行，
	// 而是生成一个 consent 令牌，等前端用户「允许/拒绝」后再恢复 ReAct 循环。
	pendingMu sync.Mutex
	pending   map[string]*pendingSession
}

// ConsentRequest 一次待确认的权限请求（前端弹窗用）。
type ConsentRequest struct {
	Token string            `json:"token"`
	Tool  string            `json:"tool"`
	Args  map[string]string `json:"args"`
	Desc  string            `json:"desc,omitempty"`
}

// ChatResult 一轮副驾驶对话的结果：最终回复 + 工具轨迹 + 待确认请求（若有）。
type ChatResult struct {
	Reply   string           `json:"reply"`
	Traces  []ToolTrace      `json:"traces"`
	Pending []ConsentRequest `json:"pending_consents,omitempty"`
}

// pendingSession 一个被挂起的审批会话：保存当前消息序列、待确认的工具与已产生轨迹。
type pendingSession struct {
	messages []Message
	tool     ToolCall
	args     map[string]string
	traces   []ToolTrace
}

func New(cfg config.AIConfig, executor ToolExecutor) *Copilot {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	return &Copilot{
		cfg:      cfg,
		executor: executor,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
		pending:  make(map[string]*pendingSession),
	}
}

// Enabled 返回 AI 副驾驶是否可调用（配置齐全）。
func (c *Copilot) Enabled() bool {
	return c.cfg.Enabled && c.cfg.BaseURL != "" && c.cfg.APIKey != "" && c.cfg.Model != ""
}

// Config 返回当前配置（前端设置页展示用）。
func (c *Copilot) Config() config.AIConfig { return c.cfg }

// Reconfigure 热更新配置。
func (c *Copilot) Reconfigure(cfg config.AIConfig) {
	c.cfg = cfg
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	c.client.Timeout = time.Duration(timeout) * time.Second
}

// Chat 单轮对话入口（兼容无审批的简单调用）：返回助手最终文本 + 工具调用轨迹。
func (c *Copilot) Chat(ctx context.Context, history []Message) (string, []ToolTrace, error) {
	res, err := c.ChatWithConsent(ctx, history)
	if err != nil {
		return "", nil, err
	}
	return res.Reply, res.Traces, nil
}

// ChatWithConsent 单轮对话入口：组装系统提示 + 历史消息，调用 LLM；
// 若模型请求工具调用则执行并回喂，循环至最终回复。normal 权限模式下，
// 影响会话的操作不自动执行，而是返回 pending_consents 挂起等用户确认。
func (c *Copilot) ChatWithConsent(ctx context.Context, history []Message) (*ChatResult, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("AI copilot not configured: set ai.base_url/api_key/model in config")
	}
	if c.executor == nil {
		return nil, fmt.Errorf("AI copilot executor not available")
	}
	messages := c.buildMessages(history)
	return c.runLoop(ctx, messages)
}

// buildMessages 组装系统提示（注入当前在线会话清单）+ 历史消息。
// systemPrompt 返回 agent 的完整系统提示（角色 + 工具面 + ReAct 方法论 + 自主提权闭环 + 失败恢复 + 只输出建议）。
func (c *Copilot) systemPrompt() string {
	sysBase := "你是 ToShell C2 平台的 AI 副驾驶（agent），帮助安全测试人员完整执行操作闭环。\n" +
		"你可以调用工具完成：会话管理（session_list/session_context/session_kill）、" +
		"命令下发（task_submit/task_result/task_wait）、文件操作（file_list/file_download）、" +
		"进程操作（process_list/process_kill）、截图（screenshot）、凭据收集（credentials）、" +
		"隧道/端口转发（tunnel_start/tunnel_list/tunnel_stop）、插件执行（plugin_list/plugin_load）、" +
		"情报查询（intel_query）、攻击建议（attack_suggest）、任务流执行（delegate/playbook_status）、" +
		"联网搜索（web_search）、远程下载工具（remote_download，下载到服务端 data/tools/ 可重复使用）与工具分发" +
		"（tool_list 看已下载工具；plugin_upload 把工具上传为插件→plugin_load 加载；fileless_exec 内存加载执行，不落盘）。\n" +
		"工作方式（ReAct 闭环）：\n" +
		"1. 先侦察：基于给定【当前在线会话】选合适会话，再用 session_list/session_context 了解目标，不臆造数据。\n" +
		"2. 再行动：基于上下文选定思路后，用 task_submit/file_list/process_list/screenshot/credentials 等下任务，拿到 task_id。\n" +
		"3. 必等结果：用 task_wait 轮询任务直到完成，读取真实输出；不要下发后立即汇报（那是未执行的结果）。\n" +
		"4. 分析汇报：基于真实输出用简洁中文总结（关键信息、异常、下一步建议）。\n" +
		"若某任务需要多步（列目录→看文件→读凭据→横向），按顺序连续调用工具完成完整链路。\n" +
		"收敛原则（**严格执行，避免冗余/重复**）：\n" +
		"  - **task_id 只能来自工具返回**（task_submit/run_command/fileless_exec 等的 task_id 字段），**严禁自己编造或猜测 task_id**；task_wait 报 task not found 时，说明该任务未成功，应**重新用工具下发**，而不是对同一命令重复执行。\n" +
		"  - 每拿到一次完整结果就**立即停止**该信息点的搜集，不要对**完全相同的命令/参数**重发第二次（已见过该数据）。\n" +
		"  - 连续 2 次相同命令无新增信息 → 判定该路径已到头，改用其它路径或直接进入「输出建议」。\n" +
		"  - 拿到足够信息后**必须输出最终中文答复**；不要为了凑步数反复执行无意义命令。\n" +
		"任务流编排：当目标可标准化/批量执行时，优先用 delegate 启动任务流（确定性多步链路）执行，再用 playbook_status 轮询进度；" +
		"不要逐个手工重复下发命令。\n" +
		"自主原则：收到目标时先识别信息缺口并补齐（session_context/intel_query/侦察类），再决定行动，无需每步征询用户；" +
		"信息不足时先深入获取，不要臆测。\n" +
		"【自主提权闭环】提权是高危操作，**先评估、后谨慎行动**，绝不要一提到提权就无脑连发工具：\n" +
		"  0 警觉：先判断是否**真的需要提权**——用 run_command(whoami + whoami /groups) 看当前身份与权限；" +
		"若已是 admin/SYSTEM 或操作不需要更高权限，**就不要再执行提权**，直接说明并进入待命。\n" +
		"  ① 评估路径：只有确认「当前权限不足且目标确实需要提权」后，才继续。结合环境（process_list/check_av 看 EDR、system_info/net_connections 看攻击面）" +
		"选**一条最可能成功**的路径（如 Windows 普通用户→UAC，Linux→SUID/内核），不要同时铺开多条。\n" +
		"  ② 确认工具：先 tool_list 看是否已有可用工具；没有再用 web_search 检索，remote_download 到服务端，" +
		"并 tool_download_status / tool_list **确认拿到且平台/架构匹配**。**严禁**对不存在或不匹配的工具/载荷执行 fileless_exec / plugin_load（会崩溃植入端导致掉线）。\n" +
		"  ③ 谨慎执行：一次只执行**一个**工具/动作，执行前说明意图，用 task_wait 等真实结果。\n" +
		"  ④ 验证：提权后 run_command(whoami /priv 或 id) 确认权限确实提升；失败则**立即停止**，换路径或回退都**必须先说明**，绝不反复重试同一工具。\n" +
		"  ⑤ 待命：完成/失败后都转入「等待你后续指令」，把结果和建议简要汇报，不要擅自扩大操作范围。\n" +
		"【失败恢复】工具调用失败或返回异常时，**绝不无脑重试/狂炸**：\n" +
		"  - 先分析失败原因：是参数错、会话掉线、还是工具不存在/不匹配；据此选择**换等价工具**或**先向用户说明**。\n" +
		"  - 一次失败就让**下一步**换路径，不要连续用同一工具反复执行（已判定的重复调用会被强制终止）。\n" +
		"  - **若出现 network error / 会话掉线（执行高危操作后植入端无响应）**：立即停止所有后续攻击动作，判定为「会话疑似中断」，" +
		"先向用户说明「该操作可能导致植入端掉线」，建议重新上线植入端或改用更稳妥的命令，**绝不要继续对同一会话执行更多命令**。\n" +
		"  - 若确实无法继续，必须向用户**说明失败原因 + 可行的替代方案建议**，绝不要输出空白或只报错误。\n" +
		"【输出要求】最终答复**只输出结论与建议**，不要大段罗列工具原始结果/命令输出/全部步骤明细——" +
		"我只要【现状】(当前会话/权限/环境的简短判断) + 【建议】(下一步该做什么、怎么做的清晰可执行建议) + 【为何】一句话依据。" +
		"与待命状态呼应，最后以「需要我继续执行吗？」收尾，等待用户指令。\n" +
		"下载约定：需要下载工具/载荷/文件到服务器时，**必须用 remote_download(url)**（服务端下载到 data/tools/，快且可靠，可复用）；" +
		"**严禁**在目标会话上用手动命令（certutil / powershell Invoke-WebRequest / curl / bitsadmin 等）下载——" +
		"那些会在植入端长时间阻塞、URL 易 404、且触发行为检测。下载后用 tool_list 确认，再用 plugin_upload（上传为插件）或 fileless_exec（内存加载）分发使用。"
	if ov := c.currentSessions(); ov != "" {
		sysBase += "\n\n【当前在线会话】\n" + ov +
			"\n以上是当前上线的目标会话。需要时用 session_context 获取某会话详细上下文，结合上下文判断下一步，无需每步都问用户；若上下文不足，先深入获取再给建议。"
	}
	return sysBase
}

func (c *Copilot) buildMessages(history []Message) []Message {
	sysBase := c.systemPrompt()
	messages := make([]Message, 0, len(history)+1)
	messages = append(messages, Message{Role: "system", Content: sysBase})
	messages = append(messages, history...)
	return messages
}

// runLoop ReAct 循环主体；normal 模式下遇影响会话操作会挂起并返回 pending。
func (c *Copilot) runLoop(ctx context.Context, messages []Message) (*ChatResult, error) {
	maxTurns := c.cfg.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 20
	}
	var traces []ToolTrace
	lastCall := ""
	repeatCount := 0
	for turn := 0; turn < maxTurns; turn++ {
		resp, err := c.complete(ctx, messages)
		if err != nil {
			return nil, err
		}
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("LLM returned no choices")
		}
		msg := resp.Choices[0].Message
		messages = append(messages, msg)
		if len(msg.ToolCalls) == 0 {
			return &ChatResult{Reply: msg.Content, Traces: traces}, nil
		}
		for _, tc := range msg.ToolCalls {
			args := map[string]string{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			callKey := tc.Function.Name + "|" + tc.Function.Arguments
			if callKey == lastCall {
				repeatCount++
			} else {
				lastCall = callKey
				repeatCount = 1
			}
			if repeatCount >= 3 {
				logging.Warn("ai", "copilot tool loop detected: %s called %d times with same args", tc.Function.Name, repeatCount)
				return &ChatResult{Reply: buildActionSummary(traces), Traces: traces}, nil
			}
			// 权限护栏：normal 模式下影响会话的操作挂起等用户确认；任务流(delegate)除外。
			if c.cfg.ConsentMode == "normal" && isRiskyTool(tc.Function.Name) {
				token := c.newConsentToken()
				c.pendingMu.Lock()
				c.pending[token] = &pendingSession{
					messages: append([]Message(nil), messages...),
					tool:     tc,
					args:     args,
					traces:   append([]ToolTrace(nil), traces...),
				}
				c.pendingMu.Unlock()
				return &ChatResult{
					Reply:   "✋ 以下操作会影响目标会话，需要你确认后才会执行。",
					Traces:  traces,
					Pending: []ConsentRequest{{Token: token, Tool: tc.Function.Name, Args: args, Desc: toolDesc(tc.Function.Name)}},
				}, nil
			}
			result, err := c.executor.InvokeTool(tc.Function.Name, args)
			trace := ToolTrace{Name: tc.Function.Name, Args: args}
			var out string
			if err != nil {
				out = "error: " + err.Error()
				trace.Error = err.Error()
			} else {
				if b, jerr := json.Marshal(result); jerr == nil {
					out = string(b)
				} else {
					out = fmt.Sprintf("%v", result)
				}
			}
			trace.Result = out
			traces = append(traces, trace)
			messages = append(messages, Message{Role: "tool", ToolCallID: tc.ID, Content: truncate(out, 4000)})
		}
	}
	logging.Warn("ai", "copilot tool loop reached %d turns, returning action summary", maxTurns)
	return &ChatResult{Reply: buildActionSummary(traces), Traces: traces}, nil
}

// ResolveConsent 用户对挂起的操作做决定：allow→执行该工具，deny→跳过；然后恢复 ReAct 循环。
func (c *Copilot) ResolveConsent(ctx context.Context, token string, allow bool) (*ChatResult, error) {
	c.pendingMu.Lock()
	p := c.pending[token]
	if p != nil {
		delete(c.pending, token)
	}
	c.pendingMu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("consent request not found or already resolved")
	}

	var out string
	if allow {
		res, err := c.executor.InvokeTool(p.tool.Function.Name, p.args)
		if err != nil {
			out = "error: " + err.Error()
		} else {
			if b, jerr := json.Marshal(res); jerr == nil {
				out = string(b)
			} else {
				out = fmt.Sprintf("%v", res)
			}
		}
	} else {
		out = "用户已拒绝该操作，未执行。请向用户说明，不要再次请求同一操作。"
	}

	msgs := append(p.messages, Message{Role: "tool", ToolCallID: p.tool.ID, Content: truncate(out, 4000)})
	res, err := c.runLoop(ctx, msgs)
	if err != nil {
		return nil, err
	}
	// 合并本轮挂起前的轨迹 + 当前恢复执行产生的轨迹 + 本次工具结果
	merged := append([]ToolTrace(nil), p.traces...)
	merged = append(merged, res.Traces...)
	merged = append(merged, ToolTrace{Name: p.tool.Function.Name, Args: p.args, Result: truncate(out, 120)})
	res.Traces = merged
	return res, nil
}

func (c *Copilot) newConsentToken() string {
	return fmt.Sprintf("c-%d-%d", time.Now().UnixNano(), consentSeq.Add(1))
}

// newConsentToken 包级生成唯一审批令牌（供 AgentRun 使用）。
func newConsentToken() string {
	return fmt.Sprintf("c-%d-%d", time.Now().UnixNano(), consentSeq.Add(1))
}

// ResolveAgentConsent 处理 agent 挂起的审批：allow→执行该工具，deny→跳过；
// 然后往 run 追加 tool 结果消息，并恢复自主循环（异步）。返回最终结果或新挂起。
func (c *Copilot) ResolveAgentConsent(ctx context.Context, run *AgentRun, allow bool) (*ChatResult, error) {
	run.mu.Lock()
	p := run.Pending
	run.Pending = nil
	run.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("no pending consent on run %s", run.ID)
	}

	var out string
	if allow {
		run.emit(AgentEventToolStart, ToolStart{Name: p.tool.Function.Name, Args: p.args}, "")
		res, err := c.executor.InvokeTool(p.tool.Function.Name, p.args)
		if err != nil {
			out = "error: " + err.Error()
		} else {
			if b, jerr := json.Marshal(res); jerr == nil {
				out = string(b)
			} else {
				out = fmt.Sprintf("%v", res)
			}
		}
	} else {
		out = "用户已拒绝该操作，未执行。请向用户说明，不要再次请求同一操作。"
	}

	trace := ToolTrace{Name: p.tool.Function.Name, Args: p.args, Result: truncate(out, 4000)}
	run.Traces = append(run.Traces, trace)
	run.emit(AgentEventToolResult, ToolResult{Name: p.tool.Function.Name, Result: truncate(out, 4000)}, "")

	// 追加 tool 结果消息，恢复循环。用 p.messages 作为基础，避免重复。
	run.Messages = append(p.messages, Message{Role: "tool", ToolCallID: p.tool.ID, Content: truncate(out, 4000)})

	// 后台继续自主循环由调用方（resumeAgentAsync）发起
	return nil, nil
}

// toolDesc 给同意弹窗一个工具中文说明。
func toolDesc(name string) string {
	switch name {
	case "task_submit", "run_command":
		return "向会话下发命令"
	case "file_list":
		return "列出会话文件"
	case "file_download":
		return "下载会话文件"
	case "process_list":
		return "枚举会话进程"
	case "process_kill":
		return "结束会话进程"
	case "screenshot":
		return "对会话截屏"
	case "credentials":
		return "收集会话凭据"
	case "session_kill":
		return "终止会话"
	case "plugin_load":
		return "注入插件到会话"
	case "tunnel_start":
		return "启动隧道代理（内网访问）"
	case "tunnel_stop":
		return "停止隧道代理"
	case "user_info":
		return "读取会话用户/权限"
	case "system_info":
		return "读取会话系统信息"
	case "service_list":
		return "枚举会话服务"
	case "check_av":
		return "检测会话杀软"
	case "net_info":
		return "读取会话网络配置"
	case "net_connections":
		return "列出会话网络连接"
	case "env_vars":
		return "读取会话环境变量"
	case "scheduled_tasks":
		return "列出会话计划任务"
	default:
		return "影响目标会话的操作"
	}
}

// Summarize 单次纯文本 LLM 调用（不启用工具循环），用于剧本/子代理完成后的
// 智能总结：把执行结果喂给 LLM，产出中文结论与下一步建议。返回模型文本。
func (c *Copilot) Summarize(ctx context.Context, system, user string) (string, error) {
	if !c.Enabled() {
		return "", fmt.Errorf("AI copilot not configured: set ai.base_url/api_key/model in config")
	}
	req := chatRequest{
		Model:       c.cfg.Model,
		Messages:    []Message{{Role: "system", Content: system}, {Role: "user", Content: user}},
		Temperature: 0.5,
		MaxTokens:   2400, // 保证「结果综述 + 攻击判断 + 下一步建议」完整输出，不被截断
	}
	body, _ := json.Marshal(req)

	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	url := base + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API %s: %s", resp.Status, truncate(string(raw), 500))
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("LLM bad response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("LLM error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}

// currentSessions 拉取当前在线会话的精简清单（注入 system prompt 帮 AI 了解战场）。
// 失败或无法解析时返回空串（不影响对话）。
func (c *Copilot) currentSessions() string {
	if c.executor == nil {
		return ""
	}
	res, err := c.executor.InvokeTool("session_list", nil)
	if err != nil {
		return ""
	}
	b, _ := json.Marshal(res)
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	arr, _ := m["sessions"].([]interface{})
	if len(arr) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, item := range arr {
		if i >= 30 {
			break
		}
		sm, _ := item.(map[string]interface{})
		id, _ := sm["id"].(string)
		host, _ := sm["hostname"].(string)
		os, _ := sm["os"].(string)
		status, _ := sm["status"].(string)
		listener, _ := sm["listener"].(string)
		sb.WriteString(fmt.Sprintf("- %s  %s  (%s)  listener=%s  status=%s\n", id, host, os, listener, status))
	}
	return sb.String()
}

// buildActionSummary 把已完成的工具调用整理成可读的中文动作清单。
func buildActionSummary(traces []ToolTrace) string {
	if len(traces) == 0 {
		return "已达工具调用轮数上限，但本轮未完成任何工具调用。请尝试重新表述，或直接告诉我具体要做什么。"
	}
	var b strings.Builder
	b.WriteString("已完成的步骤与建议：\n\n")
	for i, t := range traces {
		if t.Error != "" {
			b.WriteString(fmt.Sprintf("%d. %s ❌ 失败（%s）\n", i+1, t.Name, t.Error))
		} else if s := summarizeToolResult(t.Name, t.Result); s != "" {
			b.WriteString(fmt.Sprintf("%d. %s ✅ %s\n", i+1, t.Name, s))
		} else {
			b.WriteString(fmt.Sprintf("%d. %s ✅\n", i+1, t.Name))
		}
	}
	b.WriteString("\n【建议】需要我继续执行下一步吗？告诉我具体目标，或我按红队思路给出可执行的后续路径。")
	return b.String()
}

// summarizeToolResult 从工具原始结果中提取一行可读摘要。
func summarizeToolResult(name, result string) string {
	if result == "" {
		return ""
	}
	switch name {
	case "task_submit", "file_list", "file_download", "process_list", "process_kill",
		"screenshot", "credentials", "task_result":
		// JSON 结果：尝试解析出关键字段
		var m map[string]interface{}
		if json.Unmarshal([]byte(result), &m) == nil {
			parts := []string{}
			if v, ok := m["task_id"]; ok {
				parts = append(parts, fmt.Sprintf("task_id=%v", v))
			}
			if v, ok := m["status"]; ok {
				parts = append(parts, fmt.Sprintf("status=%v", v))
			}
			if v, ok := m["exit_code"]; ok {
				parts = append(parts, fmt.Sprintf("exit=%v", v))
			}
			if len(parts) > 0 {
				return strings.Join(parts, " ")
			}
		}
	case "task_wait":
		var m map[string]interface{}
		if json.Unmarshal([]byte(result), &m) == nil {
			status, _ := m["status"].(string)
			output, _ := m["output"].(string)
			if status == "completed" {
				o := truncate(output, 120)
				return fmt.Sprintf("任务完成，输出: %s", o)
			}
			if status == "failed" {
				return "任务失败: " + truncate(fmt.Sprint(m["error"]), 120)
			}
			return fmt.Sprintf("任务状态: %s", status)
		}
	case "session_list":
		var m map[string]interface{}
		if json.Unmarshal([]byte(result), &m) == nil {
			if v, ok := m["count"]; ok {
				return fmt.Sprintf("共 %v 个会话", v)
			}
		}
	case "intel_query":
		var m map[string]interface{}
		if json.Unmarshal([]byte(result), &m) == nil {
			if v, ok := m["items"]; ok {
				if arr, isArr := v.([]interface{}); isArr {
					return fmt.Sprintf("情报库 %d 条", len(arr))
				}
			}
		}
	}
	return truncate(result, 120)
}

// complete 调用一次 chat/completions。
func (c *Copilot) complete(ctx context.Context, messages []Message) (*chatResponse, error) {
	req := chatRequest{
		Model:      c.cfg.Model,
		Messages:   messages,
		Tools:      toolSchemas(),
		ToolChoice: "auto",
	}
	body, _ := json.Marshal(req)

	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	// BaseURL 兼容两种写法：https://api.deepseek.com 或 https://api.deepseek.com/v1
	// （chat/completions 路径总是拼接 /chat/completions）
	url := base + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LLM API %s: %s", resp.Status, truncate(string(raw), 500))
	}

	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("LLM bad response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("LLM error: %s", out.Error.Message)
	}
	return &out, nil
}

// ─── 流式补全（SSE）─────────────────────────────────────────────────
// 用 stream:true 调用 chat/completions，逐 token 回调。OpenAI 兼容响应为
// `data: {...}\n\n` 行；DeepSeek 系在 delta 里带 reasoning_content（思考）。
// 返回 AgentStream：思考增量(thinking)、正文增量(content)、最终完整消息。
type AgentStream struct {
	Thinking string // 累积思考文本（reasoning_content）
	Content  string // 累积正文文本（content）
	// ToolCalls 若最终需要调用工具则非空（流式下工具逐段拼接）。
	ToolCalls []ToolCall
}

// OnToken 回调：phase=thinking|content，text 为增量。
type OnToken func(phase, text string)

// completeStream 流式调用 LLM。onToken 每收到增量触发一次；返回累积结果。
func (c *Copilot) completeStream(ctx context.Context, messages []Message, onToken OnToken) (*AgentStream, error) {
	req := chatRequest{
		Model:      c.cfg.Model,
		Messages:   messages,
		Tools:      toolSchemas(),
		ToolChoice: "auto",
		Stream:     true,
	}
	body, _ := json.Marshal(req)

	base := strings.TrimSuffix(c.cfg.BaseURL, "/")
	url := base + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return nil, fmt.Errorf("LLM API %s: %s", resp.Status, truncate(string(raw), 500))
	}

	ag := &AgentStream{}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	// tool 增量拼接（按 index）
	type toolAgg struct {
		id, name, args string
	}
	tools := map[int]*toolAgg{}
	var toolOrder []int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == "data: [DONE]" || line == "[DONE]" {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var chunk struct {
			Choices []struct {
				Delta struct {
					ReasoningContent string          `json:"reasoning_content"`
					Content          string          `json:"content"`
					ToolCalls        []streamToolCall `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue // 忽略无法解析的心跳/注释
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		d := chunk.Choices[0].Delta
		if d.ReasoningContent != "" {
			ag.Thinking += d.ReasoningContent
			if onToken != nil {
				onToken("thinking", d.ReasoningContent)
			}
		}
		if d.Content != "" {
			ag.Content += d.Content
			// 过滤纯空白增量（避免 SSE 逐 token 推送空格/换行导致前端大量空行）；
			// 仍累积进 ag.Content 保证最终答复完整，只是不逐 token 事件。
			if onToken != nil && strings.TrimSpace(d.Content) != "" {
				onToken("content", d.Content)
			}
		}
		for _, tc := range d.ToolCalls {
			idx := tc.Index
			if _, ok := tools[idx]; !ok {
				tools[idx] = &toolAgg{}
				toolOrder = append(toolOrder, idx)
			}
			t := tools[idx]
			if tc.ID != "" {
				t.id = tc.ID
			}
			if tc.Function.Name != "" {
				t.name += tc.Function.Name
			}
			t.args += tc.Function.Arguments
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("SSE read failed: %w", err)
	}

	// 按出现顺序输出工具调用
	for _, idx := range toolOrder {
		t := tools[idx]
		if t.name == "" {
			continue
		}
		ag.ToolCalls = append(ag.ToolCalls, ToolCall{
			ID:   t.id,
			Type: "function",
			Function: ToolCallFunc{Name: t.name, Arguments: t.args},
		})
	}
	return ag, nil
}

// streamToolCall 流式工具调用增量块。
type streamToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ─── 自主 Agent 循环 ────────────────────────────────────────────────
// RunAgent 在后台驱动一个 AgentRun 自主运行：LLM 流式思考 → 若请求工具则
// 执行并回喂 → 循环 → 直至产出最终答复。全程经 run.Events() 推事件，异步不阻塞。
// 返回最终 AgentStream（含 ToolCalls 供调用方判断是否命中工具，normal 模式走审批）。
func (c *Copilot) RunAgent(ctx context.Context, run *AgentRun) (*AgentStream, error) {
	// 并发上限：由 AgentManager 负责，这里只管单 run 循环。
	if !c.Enabled() {
		err := fmt.Errorf("AI copilot not configured: set ai.base_url/api_key/model in config")
		run.emitRaw(AgentEvent{Kind: AgentEventError, Error: err.Error()})
		run.setStatus(AgentError)
		run.closeEvents()
		return nil, err
	}

	// 确保 run.Messages 首条是系统提示：自主 agent 必须带角色/方法论指引。
	// （新增/续接时都要保证，否则 agent 只拿到用户历史，缺少"该怎么做"的指引。）
	run.mu.Lock()
	if len(run.Messages) == 0 || run.Messages[0].Role != "system" {
		sys := Message{Role: "system", Content: c.systemPrompt()}
		msgs := make([]Message, 0, len(run.Messages)+1)
		msgs = append(msgs, sys)
		msgs = append(msgs, run.Messages...)
		run.Messages = msgs
	}
	run.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	run.mu.Lock()
	run.cancel = cancel
	run.mu.Unlock()
	defer cancel()

	run.setStatus(AgentRunning)
	run.emitRaw(AgentEvent{Kind: AgentEventMessage, Data: json.RawMessage(`""`)})

	maxTurns := run.MaxTurns
	if maxTurns <= 0 {
		maxTurns = c.cfg.MaxTurns
		if maxTurns <= 0 {
			maxTurns = 20
		}
	}

	lastCall := ""
	repeatCount := 0
	consecutiveFail := 0 // 连续失败工具计数：超过阈值强制收敛，避免 agent 无限瞎试/幻觉
	var fullThinking strings.Builder
	var fullContent strings.Builder

	for turn := 0; turn < maxTurns; turn++ {
		// 取消检查
		select {
		case <-ctx.Done():
			run.emitRaw(AgentEvent{Kind: AgentEventError, Error: errAgentCancelled.Error()})
			run.setStatus(AgentError)
			return nil, errAgentCancelled
		default:
		}

		ag, err := c.completeStream(ctx, run.Messages, func(phase, text string) {
			if phase == "thinking" {
				fullThinking.WriteString(text)
				run.emit(AgentEventThinking, text, "")
			} else {
				fullContent.WriteString(text)
				run.emit(AgentEventMessage, text, "")
			}
		})
		if err != nil {
			// 出错兜底：绝不让 run 停在「无回复」状态。
			// 若已累积动作则输出动作摘要；否则给出明确的错误说明 + 建议，供用户知晓并决定下一步。
			var reply string
			if len(run.Traces) > 0 {
				reply = buildActionSummary(run.Traces)
			} else {
				reply = "❌ 本次执行遇到异常，未能完成：`" + err.Error() + "`。\n\n" +
					"【建议】可以换一种更明确的表述重新告诉我目标（例如指定会话 ID、命令或要执行的操作），" +
					"或确认 AI 服务（ai.base_url/api_key/model）配置正确、目标会话在线后重试。"
			}
			run.setReply(reply)
			run.emit(AgentEventFinal, reply, "")
			run.emitRaw(AgentEvent{Kind: AgentEventError, Error: err.Error()})
			run.setStatus(AgentError)
			run.closeEvents()
			return nil, err
		}

		// 记录本轮消息
		run.Messages = append(run.Messages, Message{
			Role:      "assistant",
			Content:   ag.Content,
			ToolCalls: ag.ToolCalls,
		})

		if len(ag.ToolCalls) == 0 {
			// 最终答复
			run.setReply(ag.Content)
			run.emit(AgentEventFinal, ag.Content, "")
			run.emitRaw(AgentEvent{Kind: AgentEventDone})
			run.setStatus(AgentDone)
			run.closeEvents()
			return ag, nil
		}

		// 执行工具调用：一次只做一个（严格串行，避免多任务并发导致结果与任务错位）。
		// 单个工具（尤其 task_submit/run_command 等下发任务类）执行并 task_wait 完成后，
		// 把结果以 tool 消息回喂，回到 LLM 决定下一步，保证结果与任务一一对应、不乱序。
		tc := ag.ToolCalls[0]
		args := map[string]string{}
		if tc.Function.Arguments != "" {
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
		}
		callKey := tc.Function.Name + "|" + tc.Function.Arguments
		if callKey == lastCall {
			repeatCount++
		} else {
			lastCall = callKey
			repeatCount = 1
		}
		if repeatCount >= 3 {
			logging.Warn("ai", "agent %s: tool loop detected: %s repeated %d times", run.ID, tc.Function.Name, repeatCount)
			summary := buildActionSummary(run.Traces)
			run.setReply(summary)
			run.emit(AgentEventFinal, summary, "")
			run.emitRaw(AgentEvent{Kind: AgentEventDone})
			run.setStatus(AgentDone)
			run.closeEvents()
			return nil, fmt.Errorf("tool loop detected")
		}

		// 权限护栏：normal 模式下影响会话的操作挂起等确认（任务流除外）
		if c.cfg.ConsentMode == "normal" && isRiskyTool(tc.Function.Name) {
			c.waitForConsent(ctx, run, tc, args)
			// run 已被挂起（awaiting_consent），停止本轮循环，等 resumeAgentAsync 恢复。
			return nil, errAgentPaused
		}

		// 执行工具
		run.emit(AgentEventToolStart, ToolStart{Name: tc.Function.Name, Args: args}, "")
		result, err := c.executor.InvokeTool(tc.Function.Name, args)
		trace := ToolTrace{Name: tc.Function.Name, Args: args}
		var out string
		if err != nil {
			out = "error: " + err.Error()
			trace.Error = err.Error()
		} else {
			if b, jerr := json.Marshal(result); jerr == nil {
				out = string(b)
			} else {
				out = fmt.Sprintf("%v", result)
			}
		}

		// 失败刹车：连续失败 >= 3 次 → 强制收敛，输出已完成动作+下一步建议，不再让 LLM 无限瞎试。
		isFail := err != nil || trace.Error != "" || strings.Contains(out, `"failed"`) || strings.Contains(out, `"exit_code":-1`)
		if isFail {
			consecutiveFail++
		} else {
			consecutiveFail = 0
		}
		if consecutiveFail >= 3 {
			logging.Warn("ai", "agent %s: %d consecutive failures, converging to summary", run.ID, consecutiveFail)
			run.Traces = append(run.Traces, trace)
			run.emit(AgentEventToolResult, ToolResult{Name: tc.Function.Name, Result: truncate(out, 4000), Error: trace.Error}, "")
			summary := buildActionSummary(run.Traces)
			run.setReply(summary)
			run.emit(AgentEventFinal, summary, "")
			run.emitRaw(AgentEvent{Kind: AgentEventDone})
			run.setStatus(AgentDone)
			run.closeEvents()
			return nil, fmt.Errorf("%d consecutive tool failures", consecutiveFail)
		}

		trace.Result = out
		run.Traces = append(run.Traces, trace)
		run.emit(AgentEventToolResult, ToolResult{Name: tc.Function.Name, Result: truncate(out, 4000), Error: trace.Error}, "")
		run.Messages = append(run.Messages, Message{Role: "tool", ToolCallID: tc.ID, Content: truncate(out, 4000)})
	}

	// 达到轮数上限：输出已完成的动作摘要
	summary := buildActionSummary(run.Traces)
	run.setReply(summary)
	run.emit(AgentEventFinal, summary, "")
	run.emitRaw(AgentEvent{Kind: AgentEventDone})
	run.setStatus(AgentDone)
	run.closeEvents()
	return nil, fmt.Errorf("reached max turns %d", maxTurns)
}

// waitForConsent normal 模式下挂起 run，等前端 allow/deny。不返回——run 状态
// 已置为 awaiting_consent，调用方应停止本轮循环，由 resumeAgentAsync 恢复。
func (c *Copilot) waitForConsent(ctx context.Context, run *AgentRun, tc ToolCall, args map[string]string) {
	run.mu.Lock()
	run.Pending = &pendingState{
		messages: append([]Message(nil), run.Messages...),
		tool:     tc,
		args:     args,
		traces:   append([]ToolTrace(nil), run.Traces...),
	}
	run.mu.Unlock()
	run.setStatus(AgentWaitConsent)

	req := ConsentRequest{Token: newConsentToken(), Tool: tc.Function.Name, Args: args, Desc: toolDesc(tc.Function.Name)}
	run.emit(AgentEventConsent, req, "")
}



// ToolTrace 一次工具调用的执行轨迹（前端展示）。
type ToolTrace struct {
	Name   string            `json:"name"`
	Args   map[string]string `json:"args,omitempty"`
	Result string            `json:"result,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// toolSchemas 将 MCP 工具清单映射为 OpenAI function calling schema。
func toolSchemas() []ToolSchema {
	defs := []struct {
		name, desc string
		params     []string // 参数名（全部字符串）
	}{
		{"intel_query", "查询跨会话情报库（IP/账号/哈希/共享/域名）", []string{"kind"}},
		{"session_context", "获取指定会话的上下文摘要（OS/权限/监听器/最近任务）", []string{"session_id"}},
		{"task_submit", "向会话下发命令任务（执行后返回任务 ID）", []string{"session_id", "command"}},
		{"task_result", "查询单个任务的状态与输出（立即返回当前状态，不等待）", []string{"task_id"}},
		{"task_wait", "轮询等待任务完成（下发任务后调用），返回最终输出/退出码。参数: task_id, timeout_sec（默认 60）", []string{"task_id", "timeout_sec"}},
		{"session_list", "列出所有活跃会话（ID/主机名/OS/监听器/状态）", nil},
		{"file_list", "列出会话上的目录内容（结果通过 task_wait 获取）", []string{"session_id", "path"}},
		{"file_download", "从会话下载文件到服务器（结果通过 task_wait 获取）", []string{"session_id", "path"}},
		{"process_list", "列出会话上的进程（结果通过 task_wait 获取）", []string{"session_id"}},
		{"process_kill", "结束会话上的进程", []string{"session_id", "pid"}},
		{"screenshot", "对会话截屏（结果通过 task_wait 获取，含 base64 图片）", []string{"session_id"}},
		{"credentials", "收集会话上的凭据（all/browser/wifi/rdp/lsa，结果通过 task_wait 获取）", []string{"session_id", "action"}},
		{"session_kill", "终止会话（植入端退出）", []string{"session_id"}},
		{"delegate", "子代理：在指定会话执行剧本（确定性多步链路），支持多会话并行。参数: playbook_id + session_id 或 session_ids", []string{"playbook_id", "session_id", "session_ids"}},
		{"playbook_status", "查询剧本运行进度（delegate 返回 run_id 后查询）", []string{"run_id"}},
		{"attack_suggest", "基于会话上下文给出下一步操作建议（提权/注入/凭据等）", []string{"session_id"}},
		{"plugin_list", "列出已上传的插件（ID/名称/类型 exe/dll/shellcode/bof）", nil},
		{"plugin_load", "把插件加载到指定会话执行。参数: session_id, plugin_id, args(可选)", []string{"session_id", "plugin_id", "args"}},
		{"tunnel_start", "为指定会话启动 SOCKS5 隧道代理（本地端口转发，代理横向访问内网）。参数: session_id, local_port(可选默认1080)", []string{"session_id", "local_port"}},
		{"tunnel_list", "列出当前所有隧道代理（会话 ID/本地端口/隧道数）", nil},
		{"tunnel_stop", "停止指定会话的隧道代理。参数: session_id", []string{"session_id"}},
		{"web_search", "联网搜索：查询情报/工具/漏洞/用法。参数: query", []string{"query"}},
		{"remote_download", "从 URL 下载工具到服务端本地 data/tools/ 持久保存（可重复使用）。异步：立即返回 dl_id，用 tool_download_status 查询进度。参数: url", []string{"url"}},
		{"tool_download_status", "查询一次远程下载的进度/结果（remote_download 返回 dl_id 后调用）。参数: dl_id", []string{"dl_id"}},
		{"tool_list", "列出服务端 data/tools/ 已下载的可复用工具", nil},
		{"plugin_upload", "把 data/tools/ 下的工具上传为插件（BOF/DLL/EXE/shellcode），之后用 plugin_load 加载到会话。参数: source, name(可选), description(可选)", []string{"source", "name", "description"}},
		{"fileless_exec", "把 data/tools/ 下的工具按 kind(bof/shellcode/dll/exe) 内存加载执行（不落盘）。参数: session_id, source, kind(可选), args(可选)", []string{"session_id", "source", "kind", "args"}},
		{"run_command", "向会话下发任意命令并返回待轮询任务（task_wait 取结果）。参数: session_id, command", []string{"session_id", "command"}},
		{"user_info", "获取会话当前用户/权限/本机用户", []string{"session_id"}},
		{"system_info", "获取会话系统信息（systeminfo）", []string{"session_id"}},
		{"service_list", "枚举会话上的 Windows 服务", []string{"session_id"}},
		{"check_av", "检测会话上的杀软/EDR 相关进程", []string{"session_id"}},
		{"net_info", "获取会话网络配置（ipconfig /all）", []string{"session_id"}},
		{"net_connections", "列出会话上的网络连接（netstat -ano）", []string{"session_id"}},
		{"env_vars", "获取会话环境变量", []string{"session_id"}},
		{"scheduled_tasks", "列出会话上的计划任务", []string{"session_id"}},
	}
	schemas := make([]ToolSchema, 0, len(defs))
	for _, d := range defs {
		props := map[string]interface{}{}
		required := []string{}
		for _, p := range d.params {
			props[p] = map[string]interface{}{"type": "string", "description": p}
			required = append(required, p)
		}
		schemas = append(schemas, ToolSchema{
			Type: "function",
			Function: ToolSchemaFunction{
				Name:        d.name,
				Description: d.desc,
				Parameters: map[string]interface{}{
					"type":       "object",
					"properties": props,
					"required":   required,
				},
			},
		})
	}
	return schemas
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isRiskyTool 判定一个工具是否影响目标会话（需要在「正常」权限模式下获用户同意）。
// 读取/查询类（session_list/session_context/intel_query/attack_suggest/plugin_list/tunnel_list）
// 与任务流（delegate/playbook_status）除外。
func isRiskyTool(name string) bool {
	switch name {
	case "task_submit", "task_kill", "run_command", "user_info", "system_info",
		"service_list", "check_av", "net_info", "net_connections", "env_vars", "scheduled_tasks",
		"file_list", "file_download", "process_list", "process_kill",
		"screenshot", "credentials", "session_kill", "plugin_load", "fileless_exec",
		"tunnel_start", "tunnel_stop":
		return true
	default:
		return false
	}
}

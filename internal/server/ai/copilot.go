// Package ai 实现 AI 副驾驶：OpenAI 兼容的 LLM 聊天 + 工具调用循环。
// 工具即 internal/server/api 暴露的 MCP 工具（intel_query/session_list/
// session_context/task_submit/attack_suggest），LLM 决策调用、执行结果
// 回喂后继续对话，直至模型产出最终回复或达到轮数上限。
package ai

import (
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
func (c *Copilot) buildMessages(history []Message) []Message {
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
		"收敛原则：拿到足够信息后**必须输出最终中文答复**；同一工具不要重复相同参数。若某操作被权限模式拦截，向用户说明需确认。\n" +
		"任务流编排：当目标可标准化/批量执行时，优先用 delegate 启动任务流（确定性多步链路）执行，再用 playbook_status 轮询进度；" +
		"不要逐个手工重复下发命令。\n" +
		"自主原则：收到目标时先识别信息缺口并补齐（session_context/intel_query/侦察类），再决定行动，无需每步征询用户；" +
		"信息不足时先深入获取，不要臆测。\n" +
		"输出格式：最终答复用 Markdown 结构化——【结论】【关键信息/证据】【下一步建议】，多步操作给清晰编号/表格；" +
		"涉及攻击路径时按红队思维给出横向/提权/凭据/域渗透等优先级建议。\n" +
		"下载约定：需要下载工具/载荷/文件到服务器时，**必须用 remote_download(url)**（服务端下载到 data/tools/，快且可靠，可复用）；" +
		"**严禁**在目标会话上用手动命令（certutil / powershell Invoke-WebRequest / curl / bitsadmin 等）下载——" +
		"那些会在植入端长时间阻塞、URL 易 404、且触发行为检测。下载后用 tool_list 确认，再用 plugin_upload（上传为插件）或 fileless_exec（内存加载）分发使用。"
	if ov := c.currentSessions(); ov != "" {
		sysBase += "\n\n【当前在线会话】\n" + ov +
			"\n以上是当前上线的目标会话。需要时用 session_context 获取某会话详细上下文，结合上下文判断下一步，无需每步都问用户；若上下文不足，先深入获取再给建议。"
	}
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
	b.WriteString(fmt.Sprintf("本轮已达到工具调用轮数上限，先汇报已完成的操作（共 %d 步）：\n\n", len(traces)))
	for i, t := range traces {
		b.WriteString(fmt.Sprintf("%d. **%s**", i+1, t.Name))
		if len(t.Args) > 0 {
			args, _ := json.Marshal(t.Args)
			b.WriteString(fmt.Sprintf(" %s", args))
		}
		b.WriteString("\n")
		if t.Error != "" {
			b.WriteString(fmt.Sprintf("   ❌ 失败: %s\n", t.Error))
			continue
		}
		// 提取关键结果：任务类工具展示 task_id 与状态，查询类展示摘要
		summary := summarizeToolResult(t.Name, t.Result)
		if summary != "" {
			b.WriteString("   ✅ " + summary + "\n")
		}
	}
	b.WriteString("\n如需继续（例如等待某个任务完成、查看某步的完整输出），直接告诉我即可。")
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
		{"remote_download", "从 URL 下载工具到服务端本地 data/tools/ 持久保存（可重复使用）。参数: url", []string{"url"}},
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

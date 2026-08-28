package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"toshell/internal/server/ai"
	"toshell/internal/server/config"
)

// ─── AI 副驾驶：聊天端点 ─────────────────────────────────────────────
// POST /api/v1/copilot/chat  发送一轮对话（携带历史消息），返回助手回复与工具调用轨迹。
// GET  /api/v1/copilot/status 返回 AI 副驾驶配置状态（是否可用/模型名）。

// InvokeTool 实现 ai.ToolExecutor：AI 副驾驶的工具调用与 MCP 端点共用实现。
func (s *Server) InvokeTool(name string, args map[string]string) (interface{}, error) {
	return s.invokeTool(name, args)
}

// ReconfigureCopilot 配置热更新时同步 AI 副驾驶（无需重启进程）。
func (s *Server) ReconfigureCopilot(cfg config.AIConfig) {
	if s.copilot == nil {
		s.copilot = ai.New(cfg, s)
		return
	}
	s.copilot.Reconfigure(cfg)
}

// copilotStatus 返回 AI 副驾驶可用性。
func (s *Server) copilotStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cp := s.copilot
	enabled := cp != nil && cp.Enabled()
	model := ""
	consentMode := "auto"
	if cp != nil {
		model = cp.Config().Model
		consentMode = cp.Config().ConsentMode
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":      enabled,
		"model":        model,
		"consent_mode": consentMode,
		"notice":       "AI 副驾驶：在 configs/server.yaml 配置 ai.base_url/api_key/model 后启用；ai.consent_mode=normal 时影响会话的操作需用户同意（任务流除外）",
	})
}

// copilotChatHandler 单轮对话：接收 {messages:[{role,content}...]}，
// 返回 {reply, traces:[{name,args,result,error}]}。
func (s *Server) copilotChatHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cp := s.copilot
	if cp == nil || !cp.Enabled() {
		http.Error(w, `{"error":"AI copilot not configured (ai.base_url/api_key/model)"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Messages []ai.Message `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 {
		http.Error(w, `{"error":"messages required"}`, http.StatusBadRequest)
		return
	}

	// 限制历史长度：防止上下文爆炸（保留最近 20 条，每条截断字符数控制 token）
	if len(req.Messages) > 20 {
		req.Messages = req.Messages[len(req.Messages)-20:]
	}
	for i, m := range req.Messages {
		if len(m.Content) > 4000 {
			req.Messages[i].Content = m.Content[:4000] + "..."
		}
	}

	// 副驾驶 ReAct + 工具循环可能耗时较长：放宽到 180s（配合上下文压缩减少轮次不再易超时）
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()

	res, err := cp.ChatWithConsent(ctx, req.Messages)
	if err != nil {
		msg := strings.ReplaceAll(err.Error(), `"`, `\"`)
		http.Error(w, `{"error":"`+msg+`"}`, http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reply":            res.Reply,
		"traces":           res.Traces,
		"pending_consents": res.Pending,
	})
}

// copilotConsentHandler 处理用户对副驾驶的操作审批：allow→执行，deny→跳过，然后恢复 ReAct 循环。
// POST /api/v1/copilot/consent  body {token, decision:"allow"|"deny"}
func (s *Server) copilotConsentHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cp := s.copilot
	if cp == nil || !cp.Enabled() {
		http.Error(w, `{"error":"AI copilot not configured"}`, http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Token    string `json:"token"`
		Decision string `json:"decision"` // allow / deny
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, `{"error":"token and decision required"}`, http.StatusBadRequest)
		return
	}
	allow := req.Decision != "deny"

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	res, err := cp.ResolveConsent(ctx, req.Token, allow)
	if err != nil {
		msg := strings.ReplaceAll(err.Error(), `"`, `\"`)
		http.Error(w, `{"error":"`+msg+`"}`, http.StatusNotAcceptable)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reply":            res.Reply,
		"traces":           res.Traces,
		"pending_consents": res.Pending,
	})
}

// ─── 异步自主 Agent 端点 ────────────────────────────────────────────
// POST /api/v1/agent/chat                  创建 run（非阻塞，立即返回 run_id）
// GET  /api/v1/agent/runs/{id}/events       SSE 事件流（thinking/message/tool_start/tool_result/final/done）
// GET  /api/v1/agent/runs/{id}              查询 run 状态/轨迹/最终答复
// POST /api/v1/agent/runs/{id}/cancel       取消 run
// POST /api/v1/agent/runs/{id}/consent      处理审批（allow/deny），恢复自主循环

// agentChatRequest 创建/续接 run 的请求体。messages 为历史消息（含最新用户指令）。
// session_id 用于续接同一个「自主记忆」会话：带空/不带则新建并返回新 run_id 作为 session_id。
// 后续指令带上 session_id 即把新消息追加到同一上下文，保持 agent 的完整记忆。
type agentChatRequest struct {
	Messages   []ai.Message `json:"messages"`
	SessionID  string       `json:"session_id"`
}

// agentChatHandler 创建/续接异步 agent run：立即返回 run_id + session_id，ReAct 循环后台自主运行。
func (s *Server) agentChatHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cp := s.copilot
	if cp == nil || !cp.Enabled() {
		http.Error(w, `{"error":"AI copilot not configured (ai.base_url/api_key/model)"}`, http.StatusServiceUnavailable)
		return
	}
	var req agentChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 {
		http.Error(w, `{"error":"messages required"}`, http.StatusBadRequest)
		return
	}

	// 续接逻辑：带 session_id 且该 run 仍存在 → 追加消息到长期记忆，复用其上下文继续。
	if req.SessionID != "" {
		if run := s.agentMgr.Get(req.SessionID); run != nil {
			newUser := lastUserMessages(req.Messages)
			run.AppendMessages(newUser)
			run.ResetForResume()
			go s.runAgentAsync(context.Background(), run)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"run_id":     run.ID,
				"session_id": run.ID,
				"status":     run.Status,
			})
			return
		}
	}

	// 新建 run：限制历史长度，保留最近 20 条、每条截断控制 token
	if len(req.Messages) > 20 {
		req.Messages = req.Messages[len(req.Messages)-20:]
	}
	for i, m := range req.Messages {
		if len(m.Content) > 4000 {
			req.Messages[i].Content = m.Content[:4000] + "..."
		}
	}

	run := s.agentMgr.NewRun(req.Messages, 0)
	// 并发上限：后台启动，超出则排队等待槽位。
	// 用 context.Background()：run 必须脱离请求生命周期（POST 返回后 r.Context() 即取消），
	// 否则 run 会立即被杀。run 的生命周期独立，靠显式 cancel / 完成结束。
	go s.runAgentAsync(context.Background(), run)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id":     run.ID,
		"session_id": run.ID, // 首次：session_id 即 run_id，前端存下来用于续接
		"status":     run.Status,
	})
}

// lastUserMessages 从请求消息里提取最新一条 user 指令用于续接追加。
func lastUserMessages(msgs []ai.Message) []ai.Message {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return []ai.Message{msgs[i]}
		}
	}
	return msgs
}

// runAgentAsync 后台启动 run；受并发上限约束（超出则等一个 slot 释放）。
func (s *Server) runAgentAsync(parent context.Context, run *ai.AgentRun) {
	cp := s.copilot
	if cp == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// 等待并发槽位（信号量）
	if !s.agentMgr.Acquire(ctx) {
		// 被取消：不执行
		return
	}
	defer s.agentMgr.Release()

	_, err := cp.RunAgent(ctx, run)
	if err != nil { /* RunAgent 内部已 emit error 事件 */
	}
	// 完成后延迟清理：作为「自主记忆」会话保留较久（30 分钟），
	// 以便前端带 session_id 续接时仍能复用同一 run 的完整上下文。
	if run.Status == ai.AgentDone || run.Status == ai.AgentError {
		go func() {
			time.Sleep(30 * time.Minute)
			s.agentMgr.Remove(run.ID)
		}()
	}
}

// resumeAgentAsync 后台恢复一个已挂起的 run（审批后继续自主循环）。
// 使用独立 context（不随请求结束），仍受并发上限约束，且可被 cancel。
func (s *Server) resumeAgentAsync(run *ai.AgentRun) {
	cp := s.copilot
	if cp == nil {
		return
	}
	go func() {
		ctx := context.Background()
		if !s.agentMgr.Acquire(ctx) {
			return
		}
		defer s.agentMgr.Release()
		_, err := cp.RunAgent(ctx, run)
		if err != nil { /* RunAgent 内部已 emit error/无事件 */
		}
		if run.Status == ai.AgentDone || run.Status == ai.AgentError {
			go func() {
				time.Sleep(30 * time.Minute)
				s.agentMgr.Remove(run.ID)
			}()
		}
	}()
}

// agentRunHandler 查询 run 状态、轨迹与最终答复。
func (s *Server) agentRunHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	run := s.agentMgr.Get(agentIDFromPath(r))
	if run == nil {
		http.Error(w, `{"error":"run not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": run.ID,
		"status": run.Status,
		"traces": run.Traces,
		"reply":  run.FinalReply,
	})
}

// agentCancelHandler 取消 run 的循环。
func (s *Server) agentCancelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	run := s.agentMgr.Get(agentIDFromPath(r))
	if run == nil {
		http.Error(w, `{"error":"run not found"}`, http.StatusNotFound)
		return
	}
	run.Cancel()
	json.NewEncoder(w).Encode(map[string]interface{}{"run_id": run.ID, "status": "cancelled"})
}

// agentConsentHandler 处理 run 的审批决定。
func (s *Server) agentConsentHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cp := s.copilot
	if cp == nil || !cp.Enabled() {
		http.Error(w, `{"error":"AI copilot not configured"}`, http.StatusServiceUnavailable)
		return
	}
	run := s.agentMgr.Get(agentIDFromPath(r))
	if run == nil {
		http.Error(w, `{"error":"run not found"}`, http.StatusNotFound)
		return
	}
	var req struct {
		Decision string `json:"decision"` // allow / deny
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	allow := req.Decision != "deny"

	// ResolveAgentConsent：执行/跳过工具并追加结果消息到 run
	if _, err := cp.ResolveAgentConsent(context.Background(), run, allow); err != nil {
		msg := strings.ReplaceAll(err.Error(), `"`, `\"`)
		http.Error(w, `{"error":"`+msg+`"}`, http.StatusNotAcceptable)
		return
	}
	// 恢复自主循环（后台，独立 context，沿用 run 的取消能力）
	s.resumeAgentAsync(run)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": run.ID,
		"status": run.Status,
	})
}

// agentEventsHandler SSE 事件流：实时推送 run 的 thinking/message/tool/final/done。
func (s *Server) agentEventsHandler(w http.ResponseWriter, r *http.Request) {
	cp := s.copilot
	if cp == nil || !cp.Enabled() {
		http.Error(w, `{"error":"AI copilot not configured"}`, http.StatusServiceUnavailable)
		return
	}
	run := s.agentMgr.Get(agentIDFromPath(r))
	if run == nil {
		http.Error(w, `{"error":"run not found"}`, http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// 推一个初始状态事件
	writeSSE(w, flusher, "status", map[string]interface{}{"run_id": run.ID, "status": run.Status})
	// 若 run 已结束（订阅晚于执行结束），直接回放最终状态
	if run.Status == ai.AgentDone || run.Status == ai.AgentError {
		writeSSE(w, flusher, "state", map[string]interface{}{"done": true, "reply": run.FinalReply})
		return
	}

	// 订阅事件
	events := run.Events()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			writeSSE(w, flusher, string(ev.Kind), dataPayload(ev))
			if ev.Kind == ai.AgentEventDone || ev.Kind == ai.AgentEventError {
				writeSSE(w, flusher, "state", map[string]interface{}{"done": true, "error": ev.Error})
				return
			}
		}
	}
}

// writeSSE 写一行 SSE 事件（event + data）。
func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	b, _ := json.Marshal(data)
	w.Write([]byte("event: " + event + "\ndata: " + string(b) + "\n\n"))
	flusher.Flush()
}

// dataPayload 把 AgentEvent 的 Data 反序列化为可发送对象（无 data 则用空对象）。
func dataPayload(ev ai.AgentEvent) interface{} {
	if len(ev.Data) == 0 {
		if ev.Error != "" {
			return map[string]interface{}{"error": ev.Error}
		}
		return map[string]interface{}{}
	}
	return json.RawMessage(ev.Data)
}

// agentIDFromPath 从请求路径里取出 run id（/api/v1/agent/runs/{id}[/...])。
// 稳健解析：找到路径段 "runs" 后面紧跟的那一段即为 id，兼容带/不带子路径两种形式。
func agentIDFromPath(r *http.Request) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, p := range parts {
		if p == "runs" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	// 兜底：取倒数第二段（形如 .../runs/{id}/events）
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

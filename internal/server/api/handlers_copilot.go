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

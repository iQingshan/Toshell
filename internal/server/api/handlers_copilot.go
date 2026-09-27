package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
		// 重建出来的 Copilot 必须重新注入结果外置存储：否则热更新一次之后
		// "超限结果外置 + result_read 回读"就静默退化成无句柄的内联截断（很难发现）。
		s.applyResultStore(s.copilot)
		// 同理必须重新注入长任务通道：否则"AI 原本未启用、后来在设置页启用"这条路径上
		// 造出来的 Copilot 没有 longTasks，所有工具都会静默退回同步等待（并发槽位重新被
		// 分钟级工具占满），而且不会有任何报错 —— 只有重启服务端才会恢复。
		s.applyLongTaskExecutor(s.copilot)
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
	// 生效策略统一由 ai.EffectiveConsentPolicy 解析（与循环里的判定同一个函数）：
	// consent_policy 是 v1.4.0 的新键，consent_mode 作为旧键继续回传（auto/normal 映射）。
	policy := ai.EffectiveConsentPolicy("", "")
	if cp != nil {
		model = cp.Config().Model
		cfg := cp.Config()
		policy = ai.EffectiveConsentPolicy(cfg.ConsentPolicy, cfg.ConsentMode)
	}
	legacyMode := "normal"
	if policy == ai.ConsentPolicyOff {
		legacyMode = "auto"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":        enabled,
		"model":          model,
		"consent_policy": policy,
		"consent_mode":   legacyMode,
		"notice":         "AI 副驾驶：在 configs/server.yaml 配置 ai.base_url/api_key/model 后启用；ai.consent_policy=graded（默认）时查询/影响类工具需用户同意，all=全部需同意，off=全自动",
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
		"trace_id":         res.TraceID,
		"stop_reason":      res.StopReason,
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
		"trace_id":         res.TraceID,
		"stop_reason":      res.StopReason,
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
	Messages  []ai.Message `json:"messages"`
	SessionID string       `json:"session_id"`
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
				"trace_id":   run.TraceID,
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
		"trace_id":   run.TraceID,
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
	// 挂起（等审批 / 等长任务）**不是终态**：run 必须留在内存里等外部事件唤醒恢复，
	// 绝不能按"已完成"清理——清掉就再也没有东西能把它接回来了。
	status, _ := run.WaitState()
	if status == ai.AgentWaitConsent || status == ai.AgentWaitTask {
		return
	}
	// 完成后延迟清理：作为「自主记忆」会话保留较久（30 分钟），
	// 以便前端带 session_id 续接时仍能复用同一 run 的完整上下文。
	if status == ai.AgentDone || status == ai.AgentError {
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
		status, _ := run.WaitState()
		if status == ai.AgentWaitConsent || status == ai.AgentWaitTask {
			return
		}
		if status == ai.AgentDone || status == ai.AgentError {
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
	// 等待态必须"看得见"：status 会是 awaiting_task/awaiting_consent，
	// waiting_on 描述在等谁（新增可选字段，既有字段名与语义不变）。
	status, waitingOn := run.WaitState()
	taskID, taskTimeout := run.PendingTaskInfo()
	// v1.4.0 S2 可观测性：当前上下文估算 token / 是否被压缩过 / 本 run 累计 token。
	// 全部是**新增可选字段**，既有字段名与语义一律不变（老前端忽略即可）。
	ctxTokens, ctxBudget, ctxCompressed := run.ContextSnapshot()
	tokenUsage := run.TokenUsage()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id":           run.ID,
		"status":           status,
		"objective":        run.Objective,
		"plan":             run.Plan,
		"traces":           run.Traces,
		"timeline":         run.Timeline,
		"reply":            run.FinalReply,
		"trace_id":         run.TraceID,
		"stop_reason":      run.StopReason,
		"waiting_on":       waitingOn,
		"task_id":          taskID,
		"task_timeout_sec": taskTimeout,
		// 上下文与 token（新增可选）
		"context_tokens":           ctxTokens,
		"context_budget_tokens":    ctxBudget,
		"context_compressed":       ctxCompressed,
		"prompt_tokens":            tokenUsage.PromptTokens,
		"completion_tokens":        tokenUsage.CompletionTokens,
		"token_usage_estimated":    tokenUsage.EstimatedTokens,
		"token_usage_total":        tokenUsage.Total(),
		"token_calibration_factor": tokenUsage.Calibration.EffectiveFactor(),
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

// ─── SSE 事件流（含断点续传，v1.4.0 S2）───────────────────────────────
//
// 对外契约**只新增可选内容**，既有事件名/字段名一律不动：
//   - 每条 run 事件多一行 `id: <seq>`（run 内单调递增，从 1 开始）；
//   - 对象载荷里额外注入 `seq`/`run_id`/`ts`（thinking/message/final 的 data 仍是
//     JSON 字符串，原因见 ai.buildEventPayload —— 包成对象会破坏老前端的字符串累加）；
//   - 连接建立时发 `retry: <ms>`（SSE 规范的自动重连间隔建议）；
//   - 空闲时周期性发心跳注释帧 `:\n\n`（是注释，不是事件，不进回放缓冲）；
//   - 新增事件 `resync`（载荷见 ai.ResyncInfo），仅在缺口无法补齐时出现。
//
// 续传参数：`Last-Event-ID` 请求头优先，其次 `?last_event_id=<seq>`
// （浏览器 EventSource 无法自定义请求头；非 EventSource 客户端也可用它显式要求
// "从某个 seq 之后给我"，例如 ?last_event_id=0 = 把缓冲里的都给我）。
const agentSSERetryMS = 3000

// agentSSEHeartbeatInterval 心跳间隔。用变量（不是常量）方便单测压到毫秒级验证。
var agentSSEHeartbeatInterval = 15 * time.Second

// agentEventsHandler SSE 事件流：实时推送 run 的 thinking/message/tool/final/done，
// 并支持基于 `id:` / `Last-Event-ID` 的断点续传（v1.4.0 S2）。
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

	// 重连间隔建议（SSE 规范字段，控制帧不带 id:）。
	fmt.Fprintf(w, "retry: %d\n\n", agentSSERetryMS)
	flusher.Flush()

	// 初始状态帧：控制帧，**不带 id:**——它不对应任何 run 事件，带上会把客户端的
	// 续传水位线推到一个虚假位置，重连时反而漏掉真正的事件。
	writeSSE(w, flusher, "status", map[string]interface{}{"run_id": run.ID, "status": run.Status})

	lastID, hasLastID := parseLastEventID(r)

	// ── 交接算法（"不重不丢"的关键）──────────────────────────────────
	//  ① 先拿 live 通道引用（与丢弃通知）；
	//  ② 再取环形缓冲快照：seq 分配与快照在同一把锁下互斥，所以"seq > 快照 Head
	//     的事件"必然产生于快照之后 —— 它们的投递只有两种结局：成功进通道（我们在
	//     读，必然按 seq 升序收到）或被丢弃（丢弃水位会显式告知），没有第三条路；
	//  ③ 回放 (L, Head] 的缓冲事件，边发边把 lastSent 推到已发位置；
	//  ④ 切实时：通道里读到的 seq ≤ lastSent 一律跳过 —— 那正是"同一条事件既在
	//     快照里、也在通道里各出现一次"的重叠部分（快照与通道之间没有任何真空期，
	//     重叠是必然的，去重比"保证不重叠"可靠得多）。
	//
	// 反过来"先回放、后订阅"为什么不行：回放期间产生的事件只能靠通道缓冲兜住，
	// 一旦缓冲被填满（thinking 密集时真的会），这段窗口里的事件既不在我们回放过的
	// 快照里、也不会被我们读到，就成了**静默丢失**。先订阅后快照把保证建立在
	// "我们已经持有通道"上，而不是"缓冲区恰好还有余量"上。
	events := run.Events()
	drops := run.DropNotify()
	snap := run.EventSnapshot()
	terminal := run.Status == ai.AgentDone || run.Status == ai.AgentError

	var replay []ai.RingEvent
	var lastSent uint64
	switch {
	case hasLastID && lastID > snap.Head:
		// 客户端水位线比服务端还高：重启后 run 被恢复（同一个 run id、内存序号从头开始）、
		// 或者压根是个脏 id。这里按"从当前开始"处理，**绝不能**把 lastSent 设成 lastID：
		// 那样新事件（seq 从 1 重新开始）会一直小于水位线而被去重逻辑全部跳过，
		// 客户端表现为永久黑屏 —— 宁可让它多收到几条，也不能让它一条都收不到。
		lastSent = snap.Head
	case hasLastID && lastID+1 < snap.Oldest:
		// 需要的事件已经被淘汰：补充不了，必须显式告知（不能假装连续）。
		writeResync(w, flusher, ai.ResyncInfo{
			Reason: "events_expired", Oldest: snap.Oldest, Current: snap.Head,
			Status: string(run.Status), Reply: run.FinalReply, Ts: time.Now().UnixMilli(),
		})
		// 之后只推实时事件：与其补一段中间缺了一块的"半个故事"，不如让客户端
		// 按 resync 的提示去重取 run 详情，再从这里接着看。
		lastSent = snap.Head
	case hasLastID:
		replay = snap.After(lastID)
	case terminal:
		// 无水位线的终态晚订阅：回放缓冲尾部（有上限），让晚到者也能看到
		// thinking/tool 过程，再推终态事件。运行中的 run 不在这个分支：
		// "从当前开始"才是它的语义（要全量回放可显式传 ?last_event_id=0）。
		replay = snap.Tail(ai.AgentReplayTailMax)
	default:
		lastSent = snap.Head
	}

	// floor：本连接"从哪个 seq 开始覆盖内容"（回放第一条之前 / 客户端水位线）。
	// 只有落在它之后的丢弃才与这条连接相关（否则是连接开始前就发生、客户端本来
	// 也看不到的内容缺失，报出来只是噪音）。
	floor := lastSent
	if len(replay) > 0 {
		floor = replay[0].Seq - 1
	}
	if hasLastID && lastID <= snap.Head {
		floor = lastID
	}

	for _, rec := range replay {
		writeRingEvent(w, flusher, rec)
		lastSent = rec.Seq
	}
	// 连接建立时先补报一次丢弃缺口（运行中丢过的事件谁也没收到，回放里也没有）。
	dropReported := reportDrop(w, flusher, run, floor)

	// 终态 run：回放之后推终态事件就收尾（state 保留，老前端兼容）。
	if terminal {
		writeSSE(w, flusher, "state", map[string]interface{}{"done": true, "reply": run.FinalReply})
		return
	}

	hb := time.NewTicker(agentSSEHeartbeatInterval)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			// 心跳注释帧（`:` 开头的行是 SSE 注释）：不是事件、不进回放缓冲、不占 seq，
			// 只为防止中间的代理/防火墙把空闲的长连接掐掉。
			w.Write([]byte(":\n\n"))
			flusher.Flush()
		case <-drops:
			// 通道满时 emit 敲醒我们：读真实丢弃水位并告知客户端。
			if !dropReported {
				dropReported = reportDrop(w, flusher, run, floor)
			}
		case ev, ok := <-events:
			if !ok {
				// run 结束（事件通道关闭）：收尾前把还没告知的缺口补报一次，
				// 否则"最后一次 emit 被丢弃、随后 run 结束"就是一次静默缺口。
				if !dropReported {
					reportDrop(w, flusher, run, floor)
				}
				return
			}
			if ev.Seq != 0 && ev.Seq <= lastSent {
				continue // 回放/实时流的重叠：同一条事件只发一次
			}
			writeAgentEvent(w, flusher, ev)
			if ev.Seq > lastSent {
				lastSent = ev.Seq
			}
			if !dropReported {
				dropReported = reportDrop(w, flusher, run, floor)
			}
			if ev.Kind == ai.AgentEventDone || ev.Kind == ai.AgentEventError {
				writeSSE(w, flusher, "state", map[string]interface{}{"done": true, "error": ev.Error})
				return
			}
		}
	}
}

// parseLastEventID 读客户端续传水位线：Last-Event-ID 头优先，其次 ?last_event_id=。
// 缺失或非数字一律当作"没有水位线"（宁可回到默认语义，也不要瞎猜一个序号）。
func parseLastEventID(r *http.Request) (uint64, bool) {
	raw := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("last_event_id"))
	}
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// reportDrop 在"缺口落在本连接覆盖范围内"时发一条 resync{events_dropped}。
//
// 一条连接只报一次：resync 的语义是"这条流不完整，去重取 run 详情"，
// 客户端已经知道之后，再刷屏没有新信息（丢了多少条由 dropped_count 给出）。
// 返回 true 表示本次（或之前）已经报过。
func reportDrop(w http.ResponseWriter, flusher http.Flusher, run *ai.AgentRun, floor uint64) bool {
	after, count, status, reply := run.DropState()
	if count == 0 || after < floor {
		return false
	}
	writeResync(w, flusher, ai.ResyncInfo{
		Reason: "events_dropped", DroppedAfter: after, DroppedCount: count,
		Status: string(status), Reply: reply, Ts: time.Now().UnixMilli(),
	})
	return true
}

// writeResync 写一条 resync 控制帧（不带 id:，理由同 status）。
func writeResync(w http.ResponseWriter, flusher http.Flusher, info ai.ResyncInfo) {
	writeSSE(w, flusher, string(ai.AgentEventResync), info)
}

// writeAgentEvent 写一条实时 run 事件（载荷已在 emit 时序列化并注入 seq/run_id/ts）。
func writeAgentEvent(w http.ResponseWriter, flusher http.Flusher, ev ai.AgentEvent) {
	payload := ev.Payload
	if len(payload) == 0 {
		// 兜底：没有预序列化载荷的事件（理论上不该出现）现场序列化。
		b, _ := json.Marshal(dataPayload(ev))
		payload = b
	}
	writeSSERaw(w, flusher, ev.Seq, string(ev.Kind), payload)
}

// writeRingEvent 写一条回放事件：载荷是缓冲里存好的字节，零解析、零再序列化。
func writeRingEvent(w http.ResponseWriter, flusher http.Flusher, rec ai.RingEvent) {
	writeSSERaw(w, flusher, rec.Seq, string(rec.Kind), rec.Payload)
}

// writeSSE 写一个控制帧（无 id）。
func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	b, _ := json.Marshal(data)
	writeSSERaw(w, flusher, 0, event, b)
}

// writeSSERaw 组装一个 SSE 帧；seq>0 时带 `id:`。
func writeSSERaw(w http.ResponseWriter, flusher http.Flusher, seq uint64, event string, data []byte) {
	if seq > 0 {
		fmt.Fprintf(w, "id: %d\n", seq)
	}
	w.Write([]byte("event: " + event + "\ndata: "))
	w.Write(data)
	w.Write([]byte("\n\n"))
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

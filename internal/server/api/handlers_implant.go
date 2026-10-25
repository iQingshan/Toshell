package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/protocol"
	"toshell/internal/common/types"
	"toshell/internal/server/task"
)

// ─── 植入端协议兼容端点（历史兼容，审计 H1/M1/M4）───────────────────────────────
//
// 背景：植入端模板**不使用**这三个端点（模板里唯一出现 /api/v1/implant 的是
// uac_windows.go 的 /api/v1/implant/uac/<token>，那是另一个免认证端点）。它们只是
// 为老工具/脚本保留的兼容入口。但在 2026-10-24 的审计里，它们因为“未认证 + 只按
// TaskID 操作全局状态”成为 High（H1）与 Medium（M1/M4）：
//
//   - /result：任何人可伪造/终止任意任务结果（TaskID 是进程内全局递增、可预测）；
//   - /register：任何人可伪造会话并触发上线通知（通知轰炸）；
//   - /heartbeat：任何人可覆盖**所有**会话指标，并把已死会话状态置回 active；
//   - 三者都无请求体上限，32 MiB body 可被完整读入内存。
//
// 现在的三层防护：
//  1. 路由层：/api/v1/implant/{register,heartbeat,result} 挂 auth.Middleware
//     （JWT 或 X-API-Key，见 api.go 的 setupRoutes）；
//  2. Web 防护层：这三个路径不再命中 implantExemptPrefixes，与其它管理 API 一样
//     经过 webGate；
//  3. handler 层：结果必须带 SessionID 且与任务归属一致；心跳只能写自己那条会话，
//     且不能把 dead/离线会话改回 active。
//
// 只有 /api/v1/implant/payload/ 与 /api/v1/implant/uac/ 仍然免认证 —— 这是产品有意
// 设计（目标机在没有任何凭据时必须能下载载荷），不属于本文件的 handler。

// implantMaxBodyBytes 兼容端点的请求体上限（审计 M4）。
// 64 KiB 足够注册信息/心跳指标/单条任务结果这些小型 JSON；任务输出本身走监听器
// 通道，不经过这里。超限直接 413，避免把 32 MiB 甚至更大的 body 读进内存。
const implantMaxBodyBytes = 64 << 10

// implantSessionID 从 SessionID / session_id 两种写法里取非空值。
//
// 兼容两种风格：老脚本/Go 工具用结构体字段名（SessionID），新脚本习惯 snake_case。
// 三个兼容端点现在都要求显式给出会话身份（审计 H1 的修复前提：认证只能证明
// “你是管理员”，不能证明“你是这条结果的归属会话”）。
func implantSessionID(sessionID, sessionIDAlt string) string {
	if v := strings.TrimSpace(sessionID); v != "" {
		return v
	}
	return strings.TrimSpace(sessionIDAlt)
}

// validImplantSessionID 校验注册端点显式指定的会话 ID。
// 会话 ID 会进日志、数据库与前端事件，限制为可打印、无路径分隔符的单段字符串；
// 这不是“认证”（认证由 auth.Middleware 负责），只是拒绝明显异常的输入。
func validImplantSessionID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// decodeImplantJSON 读取并解析兼容端点的 JSON body，超限/非法时直接写响应并返回 false。
//
// 先整体读入（在 MaxBytesReader 的 64 KiB 闸门之后）再 Unmarshal，而不是用 Decoder
// 只读第一个 JSON 值：这样“合法 JSON + 32 MiB 尾部垃圾”也会被算进上限并回 413，
// 不会出现“解析成功就返回 200、尾部的超大 body 仍留在连接里”的盲区。
func decodeImplantJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, implantMaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("请求体超过 %d 字节上限（兼容端点只接受小型 JSON）", implantMaxBodyBytes))
			return false
		}
		writeJSONError(w, http.StatusBadRequest, "读取请求体失败")
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return false
	}
	return true
}

// ─── register ────────────────────────────────────────────────────────────────

// implantRegisterNotifyMinInterval 同一来源 IP 触发上线通知的最小间隔。
//
// 为什么需要（审计 M1）：register 现在虽然要求管理员凭据，但一个写错的脚本/循环
// 重试仍会每秒注册一批不同 ID 的假会话，每次 BroadcastSessionOnline 都会推一条
// 上线事件（前端/未来的 webhook 接收端被打爆）。按来源 IP 做简单内存限频：
// 同一 IP 60 秒内最多触发 1 次上线通知；注册本身照常成功（幂等更新会话），
// 只是不再广播。
//
// 注意：这是防“管理员误用”的，不是防“有凭据的攻击者”——持有管理员凭据的人本来
// 就能直接读会话/发任务，限频挡不住也不需要挡。
const implantRegisterNotifyMinInterval = time.Minute

var (
	implantNotifyMu   sync.Mutex
	implantNotifyLast = map[string]time.Time{}
)

// allowImplantRegisterNotify 报告本次是否允许触发上线通知（纯内存、按 IP 限频）。
func allowImplantRegisterNotify(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	implantNotifyMu.Lock()
	defer implantNotifyMu.Unlock()
	if last, ok := implantNotifyLast[ip]; ok && now.Sub(last) < implantRegisterNotifyMinInterval {
		return false
	}
	implantNotifyLast[ip] = now
	// 惰性清理：条目数超过阈值时清掉已过窗口的 IP，避免长期运行内存增长。
	if len(implantNotifyLast) > 1024 {
		cutoff := now.Add(-implantRegisterNotifyMinInterval)
		for k, t := range implantNotifyLast {
			if t.Before(cutoff) {
				delete(implantNotifyLast, k)
			}
		}
	}
	return true
}

// implantRegisterHandler 兼容端点：显式注册（或刷新）一条会话。
//
// SessionID 必填：既然现在只有管理员能调用，会话身份就由调用方显式指定，
// 而不是从请求字节里拼一个不可信 ID（旧实现是 hex(body[:8]) + UnixNano，
// 既不可控又会在 body<8 时 panic）。同名会话已存在时按“重连注册”刷新其信息，
// 保留 Session 对象本身（隧道/shell handler 不会丢）。
func (s *Server) implantRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		protocol.Register
		SessionID    string `json:"SessionID"`
		SessionIDAlt string `json:"session_id"`
	}
	if !decodeImplantJSON(w, r, &body) {
		return
	}

	sessionID := implantSessionID(body.SessionID, body.SessionIDAlt)
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少 SessionID：注册端点要求显式给出会话 ID（SessionID 或 session_id）")
		return
	}
	if !validImplantSessionID(sessionID) {
		writeJSONError(w, http.StatusBadRequest, "SessionID 非法：只允许 1-128 个可打印字符，且不能包含 / 或 \\")
		return
	}
	if s.sessionMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session manager 未就绪")
		return
	}

	now := time.Now()
	sessInfo := &types.SessionInfo{
		ID:           sessionID,
		Hostname:     body.Hostname,
		Username:     body.Username,
		OS:           body.OS,
		Arch:         body.Arch,
		PID:          body.PID,
		ProcessName:  body.ProcessName,
		ProcessPath:  body.ProcessPath,
		IPAddresses:  body.IPAddresses,
		MACAddresses: body.MACAddresses,
		Domain:       body.Domain,
		FirstSeen:    now,
		LastSeen:     now,
		Status:       "active",
		Listener:     "api",
		RemoteAddr:   r.RemoteAddr,
	}

	if err := s.sessionMgr.Add(sessInfo); err != nil {
		// 会话已存在：按重连注册刷新（保留原 Session 对象，避免隧道/shell handler 丢失）。
		if uerr := s.sessionMgr.RefreshInfo(sessionID, sessInfo); uerr != nil {
			writeJSONError(w, http.StatusInternalServerError, "注册会话失败："+uerr.Error())
			return
		}
	}

	fmt.Printf("[INFO] [implant] Session registered via authenticated API: %s (%s@%s)\n",
		sessionID, body.Username, body.Hostname)

	// 通知限频：同一 IP 每分钟最多触发一次上线通知（审计 M1 的通知轰炸）。
	if allowImplantRegisterNotify(clientIP(r)) {
		s.BroadcastSessionOnline(sessInfo)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"registered"}`))
}

// ─── heartbeat ───────────────────────────────────────────────────────────────

// implantHeartbeatHandler 兼容端点：只刷新**请求体指定**的那一条会话。
//
// 审计 M1 修复要点：
//   - 旧实现遍历所有会话，把同一份心跳无条件写给每一条（跨会话污染）；
//   - 旧实现按存活判定把 dead 会话状态写回 active（无限复活）。
//
// 现在的选择是“**拒绝**已 dead/离线会话的心跳”，而不是“只更新指标不改状态”。
// 理由：LastSeen 是判活的唯一依据（Session.IsAlive 只看向 LastSeen），只要刷新
// LastSeen，ListInfo/GetStatus 就会把会话重新算成 active —— 那正是审计说的“复活”。
// 所以对已 dead/离线的会话，状态与指标一律不写，返回 409：想复活请走注册端点
// 或由监听器重连，语义清晰且不会留下“指标变了但状态没变”的半更新。
func (s *Server) implantHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		protocol.Heartbeat
		SessionID    string `json:"SessionID"`
		SessionIDAlt string `json:"session_id"`
	}
	if !decodeImplantJSON(w, r, &body) {
		return
	}

	sessionID := implantSessionID(body.SessionID, body.SessionIDAlt)
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少 SessionID：心跳端点要求显式给出会话 ID（SessionID 或 session_id）")
		return
	}
	if s.sessionMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session manager 未就绪")
		return
	}

	// 用 ListInfo 的副本判状态：它已经在锁内算出 active/asleep，避免直接裸读
	// 共享的 Session.Info（listener 可能并发置 dead）。
	status, ok := s.implantSessionLiveStatus(sessionID)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "session not found: "+sessionID)
		return
	}
	if status != "active" {
		writeJSONError(w, http.StatusConflict,
			"会话已离线/已判死，拒绝心跳复活；请重新注册或由监听器重连")
		return
	}

	if err := s.sessionMgr.UpdateHeartbeat(sessionID, &body.Heartbeat); err != nil {
		if strings.Contains(err.Error(), "session not found") {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// implantSessionLiveStatus 返回会话的展示状态（active/asleep/dead）以及是否存在。
// 走 ListInfo 的副本而不是裸读共享指针：listener 与判活检查会并发改 Status/LastSeen。
func (s *Server) implantSessionLiveStatus(sessionID string) (string, bool) {
	for _, info := range s.sessionMgr.ListInfo() {
		if info.ID == sessionID {
			return info.Status, true
		}
	}
	return "", false
}

// ─── result ──────────────────────────────────────────────────────────────────

// implantResultHandler 兼容端点：上报任务结果。
//
// 审计 H1 的修复核心：TaskID 是进程内全局递增、极易预测；旧实现只按 TaskID
// 调 Complete/Fail，不校验归属，于是任何能打这个端点的人都能伪造/终止任意任务，
// 并把可控文本送进 Agent 的上下文。现在：
//   - 认证层保证调用者是管理员；
//   - 这里再要求显式 SessionID，且必须是真实存在的会话；
//   - 用 CompleteForSession/FailWithResultForSession 校验 task.SessionID == SessionID，
//     归属不符直接 403，任务状态一点不改。
func (s *Server) implantResultHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		protocol.Result
		SessionID    string `json:"SessionID"`
		SessionIDAlt string `json:"session_id"`
	}
	if !decodeImplantJSON(w, r, &body) {
		return
	}

	sessionID := implantSessionID(body.SessionID, body.SessionIDAlt)
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少 SessionID：结果端点要求显式给出上报会话（SessionID 或 session_id）")
		return
	}
	if s.sessionMgr == nil || s.taskMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session/task manager 未就绪")
		return
	}
	if _, err := s.sessionMgr.Get(sessionID); err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found: "+sessionID)
		return
	}
	if body.TaskID == 0 {
		writeJSONError(w, http.StatusBadRequest, "缺少 TaskID")
		return
	}

	if body.ExitCode == 0 && body.Error == "" {
		if err := s.taskMgr.CompleteForSession(body.TaskID, sessionID, body.ExitCode, body.Output); err != nil {
			writeImplantResultError(w, err)
			return
		}

		// 摘要：按 rune 边界截断 + 展示层编码归一（旧 output[:200] 会切坏中文）
		outputSummary := summarizeOutput(body.Output, 200)

		// Broadcast task_completed event
		if s.wsHub != nil {
			taskInfo, err := s.taskMgr.Get(body.TaskID)
			taskType := ""
			if err == nil && taskInfo != nil {
				taskType = taskInfo.TaskType
			}

			s.wsHub.Broadcast(WSEvent{
				Type: "task_completed",
				Payload: map[string]interface{}{
					"task_id":    body.TaskID,
					"task_type":  taskType,
					"session_id": sessionID,
					"exit_code":  body.ExitCode,
					"output":     outputSummary,
				},
			})
		}
	} else {
		// 失败也要留下输出与退出码（v1.4.0 S6 P0-2 的既定语义；旧路径用
		// FailWithResult，这里用带归属校验的同语义版本）。
		if err := s.taskMgr.FailWithResultForSession(body.TaskID, sessionID, body.ExitCode, body.Output, body.Error); err != nil {
			writeImplantResultError(w, err)
			return
		}

		// Broadcast task_failed event
		if s.wsHub != nil {
			taskInfo, _ := s.taskMgr.Get(body.TaskID)
			taskType := ""
			if taskInfo != nil {
				taskType = taskInfo.TaskType
			}

			s.wsHub.Broadcast(WSEvent{
				Type: "task_failed",
				Payload: map[string]interface{}{
					"task_id":    body.TaskID,
					"task_type":  taskType,
					"session_id": sessionID,
					"exit_code":  body.ExitCode,
					"output":     summarizeOutput(body.Output, 200),
					"error":      displayOutput(body.Error),
				},
			})
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// writeImplantResultError 把 task 层的归属/存在性错误映射成明确的 HTTP 状态码。
func writeImplantResultError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, task.ErrTaskNotOwnedBySession):
		writeJSONError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, task.ErrTaskNotFound) || strings.Contains(err.Error(), "task not found"):
		writeJSONError(w, http.StatusNotFound, err.Error())
	default:
		writeJSONError(w, http.StatusBadRequest, err.Error())
	}
}

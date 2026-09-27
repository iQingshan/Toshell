package api

import (
	"net/http"
)

// sessionGuard 会话存在性预检（v1.4.0 工程质量修复）。
//
// 为什么需要它：现在多数"下发任务"的 handler 直接把 `taskMgr.Create*` 的错误一律当 500 返回，
// 而 `task.Manager.Create` 在会话不存在时返回的是 `session not found: <id>` —— 于是一个
// **客户端输入错误**（会话 id 写错/会话已下线并被清理）被报成 **5xx 服务端故障**：
//
//   - 调用方（脚本/外部 MCP 客户端）会以为服务端坏了并触发重试，而不是修正会话 id；
//   - 监控与告警把这类 5xx 计入服务端错误率，掩盖真正的问题；
//   - 路由存在性探测（`scripts/e2e_smoke.ps1`）明确把"会话不存在应返回 4xx"列为验收点。
//
// 语义约定（本文件是全项目这一约定的唯一出处，新 handler 请复用）：
//
//	会话不存在 / 非 active → 404 session_not_found（客户端输入问题，别重试）
//	listener 未就绪       → 503 listener_unavailable（服务端暂时不可用，可退避重试）
//	其余框架内部错误       → 保持 500（真正的服务端故障）
//
// 注意：这里只做**存在性**判定，与 `task.Manager.Create` 的校验口径保持一致（它也只 Get 一次），
// 不额外要求会话 active —— 已下线的会话仍允许创建任务（心跳恢复后会被取走），这是既有语义。
func (s *Server) requireSession(w http.ResponseWriter, id string) bool {
	if s.sessionMgr == nil {
		return true // 未装配会话管理器（单测/精简装配）时不拦截，交给下游判定
	}
	sess, err := s.sessionMgr.Get(id)
	if err != nil || sess == nil || sess.Info == nil {
		http.Error(w, `{"error":"session not found: `+id+`"}`, http.StatusNotFound)
		return false
	}
	return true
}

// requireListener listener 未就绪 → 503（此前是 500：这是"暂时不可用"，不是"内部错误"）。
func (s *Server) requireListener(w http.ResponseWriter) bool {
	if s.listener == nil {
		http.Error(w, `{"error":"listener not available"}`, http.StatusServiceUnavailable)
		return false
	}
	return true
}

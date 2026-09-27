package api

import (
	"net/http"

	"github.com/gorilla/mux"
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
//	会话不存在            → 404 session_not_found（客户端输入问题，别重试）
//	会话存在但需要 active  → 由 handler 自己判（见下），本文件不代劳
//	listener 未就绪       → 503 listener_unavailable（服务端暂时不可用，可退避重试）
//	其余框架内部错误       → 保持 500（真正的服务端故障）
//
// ⚠️ **这里只判"存在性"，不判 active**（v1.4.0 S5 复核时明确）：口径与 `task.Manager.Create`
// 完全一致（它也只 Get 一次），因为"已下线但仍在库/内存里的会话"依然允许创建任务（心跳恢复后
// 会被取走），这是既有语义。**需要 active 的下发路径请在 handler 里自己加判定**
// （例如 `internal/server/api/handlers_modules.go` 的模块下发就显式要求 active；
// 不要指望本函数——曾经本文件的注释写成"非 active → 404"，与实现不符，容易误导后来者）。
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

// requireSessionFromPath 从 URL 路径参数（mux 变量名固定为 `id`）取会话 id 并做存在性预检。
//
// 存在意义：本项目的会话级路由**全部**是 `/sessions/{id}/...` 形态，散落的
// `if _, err := s.sessionMgr.Get(id); err != nil { 500 }` 很容易写漏或写错状态码。
// 统一走这个薄封装，新 handler 只要一行即可获得正确的 404 语义。
func (s *Server) requireSessionFromPath(w http.ResponseWriter, r *http.Request) bool {
	return s.requireSession(w, sessionIDFromPath(r))
}

// sessionIDFromPath 取路径里的会话 id（无 mux 变量时返回空串）。
func sessionIDFromPath(r *http.Request) string {
	if r == nil {
		return ""
	}
	if vars := mux.Vars(r); vars != nil {
		return vars["id"]
	}
	return ""
}

// requireListener listener 未就绪 → 503（此前是 500：这是"暂时不可用"，不是"内部错误"）。
func (s *Server) requireListener(w http.ResponseWriter) bool {
	if s.listener == nil {
		http.Error(w, `{"error":"listener not available"}`, http.StatusServiceUnavailable)
		return false
	}
	return true
}

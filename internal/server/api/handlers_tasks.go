package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"unicode/utf8"

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

	// 列表同样只回展示副本：Output 已做编码归一（原始结果仍在 task/DB 里）。
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": taskDisplays(tasks),
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

// taskCreateMaxBodyBytes 创建任务端点（POST /api/v1/tasks）的请求体上限（审计 N2/M4 收口）。
//
// 1 MiB：command/args 是操作员手输的命令行，正常请求几百字节；1 MiB 已经比任何
// 正常任务大三个数量级。任务输出走监听器通道回传，不经过这个端点。超限 413。
const taskCreateMaxBodyBytes = 1 << 20

func (s *Server) createTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, ok := readBodyLimited(w, r, taskCreateMaxBodyBytes, "创建任务")
	if !ok {
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

	// raw=1：回读**原始字节**（不转换），给排障/取证/下载用。
	// 为什么用 base64：原始输出可能是非法 UTF-8（GBK/二进制），JSON 字符串承载不了，
	// 直接塞进 output 会被替换成 U+FFFD —— 那等于把"原始结果可回读"这条边界弄丢。
	// 默认（不带 raw）：output/error 是服务端按展示解码后的文本（GBK → UTF-8）。
	if raw := r.URL.Query().Get("raw"); raw == "1" || raw == "true" {
		// 用"先序列化再补字段"而不是手抄一遍字段名：TaskInfo 新增字段时这里自动跟上。
		payload := map[string]interface{}{}
		if b, merr := json.Marshal(t); merr == nil {
			_ = json.Unmarshal(b, &payload)
		}
		payload["output"] = t.Output // 原样（非法 UTF-8 会被 JSON 标成 U+FFFD，仅供兼容）
		payload["output_b64"] = base64.StdEncoding.EncodeToString([]byte(t.Output))
		payload["output_bytes"] = len(t.Output)
		payload["output_encoding"] = "raw"
		payload["output_is_binary"] = !utf8.ValidString(t.Output)
		payload["error"] = t.Error
		json.NewEncoder(w).Encode(payload)
		return
	}

	json.NewEncoder(w).Encode(newTaskDisplay(t))
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

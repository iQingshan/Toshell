package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// ─── 通道健康仪表板 ─────────────────────────────────────────────────
// GET /api/v1/channels/health —— 返回 TCP/HTTP/WS/MQTT 四通道的
// 在线会话数、总会话数、运行中监听器实例数。供前端通道健康卡展示。

type channelHealth struct {
	Type      string `json:"type"`
	Online    int    `json:"online"`
	Total     int    `json:"total_session"`
	Listeners int    `json:"listeners"`
	Running   bool   `json:"running"`
}

// channelsHealthHandler 聚合四通道健康状态。
func (s *Server) channelsHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 会话通道分布（session.Manager）
	byListener := s.sessionMgr.CountByListener()

	// 监听器实例分布（listenerRouter）
	listenerCnt := map[string]int{"tcp": 0, "http": 0, "websocket": 0, "mqtt": 0}
	if router, ok := s.listener.(*listenerRouter); ok {
		listenerCnt = router.ChannelHealth()
	}

	// 四通道固定顺序
	order := []string{"tcp", "http", "websocket", "mqtt"}
	channels := make([]channelHealth, 0, len(order))
	totalOnline, totalSession := 0, 0
	for _, typ := range order {
		st := byListener[typ]
		if st == nil {
			st = map[string]int{"total": 0, "online": 0}
		}
		online := st["online"]
		total := st["total"]
		listeners := listenerCnt[typ]
		totalOnline += online
		totalSession += total
		channels = append(channels, channelHealth{
			Type:      typ,
			Online:    online,
			Total:     total,
			Listeners: listeners,
			Running:   listeners > 0,
		})
	}
	// 未知通道（会话 Listener 字段异常）补全统计
	if unknown := byListener["unknown"]; unknown != nil && unknown["total"] > 0 {
		totalSession += unknown["total"]
		totalOnline += unknown["online"]
	}

	sort.SliceStable(channels, func(i, j int) bool {
		return channels[i].Online > channels[j].Online
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"channels":      channels,
		"total_online":  totalOnline,
		"total_session": totalSession,
		"timestamp":     time.Now().Unix(),
	})
}

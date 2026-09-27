package api

import (
	"encoding/json"
	"testing"
	"time"

	"toshell/internal/common/types"
)

// 读取并清空 hub 上已投递的事件（测试用；hub 未 Run 时事件留在 channel 里）。
func drainEvents(h *WSHub) []WSEvent {
	var out []WSEvent
	for {
		select {
		case raw := <-h.broadcast:
			var ev WSEvent
			if err := json.Unmarshal(raw, &ev); err == nil {
				out = append(out, ev)
			}
		default:
			return out
		}
	}
}

func eventTypes(events []WSEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}

func withShortGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := sessionOfflineGrace
	sessionOfflineGrace = d
	t.Cleanup(func() { sessionOfflineGrace = old })
}

// 新会话上线：广播一次；重复注册（闪断重连/心跳恢复）不再重复广播。
func TestBroadcastSessionOnlineDeduplicates(t *testing.T) {
	hub := NewWSHub()
	s := &Server{wsHub: hub}
	info := &types.SessionInfo{ID: "sess-1", Hostname: "PC1"}

	if !s.BroadcastSessionOnline(info) {
		t.Fatal("首次上线应广播并返回 true")
	}
	if got := eventTypes(drainEvents(hub)); len(got) != 1 || got[0] != "session_online" {
		t.Fatalf("首次上线事件错误: %v", got)
	}

	// 重复注册：不应再广播，也不应重复触发上线通知
	if s.BroadcastSessionOnline(info) {
		t.Fatal("重复上线不应广播")
	}
	if got := drainEvents(hub); len(got) != 0 {
		t.Fatalf("重复上线不应产生事件: %v", eventTypes(got))
	}
}

// P0-1 核心：闪断重连（offline 后观察窗内 online）全程不发任何事件。
func TestReconnectWithinGraceSuppressesFlicker(t *testing.T) {
	withShortGrace(t, 120*time.Millisecond)
	hub := NewWSHub()
	s := &Server{wsHub: hub}
	info := &types.SessionInfo{ID: "sess-1", Hostname: "PC1"}

	s.BroadcastSessionOnline(info)
	drainEvents(hub)

	// 连接断开 → 判死（进入观察窗，不立即广播）
	s.BroadcastSessionOffline("sess-1")
	if s.PendingOfflineCount() != 1 {
		t.Fatalf("应在观察窗内等待，pending=%d", s.PendingOfflineCount())
	}
	if got := drainEvents(hub); len(got) != 0 {
		t.Fatalf("观察窗内不应广播 offline: %v", eventTypes(got))
	}

	// 观察窗内重连 → 取消离线广播，且不再补发 online（前端从未看到离线）
	if s.BroadcastSessionOnline(info) {
		t.Fatal("观察窗内恢复不应广播 online")
	}
	time.Sleep(200 * time.Millisecond)
	if s.PendingOfflineCount() != 0 {
		t.Fatal("观察窗内恢复后不应再广播 offline")
	}
	if got := drainEvents(hub); len(got) != 0 {
		t.Fatalf("整个闪断过程不应产生任何事件（消除闪烁）: %v", eventTypes(got))
	}
}

// 真实掉线：观察窗过期后才广播 offline，之后复活要广播 online。
func TestRealOfflineBroadcastAfterGrace(t *testing.T) {
	withShortGrace(t, 60*time.Millisecond)
	hub := NewWSHub()
	s := &Server{wsHub: hub}
	info := &types.SessionInfo{ID: "sess-9", Hostname: "PC9"}

	s.BroadcastSessionOnline(info)
	drainEvents(hub)

	s.BroadcastSessionOffline("sess-9")
	// 等"事件真的到达 hub"，而不是只等 pending 计数归零：flushSessionOffline 先清 pending
	// 再投递事件，两者之间有一个很小的竞争窗口 —— 只盯计数会偶发拿到空事件列表
	// （2026-09-27 的 CI 上就红过一次：日志里已经打印"广播 session_offline"，断言却看到 []）。
	// 断言的目标本来就是"事件"，所以直接等事件。
	deadline := time.Now().Add(2 * time.Second)
	var events []WSEvent
	for time.Now().Before(deadline) {
		events = drainEvents(hub)
		if len(events) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(events) != 1 || events[0].Type != "session_offline" {
		t.Fatalf("观察窗过期后应广播 offline，实际: %v", eventTypes(events))
	}
	if s.PendingOfflineCount() != 0 {
		t.Fatalf("广播后不该再有待广播会话，实际 %d", s.PendingOfflineCount())
	}

	// 复活：观察窗外恢复 → 广播 online
	if !s.BroadcastSessionOnline(info) {
		t.Fatal("真实复活应广播 online")
	}
	if got := eventTypes(drainEvents(hub)); len(got) != 1 || got[0] != "session_online" {
		t.Fatalf("复活事件错误: %v", got)
	}
}

// 从未广播过在线的会话判死时不产生事件（避免前端收到无法对应的 offline）。
func TestOfflineForUnknownSessionIsIgnored(t *testing.T) {
	withShortGrace(t, 30*time.Millisecond)
	hub := NewWSHub()
	s := &Server{wsHub: hub}

	s.BroadcastSessionOffline("never-seen")
	if s.PendingOfflineCount() != 0 {
		t.Fatal("未上线过的会话不应进入离线观察窗")
	}
	time.Sleep(80 * time.Millisecond)
	if got := drainEvents(hub); len(got) != 0 {
		t.Fatalf("不应产生事件: %v", eventTypes(got))
	}
}

// 反复抖动（多次 offline）不应顺延离线广播，避免始终不下线。
func TestRepeatedOfflineKeepsOriginalDeadline(t *testing.T) {
	withShortGrace(t, 100*time.Millisecond)
	hub := NewWSHub()
	s := &Server{wsHub: hub}
	info := &types.SessionInfo{ID: "sess-x"}

	s.BroadcastSessionOnline(info)
	drainEvents(hub)

	s.BroadcastSessionOffline("sess-x")
	time.Sleep(60 * time.Millisecond)
	s.BroadcastSessionOffline("sess-x") // 重复判死：不应重置定时器
	time.Sleep(80 * time.Millisecond)

	events := drainEvents(hub)
	if len(events) != 1 || events[0].Type != "session_offline" {
		t.Fatalf("重复判死应保持原截止时间，实际: %v", eventTypes(events))
	}
}

func TestForgetSessionBroadcastClearsState(t *testing.T) {
	withShortGrace(t, 2*time.Second)
	hub := NewWSHub()
	s := &Server{wsHub: hub}
	info := &types.SessionInfo{ID: "sess-del"}

	s.BroadcastSessionOnline(info)
	s.BroadcastSessionOffline("sess-del")
	if s.PendingOfflineCount() != 1 {
		t.Fatal("应有一个待广播离线")
	}
	s.ForgetSessionBroadcast("sess-del")
	if s.PendingOfflineCount() != 0 {
		t.Fatal("删除会话后应清理观察窗")
	}
	drainEvents(hub)

	// 清理后重新上线应重新广播
	if !s.BroadcastSessionOnline(info) {
		t.Fatal("清理状态后重新上线应广播")
	}
}

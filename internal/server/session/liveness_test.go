package session

import (
	"testing"
	"time"

	"toshell/internal/common/types"
)

// TestNextLivenessFlipMatchesIsAliveAt 翻转时刻必须与 isAliveAt 严格同源：
// 在翻转时刻之前判定恒为存活、之后恒为离线。这是"事件驱动等待会话掉线"能成立的前提——
// 算早了只是多醒一次，算晚了就会漏掉掉线、让等待方白等满整个任务超时。
func TestNextLivenessFlipMatchesIsAliveAt(t *testing.T) {
	m := New()
	id := "sess-flip-1"
	now := time.Now()
	if err := m.Add(&types.SessionInfo{ID: id, Hostname: "h", Username: "u", OS: "windows"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sess, err := m.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// 固定心跳时刻，避免用例受"创建时刻"影响。
	sess.LastSeen = now.Add(-10 * time.Second)

	flip, ok := m.NextLivenessFlip(id, now)
	if !ok {
		t.Fatal("会话存在时 ok 应为 true")
	}
	if !flip.After(sess.LastSeen) {
		t.Fatalf("翻转时刻 %v 应晚于 LastSeen %v", flip, sess.LastSeen)
	}
	if sess.isAliveAt(flip.Add(-time.Millisecond)) != true {
		t.Fatal("翻转时刻之前必须仍判定为存活（否则会把在线会话误判掉线）")
	}
	if sess.isAliveAt(flip) != false {
		t.Fatal("翻转时刻必须判定为离线（否则等待方永远等不到掉线熔断）")
	}

	// 忙期放宽：忙期内的翻转变为 min(BusyUntil, LastSeen+timeout*BusyGrace)。
	sess.MarkBusy(10 * time.Minute)
	busyFlip, _ := m.NextLivenessFlip(id, now)
	if !busyFlip.After(flip) {
		t.Fatalf("忙期应把翻转时刻推后：busy=%v base=%v", busyFlip, flip)
	}
	if sess.isAliveAt(busyFlip.Add(-time.Millisecond)) != true || sess.isAliveAt(busyFlip) != false {
		t.Fatal("忙期下的翻转时刻与 isAliveAt 不一致")
	}

	// 不存在的会话：ok=false（调用方按离线处理）。
	if _, ok := m.NextLivenessFlip("nope", now); ok {
		t.Fatal("会话不存在时 ok 应为 false")
	}
}

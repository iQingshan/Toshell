package session

import (
	"testing"
	"time"
)

// withTimeoutConfig 临时设置判活基准与默认心跳间隔（测试用）。
func withTimeoutConfig(t *testing.T, base, defaultInterval time.Duration) {
	t.Helper()
	oldBase, oldInterval := HeartbeatTimeout, DefaultHeartbeatInterval
	HeartbeatTimeout = base
	DefaultHeartbeatInterval = defaultInterval
	t.Cleanup(func() {
		HeartbeatTimeout = oldBase
		DefaultHeartbeatInterval = oldInterval
	})
}

// P0-1：判活阈值必须留出余量，避免心跳间隔与超时几乎零余量时反复抖动。
func TestEffectiveTimeoutHasHeartbeatMargin(t *testing.T) {
	withTimeoutConfig(t, 60*time.Second, 5*time.Second)

	s := &Session{LastSeen: time.Now()}
	// 未采样到实测间隔：MarginFactor(4)×默认间隔=20s 小于 2 倍基准(120s)，
	// 额外放宽到 2 倍基准，再加固定抖动容差 OfflineJitterGrace(15s) = 135s，
	// 保证会话刚上线时首个心跳（可能刚好踩线）不会把它判死。
	if got := s.EffectiveTimeout(); got != 135*time.Second {
		t.Fatalf("无采样时阈值 = %v, want 135s（2 倍基准首周期保护 + 15s 抖动容差）", got)
	}

	// 默认间隔与基准相当时：4×60 + 15 = 255s
	withTimeoutConfig(t, 60*time.Second, 60*time.Second)
	s2 := &Session{LastSeen: time.Now()}
	if got := s2.EffectiveTimeout(); got != 255*time.Second {
		t.Fatalf("默认间隔 60s 时阈值 = %v, want 255s（4 倍间隔 + 15s）", got)
	}

	// 实测心跳间隔 62s（60s + jitter）→ 4×62 + 15 = 263s
	withTimeoutConfig(t, 60*time.Second, 5*time.Second)
	s.observedInterval = 62 * time.Second
	if got := s.EffectiveTimeout(); got != 263*time.Second {
		t.Fatalf("阈值 = %v, want 263s（4 倍心跳间隔 + 15s）", got)
	}

	// 心跳很快时保持基准值（不因自适应而收紧到不可用）
	fast := &Session{LastSeen: time.Now(), observedInterval: 5 * time.Second}
	if got := fast.EffectiveTimeout(); got != 60*time.Second {
		t.Fatalf("快心跳阈值 = %v, want 60s", got)
	}
}

// 回归：心跳迟到几秒不再被误判离线（旧实现 60s 阈值 + 62s 心跳 = 必然误判）。
func TestHeartbeatJitterDoesNotKillSession(t *testing.T) {
	withTimeoutConfig(t, 60*time.Second, 5*time.Second)

	s := &Session{observedInterval: 62 * time.Second}
	now := time.Now()

	s.LastSeen = now.Add(-62 * time.Second)
	if !s.isAliveAt(now) {
		t.Fatal("62s 前心跳（间隔 62s）不应判离线")
	}
	s.LastSeen = now.Add(-170 * time.Second)
	if !s.isAliveAt(now) {
		t.Fatal("170s < 263s 阈值，不应判离线")
	}
	// 真正失联（超过 4 倍间隔 + 抖动容差 = 263s）才判死
	s.LastSeen = now.Add(-300 * time.Second)
	if s.isAliveAt(now) {
		t.Fatal("超过 4 倍心跳间隔 + 抖动容差应判离线")
	}
}

// 忙期（长任务运行中）阈值再放宽 BusyGrace 倍。
func TestBusyGraceExtendsTimeout(t *testing.T) {
	withTimeoutConfig(t, 60*time.Second, 5*time.Second)

	now := time.Now()
	// observedInterval 5s → 阈值 60s，忙期宽限 = 180s
	s := &Session{
		LastSeen:         now.Add(-150 * time.Second),
		BusyUntil:        now.Add(30 * time.Second),
		observedInterval: 5 * time.Second,
	}
	if !s.isAliveAt(now) {
		t.Fatal("忙期 150s 无心跳仍应判存活（60s×3=180s 宽限）")
	}
	s.LastSeen = now.Add(-200 * time.Second)
	if s.isAliveAt(now) {
		t.Fatal("忙期超过宽限也应判离线")
	}
	// 忙期结束后回到正常阈值
	s.BusyUntil = now.Add(-time.Second)
	s.LastSeen = now.Add(-90 * time.Second)
	if s.isAliveAt(now) {
		t.Fatal("非忙期 90s 无心跳（>60s 阈值）应判离线")
	}
}

// ObserveHeartbeat：间隔变大立即生效，变小缓慢回收。
func TestObserveHeartbeatAdapts(t *testing.T) {
	s := &Session{LastSeen: time.Now()}
	s.ObserveHeartbeat() // 首次采样只记快照
	if s.observedInterval != 0 {
		t.Fatalf("首次采样不应产生间隔: %v", s.observedInterval)
	}

	s.LastSeen = s.LastSeen.Add(62 * time.Second)
	s.ObserveHeartbeat()
	if s.observedInterval != 62*time.Second {
		t.Fatalf("实测间隔 = %v, want 62s", s.observedInterval)
	}

	// 间隔变大：立即采用
	s.LastSeen = s.LastSeen.Add(120 * time.Second)
	s.ObserveHeartbeat()
	if s.observedInterval != 120*time.Second {
		t.Fatalf("间隔变大应立即采用: %v", s.observedInterval)
	}

	// 间隔变小：缓慢回收（不瞬间掉到太小）
	s.LastSeen = s.LastSeen.Add(5 * time.Second)
	s.ObserveHeartbeat()
	if s.observedInterval >= 120*time.Second || s.observedInterval <= 5*time.Second {
		t.Fatalf("间隔变小应平滑回收: %v", s.observedInterval)
	}

	// 多次采样后逐步收敛到快心跳附近
	for i := 0; i < 200; i++ {
		s.LastSeen = s.LastSeen.Add(5 * time.Second)
		s.ObserveHeartbeat()
	}
	if s.observedInterval > 15*time.Second {
		t.Fatalf("长期快心跳应收敛: %v", s.observedInterval)
	}
}

// LastSeen 未推进时不应改动采样值（例如 checker 高频调用）。
func TestObserveHeartbeatIgnoresUnchangedLastSeen(t *testing.T) {
	s := &Session{LastSeen: time.Now()}
	s.ObserveHeartbeat()
	s.observedInterval = 60 * time.Second
	for i := 0; i < 5; i++ {
		s.ObserveHeartbeat()
	}
	if s.observedInterval != 60*time.Second {
		t.Fatalf("心跳未推进不应改变采样: %v", s.observedInterval)
	}
}

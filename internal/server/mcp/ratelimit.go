package mcp

import (
	"fmt"
	"sync"
	"time"
)

// ─── 限流：三道互相独立、各自 fail-closed 的闸 ────────────────────────
//
// 只读工具本身不贵，但"工具调用"是 C2 的操作面：一个跑飞的 Agent（或一个拿到 token
// 的脚本）可以在几秒内下发上千条任务、写爆结果目录、把植入端打崩。所以按 **token 维度**
// 设三道闸，任何一道超限都返回 CodeRateLimited：
//
//	闸 1 RPM      —— 滑动窗口每分钟调用数（默认 60）。突发按"最近 60 秒"精确计数，
//	                 不用固定窗口（固定窗口在跨窗口边界会放行 2 倍流量）。
//	闸 2 并发      —— 同一 token 同时正在执行（未返回）的调用数（默认 4）。防止
//	                 长任务把服务端 goroutine / 植入端会话打满。
//	闸 3 挂起句柄  —— 同一 token 尚未读取完的外置结果句柄数（默认 32）。这是
//	                 **磁盘水位闸**：结果外置是"把结果写到服务端磁盘"，必须有人读或者
//	                 等 TTL 过期，否则一个循环调用的 Agent 能把结果目录写满。
//
// 实现刻意零依赖（标准库），不引 golang.org/x/time/rate。
//
// 闸 3 的释放路径有两条（都在下面实现）：
//   - `resources/read` 把某个句柄**读完**（offset+len >= total）→ 释放；
//   - 句柄存活超过 result_ttl → 在下次检查时惰性剔除（与 ResultStore.GC 的口径一致）。
//
// 取舍：闸 3 超限时**不做** FIFO 淘汰（淘汰意味着服务端替客户端删结果，可能删掉
// 还没读的关键输出）。代价是"挂起句柄满且客户端不读"时后续调用会被 429 挡住，
// 直到客户端读结果或等 TTL 过期——这是刻意的 fail-closed 选择。

// HandleRef 一个外置结果句柄的记账项。
type HandleRef struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// LimitDecision 限流判定结果。
type LimitDecision struct {
	Allowed    bool
	Gate       string // rpm / concurrent / handles（Allowed 为 false 时有效）
	Limit      int
	Current    int
	RetryAfter time.Duration
}

// Message 生成给客户端看的说明（会进信封 error.message）。
func (d LimitDecision) Message() string {
	switch d.Gate {
	case gateRPM:
		return fmt.Sprintf("触发限流：每分钟调用数超过上限 %d（rpm）", d.Limit)
	case gateConcurrent:
		return fmt.Sprintf("触发限流：同一令牌同时执行的调用数超过上限 %d", d.Limit)
	case gateHandles:
		return fmt.Sprintf("触发限流：未读取的外置结果句柄数超过上限 %d，请先用 resources/read 读完或等待结果 TTL 过期", d.Limit)
	default:
		return "触发限流"
	}
}

const (
	gateRPM        = "rpm"
	gateConcurrent = "concurrent"
	gateHandles    = "handles"
)

// token state 默认参数。
const (
	defaultMaxRPM           = 60
	defaultMaxConcurrent    = 4
	defaultMaxPendingHandle = 32

	// rpmWindow 滑动窗口长度：一分钟。
	rpmWindow = time.Minute
	// tokenIdleTTL token 状态在无活动多久后被回收（防止 map 无限增长）。
	tokenIdleTTL = 30 * time.Minute
)

// tokenState 单个 token 的限流状态。一把小锁，临界区全是内存操作（无 IO）。
type tokenState struct {
	mu sync.Mutex

	// 闸 1：环形数组存最近 rpm 次调用的时间戳。
	window []time.Time
	winIdx int
	winLen int

	// 闸 2：正在执行的调用数。
	inflight int

	// 闸 3：未读完的句柄（FIFO 顺序）。
	handles []HandleRef

	lastSeen time.Time
}

// Limiter 按 token 维度限流。并发安全。
type Limiter struct {
	mu       sync.Mutex
	perToken map[string]*tokenState

	rpm        int
	maxConc    int
	maxHandles int
	handleTTL  time.Duration
}

// NewLimiter 构造限流器。rpm / maxConc / maxHandles <= 0 时取默认值
// （默认值而不是"不限"，符合 fail-closed 口径）。
func NewLimiter(rpm, maxConc, maxHandles int, handleTTL time.Duration) *Limiter {
	if rpm <= 0 {
		rpm = defaultMaxRPM
	}
	if maxConc <= 0 {
		maxConc = defaultMaxConcurrent
	}
	if maxHandles <= 0 {
		maxHandles = defaultMaxPendingHandle
	}
	if handleTTL <= 0 {
		handleTTL = 24 * time.Hour
	}
	return &Limiter{
		perToken:   make(map[string]*tokenState),
		rpm:        rpm,
		maxConc:    maxConc,
		maxHandles: maxHandles,
		handleTTL:  handleTTL,
	}
}

// Limits 返回生效的三道上限（启动日志用）。
func (l *Limiter) Limits() (rpm, maxConc, maxHandles int) {
	if l == nil {
		return 0, 0, 0
	}
	return l.rpm, l.maxConc, l.maxHandles
}

func (l *Limiter) state(tokenID string) *tokenState {
	if tokenID == "" {
		tokenID = "anonymous"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.perToken[tokenID]
	if st == nil {
		st = &tokenState{window: make([]time.Time, l.rpm)}
		l.perToken[tokenID] = st
	}
	return st
}

// Lease 一次已获批的执行配额。必须 Release（幂等）。
type Lease struct {
	lim   *Limiter
	token string
	once  sync.Once
}

// Release 归还并发配额（可重复调用）。
func (ls *Lease) Release() {
	if ls == nil || ls.lim == nil {
		return
	}
	ls.once.Do(func() {
		st := ls.lim.state(ls.token)
		st.mu.Lock()
		if st.inflight > 0 {
			st.inflight--
		}
		st.lastSeen = time.Now()
		st.mu.Unlock()
	})
}

// Acquire 申请执行配额：依次检查闸 3（挂起句柄）→ 闸 2（并发）→ 记账闸 1（RPM）。
//
// 顺序说明：只有全部通过才记 RPM，避免"被闸 2/3 拒掉的请求也消耗 RPM 配额"
// （否则客户端会在并发满时被双重惩罚）。
func (l *Limiter) Acquire(tokenID string) (*Lease, LimitDecision) {
	if l == nil {
		return &Lease{}, LimitDecision{Allowed: true}
	}
	st := l.state(tokenID)
	now := time.Now()

	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = now

	// 闸 3：挂起句柄（先按 TTL 惰性剔除过期项）。
	st.pruneHandlesLocked(now, l.handleTTL)
	if len(st.handles) >= l.maxHandles {
		return nil, LimitDecision{Gate: gateHandles, Limit: l.maxHandles, Current: len(st.handles), RetryAfter: time.Second}
	}

	// 闸 2：并发。
	if st.inflight >= l.maxConc {
		return nil, LimitDecision{Gate: gateConcurrent, Limit: l.maxConc, Current: st.inflight, RetryAfter: time.Second}
	}

	// 闸 1：RPM 滑动窗口（记账放在最后，避免被闸 2/3 拒掉的调用也消耗 RPM 配额）。
	if dec := st.allowRPMLocked(now, l.rpm); !dec.Allowed {
		return nil, dec
	}

	st.inflight++
	return &Lease{lim: l, token: tokenID}, LimitDecision{Allowed: true}
}

// AllowRPM 单独施加闸 1（请求级 RPM 计数）。
//
// 用途：`tools/call` 走 Acquire（三道闸一起，且审计里能带上工具名），
// 其余 JSON-RPC 方法（ping / tools/list / resources/* / initialize / 通知）
// 由 server 在每个请求上调用本方法——"每个请求都算一次 RPM"，
// 否则拿到 token 的脚本可以用 ping 或 tools/list 无限刷服务端。
func (l *Limiter) AllowRPM(tokenID string) LimitDecision {
	if l == nil {
		return LimitDecision{Allowed: true}
	}
	st := l.state(tokenID)
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = now
	return st.allowRPMLocked(now, l.rpm)
}

// allowRPMLocked 闸 1 的核心：最近 60 秒内的调用次数未满则记账放行，否则给出重试等待。
func (st *tokenState) allowRPMLocked(now time.Time, rpm int) LimitDecision {
	if st.winLen >= rpm {
		oldest := st.window[st.winIdx]
		if elapsed := now.Sub(oldest); elapsed < rpmWindow {
			return LimitDecision{
				Gate:       gateRPM,
				Limit:      rpm,
				Current:    st.winLen,
				RetryAfter: rpmWindow - elapsed,
			}
		}
	}
	st.window[st.winIdx] = now
	st.winIdx = (st.winIdx + 1) % rpm
	if st.winLen < rpm {
		st.winLen++
	}
	return LimitDecision{Allowed: true}
}

// NoteHandle 登记一个新产生的外置结果句柄（计入闸 3）。
func (l *Limiter) NoteHandle(tokenID, handle string) {
	if l == nil || handle == "" {
		return
	}
	st := l.state(tokenID)
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneHandlesLocked(now, l.handleTTL)
	st.handles = append(st.handles, HandleRef{ID: handle, At: now})
	st.lastSeen = now
}

// ReleaseHandle 释放一个句柄配额（客户端已把该结果读完）。
func (l *Limiter) ReleaseHandle(tokenID, handle string) {
	if l == nil || handle == "" {
		return
	}
	st := l.state(tokenID)
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range st.handles {
		if st.handles[i].ID == handle {
			st.handles = append(st.handles[:i], st.handles[i+1:]...)
			break
		}
	}
	st.lastSeen = time.Now()
}

// Handles 返回该 token 当前挂起的句柄（FIFO，供 resources/list 展示）。
func (l *Limiter) Handles(tokenID string) []HandleRef {
	if l == nil {
		return nil
	}
	st := l.state(tokenID)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneHandlesLocked(time.Now(), l.handleTTL)
	out := make([]HandleRef, len(st.handles))
	copy(out, st.handles)
	return out
}

// PendingHandles 挂起句柄数（自检/日志用）。
func (l *Limiter) PendingHandles(tokenID string) int {
	return len(l.Handles(tokenID))
}

// pruneHandlesLocked 惰性剔除超过 TTL 的句柄（与 ResultStore 的 TTL 口径一致：
// 服务端已经不再保证它可读，就不该继续占着客户端的配额）。
func (st *tokenState) pruneHandlesLocked(now time.Time, ttl time.Duration) {
	if len(st.handles) == 0 {
		return
	}
	keep := st.handles[:0]
	for _, h := range st.handles {
		if now.Sub(h.At) < ttl {
			keep = append(keep, h)
		}
	}
	st.handles = keep
}

// Sweep 回收长时间无活动的 token 状态（后台 ticker 调用）。返回回收的 token 数。
func (l *Limiter) Sweep() int {
	if l == nil {
		return 0
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for k, st := range l.perToken {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen) > tokenIdleTTL
		busy := st.inflight > 0
		st.mu.Unlock()
		if idle && !busy {
			delete(l.perToken, k)
			removed++
		}
	}
	return removed
}

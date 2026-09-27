package ai

import (
	"encoding/json"
	"time"
)

// ─── run 内事件环形缓冲（SSE 断点续传用，v1.4.0 S2）────────────────────
//
// 为什么必须有界：thinking/message 是**逐 token 增量**，一次 run 轻易上万条。
// 无界缓冲等于把一次 run 的全部正文与工具结果常驻内存（并发 run 下是几十 MB），
// 所以这里只保留"最近 AgentEventRingSize 条且总字节 ≤ agentEventRingBytes"的
// **已序列化载荷**：
//   - 不存 *AgentRun / Message / mcp.Result 这类大对象，避免回放缓冲把已经外置或
//     截断的大结果又钉死在内存里；
//   - 写进缓冲的就是最终要写到 SSE data: 的那串字节，回放时零解析、零再序列化
//     （重连回放通常发生在 SSE handler 里，走一遍 JSON 解析纯属浪费）。
//
// 淘汰语义（写清，避免以后有人"顺手"放宽）：
//   - 条数上限 512、字节上限 2 MiB，**两者任一超限都从最旧一条开始淘汰**，
//     直到回到预算内，所以单次写入可能淘汰多条；
//   - 单条载荷自己就超过字节上限时，它会被自己挤掉（宁可回放不了这一条，
//     也不让一条超大事件把整个预算撑爆）——它仍然会正常推给**在线的**客户端；
//   - 淘汰掉的事件无法再回放：客户端带着早于 Oldest 的 Last-Event-ID 重连时，
//     服务端必须发 resync{reason:events_expired} 显式告知（见 api 层），而不是
//     假装流是连续的——静默跳过会让前端把"缺了一段过程"误当成"任务本来就这样"。
const (
	// AgentEventRingSize 回放缓冲的条数上限。
	AgentEventRingSize = 512
	// agentEventRingBytes 回放缓冲的载荷字节上限（2 MiB）。thinking 增量很密集，
	// 条数上限其实先到；字节上限是给 tool_result/consent 这类大载荷兜底的。
	agentEventRingBytes = 2 << 20
	// AgentReplayTailMax 对"无 Last-Event-ID 的终态 run 晚订阅"回放的最大条数：
	// 晚到者只想看过程，不该因为一次连接就吐几百条历史（尤其是 message 增量）。
	// 导出是因为回放发生在 HTTP 层（internal/server/api 的 SSE handler）。
	AgentReplayTailMax = 200
)

// RingEvent 环形缓冲里的一条事件。
//
// Payload 是**已经**注入好 seq/run_id/ts 的完整 SSE data 体，可直接写网。
// 它由 buildEventPayload 生成、写入后不再改写，因此快照之间可以安全共享
// 这份字节（不需要深拷贝）。
type RingEvent struct {
	Seq     uint64
	Kind    AgentEventKind
	Payload []byte
	Ts      int64
}

// EventSnapshot 环形缓冲的一致性快照（同一把锁内取，保证 Oldest/Head/条目自洽）。
//
// 语义：保留区间 = [Oldest, Head]；Head=0 表示这个 run 还没发过任何事件。
// 客户端水位线为 L 时：
//   - L+1 >= Oldest → 缺失的事件都在缓冲里，可以补齐；
//   - L+1 <  Oldest → 需要的事件已被淘汰，只能显式告知（events_expired）。
type EventSnapshot struct {
	// Oldest 缓冲里最旧一条的 seq；缓冲为空时 = Head+1（什么都没留下）。
	Oldest uint64
	// Head 已分配的最大 seq（最后一条成功投递事件的序号）。
	Head uint64
	// DroppedAfter / DroppedCount：自 DroppedAfter 之后发生过 DroppedCount 次
	// "通道满丢弃"（见 eventRing.markDrop）。0 表示没有未告知的丢弃。
	DroppedAfter uint64
	DroppedCount int

	entries []RingEvent
}

// After 返回 seq 之后的全部保留事件（按 seq 升序）。返回值是副本切片。
func (s EventSnapshot) After(seq uint64) []RingEvent {
	out := make([]RingEvent, 0, len(s.entries))
	for _, rec := range s.entries {
		if rec.Seq > seq {
			out = append(out, rec)
		}
	}
	return out
}

// Tail 返回最近的至多 max 条事件（按 seq 升序）。终态 run 晚订阅用它做有上限回放。
func (s EventSnapshot) Tail(max int) []RingEvent {
	if max <= 0 || len(s.entries) == 0 {
		return nil
	}
	start := len(s.entries) - max
	if start < 0 {
		start = 0
	}
	out := make([]RingEvent, len(s.entries)-start)
	copy(out, s.entries[start:])
	return out
}

// Len 当前保留条数（测试与可观测性用）。
func (s EventSnapshot) Len() int { return len(s.entries) }

// eventRing 定长环形缓冲 + 序号分配 + 丢弃水位。**必须由调用方持锁访问**
// （AgentRun.mu）——序号分配、写缓冲、投递通道要在同一个临界区里完成，
// 否则并发 emit 会让"通道里的顺序"与"seq 顺序"不一致，重连去重就会吃掉事件。
type eventRing struct {
	buf   []RingEvent
	start int // 逻辑第一条的物理下标
	n     int // 当前条数
	bytes int // 当前载荷总字节

	// nextSeq 已分配的最大 seq（0 = 还没发过事件；事件 seq 从 1 开始）。
	nextSeq uint64
	// droppedAfter / droppedCount 见 markDrop。
	droppedAfter uint64
	droppedCount int
}

func newEventRing(size int) *eventRing {
	if size <= 0 {
		size = AgentEventRingSize
	}
	return &eventRing{buf: make([]RingEvent, size)}
}

// peekNext 下一条事件的序号（调用方持锁，随后要用同一个 seq 构造载荷）。
func (g *eventRing) peekNext() uint64 { return g.nextSeq + 1 }

// push 写入一条事件并推进序号。
func (g *eventRing) push(rec RingEvent) {
	// 防御：seq 必须是连续的下一个（同一把锁内分配，正常情况下恒成立）。
	if rec.Seq != g.nextSeq+1 {
		rec.Seq = g.nextSeq + 1
	}
	g.nextSeq = rec.Seq
	if g.n == len(g.buf) {
		g.evictOldest() // 条数上限
	}
	g.buf[(g.start+g.n)%len(g.buf)] = rec
	g.n++
	g.bytes += len(rec.Payload)
	for g.bytes > agentEventRingBytes && g.n > 0 {
		g.evictOldest() // 字节上限（单条超大时会把刚写入的这条也淘汰）
	}
}

// evictOldest 淘汰最旧一条并释放其载荷引用。
func (g *eventRing) evictOldest() {
	if g.n == 0 {
		return
	}
	old := g.buf[g.start]
	g.buf[g.start] = RingEvent{} // 断开引用，别让被淘汰的载荷还挂在缓冲数组上
	g.start = (g.start + 1) % len(g.buf)
	g.n--
	g.bytes -= len(old.Payload)
	if g.bytes < 0 {
		g.bytes = 0
	}
}

// oldest 缓冲里最旧一条的 seq；空缓冲返回 nextSeq+1（= 什么都没保留）。
func (g *eventRing) oldest() uint64 {
	if g.n == 0 {
		return g.nextSeq + 1
	}
	return g.buf[g.start].Seq
}

// markDrop 记录一次"事件因通道满被丢弃"。
//
// 为什么被丢的事件**不占 seq**：seq 的口径是"已投递事件"，被丢的事件从没进过
// 客户端，占号只会在 seq 空间里留一个无法回放的洞、还要为此存占位记录。
// 缺口改由 droppedAfter（丢弃前最后一个成功投递的 seq）+ droppedCount 表达，
// 由 SSE handler 转成 resync{reason:events_dropped} 显式告知。
// droppedAfter 每次都更新到最新的 head：客户端水位线只要 ≤ 它，就说明该客户端
// 经历过（至少一次）丢弃——反之若水位线已经越过它，那它必然拿不到被丢的事件，
// 逻辑上不可能"没受影响"，所以不需要更复杂的状态。
func (g *eventRing) markDrop() {
	g.droppedAfter = g.nextSeq
	g.droppedCount++
}

// clear 清空回放缓冲（ResetForResume：复用 run 续接新指令 = 新的执行片段）。
//
// **不重置 nextSeq**：seq 在一个 run 内必须单调不回退。否则老连接带着旧的
// Last-Event-ID 重连时，新事件的 seq 全都小于它的水位线，会被去重逻辑全部跳过，
// 前端表现为"重连后永远没有新事件"。
func (g *eventRing) clear() {
	for i := range g.buf {
		g.buf[i] = RingEvent{}
	}
	g.start, g.n, g.bytes = 0, 0, 0
	g.droppedAfter, g.droppedCount = 0, 0
}

// snapshot 取一致性快照（调用方持锁）。
func (g *eventRing) snapshot() EventSnapshot {
	s := EventSnapshot{
		Oldest:       g.oldest(),
		Head:         g.nextSeq,
		DroppedAfter: g.droppedAfter,
		DroppedCount: g.droppedCount,
	}
	if g.n == 0 {
		return s
	}
	s.entries = make([]RingEvent, 0, g.n)
	for i := 0; i < g.n; i++ {
		rec := g.buf[(g.start+i)%len(g.buf)]
		// Payload 只共享引用：环形缓冲从不改写已写入的载荷字节。
		s.entries = append(s.entries, RingEvent{Seq: rec.Seq, Kind: rec.Kind, Payload: rec.Payload, Ts: rec.Ts})
	}
	return s
}

// buildEventPayload 生成 SSE data: 体，并注入 seq / run_id / ts。
//
// 为什么对象载荷才注入、字符串载荷保持原样：
// thinking / message / final 的 data **本来就是一个 JSON 字符串**（前端按字符串
// 累加正文）。把它们包成对象会让老前端的 `typeof ev.data === 'string'` 判断失效，
// 正文渲染直接坏掉——所以这三个事件只把 seq 放在 SSE 的 `id:` 字段里（EventSource
// 的 Last-Event-ID 语义只依赖 id:，与载荷无关）。其余事件（tool_start/tool_result/
// consent/task_wait/trace/done/error）的 data 是 JSON 对象，多几个键老前端会忽略。
func buildEventPayload(ev AgentEvent, seq uint64, runID string, ts int64) []byte {
	if len(ev.Data) == 0 {
		obj := map[string]interface{}{"seq": seq, "run_id": runID, "ts": ts}
		if ev.Error != "" {
			obj["error"] = ev.Error
		}
		b, err := json.Marshal(obj)
		if err != nil {
			return []byte(`{}`)
		}
		return b
	}
	// 标量/字符串载荷：原样透传（见上面的为什么）。
	if ev.Data[0] != '{' {
		return append([]byte(nil), ev.Data...)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(ev.Data, &obj); err != nil {
		// 载荷不是合法对象（理论上不会发生）：宁可不注入，也不要丢事件。
		return append([]byte(nil), ev.Data...)
	}
	if b, err := json.Marshal(seq); err == nil {
		obj["seq"] = b
	}
	if b, err := json.Marshal(runID); err == nil {
		obj["run_id"] = b
	}
	if b, err := json.Marshal(ts); err == nil {
		obj["ts"] = b
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return append([]byte(nil), ev.Data...)
	}
	return b
}

// eventTs 事件时间戳（unix ms）。抽出来只为让 emit 的意图更清楚。
func eventTs() int64 { return time.Now().UnixMilli() }

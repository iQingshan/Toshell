package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ─── 事件环形缓冲与 SSE 断点续传的单元用例 ─────────────────────────────
//
// 全部不联网、不需要 LLM/植入端：事件直接用 run.EmitEvent 注入。
// 注意本机不能跑 -race（环境限制），但并发用例仍然断言了"通道到达顺序 == seq 顺序"
// 这条最关键的不变量（它是交接去重正确性的前提）。

// TestEventRingEvictsOldestAtCapacity 条数上限：只保留最近 N 条，淘汰从最旧开始。
func TestEventRingEvictsOldestAtCapacity(t *testing.T) {
	g := newEventRing(4)
	for i := 0; i < 6; i++ {
		seq := g.peekNext()
		g.push(RingEvent{Seq: seq, Kind: AgentEventMessage, Payload: []byte(fmt.Sprintf(`"m%d"`, i))})
	}
	snap := g.snapshot()
	if snap.Head != 6 || snap.Oldest != 3 {
		t.Fatalf("head/oldest = %d/%d, want 6/3（容量 4 时应保留 seq 3..6）", snap.Head, snap.Oldest)
	}
	if snap.Len() != 4 {
		t.Fatalf("保留条数 = %d, want 4", snap.Len())
	}
	got := snap.After(0)
	if len(got) != 4 || got[0].Seq != 3 || got[3].Seq != 6 {
		t.Fatalf("After(0) = %+v, want seq 3,4,5,6", seqsOf(got))
	}
	if tail := snap.After(4); len(tail) != 2 || tail[0].Seq != 5 {
		t.Fatalf("After(4) = %v, want 5,6", seqsOf(tail))
	}
	// 回放窗口的判定口径：需要的事件（L+1 起）是否已被淘汰。
	// L=2 → 需要 3..6，oldest=3 → 可补齐；L=1 → 需要 2，已被淘汰 → 必须报过期。
	if 2+1 < snap.Oldest {
		t.Fatalf("L=2 时不应判为过期（+1=%d oldest=%d）", 2+1, snap.Oldest)
	}
	if !(1+1 < snap.Oldest) {
		t.Fatalf("L=1 时应判为过期（需要 seq=2，oldest=%d）", snap.Oldest)
	}
}

// TestEventRingByteBudgetEvictsOldest 字节上限：thinking 增量很密集，条数上限先到；
// 字节上限是给 tool_result 这类大载荷兜底的——两者任一超限都从最旧开始淘汰。
func TestEventRingByteBudgetEvictsOldest(t *testing.T) {
	g := newEventRing(AgentEventRingSize)
	big := make([]byte, 1<<20) // 1 MiB
	for i := 0; i < 3; i++ {
		g.push(RingEvent{Seq: g.peekNext(), Kind: AgentEventToolResult, Payload: big})
	}
	snap := g.snapshot()
	if snap.Len() != 2 {
		t.Fatalf("字节预算 %d 下 3×1MiB 应只保留 2 条，实际 %d", agentEventRingBytes, snap.Len())
	}
	if snap.Oldest != 2 {
		t.Fatalf("应淘汰最旧的 seq=1，oldest=%d", snap.Oldest)
	}

	// 单条载荷自己就超预算：它会被自己挤掉（宁可回放不了这一条，也不让一条超大
	// 事件把整个预算撑爆）——但它仍然会正常推给在线客户端。
	g.push(RingEvent{Seq: g.peekNext(), Kind: AgentEventToolResult, Payload: make([]byte, 3<<20)})
	snap = g.snapshot()
	if snap.Len() != 0 {
		t.Fatalf("超预算单条应把自己淘汰掉，实际保留 %d 条", snap.Len())
	}
	if snap.Oldest != snap.Head+1 {
		t.Fatalf("空缓冲的 oldest 应为 head+1（%d），实际 %d", snap.Head+1, snap.Oldest)
	}
}

// TestEventRingClearKeepsSeqMonotonic 复用 run 续接新指令时缓冲清空，
// 但 **seq 不能回退**：否则老连接带着旧的 Last-Event-ID 重连，新事件 seq 全小于
// 它的水位线，会被去重逻辑全部跳过（前端表现：重连后永远没有新事件）。
func TestEventRingClearKeepsSeqMonotonic(t *testing.T) {
	g := newEventRing(8)
	for i := 0; i < 3; i++ {
		g.push(RingEvent{Seq: g.peekNext(), Kind: AgentEventMessage, Payload: []byte(`"x"`)})
	}
	g.markDrop()
	g.clear()

	snap := g.snapshot()
	if snap.Len() != 0 || snap.Head != 3 || snap.Oldest != 4 {
		t.Fatalf("clear 后 len/head/oldest = %d/%d/%d, want 0/3/4", snap.Len(), snap.Head, snap.Oldest)
	}
	if snap.DroppedCount != 0 || snap.DroppedAfter != 0 {
		t.Fatalf("clear 应重置丢弃水位（新执行片段），实际 after=%d count=%d", snap.DroppedAfter, snap.DroppedCount)
	}
	if next := g.peekNext(); next != 4 {
		t.Fatalf("clear 后下一条 seq = %d, want 4（seq 必须单调不回退）", next)
	}
}

// TestBuildEventPayloadStringVsObject 载荷注入的边界：
//   - 字符串载荷（thinking/message/final）**原样透传**——包成对象会让老前端
//     `typeof ev.data === 'string'` 的正文累加直接坏掉；
//   - 对象载荷就地注入 seq/run_id/ts（老前端多几个键会忽略）；
//   - 非法对象载荷宁可原样透传，也不丢事件。
func TestBuildEventPayloadStringVsObject(t *testing.T) {
	str := buildEventPayload(AgentEvent{Kind: AgentEventMessage, Data: json.RawMessage(`"hello"`)}, 7, "ag-1", 1234)
	if string(str) != `"hello"` {
		t.Fatalf("字符串载荷被改动了: %s", str)
	}

	obj := buildEventPayload(AgentEvent{Kind: AgentEventToolStart, Data: json.RawMessage(`{"name":"exec"}`)}, 7, "ag-1", 1234)
	var got map[string]interface{}
	if err := json.Unmarshal(obj, &got); err != nil {
		t.Fatalf("对象载荷不是合法 JSON: %v (%s)", err, obj)
	}
	if got["name"] != "exec" {
		t.Fatalf("原有字段丢失: %s", obj)
	}
	if got["seq"] != float64(7) || got["run_id"] != "ag-1" || got["ts"] != float64(1234) {
		t.Fatalf("seq/run_id/ts 没注入对: %s", obj)
	}

	bare := buildEventPayload(AgentEvent{Kind: AgentEventError, Error: "boom"}, 8, "ag-1", 1)
	var em map[string]interface{}
	if err := json.Unmarshal(bare, &em); err != nil || em["error"] != "boom" || em["seq"] != float64(8) {
		t.Fatalf("error 事件载荷应有 error/seq: %s", bare)
	}

	broken := buildEventPayload(AgentEvent{Kind: AgentEventToolResult, Data: json.RawMessage(`[1,2]`)}, 9, "ag-1", 1)
	if string(broken) != `[1,2]` {
		t.Fatalf("非对象载荷应原样透传，实际 %s", broken)
	}
}

// TestEmitAssignsSeqAndPayload 事件序号与载荷 seq 一致、run_id/ts 齐全。
func TestEmitAssignsSeqAndPayload(t *testing.T) {
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)

	run.EmitEvent(AgentEventThinking, "想", "")
	run.EmitEvent(AgentEventToolStart, ToolStart{Name: "exec", TraceID: "tr-1"}, "")
	run.EmitEvent(AgentEventFinal, "答复", "")

	var want []uint64 = []uint64{1, 2, 3}
	for _, wantSeq := range want {
		select {
		case ev := <-run.Events():
			if ev.Seq != wantSeq {
				t.Fatalf("事件 seq = %d, want %d", ev.Seq, wantSeq)
			}
			if ev.Ts == 0 {
				t.Fatalf("事件 ts 未填充")
			}
			if ev.Kind == AgentEventThinking || ev.Kind == AgentEventFinal {
				if string(ev.Payload) != string(ev.Data) {
					t.Fatalf("%s 载荷应原样透传，payload=%s data=%s", ev.Kind, ev.Payload, ev.Data)
				}
				continue
			}
			var got map[string]interface{}
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("对象载荷非法: %v", err)
			}
			if got["seq"] != float64(ev.Seq) || got["run_id"] != run.ID {
				t.Fatalf("载荷 seq/run_id 与事件不一致: %s", ev.Payload)
			}
		default:
			t.Fatalf("seq=%d 的事件没有投递", wantSeq)
		}
	}

	snap := run.EventSnapshot()
	if snap.Head != 3 || snap.Len() != 3 || snap.Oldest != 1 {
		t.Fatalf("快照 head/len/oldest = %d/%d/%d, want 3/3/1", snap.Head, snap.Len(), snap.Oldest)
	}
}

// TestEmitDropMarksWatermarkWithoutConsumingSeq 通道满时的丢弃路径：
//   - 不占 seq（seq 口径是"已投递事件"，被丢的事件从没进过客户端，
//     占号只会在回放缓冲里留一个无法回放的洞）；
//   - droppedAfter 记"丢弃前最后一个成功投递的 seq"，droppedCount 累加；
//   - 敲一下 dropNotify（否则通道满期间没有新事件可读，缺口永远没人告知客户端）；
//   - 被丢的事件不进回放缓冲（回放不能补发它从没投递过的东西）。
func TestEmitDropMarksWatermarkWithoutConsumingSeq(t *testing.T) {
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)

	capacity := cap(run.events)
	for i := 0; i < capacity; i++ {
		run.EmitEvent(AgentEventMessage, "x", "")
	}
	before := run.EventSnapshot()
	if before.Head != uint64(capacity) {
		t.Fatalf("填满后 head = %d, want %d", before.Head, capacity)
	}
	if before.DroppedCount != 0 {
		t.Fatalf("还没丢事件，droppedCount 应为 0")
	}

	run.EmitEvent(AgentEventMessage, "y", "")
	after := run.EventSnapshot()
	if after.Head != before.Head {
		t.Fatalf("被丢弃的事件不应占用 seq：head %d → %d", before.Head, after.Head)
	}
	if after.DroppedCount != 1 || after.DroppedAfter != before.Head {
		t.Fatalf("丢弃水位 = after:%d count:%d, want after:%d count:1",
			after.DroppedAfter, after.DroppedCount, before.Head)
	}
	select {
	case <-run.DropNotify():
	default:
		t.Fatalf("丢弃后应敲一下 dropNotify（否则 SSE handler 无法醒来告知缺口）")
	}

	// 腾出一个位置后继续投递：seq 紧接在丢弃前那条之后（连续，不跳号）。
	<-run.Events()
	run.EmitEvent(AgentEventMessage, "z", "")
	got := run.EventSnapshot()
	if got.Head != before.Head+1 {
		t.Fatalf("丢弃后的下一条事件 seq = %d, want %d（被丢事件不占号）", got.Head, before.Head+1)
	}
	if got.DroppedCount != 1 || got.DroppedAfter != before.Head {
		t.Fatalf("后续成功投递不应改变丢弃水位: after=%d count=%d", got.DroppedAfter, got.DroppedCount)
	}
}

// TestEmitConcurrentKeepsSeqOrder 并发 emit 的不变量：**通道到达顺序必须等于 seq 顺序**。
//
// 为什么这条最重要：重连交接靠"seq ≤ 已发水位线就跳过"去重；一旦两条并发事件
// 的到达顺序与 seq 相反，后到的那条（较小的 seq）会被当成重复**静默吃掉**。
// 所以 emit 把「分配 seq → 投递通道 → 写回放缓冲」放在同一个临界区里。
//
// 本机不能跑 -race，但顺序不变量与"一条不丢"在这里都能断言（事件数 < 通道容量，
// 因此不应出现丢弃）。
func TestEmitConcurrentKeepsSeqOrder(t *testing.T) {
	const writers, perWriter = 4, 400
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				run.EmitEvent(AgentEventMessage, fmt.Sprintf("w%d-%d", w, i), "")
			}
		}(w)
	}
	wg.Wait()

	total := writers * perWriter
	if snap := run.EventSnapshot(); snap.Head != uint64(total) || snap.DroppedCount != 0 {
		t.Fatalf("head=%d dropped=%d, want %d/0（事件数应小于通道容量，不该丢）",
			snap.Head, snap.DroppedCount, total)
	}
	prev := uint64(0)
	for i := 0; i < total; i++ {
		select {
		case ev := <-run.Events():
			if ev.Seq != prev+1 {
				t.Fatalf("第 %d 条事件 seq=%d，期望 %d（到达顺序与 seq 顺序不一致）", i, ev.Seq, prev+1)
			}
			prev = ev.Seq
		default:
			t.Fatalf("只收到 %d 条，期望 %d 条", i, total)
		}
	}
	// 回放缓冲只保留最近 AgentEventRingSize 条，且载荷 seq 自洽。
	snap := run.EventSnapshot()
	if snap.Len() != AgentEventRingSize {
		t.Fatalf("回放缓冲保留 %d 条, want %d", snap.Len(), AgentEventRingSize)
	}
	entries := snap.After(0)
	if last := entries[len(entries)-1]; last.Seq != uint64(total) || strings.HasPrefix(string(last.Payload), "{") {
		// 字符串载荷（message）按设计不注入 seq，只透传；seq 由事件记录/SSE 的 id: 承载。
		t.Fatalf("最新一条应为 seq=%d 的字符串载荷，实际 seq=%d payload=%s", total, last.Seq, last.Payload)
	}
}

// TestResetForResumeClearsRingKeepsSeq 复用 run 续接新指令后：
// 回放缓冲清空、seq 继续、事件通道容量不变（历史坑见 agentEventBuffer 注释）。
func TestResetForResumeClearsRingKeepsSeq(t *testing.T) {
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)
	run.EmitEvent(AgentEventMessage, "旧片段", "")
	run.EmitEvent(AgentEventMessage, "旧片段2", "")

	run.ResetForResume()
	snap := run.EventSnapshot()
	if snap.Len() != 0 || snap.Head != 2 || snap.Oldest != 3 {
		t.Fatalf("恢复后 len/head/oldest = %d/%d/%d, want 0/2/3", snap.Len(), snap.Head, snap.Oldest)
	}
	if cap(run.Events()) != agentEventBuffer {
		t.Fatalf("恢复后事件通道容量 = %d, want %d", cap(run.Events()), agentEventBuffer)
	}
	run.EmitEvent(AgentEventMessage, "新片段", "")
	if got := run.EventSnapshot(); got.Head != 3 {
		t.Fatalf("恢复后新事件 seq = %d, want 3（seq 必须跨恢复单调）", got.Head)
	}
}

// TestEmitAfterCloseIsSafe run 终态关闭事件通道后仍有事件到达（任务恢复桥在另一个
// goroutine 上补发）时应静默丢弃，而不是 panic: send on closed channel。
func TestEmitAfterCloseIsSafe(t *testing.T) {
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)
	run.EmitEvent(AgentEventDone, DoneInfo{TraceID: "tr-1"}, "")
	run.closeEvents()
	run.EmitEvent(AgentEventError, nil, "late") // 不应 panic
	if got := run.EventSnapshot(); got.Head != 1 {
		t.Fatalf("关闭后的事件不应进入事件流（head=%d, want 1）", got.Head)
	}
	if _, ok := <-run.Events(); !ok {
		t.Fatalf("通道已关闭，读到的应是 done 事件")
	}
}

func seqsOf(recs []RingEvent) []uint64 {
	out := make([]uint64, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Seq)
	}
	return out
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"toshell/internal/server/ai"
	"toshell/internal/server/config"
)

// ─── SSE 断点续传（id: / Last-Event-ID / resync）的 HTTP 层用例 ──────────
//
// 用真实 handler + 真实 ai.AgentManager/AgentRun（httptest 请求 + 内存 ResponseWriter），
// 不联网、不需要 LLM/植入端：事件一律用 run.EmitEvent 注入。
//
// 覆盖：id 与载荷 seq 一致、无水位线=从当前开始、带水位线恰好补齐（不重不丢）、
// 回放期间并发 emit 的交接竞态、水位线过旧（events_expired）、
// 运行中丢弃（events_dropped）、终态晚订阅（有上限回放 + state）、retry/心跳、心跳不进缓冲。

// sseRecorder 可并发读写的 ResponseWriter + Flusher：
// SSE handler 在 goroutine 里持续写，测试在主 goroutine 里轮询已收到的帧。
//
// hold/holdAt 让测试能**确定性**地把 handler 卡在"回放进行到一半"的位置，
// 从而在回放中间插入新事件 —— 交接竞态用例（不重不丢）靠它才可复现。
type sseRecorder struct {
	mu    sync.Mutex
	h     http.Header
	buf   bytes.Buffer
	count int // 已写完的 SSE 帧数（以 \n\n 结尾计）

	hold   chan struct{}
	holdAt int
}

func newSSERecorder() *sseRecorder { return &sseRecorder{h: http.Header{}} }

// pauseAfterFrames 让 handler 写完第 n 帧后阻塞，直到 release() 被调用。
// 用来把 handler 精确卡在"回放进行到一半"，让测试在回放中间插入新事件。
// 返回的 release 可安全重复调用（once 保证只关一次）。
func (r *sseRecorder) pauseAfterFrames(n int) func() {
	hold := make(chan struct{})
	r.mu.Lock()
	r.hold, r.holdAt = hold, n
	r.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(hold) }) }
}

func (r *sseRecorder) Header() http.Header { return r.h }
func (r *sseRecorder) WriteHeader(int)     {}
func (r *sseRecorder) Flush()              {}

func (r *sseRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	n, err := r.buf.Write(b)
	// 只统计本次写入里的帧尾，避免每次 O(整个缓冲)。
	r.count += strings.Count(string(b), "\n\n")
	hold := r.hold
	reached := hold != nil && r.holdAt > 0 && r.count >= r.holdAt
	if reached {
		r.hold = nil
	}
	r.mu.Unlock()
	if reached {
		<-hold // 卡住 handler：测试在"回放进行中"插入新事件
	}
	return n, err
}

func (r *sseRecorder) frames() []sseFrame {
	r.mu.Lock()
	body := r.buf.String()
	r.mu.Unlock()
	return parseSSEFrames(body)
}

func (r *sseRecorder) frameCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// sseFrame 一个解析后的 SSE 帧。
type sseFrame struct {
	id      uint64
	hasID   bool
	event   string
	data    string
	retry   string
	comment bool
}

// parseSSEFrames 按 \n\n 切分事件块；未接收完整的块（没有 data/retry/注释）直接跳过，
// 避免把"写到一半的帧"当成事件。
func parseSSEFrames(body string) []sseFrame {
	var out []sseFrame
	for _, block := range strings.Split(body, "\n\n") {
		block = strings.TrimRight(block, "\n")
		if strings.TrimSpace(block) == "" {
			continue
		}
		f := sseFrame{}
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "id:"):
				if v, err := strconv.ParseUint(strings.TrimSpace(line[3:]), 10, 64); err == nil {
					f.id, f.hasID = v, true
				}
			case strings.HasPrefix(line, "event:"):
				f.event = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:"):
				f.data = strings.TrimSpace(line[5:])
			case strings.HasPrefix(line, "retry:"):
				f.retry = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, ":"):
				f.comment = true
			}
		}
		if f.data == "" && f.retry == "" && !f.comment {
			continue
		}
		out = append(out, f)
	}
	return out
}

// newSSETestServer 起一个"AI 已启用"的最小 Server：Copilot 只为过 handler 的
// Enabled() 检查，BaseURL 指向本机不存在的端口，任何真实网络调用都会立刻失败
// （用例不该走到那里）。
func newSSETestServer(t *testing.T) *Server {
	t.Helper()
	env := newAgentTaskTestEnv(t, false)
	aiCfg := config.AIConfig{
		Enabled: true, BaseURL: "http://127.0.0.1:9/v1", APIKey: "k", Model: "m",
		ConsentPolicy:        "off",
		LongTaskThresholdSec: ai.DefaultLongTaskThresholdSec,
		MaxTurns:             20,
		MaxToolCalls:         40,
		MaxWallclockSec:      900,
	}
	env.s.cfg.AI = aiCfg
	cp := ai.New(aiCfg, env.s)
	env.s.copilot = cp
	env.s.applyLongTaskExecutor(cp)
	return env.s
}

// startSSE 启动真实 handler（直接挂到 recorder 上）。ctx 在用例结束时取消。
func startSSE(t *testing.T, s *Server, runID, lastEventID, query string) *sseRecorder {
	t.Helper()
	rec := newSSERecorder()
	startSSEOn(t, s, rec, runID, lastEventID, query)
	return rec
}

func startSSEOn(t *testing.T, s *Server, rec *sseRecorder, runID, lastEventID, query string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	url := "/api/v1/agent/runs/" + runID + "/events"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	go s.agentEventsHandler(rec, req)
}

// dataEventFrames 只保留 run 数据事件（排除 retry/status/state/resync/注释）。
func dataEventFrames(frames []sseFrame) []sseFrame {
	var out []sseFrame
	for _, f := range frames {
		switch f.event {
		case "", "status", "state", "resync":
			continue
		}
		out = append(out, f)
	}
	return out
}

func findFrame(frames []sseFrame, event string) (sseFrame, bool) {
	for _, f := range frames {
		if f.event == event {
			return f, true
		}
	}
	return sseFrame{}, false
}

func frameSeqList(frames []sseFrame) []uint64 {
	out := make([]uint64, 0, len(frames))
	for _, f := range dataEventFrames(frames) {
		out = append(out, f.id)
	}
	return out
}

// assertExactSeqRun 断言事件 seq 恰好是 wantFrom..wantTo 各一次、严格递增。
func assertExactSeqRun(t *testing.T, frames []sseFrame, wantFrom, wantTo uint64, what string) {
	t.Helper()
	got := frameSeqList(frames)
	want := make([]uint64, 0, wantTo-wantFrom+1)
	for s := wantFrom; s <= wantTo; s++ {
		want = append(want, s)
	}
	if len(got) != len(want) {
		t.Fatalf("%s：收到 %d 条事件 %v，want %d 条 %v", what, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s：第 %d 条 seq=%d，want %d（完整序列 %v）", what, i, got[i], want[i], got)
		}
	}
}

func payloadSeqOf(t *testing.T, f sseFrame) uint64 {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(f.data), &m); err != nil {
		t.Fatalf("载荷不是 JSON 对象: %s (%v)", f.data, err)
	}
	raw, ok := m["seq"]
	if !ok {
		t.Fatalf("对象载荷里没有 seq 字段: %s", f.data)
	}
	var v uint64
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("载荷 seq 不是数字: %s", f.data)
	}
	return v
}

// ─── 用例 ────────────────────────────────────────────────────────────

// TestAgentEventsSSEContractAndFromNow 无 Last-Event-ID 的运行中订阅 = "从当前开始"；
// 同时钉住新增契约：retry 帧、status 控制帧不带 id、id 与载荷 seq 一致、
// 字符串载荷原样透传（不能被注入改成对象）、对象载荷带 seq/run_id/ts。
func TestAgentEventsSSEContractAndFromNow(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)

	// 连接前已产生的事件：运行中的 run 不回放（客户端没声明缺哪一段，
	// "从当前开始"是它的语义；要全量回放可显式 ?last_event_id=0）。
	run.EmitEvent(ai.AgentEventMessage, "pre-1", "") // seq 1
	run.EmitEvent(ai.AgentEventMessage, "pre-2", "") // seq 2

	rec := startSSE(t, s, run.ID, "", "")
	waitFor(t, 3*time.Second, "收到 retry + status", func() bool { return rec.frameCount() >= 2 })

	run.EmitEvent(ai.AgentEventMessage, "live-1", "")                     // seq 3
	run.EmitEvent(ai.AgentEventToolStart, ai.ToolStart{Name: "exec"}, "") // seq 4
	run.EmitEvent(ai.AgentEventThinking, "在思考", "")                       // seq 5
	waitFor(t, 3*time.Second, "收到 3 条实时事件", func() bool { return rec.frameCount() >= 5 })

	frames := rec.frames()
	if frames[0].retry != "3000" {
		t.Fatalf("第一帧应是 retry 建议，实际 %+v", frames[0])
	}
	status, ok := findFrame(frames, "status")
	if !ok || !strings.Contains(status.data, run.ID) {
		t.Fatalf("缺 status 帧或载荷不含 run_id: %+v", frames)
	}
	if status.hasID {
		t.Fatalf("status 是控制帧，不该带 id:（会污染客户端续传水位线）")
	}

	assertExactSeqRun(t, frames, 3, 5, "无水位线应从当前开始，不重放 1、2")
	dfs := dataEventFrames(frames)
	for i, f := range dfs {
		if !f.hasID || f.id == 0 {
			t.Fatalf("第 %d 条事件缺 id: %+v", i, f)
		}
	}
	// 字符串载荷（message/thinking）必须原样透传：包成对象会让老前端
	// `typeof ev.data === 'string'` 的正文累加直接坏掉。
	if dfs[0].data != `"live-1"` {
		t.Fatalf("message 载荷应原样是字符串，实际 %s", dfs[0].data)
	}
	if ds := payloadSeqOf(t, dfs[1]); ds != dfs[1].id {
		t.Fatalf("对象载荷 seq=%d 与 id=%d 不一致", ds, dfs[1].id)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(dfs[1].data), &payload); err != nil {
		t.Fatalf("tool_start 载荷非法: %v", err)
	}
	if payload["name"] != "exec" || payload["run_id"] != run.ID {
		t.Fatalf("对象载荷缺 name/run_id: %s", dfs[1].data)
	}
	if ts, _ := payload["ts"].(float64); ts <= 0 {
		t.Fatalf("对象载荷缺 ts: %s", dfs[1].data)
	}
}

// TestAgentEventsSSEReplayExactGap 带 Last-Event-ID 时必须**恰好**补齐缺口：
// 只发 L 之后的事件、各一次，然后无缝切到实时流。
//
// 这里刻意让连接前的 1..6 条事件仍留在事件通道缓冲里（没有任何消费者读过），
// 于是"快照回放"与"实时通道"对同一条事件各有一份 —— 去重逻辑必须把它们吃掉，
// 否则客户端会看到 3..6 各两遍。
func TestAgentEventsSSEReplayExactGap(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	for i := 1; i <= 6; i++ {
		run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("m%d", i), "")
	}

	rec := startSSE(t, s, run.ID, "2", "")
	waitFor(t, 3*time.Second, "回放 4 条", func() bool { return len(dataEventFrames(rec.frames())) >= 4 })

	assertExactSeqRun(t, rec.frames(), 3, 6, "回放应恰好补齐 (2,6]")

	// 无缝切实时：新事件必须继续按 seq 送达，且不能重复已回放的部分。
	run.EmitEvent(ai.AgentEventMessage, "live", "") // seq 7
	waitFor(t, 3*time.Second, "收到实时事件 seq=7", func() bool { return rec.frameCount() >= 7 })
	assertExactSeqRun(t, rec.frames(), 3, 7, "回放 + 实时应连续且不重复")
}

// TestAgentEventsSSEQueryParamLastEventID 浏览器 EventSource 无法自定义请求头，
// 也支持 ?last_event_id= 查询参数（语义与请求头完全一致）。
func TestAgentEventsSSEQueryParamLastEventID(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	for i := 1; i <= 5; i++ {
		run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("m%d", i), "")
	}

	rec := startSSE(t, s, run.ID, "", "last_event_id=4")
	waitFor(t, 3*time.Second, "回放 seq=5", func() bool { return rec.frameCount() >= 3 })
	assertExactSeqRun(t, rec.frames(), 5, 5, "查询参数水位线应只补发 (4,5]")

	// 脏值当作"没有水位线"（不瞎猜序号），且不能把 handler 打挂。
	rec2 := startSSE(t, s, run.ID, "not-a-number", "")
	waitFor(t, 3*time.Second, "脏水位线仍能建流", func() bool { return rec2.frameCount() >= 2 })
	if _, ok := findFrame(rec2.frames(), "status"); !ok {
		t.Fatalf("脏水位线下仍应发 status 帧")
	}
}

// TestAgentEventsSSEHandoffRaceNoGapNoDup 交接竞态：**回放进行中**并发 emit 事件。
//
// 用 recorder 的 hold 把 handler 卡在第 12 帧（retry + status + 10 条回放）之后，
// 此时造 21..60 —— 一部分进通道缓冲、一部分随后到达；放开后 handler 先补完剩余回放，
// 再切实时。最终客户端收到的 seq 序列必须是 6..60 且**严格连续、无重复**。
// 这是本项最容易写错的地方（先回放后订阅会丢、回放不去重会重），重复多轮以抖出时序问题。
func TestAgentEventsSSEHandoffRaceNoGapNoDup(t *testing.T) {
	s := newSSETestServer(t)
	for iter := 0; iter < 5; iter++ {
		run := s.agentMgr.NewRun(nil, 0)
		for i := 1; i <= 20; i++ {
			run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("pre-%d", i), "")
		}

		rec := newSSERecorder()
		// retry(1) + status(1) + 已回放 10 条 → 卡在回放中途
		release := rec.pauseAfterFrames(12)
		startSSEOn(t, s, rec, run.ID, "5", "")

		waitFor(t, 3*time.Second, "handler 卡在回放中途", func() bool { return rec.frameCount() >= 12 })

		// 回放进行中并发造事件 21..60。
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 21; i <= 60; i++ {
				run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("during-%d", i), "")
				time.Sleep(200 * time.Microsecond)
			}
		}()
		time.Sleep(3 * time.Millisecond) // 先让一部分事件落进通道
		release()
		wg.Wait()

		waitFor(t, 5*time.Second, fmt.Sprintf("第 %d 轮收到 6..60", iter), func() bool {
			return len(dataEventFrames(rec.frames())) >= 55
		})
		assertExactSeqRun(t, rec.frames(), 6, 60, fmt.Sprintf("第 %d 轮交接", iter))
	}
}

// TestAgentEventsSSEWatermarkAboveHeadStreamsFromNow 客户端水位线比服务端还高
// （重启后 run 被恢复：同一个 run id、内存序号从 1 重新开始；或者是个脏 id）。
// 此时必须按"从当前开始"处理：把水位线原样信下来会让新事件的 seq 一直小于它，
// 被去重逻辑全部跳过 —— 客户端表现为永久黑屏。
func TestAgentEventsSSEWatermarkAboveHeadStreamsFromNow(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	run.Status = ai.AgentRunning
	run.EmitEvent(ai.AgentEventMessage, "before-restart", "") // seq 1（重启前的旧序号）

	rec := startSSE(t, s, run.ID, "999999", "")
	waitFor(t, 3*time.Second, "status 帧", func() bool { return rec.frameCount() >= 2 })

	// 重启后的新事件（seq 2）必须送达，不能被 999999 的水位线吞掉。
	run.EmitEvent(ai.AgentEventMessage, "after-restart", "")
	waitFor(t, 3*time.Second, "水位线过高时仍能收到新事件", func() bool {
		return len(dataEventFrames(rec.frames())) >= 1
	})
	assertExactSeqRun(t, rec.frames(), 2, 2, "水位线高于 head 时应从当前开始")
}

// TestAgentEventsSSEExpiredResync 请求的水位线早于缓冲最旧事件（已被淘汰）：
// 必须发 resync{events_expired} 显式告知，并且**不补**一段中间缺了一块的"半个故事"，
// 之后只推实时事件。
func TestAgentEventsSSEExpiredResync(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	run.Status = ai.AgentRunning // 运行中掉线重连的典型场景

	// 制造淘汰：事件数 > 环形缓冲容量（512）。
	total := ai.AgentEventRingSize + 20
	for i := 1; i <= total; i++ {
		run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("m%d", i), "")
	}

	rec := startSSE(t, s, run.ID, "5", "")
	waitFor(t, 3*time.Second, "收到 resync", func() bool {
		_, ok := findFrame(rec.frames(), "resync")
		return ok
	})
	frames := rec.frames()
	rs, _ := findFrame(frames, "resync")
	if rs.hasID {
		t.Fatalf("resync 是控制帧，不该带 id:（它表示「这段补不了」，带 id 会误导续传水位线）")
	}
	var info ai.ResyncInfo
	if err := json.Unmarshal([]byte(rs.data), &info); err != nil {
		t.Fatalf("resync 载荷非法: %v (%s)", err, rs.data)
	}
	if info.Reason != "events_expired" {
		t.Fatalf("reason = %q, want events_expired", info.Reason)
	}
	if info.Current != uint64(total) {
		t.Fatalf("current = %d, want %d", info.Current, total)
	}
	if info.Oldest != uint64(total-ai.AgentEventRingSize+1) {
		t.Fatalf("oldest = %d, want %d（保留区间的下界）", info.Oldest, total-ai.AgentEventRingSize+1)
	}
	if info.Status != string(ai.AgentRunning) {
		t.Fatalf("resync 应带上 run 当前状态，实际 %q", info.Status)
	}
	if len(dataEventFrames(frames)) != 0 {
		t.Fatalf("过期时不应补发保留区间的尾巴（会造成「看起来连续」的假象）：%v", frameSeqList(frames))
	}

	// 之后实时事件照常推，水位线从 current 继续。
	run.EmitEvent(ai.AgentEventMessage, "after-resync", "") // seq total+1
	waitFor(t, 3*time.Second, "过期后仍能收到实时事件", func() bool {
		return len(dataEventFrames(rec.frames())) >= 1
	})
	assertExactSeqRun(t, rec.frames(), uint64(total+1), uint64(total+1), "过期后只推实时")
}

// TestAgentEventsSSEDroppedResyncOnConnect 运行中丢过事件（通道满）→
// 重连时即使 seq 空间是连续的，也必须补一条 resync{events_dropped}：
// 被丢的事件从没进过回放缓冲，谁也不补回来，客户端必须知道"这条流不完整"。
func TestAgentEventsSSEDroppedResyncOnConnect(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)

	capacity := cap(run.Events())
	for i := 0; i < capacity; i++ {
		run.EmitEvent(ai.AgentEventMessage, "x", "")
	}
	run.EmitEvent(ai.AgentEventMessage, "dropped", "") // 通道满 → 丢弃

	rec := startSSE(t, s, run.ID, strconv.Itoa(capacity-2), "")
	waitFor(t, 3*time.Second, "收到 resync(events_dropped)", func() bool {
		f, ok := findFrame(rec.frames(), "resync")
		return ok && strings.Contains(f.data, "events_dropped")
	})

	frames := rec.frames()
	rs, _ := findFrame(frames, "resync")
	var info ai.ResyncInfo
	if err := json.Unmarshal([]byte(rs.data), &info); err != nil {
		t.Fatalf("resync 载荷非法: %v (%s)", err, rs.data)
	}
	if info.DroppedCount != 1 || info.DroppedAfter != uint64(capacity) {
		t.Fatalf("丢弃水位 = after:%d count:%d, want after:%d count:1",
			info.DroppedAfter, info.DroppedCount, capacity)
	}
	// 丢弃不占 seq：下一条实时事件仍紧接在丢弃前那条之后（空间连续）。
	run.EmitEvent(ai.AgentEventMessage, "after-drop", "")
	waitFor(t, 3*time.Second, "丢弃后的实时事件 seq 连续", func() bool {
		return len(dataEventFrames(rec.frames())) >= 3
	})
	assertExactSeqRun(t, rec.frames(), uint64(capacity-1), uint64(capacity+1), "回放尾巴 + 连续的新事件")
}

// TestAgentEventsSSEDroppedResyncWhileStreaming 已经连着的情况下发生丢弃：
// 通道满时 emit 无法把"我丢了一条"写进通道（那正是通道满的原因），
// 必须靠 dropNotify 把 handler 叫醒去读水位，否则缺口永远没人告知客户端。
//
// 用 ?last_event_id=0 起流（显式水位线 = 从缓冲开头补），并让 handler 卡在
// "回放最后一条"之后再灌满通道 —— 这样丢弃确实发生在这条连接**已经开始收流之后**。
func TestAgentEventsSSEDroppedResyncWhileStreaming(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	run.Status = ai.AgentRunning
	capacity := cap(run.Events())

	run.EmitEvent(ai.AgentEventMessage, "pre", "") // seq 1，会在回放里发给客户端

	rec := newSSERecorder()
	// retry + status + 回放第 1 条：此刻快照已取完、handler 正在回放
	release := rec.pauseAfterFrames(3)
	startSSEOn(t, s, rec, run.ID, "0", "")
	waitFor(t, 3*time.Second, "handler 卡在回放第一条之后", func() bool { return rec.frameCount() >= 3 })

	// 通道里已有 1 条（回放那条第 1 条还没被 handler 从通道读走），
	// 再灌 capacity-1+dropped 条：capacity-1 条成功（占满缓冲），剩下 dropped 条被丢。
	const dropped = 8
	for i := 0; i < capacity-1+dropped; i++ {
		run.EmitEvent(ai.AgentEventMessage, "x", "")
	}
	release()

	// retry + status + capacity 条数据 + 1 条 resync
	waitFor(t, 10*time.Second, "收到全部缓冲事件与 resync", func() bool {
		return rec.frameCount() >= 2+capacity+1
	})
	frames := rec.frames()
	rs, ok := findFrame(frames, "resync")
	if !ok {
		t.Fatalf("通道满丢弃后必须发 resync(events_dropped)")
	}
	var info ai.ResyncInfo
	if err := json.Unmarshal([]byte(rs.data), &info); err != nil {
		t.Fatalf("resync 载荷非法: %v (%s)", err, rs.data)
	}
	if info.Reason != "events_dropped" || info.DroppedCount != dropped || info.DroppedAfter != uint64(capacity) {
		t.Fatalf("丢弃告知不准确: %+v（want reason=events_dropped after=%d count=%d）", info, capacity, dropped)
	}
	// 丢掉的 8 条不占 seq，所以客户端看到的就是 1..capacity，没有幽灵事件。
	assertExactSeqRun(t, frames, 1, uint64(capacity), "在线流应恰好拿到 1..capacity")
	if n := len(dataEventFrames(frames)); n != capacity {
		t.Fatalf("数据事件 %d 条, want %d", n, capacity)
	}
}

// TestAgentEventsSSETerminalLateSubscribeCapped 终态 run 的晚订阅：
// 先回放缓冲尾部（让晚到者也能看到 thinking/tool 过程），再推终态 state；
// 回放条数受上限约束（避免一次吐几百条）。
func TestAgentEventsSSETerminalLateSubscribeCapped(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	const total = 250
	for i := 1; i <= total; i++ {
		run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("m%d", i), "")
	}
	run.Status = ai.AgentDone
	run.FinalReply = "完成"

	rec := startSSE(t, s, run.ID, "", "")
	waitFor(t, 3*time.Second, "收到终态 state", func() bool {
		_, ok := findFrame(rec.frames(), "state")
		return ok
	})
	frames := rec.frames()
	dfs := dataEventFrames(frames)
	if len(dfs) != ai.AgentReplayTailMax {
		t.Fatalf("回放 %d 条, want %d（有上限约束）", len(dfs), ai.AgentReplayTailMax)
	}
	from := uint64(total - ai.AgentReplayTailMax + 1)
	assertExactSeqRun(t, frames, from, total, "终态晚订阅应回放尾部")

	st, ok := findFrame(frames, "state")
	if !ok {
		t.Fatalf("终态晚订阅必须保留 state 事件（老前端兼容）")
	}
	var state map[string]interface{}
	if err := json.Unmarshal([]byte(st.data), &state); err != nil {
		t.Fatalf("state 载荷非法: %v", err)
	}
	if state["done"] != true || state["reply"] != "完成" {
		t.Fatalf("state 载荷 = %s, want done:true reply:完成", st.data)
	}
}

// TestAgentEventsSSETerminalExplicitGapFill 终态 run 带水位线时仍按"恰好补齐"走
// （不被尾部回放上限截断）：客户端明确说了自己看到哪，就该把之后的都给它。
func TestAgentEventsSSETerminalExplicitGapFill(t *testing.T) {
	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	for i := 1; i <= 30; i++ {
		run.EmitEvent(ai.AgentEventMessage, fmt.Sprintf("m%d", i), "")
	}
	run.Status = ai.AgentDone
	run.FinalReply = "done"

	rec := startSSE(t, s, run.ID, "25", "")
	waitFor(t, 3*time.Second, "回放 + state", func() bool {
		_, ok := findFrame(rec.frames(), "state")
		return ok
	})
	assertExactSeqRun(t, rec.frames(), 26, 30, "终态 + 水位线应恰好补齐 (25,30]")
}

// TestAgentEventsSSEHeartbeatIsNotAnEvent 心跳注释帧：防中间代理掐空闲长连接，
// 但它**不是事件**——不占 seq、不进回放缓冲、不推进客户端水位线。
func TestAgentEventsSSEHeartbeatIsNotAnEvent(t *testing.T) {
	old := agentSSEHeartbeatInterval
	agentSSEHeartbeatInterval = 15 * time.Millisecond
	t.Cleanup(func() { agentSSEHeartbeatInterval = old })

	s := newSSETestServer(t)
	run := s.agentMgr.NewRun(nil, 0)
	rec := startSSE(t, s, run.ID, "", "")
	waitFor(t, 3*time.Second, "收到心跳注释帧", func() bool {
		for _, f := range rec.frames() {
			if f.comment {
				return true
			}
		}
		return false
	})

	frames := rec.frames()
	for _, f := range frames {
		if f.comment && (f.hasID || f.data != "") {
			t.Fatalf("心跳只能是注释帧（无 id、无 data）: %+v", f)
		}
	}
	if len(dataEventFrames(frames)) != 0 {
		t.Fatalf("空闲 run 不应产生数据事件: %v", frameSeqList(frames))
	}
	if head := run.EventSnapshot().Head; head != 0 {
		t.Fatalf("心跳不该进回放缓冲（head=%d, want 0）", head)
	}
}

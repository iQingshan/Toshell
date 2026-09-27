package task

import (
	"testing"
	"time"

	"toshell/internal/common/avops"
	"toshell/internal/common/types"
	"toshell/internal/server/session"
)

// ─── 破坏性任务禁止自动重试（v1.4.0 S6）───────────────────────────────────────
//
// 这些用例要证明的是**行为**，不是文案：
//
//	"同一条破坏性任务在超时/断线后不会被服务端自动重新投递，因此植入端不会二次执行"
//
// 服务端只有两条自动重投递路径，必须都堵住：
//  ① ListReplayable → replaySessionTasks（TCP/WS/MQTT 会话重连热迁移补发）；
//  ② RequeueSent（HTTP 轮询通道在心跳时把超期的 sent 任务重新入队）。
//
// 只堵一条等于"换个通道就能重发"，所以两条路径各有用例，且都断言"任务没有被重投递"
// 而不是"碰巧没重投递"（新任务仍是 pending 队列里的 sent 状态、refused 计数为 1）。

func newNoRetryEnv(t *testing.T) (*Manager, string) {
	t.Helper()
	sessMgr := session.New()
	sid := "noretry-" + t.Name()
	if err := sessMgr.Add(&types.SessionInfo{
		ID: sid, Hostname: "host", Username: "user", OS: "windows", Status: "active",
	}); err != nil {
		t.Fatalf("session Add: %v", err)
	}
	t.Cleanup(func() { _ = sessMgr.Remove(sid) })
	return NewIsolated(sessMgr), sid
}

// markSent 把任务推进到 sent（等价于"已派发给植入端但还没收到结果"）。
func markSent(t *testing.T, m *Manager, sid string, id uint64) *types.TaskInfo {
	t.Helper()
	got, err := m.GetNext(sid)
	if err != nil {
		t.Fatalf("GetNext: %v", err)
	}
	if got.ID != id {
		t.Fatalf("GetNext 取到的是 task %d, want %d（用例前置条件不成立）", got.ID, id)
	}
	if got.Status != StatusSent {
		t.Fatalf("派发后状态 = %s, want %s", got.Status, StatusSent)
	}
	return got
}

// TestRequeueSentRefusesDestructiveTasks 路径 ②：HTTP 轮询通道。
func TestRequeueSentRefusesDestructiveTasks(t *testing.T) {
	m, sid := newNoRetryEnv(t)

	// 一条破坏性任务（L1 edr_blind）+ 一条普通任务（file_list）
	blind, err := m.Create(sid, TaskParams{TaskType: TaskTypeEDRBlind, Data: `{}`})
	if err != nil {
		t.Fatalf("Create edr_blind: %v", err)
	}
	flist, err := m.Create(sid, TaskParams{TaskType: TaskTypeFileList, Path: "C:\\"})
	if err != nil {
		t.Fatalf("Create file_list: %v", err)
	}
	markSent(t, m, sid, blind.ID)
	markSent(t, m, sid, flist.ID)

	// staleAfter=0：两条都"超期无结果"
	requeued, refused := m.RequeueSentEx(sid, 0)
	if requeued != 1 {
		t.Fatalf("重新入队 %d 条, want 1（只有普通任务可以被重投递）", requeued)
	}
	if refused != 1 {
		t.Fatalf("拒绝重投递 %d 条, want 1（破坏性任务必须被拒）", refused)
	}

	// 硬断言：破坏性任务**没有**回到 pending（否则 HTTP 通道下次心跳就会下发 = 二次执行）
	pending := m.ListPending()
	for _, p := range pending {
		if p.ID == blind.ID {
			t.Fatalf("破坏性任务 %d 被重新放回 pending —— 重投递未被堵住（pending=%v）", blind.ID, idsOf(pending))
		}
	}
	// 它保持 sent：我们不知道植入端有没有执行过，不擅自改终态（见 RequeueSentEx 注释）
	if got, _ := m.Get(blind.ID); got.Status != StatusSent {
		t.Fatalf("被拒的破坏性任务状态 = %s, want %s（不得擅自改成终态）", got.Status, StatusSent)
	}
	if got, _ := m.Get(flist.ID); got.Status != StatusPending {
		t.Fatalf("普通任务状态 = %s, want %s（重投递对非破坏性任务必须照旧生效）", got.Status, StatusPending)
	}

	// 兼容入口：RequeueSent 的返回语义不变（= 重新入队数）
	requeued2 := m.RequeueSent(sid, 0)
	if requeued2 != 0 {
		t.Fatalf("第二次 RequeueSent 重新入队 %d 条, want 0（普通任务已回到 pending，破坏性任务永远不被重投）", requeued2)
	}
}

// TestListReplayableSkipsDestructiveTasks 路径 ①：会话重连热迁移补发。
func TestListReplayableSkipsDestructiveTasks(t *testing.T) {
	m, sid := newNoRetryEnv(t)

	cases := []struct {
		taskType string
		retry    bool
	}{
		{TaskTypeEDRBlind, false},
		{TaskTypeEDRKill, false},
		{TaskTypeProcKill, false},
		{TaskTypeBYOVDLoad, false},
		{TaskTypeBYOVDUnload, false},
		{TaskTypeBYOVDKill, false},
		{TaskTypePPLKill, false},
		{TaskTypeFileList, true},   // 普通任务照旧补发
		{TaskTypeExecModule, true}, // 未登记进动作表的破坏性以外任务不受影响
		{"av_detect", true},        // L0 只读：重跑一次侦察没有副作用
		{TaskTypeFileDown, true},   // 大文件下载依赖补发+断点续传
	}

	created := map[string]uint64{}
	for _, c := range cases {
		tk, err := m.Create(sid, TaskParams{TaskType: c.taskType, Data: "{}"})
		if err != nil {
			t.Fatalf("Create %s: %v", c.taskType, err)
		}
		created[c.taskType] = tk.ID
	}
	// 全部推进到 sent：sent 是"最危险"的那种在途状态（可能已经执行过）
	for _, c := range cases {
		markSent(t, m, sid, created[c.taskType])
	}

	replayable := m.ListReplayable(sid)
	got := map[uint64]bool{}
	for _, r := range replayable {
		got[r.ID] = true
	}
	for _, c := range cases {
		id := created[c.taskType]
		if got[id] != c.retry {
			t.Errorf("ListReplayable 对 %s：补发=%v, want %v（破坏性动作禁止自动重投递）",
				c.taskType, got[id], c.retry)
		}
	}

	// pending 状态的破坏性任务同样不补发（还没派发过也一样：断线重连补发属于自动重投递）
	p := created[TaskTypeEDRBlind]
	if err := m.Cancel(p); err == nil {
		t.Fatal("前置条件不成立：sent 状态的任务不应可取消")
	}

	// 交叉核对判定来源：任务类型 → avops 的动作表（不是任务侧另写一份名单）
	for _, tt := range []string{TaskTypeEDRBlind, TaskTypeEDRKill, TaskTypeProcKill,
		TaskTypeBYOVDLoad, TaskTypeBYOVDUnload, TaskTypeBYOVDKill, TaskTypePPLKill} {
		if !avops.TaskNoRetry(tt) {
			t.Errorf("%s 未被 avops 标为禁止自动重试（动作表与豁免名单已漂移）", tt)
		}
	}
}

// TestExpireIsTerminalAndBlocksReplay 钉住"服务端超时收口"这条独立保证：
// 一旦任务因显式超时进入终态，两条自动重投递路径都不会再碰它。
func TestExpireIsTerminalAndBlocksReplay(t *testing.T) {
	m, sid := newNoRetryEnv(t)

	blind, err := m.Create(sid, TaskParams{TaskType: TaskTypeEDRBlind, Data: `{}`})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	markSent(t, m, sid, blind.ID)

	if err := m.Expire(blind.ID, "av-ops 显式超时：120s 内未收到结果"); err != nil {
		t.Fatalf("Expire: %v", err)
	}
	got, _ := m.Get(blind.ID)
	if got.Status != StatusTimeout {
		t.Fatalf("Expire 后状态 = %s, want %s", got.Status, StatusTimeout)
	}
	if got.Error == "" {
		t.Error("Expire 必须留下原因（操作员在任务列表里要看到为什么）")
	}
	if n := len(m.ListReplayable(sid)); n != 0 {
		t.Errorf("已超时任务仍被补发：%d 条", n)
	}
	if requeued, refused := m.RequeueSentEx(sid, 0); requeued != 0 || refused != 0 {
		t.Errorf("已超时任务仍参与重投递：requeued=%d refused=%d", requeued, refused)
	}

	// 终态去重：结果帧晚到也不能把 timeout 改回 completed（谁先到谁说话）
	if err := m.Complete(blind.ID, 0, "stale result", ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got, _ := m.Get(blind.ID); got.Status != StatusTimeout {
		t.Fatalf("迟到的结果帧把终态改写成了 %s, want %s（终态必须幂等）", got.Status, StatusTimeout)
	}
	// 幂等：重复 Expire 不报错、不改状态
	if err := m.Expire(blind.ID, "again"); err != nil {
		t.Fatalf("重复 Expire 不应报错：%v", err)
	}
}

// TestExpireNotifiesWaiters 超时必须唤醒等待者：否则 Agent 的等待方要各自挂满自己的超时。
func TestExpireNotifiesWaiters(t *testing.T) {
	m, sid := newNoRetryEnv(t)
	tk, err := m.Create(sid, TaskParams{TaskType: TaskTypeEDRKill, Data: `{}`})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	markSent(t, m, sid, tk.ID)

	// 直接订阅（同步注册，无竞态窗口）：Expire 必须关掉这条通道。
	ch, unsub := m.Subscribe(tk.ID)
	defer unsub()
	if err := m.Expire(tk.ID, "服务端超时"); err != nil {
		t.Fatalf("Expire: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("Expire 未唤醒等待者（等待者只能自己超时，晚到的结论就没意义了）")
	}
	// 后到的等待者也要拿到确定结论（终态注册 → 通道立即关闭 + 即时判定命中）
	if _, outcome := m.WaitSettled(tk.ID, 0); outcome != WaitTerminal {
		t.Fatalf("WaitSettled 结论 = %v, want %v", outcome, WaitTerminal)
	}
	if n := m.WaiterCount(tk.ID); n != 0 {
		t.Fatalf("Expire 后仍有 %d 个等待者挂在表上（泄漏）", n)
	}
}

func idsOf(tasks []*types.TaskInfo) []uint64 {
	out := make([]uint64, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, t.ID)
	}
	return out
}

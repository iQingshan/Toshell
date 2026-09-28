package drivers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── 驱动加载台账 + 清场指引单测（v1.4.0 S6 P0-1）────────────────────────────
//
// 覆盖三条硬要求：
//  1. 台账跨服务端重启保留（写盘 → 新实例读回来）；
//  2. "残留"判定的纯逻辑（未下发卸载 = 残留；下发过卸载 = 不再列在 pending）；
//  3. 清场指引（BuildCleanupPlan）在"会话在线/不在线"两种情况下都给出可执行内容。

func tmpLedger(t *testing.T) *Ledger {
	t.Helper()
	l := NewLedger(filepath.Join(t.TempDir(), "loaded.json"))
	if err := l.LoadError(); err != nil {
		t.Fatalf("新台账不应有读取错误：%v", err)
	}
	return l
}

func sampleLoad(session, svc string) LedgerEntry {
	return LedgerEntry{
		SessionID: session, ServiceName: svc, DriverName: "demo",
		Device: `\\.\demo`, IOCTL: 0x222048, Purpose: PurposeKill,
		SHA256: strings.Repeat("ab", 32), Size: 4096, Source: "avops", LoadTaskID: 7,
	}
}

// TestLedgerPersistsAcrossRestart 台账必须写盘，并在"服务端重启"（新建实例）后读回来。
// 这是整个清场能力的前提：内存里的 sessionDrivers 一重启就没了。
func TestLedgerPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loaded.json")
	l := NewLedger(path)
	if err := l.RecordLoad(sampleLoad("sess-1", "demo")); err != nil {
		t.Fatalf("RecordLoad: %v", err)
	}
	if len(l.Pending()) != 1 {
		t.Fatalf("Pending = %d, want 1", len(l.Pending()))
	}

	// 模拟服务端重启：全新实例读同一个文件
	restarted := NewLedger(path)
	if err := restarted.LoadError(); err != nil {
		t.Fatalf("重启后读台账失败：%v", err)
	}
	pending := restarted.Pending()
	if len(pending) != 1 {
		t.Fatalf("重启后 Pending = %d, want 1（台账必须跨重启保留）", len(pending))
	}
	if pending[0].ServiceName != "demo" || pending[0].IOCTL != 0x222048 || pending[0].Purpose != PurposeKill {
		t.Fatalf("台账字段丢失：%+v", pending[0])
	}
	// 台账里的档案能恢复出来（服务端重启后 byovd_kill 仍能按档位选到它）
	d, ok := restarted.ProfileFor("sess-1")
	if !ok || d.Service != "demo" || d.Device != `\\.\demo` || d.Purpose != PurposeKill {
		t.Fatalf("ProfileFor 恢复失败：%+v ok=%v", d, ok)
	}

	// 文件本身必须是合法 JSON 且带语义说明（运维会直接打开看）
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("台账文件不存在：%v", err)
	}
	if !strings.Contains(string(raw), "不代表目标机执行成功") {
		t.Errorf("台账文件应写明语义边界（条目=服务端创建过任务，不是执行成功），实际：%s", string(raw))
	}

	// 卸载销账：重启后的实例记录卸载 → 两个实例都不再把它算作残留
	if err := restarted.RecordUnload("sess-1", "demo", 42); err != nil {
		t.Fatalf("RecordUnload: %v", err)
	}
	if len(restarted.Pending()) != 0 {
		t.Fatal("记录卸载后不应再算作残留")
	}
	again := NewLedger(path)
	if len(again.Pending()) != 0 {
		t.Fatal("卸载状态必须落盘（重启后不能又变成残留）")
	}
	if len(again.All()) != 1 || again.All()[0].UnloadTaskID != 42 {
		t.Fatalf("卸载记录丢失：%+v", again.All())
	}
}

// TestLedgerCorruptFileIsReportedNotFatal 台账文件损坏要"报出来"而不是让服务端起不来，
// 也不能把脏数据当正常记录用。
func TestLedgerCorruptFileIsReportedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loaded.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLedger(path)
	if l.LoadError() == nil {
		t.Fatal("损坏的台账必须通过 LoadError 报出来（否则接口会显示成「没有残留」）")
	}
	if len(l.All()) != 0 {
		t.Fatalf("损坏文件不应解析出条目：%+v", l.All())
	}
	// 仍可继续使用（记录新的加载会原子覆盖）
	if err := l.RecordLoad(sampleLoad("s", "svc")); err != nil {
		t.Fatalf("损坏后应能重新写入：%v", err)
	}
	if len(NewLedger(path).Pending()) != 1 {
		t.Fatal("重新写入后应能读回")
	}
}

// TestLedgerRejectsEntriesWithoutKeys 缺 session_id/service_name 的条目必须被拒绝：
// 服务名是清场的键，缺失等于制造一条永远清不掉的残留。
func TestLedgerRejectsEntriesWithoutKeys(t *testing.T) {
	l := tmpLedger(t)
	if err := l.RecordLoad(LedgerEntry{SessionID: "s", ServiceName: " "}); err == nil {
		t.Fatal("缺 service_name 必须拒绝记录")
	}
	if err := l.RecordLoad(LedgerEntry{SessionID: "", ServiceName: "svc"}); err == nil {
		t.Fatal("缺 session_id 必须拒绝记录")
	}
	if err := l.RecordUnload("s", "", 1); err == nil {
		t.Fatal("缺 service_name 的卸载必须拒绝记录")
	}
}

// TestLedgerUnloadWithoutRecord 没有加载记录时也要留下"卸载过"的痕迹（可查），
// 但不应伪造加载时间。
func TestLedgerUnloadWithoutRecord(t *testing.T) {
	l := tmpLedger(t)
	if err := l.RecordUnload("s", "manual_svc", 9); err != nil {
		t.Fatalf("RecordUnload: %v", err)
	}
	all := l.All()
	if len(all) != 1 || all[0].Source != "unload_without_record" {
		t.Fatalf("应留下无加载记录的卸载痕迹：%+v", all)
	}
	if !all[0].LoadedAt.IsZero() {
		t.Errorf("没有加载记录时不应伪造 LoadedAt：%+v", all[0])
	}
	if len(l.Pending()) != 0 {
		t.Fatal("记录过卸载的条目不算残留")
	}
}

// TestLedgerOrderingIsDeterministic 输出顺序必须确定（加载时间倒序 → 会话 → 服务名），
// 否则"清场指引第一条"会在两次请求之间变来变去。
func TestLedgerOrderingIsDeterministic(t *testing.T) {
	l := tmpLedger(t)
	base := time.Now().Add(-time.Hour)
	for i, e := range []LedgerEntry{
		{SessionID: "s-b", ServiceName: "z", LoadedAt: base},
		{SessionID: "s-a", ServiceName: "m", LoadedAt: base.Add(10 * time.Minute)}, // 最新
		{SessionID: "s-a", ServiceName: "a", LoadedAt: base},
	} {
		e.LoadTaskID = uint64(i)
		if err := l.RecordLoad(e); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, e := range l.Pending() {
		got = append(got, e.SessionID+"/"+e.ServiceName)
	}
	want := []string{"s-a/m", "s-a/a", "s-b/z"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("顺序 = %v, want %v（时间倒序 → 会话 → 服务名）", got, want)
	}
	// 会话内服务名列表（byovd_unload 的兜底来源）同样有序
	if svcs := l.PendingServicesForSession("s-a"); strings.Join(svcs, ",") != "m,a" {
		t.Fatalf("PendingServicesForSession = %v, want [m a]", svcs)
	}
}

// TestBuildCleanupPlan 清场指引的纯逻辑：在线/离线两种情况的判定与文案。
func TestBuildCleanupPlan(t *testing.T) {
	entries := []LedgerEntry{
		{SessionID: "SESS-ON", ServiceName: "demoa", DriverName: "demoA",
			LoadedAt: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC), LoadTaskID: 11},
		{SessionID: "sess-off", ServiceName: "demob", DriverName: "demoB",
			LoadedAt: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC), LoadTaskID: 12},
	}
	steps := BuildCleanupPlan(entries, map[string]bool{"sess-on": true})
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(steps))
	}
	// 会话 id 大小写不敏感
	if steps[0].Blocked || !steps[0].SessionAlive {
		t.Fatalf("在线会话不应被 block：%+v", steps[0])
	}
	if !steps[1].Blocked || steps[1].SessionAlive {
		t.Fatalf("离线会话必须 block 住：%+v", steps[1])
	}
	// 可执行指引：必须是一条能照抄的 byovd_unload 请求（走既有动作，不新造任务类型）
	for _, s := range steps {
		for _, want := range []string{"POST /api/v1/sessions/", "byovd_unload", "confirm", s.ServiceName} {
			if !strings.Contains(s.How, want) {
				t.Errorf("how 缺少 %q：%s", want, s.How)
			}
		}
		if !strings.Contains(s.Reason, "不代表加载一定成功") {
			t.Errorf("reason 必须写明语义边界（只记录下发）：%s", s.Reason)
		}
	}
	if !strings.Contains(steps[0].Reason, "可直接按 how 下发") {
		t.Errorf("在线会话的指引应说明可直接下发：%s", steps[0].Reason)
	}
	// 离线会话：必须写清"重启不会清掉残留 + 按服务名下发到当前在线会话"
	for _, want := range []string{"不在线", "新的 session_id", "不会", "service_name", "按需启动"} {
		if !strings.Contains(steps[1].Reason, want) {
			t.Errorf("离线会话的指引缺少 %q：\n%s", want, steps[1].Reason)
		}
	}
	if steps[0].LoadedAt != "2026-09-28T10:00:00Z" {
		t.Errorf("LoadedAt 格式 = %q", steps[0].LoadedAt)
	}
	// 不在线的条目仍然给出 TargetSessionID（旧 id），但 Blocked=true 让人不会误点
	if steps[1].TargetSessionID != "sess-off" || !steps[1].Blocked {
		t.Errorf("离线条目应保留原 session id 且标记 blocked：%+v", steps[1])
	}
	// 空输入：不 panic，返回空切片
	if got := BuildCleanupPlan(nil, nil); len(got) != 0 {
		t.Fatalf("空输入应返回空：%+v", got)
	}
}

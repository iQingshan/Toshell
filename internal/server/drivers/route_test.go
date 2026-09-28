package drivers

import (
	"strings"
	"testing"
)

// ─── 选路纯逻辑单测（v1.4.0 S6 P0-1）────────────────────────────────────────
//
// 这些用例**不读盘、不需要真实 .sys、不需要真机**：Route 的输入是 ProfileSummary +
// RouteRequest 两个纯数据结构，输出是选中的档案或 RouteError。因此"单一/多驱动的确定性
// 选择、缺档拒绝、点名档位不符"这些分支都能被精确断言（含中文拒绝文案的关键内容）。

// sumOf 造一个驱动目录摘要（Purposes 按出现情况去重排序，与 Summary() 的口径一致）。
func sumOf(ds ...Driver) ProfileSummary {
	s := ProfileSummary{SearchDirs: []string{`C:\repo\drivers`}, Total: len(ds)}
	seen := map[string]bool{}
	for _, d := range ds {
		if d.KillPIDSize == 0 {
			d.KillPIDSize = 4
		}
		s.Drivers = append(s.Drivers, d)
		if p := NormalizePurpose(d.Purpose); p != "" && !seen[p] {
			seen[p] = true
			s.Purposes = append(s.Purposes, p)
		}
	}
	sortStringsForTest(s.Purposes)
	return s
}

// sortStringsForTest 让用例里的 Purposes 与 Summary() 一样有序（避免断言依赖 map 顺序）。
func sortStringsForTest(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func killDrv(name string) Driver {
	return Driver{Name: name, File: name + ".sys", Purpose: PurposeKill,
		Device: `\\.\` + name, Service: name, IOCTL: 0x222048, KillPIDSize: 4}
}

func bothDrv(name string) Driver {
	return Driver{Name: name, File: name + ".sys", Purpose: PurposeBoth,
		Device: `\\.\` + name, Service: name, IOCTL: 0x222049, KillPIDSize: 4}
}

func rwDrv(name string) Driver {
	return Driver{Name: name, File: name + ".sys", Purpose: PurposeRW, Service: name}
}

// TestRouteDeterministicSelectionByPurpose 钉住"多驱动时的确定性选择顺序"。
//
// 顺序：档位专一度（专用档优先于 both）→ 档案名 → 文件名 → 路径。
// 这条断言是"同一份目录两次下发挑到同一个驱动"的唯一保证。
func TestRouteDeterministicSelectionByPurpose(t *testing.T) {
	sum := sumOf(killDrv("killer"), bothDrv("bothdrv"), rwDrv("rwdrv"))

	// byovd_kill：需要 kill 档 → 专用 kill 档优先于 both（即使 both 的名字更靠前）
	got, err := Route(sum, RouteRequest{Action: "byovd_kill"})
	if err != nil {
		t.Fatalf("byovd_kill 应能选到 kill 档，实际报错：%v", err)
	}
	if got.Driver.Name != "killer" || got.Source != RouteSourceCatalog {
		t.Fatalf("byovd_kill 选中 %q（source=%s），want killer/catalog", got.Driver.Name, got.Source)
	}
	if got.Driver.Device != `\\.\killer` || got.Driver.IOCTL != 0x222048 {
		t.Fatalf("选中的档案必须带 device/ioctl：%+v", got.Driver)
	}
	// 其它候选必须被回显（否则操作员不知道可以点名）
	if !strings.Contains(strings.Join(got.Notes, "｜"), "bothdrv") {
		t.Errorf("应回显其它满足档位的候选，实际 notes=%v", got.Notes)
	}

	// ppl_kill：需要 rw 档 → 挑 rwdrv（kill 与 both 都不是它的目标档）
	gotRW, err := Route(sum, RouteRequest{Action: "ppl_kill"})
	if err != nil {
		t.Fatalf("ppl_kill 应能选到 rw 档，实际报错：%v", err)
	}
	if gotRW.Driver.Name != "rwdrv" || gotRW.Purpose != PurposeRW {
		t.Fatalf("ppl_kill 选中 %+v，want rwdrv/rw", gotRW)
	}

	// 只有多个 both 档时：按档案名（不区分大小写）确定顺序
	sum2 := sumOf(bothDrv("Zeta"), bothDrv("alpha"))
	got2, err := Route(sum2, RouteRequest{Action: "byovd_kill"})
	if err != nil {
		t.Fatalf("both 档应能满足 kill 需求：%v", err)
	}
	if got2.Driver.Name != "alpha" {
		t.Fatalf("多个 both 档时应按名字确定选中 alpha，实际 %q", got2.Driver.Name)
	}
	// 同一输入重复调用必须给出同一结论（确定性）
	for i := 0; i < 5; i++ {
		again, _ := Route(sum2, RouteRequest{Action: "byovd_kill"})
		if again.Driver.Name != "alpha" {
			t.Fatalf("第 %d 次调用选中 %q，选择不确定", i, again.Driver.Name)
		}
	}
}

// TestRouteSelectProfileMatchesSummary 钉住"预览与下发共用同一份选路口径"：
// Summary().Kill/RW 与 Route 的自动选路结果必须一致（否则预览会骗人）。
func TestRouteSelectProfileMatchesSummary(t *testing.T) {
	sum := sumOf(killDrv("killer"), bothDrv("bothdrv"), rwDrv("rwdrv"))
	k, ok := selectProfile(sum.Drivers, PurposeKill, true)
	if !ok || k.Name != "killer" {
		t.Fatalf("selectProfile(kill) = %+v/%v，want killer", k, ok)
	}
	r, ok := selectProfile(sum.Drivers, PurposeRW, false)
	if !ok || r.Name != "rwdrv" {
		t.Fatalf("selectProfile(rw) = %+v/%v，want rwdrv", r, ok)
	}
	byKill, _ := Route(sum, RouteRequest{Action: "byovd_kill"})
	if byKill.Driver.Name != k.Name {
		t.Fatalf("Route 与 selectProfile 选到不同驱动：%q vs %q", byKill.Driver.Name, k.Name)
	}
	byPpl, _ := Route(sum, RouteRequest{Action: "ppl_kill"})
	if byPPLName := byPpl.Driver.Name; byPPLName != r.Name {
		t.Fatalf("Route 与 selectProfile 选到不同驱动：%q vs %q", byPPLName, r.Name)
	}
}

// TestRouteNoDriverRejectionIsActionable 缺档时必须拒绝，并写清
// "缺哪一档 / 当前有哪些档 / 目录在哪 / 需要放什么文件"（任务书要求的中文原因）。
func TestRouteNoDriverRejectionIsActionable(t *testing.T) {
	// 目录里只有 rw 档 + 一个没写 purpose 的驱动
	onlyRW := sumOf(rwDrv("rwdrv"), Driver{Name: "vague", File: "vague.sys", Purpose: ""})

	_, err := Route(onlyRW, RouteRequest{Action: "byovd_kill"})
	if err == nil {
		t.Fatal("目录里没有 kill 档时必须拒绝")
	}
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeNoDriver {
		t.Fatalf("错误码 = %+v, want %s", err, RouteCodeNoDriver)
	}
	for _, want := range []string{"无 kill 档驱动", "当前驱动目录", `C:\repo\drivers`, "档位 rw",
		"没有声明 purpose", "purpose", "manifest.json"} {
		if !strings.Contains(re.Message, want) {
			t.Errorf("拒绝文案缺少 %q：\n%s", want, re.Message)
		}
	}

	// ppl_kill 没有 rw 档：必须出现"无 rw 档驱动"这句（分级入口的排障入口依赖它）
	onlyKill := sumOf(killDrv("killer"))
	_, err = Route(onlyKill, RouteRequest{Action: "ppl_kill"})
	if err == nil {
		t.Fatal("没有 rw 档时 ppl_kill 必须拒绝")
	}
	if !strings.Contains(err.Error(), "无 rw 档驱动") {
		t.Fatalf("ppl_kill 的拒绝文案必须直说「无 rw 档驱动」，实际：%s", err.Error())
	}
	if !strings.Contains(err.Error(), "EPROCESS.Protection") {
		t.Errorf("应说明为什么需要 rw 档，实际：%s", err.Error())
	}

	// 空目录
	_, err = Route(sumOf(), RouteRequest{Action: "ppl_kill"})
	if err == nil || !strings.Contains(err.Error(), "没有任何 .sys 声明 purpose") {
		t.Fatalf("空目录的拒绝文案应说明目录是空的，实际：%v", err)
	}
}

// TestRouteRequiredDeviceIOCTLMissing kill 档但缺 device/ioctl 时必须单独说清楚
// （选了也发不出终止 IOCTL），而不是笼统报"没有驱动"。
func TestRouteRequiredDeviceIOCTLMissing(t *testing.T) {
	sum := sumOf(Driver{Name: "halfk", File: "halfk.sys", Purpose: PurposeKill, Service: "halfk"})
	_, err := Route(sum, RouteRequest{Action: "byovd_kill"})
	if err == nil {
		t.Fatal("kill 档缺 device/ioctl 时必须拒绝")
	}
	msg := err.Error()
	for _, want := range []string{"无 kill 档驱动", "缺 device 或 ioctl", "byovd_kill 需要二者齐全"} {
		if !strings.Contains(msg, want) {
			t.Errorf("拒绝文案缺少 %q：\n%s", want, msg)
		}
	}

	// 点名这个不完整的档案：错误码要更具体（profile_incomplete）
	_, err = Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "halfk"})
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeProfileIncomplete {
		t.Fatalf("点名不完整档案应回 profile_incomplete，实际 %+v", err)
	}
	if !strings.Contains(re.Message, "device") || !strings.Contains(re.Message, "ioctl") {
		t.Errorf("应指出缺哪些字段，实际：%s", re.Message)
	}
}

// TestRouteNamedProfileIsNotSilentlyReplaced 点名了档位不符的驱动必须**明确拒绝**，
// 而不是悄悄换一个 —— 静默替换是"操作员以为在用 A，实际用了 B"的安全事故。
func TestRouteNamedProfileIsNotSilentlyReplaced(t *testing.T) {
	sum := sumOf(killDrv("killer"), rwDrv("rwdrv"))

	_, err := Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "rwdrv"})
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeNamedPurposeMismatch {
		t.Fatalf("点名 rw 档做 byovd_kill 应回 named_purpose_mismatch，实际 %+v", err)
	}
	for _, want := range []string{"点名的驱动", "rw", "kill", "rwdrv"} {
		if !strings.Contains(re.Message, want) {
			t.Errorf("拒绝文案缺少 %q：%s", want, re.Message)
		}
	}

	// 点名不存在的档案：必须列出当前有哪些候选（省掉操作员再查一次）
	_, err = Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "typo_driver"})
	re, ok = err.(*RouteError)
	if !ok || re.Code != RouteCodeNamedProfileMissing {
		t.Fatalf("点名不存在的驱动应回 named_profile_missing，实际 %+v", err)
	}
	if !strings.Contains(re.Message, "killer") || !strings.Contains(re.Message, "rwdrv") {
		t.Errorf("应列出当前可用档案名，实际：%s", re.Message)
	}

	// 点名正确的 kill 档：放行，并且来源标记为 profile
	got, err := Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "killer"})
	if err != nil {
		t.Fatalf("点名 kill 档做 byovd_kill 应放行：%v", err)
	}
	if got.Source != RouteSourceProfile || got.Driver.Name != "killer" {
		t.Fatalf("source/name = %s/%s, want profile/killer", got.Source, got.Driver.Name)
	}
}

// TestRouteExplicitDeviceIOCTLBypassesPurpose 请求显式给 device+ioctl 是既有语义：
// 放行，但必须回一条"跳过了档位核对"的提示（不静默）。
func TestRouteExplicitDeviceIOCTLBypassesPurpose(t *testing.T) {
	sum := sumOf(killDrv("killer")) // 目录里有 killer，但请求显式指定别的设备
	got, err := Route(sum, RouteRequest{
		Action: "byovd_kill", AllowExplicit: true,
		ExplicitDevice: `\\.\manual`, ExplicitIOCTL: 0x999999,
	})
	if err != nil {
		t.Fatalf("显式指定应放行：%v", err)
	}
	if got.Source != RouteSourceExplicit || got.Driver.Device != `\\.\manual` || got.Driver.IOCTL != 0x999999 {
		t.Fatalf("显式指定未被采纳：%+v", got)
	}
	notes := strings.Join(got.Notes, "｜")
	for _, want := range []string{"跳过", "档位", "自行确认"} {
		if !strings.Contains(notes, want) {
			t.Errorf("显式指定必须回显风险提示（缺 %q）：%v", want, got.Notes)
		}
	}

	// 只给 device 不给 ioctl：不算"显式指定"，不能凑出一个不存在的组合；
	// 目录里有完整档案时走自动选路。
	got2, err := Route(sum, RouteRequest{Action: "byovd_kill", AllowExplicit: true, ExplicitDevice: `\\.\manual`})
	if err != nil {
		t.Fatalf("半截显式指定应回落到目录选路：%v", err)
	}
	if got2.Source != RouteSourceCatalog || got2.Driver.Name != "killer" {
		t.Fatalf("半截显式指定不应被采纳，实际 %+v", got2)
	}
}

// TestRouteSessionProfilePriority 会话档案的优先级与"合并补齐"的边界：
// 点名档案 > 会话档案 > 目录；显式值只允许补齐**会话档案**缺失的字段。
func TestRouteSessionProfilePriority(t *testing.T) {
	sum := sumOf(killDrv("killer"), bothDrv("bothdrv"))
	sess := killDrv("sessionkill")

	// 点名档案优先于会话档案（与既有 byovd_kill 的 req.Driver 覆盖语义一致）
	got, err := Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "bothdrv", Session: &sess})
	if err != nil {
		t.Fatalf("点名档案应放行：%v", err)
	}
	if got.Source != RouteSourceProfile || got.Driver.Name != "bothdrv" {
		t.Fatalf("点名档案未优先：%+v", got)
	}

	// 没有点名时用会话档案（即使目录里还有别的 kill 档）
	got2, err := Route(sum, RouteRequest{Action: "byovd_kill", Session: &sess})
	if err != nil {
		t.Fatalf("会话档案应放行：%v", err)
	}
	if got2.Source != RouteSourceSession || got2.Driver.Name != "sessionkill" {
		t.Fatalf("会话档案未被优先：%+v", got2)
	}

	// 会话档案档位不符 → 跳过它，用目录里的（而不是直接失败）
	rwSess := rwDrv("sessionrw")
	got3, err := Route(sum, RouteRequest{Action: "byovd_kill", Session: &rwSess})
	if err != nil {
		t.Fatalf("会话档案档位不符时应回落目录选路：%v", err)
	}
	if got3.Source != RouteSourceCatalog || got3.Driver.Name != "killer" {
		t.Fatalf("应回落目录里的 kill 档，实际 %+v", got3)
	}

	// 会话档案档位不符 + 目录里也没有 → 错误码要指出"是本会话登记的驱动档位不符"
	onlyRW := sumOf(rwDrv("rwdrv"))
	_, err = Route(onlyRW, RouteRequest{Action: "byovd_kill", Session: &rwSess})
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeSessionPurposeMismatch {
		t.Fatalf("应回 session_purpose_mismatch，实际 %+v", err)
	}
	if !strings.Contains(re.Message, "sessionrw") {
		t.Errorf("应指出是哪个已登记驱动的档位不符，实际：%s", re.Message)
	}

	// 显式值补齐会话档案缺的字段（同一驱动的两个来源合并；不会跨驱动拼接）
	partial := Driver{Name: "partial", File: "partial.sys", Purpose: PurposeKill,
		Service: "partial", Device: `\\.\partial`}
	got4, err := Route(sum, RouteRequest{
		Action: "byovd_kill", Session: &partial, AllowExplicit: true,
		ExplicitIOCTL: 0xABCDEF,
	})
	if err != nil {
		t.Fatalf("显式值补齐会话档案应放行：%v", err)
	}
	if got4.Driver.IOCTL != 0xABCDEF || got4.Source != RouteSourceSession {
		t.Fatalf("补齐失败：%+v", got4)
	}
	if !strings.Contains(strings.Join(got4.Notes, "｜"), "补齐") {
		t.Errorf("补齐必须在 notes 里说明：%v", got4.Notes)
	}

	// ppl_kill 只认 rw/both：会话里登记的是 kill → 不算满足
	_, err = Route(sumOf(), RouteRequest{Action: "ppl_kill", Session: &sess})
	if err == nil {
		t.Fatal("kill 档会话档案不满足 ppl_kill 的 rw 需求，必须拒绝")
	}
}

// TestRouteUnloadServiceResolution byovd_unload 的选路：
// 请求 → 会话档案 → 服务端台账，三者都空时明确拒绝。
func TestRouteUnloadServiceResolution(t *testing.T) {
	sum := sumOf(killDrv("killer")) // killer 的 service 也叫 killer

	// ① 请求直接给服务名：命中目录档案 → 详述里说明
	got, err := Route(sum, RouteRequest{Action: "byovd_unload", ServiceName: "killer"})
	if err != nil {
		t.Fatalf("按服务名卸载应放行：%v", err)
	}
	if got.Source != RouteSourceServiceName || got.Driver.Service != "killer" {
		t.Fatalf("服务名解析错误：%+v", got)
	}
	if !strings.Contains(got.Detail, "命中档案") {
		t.Errorf("应说明目录里命中了哪个档案，实际：%s", got.Detail)
	}

	// ② 目录里没有该服务名：不拒绝（手工加载的驱动同样要能卸载），但必须提示
	got2, err := Route(sum, RouteRequest{Action: "byovd_unload", ServiceName: "manual_svc"})
	if err != nil {
		t.Fatalf("目录里没有该服务名不应拒绝：%v", err)
	}
	if !strings.Contains(strings.Join(got2.Notes, "｜"), "不在服务端驱动目录") {
		t.Errorf("应提示该服务名不在目录记录里：%v", got2.Notes)
	}

	// ③ 请求没给服务名 → 用会话档案
	sess := Driver{Name: "sessdrv", Service: "sesssvc", Purpose: PurposeKill}
	got3, err := Route(sum, RouteRequest{Action: "byovd_unload", Session: &sess})
	if err != nil {
		t.Fatalf("会话档案应能提供 service_name：%v", err)
	}
	if got3.Driver.Service != "sesssvc" || !strings.Contains(strings.Join(got3.Notes, "｜"), "会话登记") {
		t.Fatalf("会话档案解析错误：%+v notes=%v", got3, got3.Notes)
	}

	// ④ 都没有 → 用台账（服务端重启后的清场路径）
	got4, err := Route(sum, RouteRequest{Action: "byovd_unload", LedgerServices: []string{"fromledger", "older"}})
	if err != nil {
		t.Fatalf("台账应能提供 service_name：%v", err)
	}
	if got4.Driver.Service != "fromledger" {
		t.Fatalf("台账应按时间倒序取第一条，实际 %q", got4.Driver.Service)
	}
	if !strings.Contains(strings.Join(got4.Notes, "｜"), "台账") {
		t.Errorf("应说明服务名来自台账：%v", got4.Notes)
	}

	// ⑤ 三者都空 → 明确拒绝（写清服务名从哪来、可以从哪拿）
	_, err = Route(sum, RouteRequest{Action: "byovd_unload"})
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeMissingServiceName {
		t.Fatalf("缺服务名应回 missing_service_name，实际 %+v", err)
	}
	for _, want := range []string{"缺 service_name", "台账", "drivers/ledger"} {
		if !strings.Contains(re.Message, want) {
			t.Errorf("拒绝文案缺少 %q：%s", want, re.Message)
		}
	}
}

// TestRouteLoadPurposeDeclaration byovd_load 的档位声明口径：
// 请求声明 → manifest 声明 → 兜底 kill（既有行为），非法档位明确拒绝。
func TestRouteLoadPurposeDeclaration(t *testing.T) {
	sum := sumOf(rwDrv("rwdrv"), Driver{Name: "bothy", File: "bothy.sys", Purpose: PurposeBoth})

	// 请求声明 rw
	got, err := Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s1", DeclaredPurpose: "RW"})
	if err != nil {
		t.Fatalf("声明 rw 应放行：%v", err)
	}
	if got.Purpose != PurposeRW || got.Driver.Purpose != PurposeRW {
		t.Fatalf("档位归一化失败：%+v", got)
	}

	// manifest 声明优先于兜底：点名 rwdrv 但没写 purpose → 用 manifest 的 rw
	got2, err := Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s2", RequestedName: "rwdrv"})
	if err != nil {
		t.Fatalf("按档案名加载应放行：%v", err)
	}
	if got2.Purpose != PurposeRW {
		t.Fatalf("应采用 manifest 声明的 rw，实际 %q", got2.Purpose)
	}

	// 请求声明覆盖 manifest 声明（操作员显式写的优先）
	got3, err := Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s3", RequestedName: "rwdrv", DeclaredPurpose: "kill"})
	if err != nil {
		t.Fatalf("请求声明应放行：%v", err)
	}
	if got3.Purpose != PurposeKill {
		t.Fatalf("请求显式声明应覆盖 manifest，实际 %q", got3.Purpose)
	}

	// 什么都没声明 → 兜底 kill（**既有行为**，不能默默改成 rw/both），并回一条提示
	got4, err := Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s4"})
	if err != nil {
		t.Fatalf("兜底 kill 应放行：%v", err)
	}
	if got4.Purpose != PurposeKill {
		t.Fatalf("兜底档位应为 kill，实际 %q", got4.Purpose)
	}
	if !strings.Contains(strings.Join(got4.Notes, "｜"), "按既有行为以 kill 档登记") {
		t.Errorf("兜底必须有提示：%v", got4.Notes)
	}

	// 非法档位：明确拒绝（不是静默当 kill）
	_, err = Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s5", DeclaredPurpose: "super"})
	re, ok := err.(*RouteError)
	if !ok || re.Code != RouteCodeUnknownPurpose {
		t.Fatalf("非法 purpose 应回 unknown_purpose，实际 %+v", err)
	}
	if !strings.Contains(re.Message, "kill / rw / both") {
		t.Errorf("应列出合法档位：%s", re.Message)
	}

	// 缺 service_name：拒绝（服务名决定落盘文件名）
	_, err = Route(sum, RouteRequest{Action: "byovd_load"})
	if re, ok := err.(*RouteError); !ok || re.Code != RouteCodeMissingServiceName {
		t.Fatalf("缺 service_name 应回 missing_service_name，实际 %+v", err)
	}

	// 点名的档案不在目录里：加载仍可继续（字节随请求带），但必须提示
	got5, err := Route(sum, RouteRequest{Action: "byovd_load", ServiceName: "s6", RequestedName: "unknownprof"})
	if err != nil {
		t.Fatalf("点名不存在的档案不应阻断加载：%v", err)
	}
	if !strings.Contains(strings.Join(got5.Notes, "｜"), "不在驱动目录里") {
		t.Errorf("应提示档案不在目录里：%v", got5.Notes)
	}
}

// TestRouteNamedUndeclaredPurposeKeepsLegacyUsable 点名一个"没写 purpose 但有 device/ioctl"的
// 老档案：必须继续可用（既有语义 = 点名即可用），但要给出醒目的补全提示；
// 而**自动选路**不认它（未声明 ≠ 通用，否则没标注的驱动会被静默用于高危动作）。
func TestRouteNamedUndeclaredPurposeKeepsLegacyUsable(t *testing.T) {
	legacy := Driver{Name: "olddrv", File: "olddrv.sys", Service: "olddrv",
		Device: `\\.\olddrv`, IOCTL: 0x222048}
	sum := sumOf(legacy)

	// 点名 → 放行 + 提示补 purpose
	got, err := Route(sum, RouteRequest{Action: "byovd_kill", RequestedName: "olddrv"})
	if err != nil {
		t.Fatalf("点名未声明 purpose 的老档案应按既有语义放行：%v", err)
	}
	if got.Driver.Name != "olddrv" || got.Source != RouteSourceProfile {
		t.Fatalf("点名档案未被采纳：%+v", got)
	}
	if !strings.Contains(strings.Join(got.Notes, "｜"), "没有在 manifest.json 里声明 purpose") {
		t.Fatalf("必须提示补 purpose：%v", got.Notes)
	}

	// 不点名 → 自动选路不认它（没声明档位 = 不参与档位选路）
	_, err = Route(sum, RouteRequest{Action: "byovd_kill"})
	if err == nil || !strings.Contains(err.Error(), "无 kill 档驱动") {
		t.Fatalf("自动选路不应选中未声明 purpose 的驱动，实际：%v", err)
	}

	// 同样没声明 purpose 但缺 device/ioctl → 点名也必须拒绝（发不出终止 IOCTL）
	_, err = Route(sumOf(Driver{Name: "olddrv", Purpose: ""}), RouteRequest{Action: "byovd_kill", RequestedName: "olddrv"})
	if re, ok := err.(*RouteError); !ok || re.Code != RouteCodeProfileIncomplete {
		t.Fatalf("点名未声明 purpose 且缺 device/ioctl 应回 profile_incomplete，实际 %+v", err)
	}
}

// TestRouteUnknownActionFailClosed 未知动作一律拒绝（不允许"猜一个档位"）。
func TestRouteUnknownActionFailClosed(t *testing.T) {
	for _, action := range []string{"", "byovd", "ppl", "amsi_etw_suppress"} {
		_, err := Route(sumOf(killDrv("killer")), RouteRequest{Action: action})
		re, ok := err.(*RouteError)
		if !ok || re.Code != RouteCodeUnknownAction {
			t.Fatalf("动作 %q 应回 unknown_action，实际 %+v", action, err)
		}
	}
}

// TestPurposeSatisfies 档位满足关系（含"未声明 purpose 不满足任何档位"）。
func TestPurposeSatisfies(t *testing.T) {
	cases := []struct {
		declared, required string
		want               bool
	}{
		{PurposeKill, PurposeKill, true},
		{PurposeBoth, PurposeKill, true},
		{PurposeRW, PurposeKill, false},
		{"", PurposeKill, false},
		{PurposeRW, PurposeRW, true},
		{PurposeBoth, PurposeRW, true},
		{PurposeKill, PurposeRW, false},
		{"", PurposeRW, false},
		{"KILL", PurposeKill, true}, // 大小写/空白归一化
		{" kill ", PurposeKill, true},
		{"", "", true},   // 不需要档位的动作
		{"rw", "", true}, // 同上
	}
	for _, c := range cases {
		if got := purposeSatisfies(c.declared, c.required); got != c.want {
			t.Errorf("purposeSatisfies(%q,%q) = %v, want %v", c.declared, c.required, got, c.want)
		}
	}
	// 专一度排序：专用档永远排在 both 前面
	if purposeRank(PurposeKill, PurposeKill) >= purposeRank(PurposeBoth, PurposeKill) {
		t.Fatal("专用档必须优先于 both 档（否则多驱动时选中结果会不符合直觉）")
	}
	if purposeRank(PurposeRW, PurposeRW) >= purposeRank(PurposeBoth, PurposeRW) {
		t.Fatal("rw 档必须优先于 both 档")
	}
}

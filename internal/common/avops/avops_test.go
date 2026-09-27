package avops

import (
	"strings"
	"testing"
)

// ─── 等级表 ──────────────────────────────────────────────────────────────────

// TestTierDefaults 钉住"分级默认值"这条对外契约：
// L0/L1 默认开、L2/L3/L4 默认关；只有 L0 只读；L1 起需要确认、且禁止自动重投递。
//
// 为什么用表驱动而不是逐个断言：这些字段会被前端、脚本、MCP 客户端与审计共同读取，
// "谁改了默认值"必须是一条能一眼看懂、能拦住回归的断言。
func TestTierDefaults(t *testing.T) {
	want := []struct {
		tier        Tier
		defaultOn   bool
		readOnly    bool
		destructive bool
		confirm     bool
		noRetry     bool
		implemented bool
	}{
		{TierL0, true, true, false, false, false, true},
		{TierL1, true, false, true, true, true, true},
		{TierL2, false, false, true, true, true, true},
		{TierL3, false, false, true, true, true, true},
		{TierL4, false, false, true, true, true, false},
	}
	got := Tiers()
	if len(got) != len(want) {
		t.Fatalf("等级数量 = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		m := got[i]
		if m.Tier != w.tier {
			t.Errorf("第 %d 级 = %s, want %s（顺序即风险高低，不允许重排）", i, m.Tier, w.tier)
		}
		if m.DefaultEnabled != w.defaultOn {
			t.Errorf("%s DefaultEnabled = %v, want %v", m.Tier, m.DefaultEnabled, w.defaultOn)
		}
		if m.ReadOnly != w.readOnly {
			t.Errorf("%s ReadOnly = %v, want %v", m.Tier, m.ReadOnly, w.readOnly)
		}
		if m.Destructive != w.destructive {
			t.Errorf("%s Destructive = %v, want %v", m.Tier, m.Destructive, w.destructive)
		}
		if m.NeedsConfirm != w.confirm {
			t.Errorf("%s NeedsConfirm = %v, want %v", m.Tier, m.NeedsConfirm, w.confirm)
		}
		if m.NoAutoRetry != w.noRetry {
			t.Errorf("%s NoAutoRetry = %v, want %v", m.Tier, m.NoAutoRetry, w.noRetry)
		}
		if m.Implemented != w.implemented {
			t.Errorf("%s Implemented = %v, want %v", m.Tier, m.Implemented, w.implemented)
		}
		if m.Name == "" || m.Description == "" {
			t.Errorf("%s 缺少中文名或说明（接口要直接展示给操作员）", m.Tier)
		}
		// 只读 ⇔ 非破坏性 是刻意维持的不变量：只读动作不可能造成不可回滚的改动。
		if m.ReadOnly == m.Destructive {
			t.Errorf("%s 的 ReadOnly(%v) 与 Destructive(%v) 组合不自洽", m.Tier, m.ReadOnly, m.Destructive)
		}
	}
}

// TestUnknownTierFallsBackToMax 未知等级串必须归到最高风险并标记不合法（fail-closed）。
func TestUnknownTierFallsBackToMax(t *testing.T) {
	for _, s := range []string{"", "L9", "l5", "L0 ", "highest", "0"} {
		m, ok := TierOf(s)
		if s == "L0 " { // 带尾部空白的合法等级：TrimSpace 后应命中
			if !ok || m.Tier != TierL0 {
				t.Errorf("TierOf(%q) = %v/%v, want L0/true（应 TrimSpace）", s, m.Tier, ok)
			}
			continue
		}
		if ok {
			t.Errorf("TierOf(%q) 不应被认作已知等级", s)
		}
		if m.Tier != MaxTier().Tier {
			t.Errorf("TierOf(%q) 回退到 %s, want 最高风险 %s", s, m.Tier, MaxTier().Tier)
		}
	}
	if MaxTier().Tier != TierL4 {
		t.Fatalf("MaxTier = %s, want L4", MaxTier().Tier)
	}
	if TierRank(TierL2) != 2 || TierRank("nope") != -1 {
		t.Errorf("TierRank 结果不符：L2=%d unknown=%d", TierRank(TierL2), TierRank("nope"))
	}
}

// ─── 动作表 ──────────────────────────────────────────────────────────────────

// TestActionTableConsistent 钉住动作表自身的自洽性：
//   - 等级已知；破坏性/确认/自动重试三个冗余字段与等级一致（不允许表内漂移）；
//   - 任务类型与能力位非空（空任务类型 = 造一个必然失败的任务）；
//   - 动作名唯一；
//   - L4 当前**没有**动作（本批未落地 AMSI/ETW 抑制，不允许造"点了没反应"的假入口）。
func TestActionTableConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Actions() {
		if seen[a.Name] {
			t.Errorf("动作名重复：%s", a.Name)
		}
		seen[a.Name] = true
		m, ok := TierOf(string(a.Tier))
		if !ok {
			t.Errorf("%s 登记了未知等级 %q", a.Name, a.Tier)
			continue
		}
		if a.Destructive != m.Destructive {
			t.Errorf("%s Destructive=%v 与等级 %s 的 %v 不一致", a.Name, a.Destructive, a.Tier, m.Destructive)
		}
		if a.NeedsConfirm != m.NeedsConfirm {
			t.Errorf("%s NeedsConfirm=%v 与等级 %s 的 %v 不一致", a.Name, a.NeedsConfirm, a.Tier, m.NeedsConfirm)
		}
		if a.AutoRetry == m.NoAutoRetry {
			t.Errorf("%s AutoRetry=%v 与等级 NoAutoRetry=%v 不一致", a.Name, a.AutoRetry, m.NoAutoRetry)
		}
		if strings.TrimSpace(a.TaskType) == "" {
			t.Errorf("%s 缺少植入端任务类型", a.Name)
		}
		if strings.TrimSpace(a.Capability) == "" {
			t.Errorf("%s 缺少能力位（新增动作必须想清楚它依赖哪个编译期能力）", a.Name)
		}
		if a.Summary == "" || a.Impact == "" {
			t.Errorf("%s 缺少 summary/impact（影响评估是接口的必填输出）", a.Name)
		}
		if a.Name != strings.ToLower(a.Name) {
			t.Errorf("%s 动作名必须是小写（对外契约）", a.Name)
		}
	}
	if n := len(ActionsOfTier(TierL4)); n != 0 {
		t.Errorf("L4 当前不应有任何动作（实现未落地），实际 %d 个", n)
	}
}

// TestActionTableCoversSixChains 钉住"6 条既有链的动作都被登记"：
// 这是本次改造的核心目标（把散落的链收进一个有分级、可审计的入口），
// 少登记一条就等于那条链在分级体系里"隐身"。
func TestActionTableCoversSixChains(t *testing.T) {
	wantTier := map[string]Tier{
		"av_detect":    TierL0, // av_detect 链
		"edr_blind":    TierL1, // edr_blind 链
		"edr_kill":     TierL2, // edr_kill 链
		"process_kill": TierL2, // process_kill 链
		"byovd_load":   TierL3, // byovd_* 链
		"byovd_unload": TierL3,
		"byovd_kill":   TierL3,
		"ppl_kill":     TierL3, // ppl_kill 链
	}
	for name, tier := range wantTier {
		a, ok := Lookup(name)
		if !ok {
			t.Errorf("动作 %s 未登记（6 条既有链必须全部覆盖）", name)
			continue
		}
		if a.Tier != tier {
			t.Errorf("动作 %s 等级 = %s, want %s", name, a.Tier, tier)
		}
	}
	if got := len(Actions()); got != len(wantTier) {
		t.Errorf("动作总数 = %d, want %d（新增动作请同时更新本用例）", got, len(wantTier))
	}
}

// TestTaskNoRetry 钉住"破坏性任务禁止服务端自动重投递"的判定口径。
func TestTaskNoRetry(t *testing.T) {
	cases := []struct {
		taskType string
		want     bool
		why      string
	}{
		{"edr_blind", true, "L1 起一律禁止自动重投递（重发 = 二次 patch/二次改注册表）"},
		{"edr_kill", true, "L2 破坏性"},
		{"process_kill", true, "L2 破坏性"},
		{"byovd_load", true, "L3 破坏性（重复加载内核驱动）"},
		{"byovd_unload", true, "L3 破坏性"},
		{"byovd_kill", true, "L3 破坏性"},
		{"ppl_kill", true, "L3 破坏性"},
		{"av_detect", false, "L0 只读，重跑一次侦察没有副作用"},
		{"file_download", false, "未登记类型：大文件传输依赖重投递+断点续传，不能一刀切"},
		{"", false, "空类型不归本表管"},
	}
	for _, c := range cases {
		if got := TaskNoRetry(c.taskType); got != c.want {
			t.Errorf("TaskNoRetry(%q) = %v, want %v（%s）", c.taskType, got, c.want, c.why)
		}
	}
}

// ─── 策略与前置检查 ──────────────────────────────────────────────────────────

func TestDefaultPolicyIsFailClosed(t *testing.T) {
	p := DefaultPolicy()
	for _, tier := range []Tier{TierL2, TierL3, TierL4} {
		ok, reason := p.TierAllowed(tier)
		if ok {
			t.Errorf("默认策略下 %s 不应允许执行", tier)
		}
		if reason == "" {
			t.Errorf("默认策略下 %s 被拒但没给人类可读原因（接口/前端要靠它解释）", tier)
		}
	}
	for _, tier := range []Tier{TierL0, TierL1} {
		if ok, _ := p.TierAllowed(tier); !ok {
			t.Errorf("默认策略下 %s 应允许（默认开）", tier)
		}
	}
	// 零值 Policy 与 DefaultPolicy 必须同效（"配置没读到"时不能变成全开/免确认）
	var zero Policy
	if zero.Normalize() != DefaultPolicy() {
		t.Errorf("零值 Policy 归一化后 = %+v, want %+v（零值必须落在最严的一侧）", zero.Normalize(), DefaultPolicy())
	}
	if ok, _ := zero.TierAllowed(TierL2); ok {
		t.Error("零值 Policy 下 L2 不应允许")
	}
	if zero.SkipConfirm {
		t.Error("零值 Policy 不应跳过二次确认（SkipConfirm 用反向字段就是为了这个）")
	}
	// 未知等级：即使 allow_l4=true 也不放行未知等级串
	open := Policy{AllowL2: true, AllowL3: true, AllowL4: true}
	if ok, _ := open.TierAllowed(Tier("L9")); ok {
		t.Error("未知等级在任何配置下都必须被拒（fail-closed）")
	}
	if ok, reason := open.TierAllowed(TierL3); !ok || reason != "" {
		t.Errorf("allow_l3=true 时 L3 应放行，实际 ok=%v reason=%q", ok, reason)
	}
}

func TestResolveTimeout(t *testing.T) {
	p := DefaultPolicy()
	cases := []struct {
		in      int
		want    int
		wantErr string
	}{
		{0, DefaultTimeoutSec, ""}, // 0 用默认
		{30, 30, ""},
		{MaxTimeoutSec, MaxTimeoutSec, ""},
		{MaxTimeoutSec + 1, 0, CodeTimeoutInvalid}, // 超上限拒绝（而不是截断）
		{-1, 0, CodeTimeoutInvalid},
	}
	for _, c := range cases {
		got, err := p.ResolveTimeout(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("ResolveTimeout(%d) 返回错误：%v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("ResolveTimeout(%d) = %d, want %d", c.in, got, c.want)
			}
			continue
		}
		if ErrorCode(err) != c.wantErr {
			t.Errorf("ResolveTimeout(%d) code = %q, want %q", c.in, ErrorCode(err), c.wantErr)
		}
		if ErrorHTTP(err, 0) != 400 {
			t.Errorf("ResolveTimeout(%d) HTTP = %d, want 400", c.in, ErrorHTTP(err, 0))
		}
	}
}

func TestCheckActionFailClosed(t *testing.T) {
	if _, err := CheckAction(""); ErrorCode(err) != CodeBadRequest {
		t.Errorf("空动作 code = %q, want %q", ErrorCode(err), CodeBadRequest)
	}
	for _, name := range []string{"edr_nuke", "AMSI_ETW_SUPPRESS", "amsi_etw_suppress", "byovd", "exec"} {
		a, err := CheckAction(name)
		if err == nil {
			t.Errorf("未知动作 %q 竟被放行（解析出 %s）", name, a.Name)
			continue
		}
		if ErrorCode(err) != CodeUnknownAction {
			t.Errorf("未知动作 %q code = %q, want %q", name, ErrorCode(err), CodeUnknownAction)
		}
		if ErrorHTTP(err, 0) != 400 {
			t.Errorf("未知动作 %q HTTP = %d, want 400", name, ErrorHTTP(err, 0))
		}
	}
	// 合法动作：大小写与空白都收敛
	for _, name := range []string{"EDR_BLIND", " edr_blind ", "ppl_kill"} {
		a, err := CheckAction(name)
		if err != nil {
			t.Errorf("CheckAction(%q) 报错：%v", name, err)
			continue
		}
		if a.Name != strings.ToLower(strings.TrimSpace(name)) {
			t.Errorf("CheckAction(%q) = %s, want 规范化后的动作名", name, a.Name)
		}
	}
}

func TestCheckTierField(t *testing.T) {
	a, err := CheckAction("edr_blind")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTierField("", a); err != nil {
		t.Errorf("tier 留空应放行（由服务端决定），实际 %v", err)
	}
	if err := CheckTierField("L1", a); err != nil {
		t.Errorf("tier 一致应放行，实际 %v", err)
	}
	if err := CheckTierField("L0", a); ErrorCode(err) != CodeTierMismatch {
		t.Errorf("用 L0 冒充 L1 的 code = %q, want %q（这是防「低等级绕过确认」的核心闸门）",
			ErrorCode(err), CodeTierMismatch)
	}
	if err := CheckTierField("L9", a); ErrorCode(err) != CodeUnknownTier {
		t.Errorf("未知 tier 的 code = %q, want %q", ErrorCode(err), CodeUnknownTier)
	}
}

func TestCheckConfirm(t *testing.T) {
	p := DefaultPolicy()
	l0, _ := CheckAction("av_detect")
	l1, _ := CheckAction("edr_blind")

	if err := CheckConfirm(p, l0, false); err != nil {
		t.Errorf("L0 不需要确认，实际 %v", err)
	}
	err := CheckConfirm(p, l1, false)
	if ErrorCode(err) != CodeConfirmationRequired {
		t.Fatalf("L1 缺 confirm 的 code = %q, want %q", ErrorCode(err), CodeConfirmationRequired)
	}
	if ErrorHTTP(err, 0) != 409 {
		t.Errorf("缺确认必须 409（前端据此弹二次确认），实际 %d", ErrorHTTP(err, 0))
	}
	if err := CheckConfirm(p, l1, true); err != nil {
		t.Errorf("L1 带 confirm 应放行，实际 %v", err)
	}
	// 操作员显式关掉强制确认：放行（但配置本身会被接口回显出来）
	relaxed := p
	relaxed.SkipConfirm = true
	if err := CheckConfirm(relaxed, l1, false); err != nil {
		t.Errorf("require_confirm=false 时应放行，实际 %v", err)
	}
}

func TestCheckCapabilityAndParams(t *testing.T) {
	a, _ := CheckAction("edr_kill")
	if err := CheckCapability(a, []string{"command", "edr_kill"}, "reported"); err != nil {
		t.Errorf("能力位齐全应放行，实际 %v", err)
	}
	err := CheckCapability(a, []string{"command"}, "os_fallback")
	if ErrorCode(err) != CodeCapabilityMissing {
		t.Errorf("能力位缺失 code = %q, want %q", ErrorCode(err), CodeCapabilityMissing)
	}
	if !strings.Contains(ErrorMessage(err), "os_fallback") && !strings.Contains(ErrorMessage(err), "兜底") {
		t.Errorf("能力位缺失的文案应说明清单来源（兜底 vs 自报），实际：%s", ErrorMessage(err))
	}

	pk, _ := CheckAction("process_kill")
	if ErrorCode(CheckRequiredParams(pk, nil)) != CodeParamsInvalid {
		t.Errorf("process_kill 缺 pid 应报 %q", CodeParamsInvalid)
	}
	if err := CheckRequiredParams(pk, map[string]interface{}{"pid": float64(1234)}); err != nil {
		t.Errorf("process_kill 带 pid 应放行，实际 %v", err)
	}
	bl, _ := CheckAction("byovd_load")
	if err := CheckRequiredParams(bl, map[string]interface{}{"driver_b64": "AAAA", "service_name": "x"}); err != nil {
		t.Errorf("byovd_load 带 driver_b64+service_name 应放行，实际 %v", err)
	}
	if err := CheckRequiredParams(bl, map[string]interface{}{"driver_b64": "AAAA"}); ErrorCode(err) != CodeParamsInvalid {
		t.Errorf("byovd_load 缺 service_name 应报 %q", CodeParamsInvalid)
	}
}

// TestParamHelpers 参数读取必须容忍 JSON 数字/字符串两种写法（前端与脚本的写法不同）。
func TestParamHelpers(t *testing.T) {
	p := map[string]interface{}{
		"s":      " x ",
		"n":      float64(1234),
		"nstr":   "1234",
		"empty":  "",
		"zero":   float64(0),
		"list":   []interface{}{"a", " b ", ""},
		"csv":    "a, b ,",
		"bool":   true,
		"toobig": float64(99999999999),
	}
	if ParamString(p, "s") != "x" {
		t.Errorf("ParamString = %q, want x", ParamString(p, "s"))
	}
	if v, ok := ParamUint32(p, "n"); !ok || v != 1234 {
		t.Errorf("ParamUint32(n) = %d/%v, want 1234/true", v, ok)
	}
	if v, ok := ParamUint32(p, "nstr"); !ok || v != 1234 {
		t.Errorf("ParamUint32(nstr) = %d/%v, want 1234/true", v, ok)
	}
	if _, ok := ParamUint32(p, "toobig"); ok {
		t.Error("超出 uint32 的数字不应被接受")
	}
	if _, ok := ParamUint32(p, "s"); ok {
		t.Error("非数字字符串不应被接受为数字参数")
	}
	if !HasParam(p, "bool") || HasParam(p, "empty") || HasParam(p, "zero") {
		t.Error("HasParam 的空值判定不符（空串/0 应视为未提供）")
	}
	if got := ParamStringSlice(p, "list"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ParamStringSlice(list) = %v, want [a b]", got)
	}
	if got := ParamStringSlice(p, "csv"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ParamStringSlice(csv) = %v, want [a b]", got)
	}
}

// TestErrorHelpers 错误码/HTTP/文案三个取值口径必须稳定（对外契约）。
func TestErrorHelpers(t *testing.T) {
	e := NewError(409, CodeConfirmationRequired, "需要确认：%s", "edr_blind")
	if e.Code != CodeConfirmationRequired || ErrorHTTP(e, 500) != 409 {
		t.Errorf("NewError 结果不符：%+v", e)
	}
	if ErrorCode(e) != CodeConfirmationRequired || ErrorMessage(e) != e.Message {
		t.Errorf("取值函数与错误对象不一致：%q / %q", ErrorCode(e), ErrorMessage(e))
	}
	if ErrorCode(nil) != "" || ErrorHTTP(nil, 500) != 500 {
		t.Error("非 *Error（含 nil）必须回落到默认值")
	}
}

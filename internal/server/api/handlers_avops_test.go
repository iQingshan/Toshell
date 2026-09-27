package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"toshell/internal/common/avops"
	"toshell/internal/common/features"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/drivers"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── AV-Ops 分级入口用例（v1.4.0 S6）─────────────────────────────────────────
//
// 全部**不联网、不需要真实植入端**：会话是进程内注册的假会话，任务是隔离的任务管理器，
// 下发用假 TaskPusher。因此这些用例能在 CI 上跑，并且能精确断言"哪一步拒绝、错误码是什么、
// 审计写了什么、任务有没有真的下发"。
//
// 覆盖的硬要求（逐条对应任务书）：
//   - 未知动作 fail-closed；
//   - L2+ 默认禁用（改配置才放行）；
//   - 缺 confirm 被拒（409 confirmation_required）；
//   - tier 与动作实际等级不符被拒（防"低等级绕过确认"）；
//   - 能力位缺失被拒；
//   - L3 无驱动被拒（"无 rw 档驱动，不可用"）；
//   - L0 能真的下发 / L1 下发后**不参与任何自动重投递**；
//   - 显式超时（0 用默认、超上限拒绝）+ 服务端超时收口；
//   - 审计落库且不含凭据/驱动字节。

type avopsTestEnv struct {
	s      *Server
	sess   *session.Manager
	tm     *task.Manager
	pusher *fakePusher
	sid    string

	mu     sync.Mutex
	audits []avopsAuditEvent

	prevCfg *config.Config
	prevWd  string
}

// newAVOpsTestEnv 构造最小可用的 Server。
//
// profile/execModule 决定会话上报的能力位（features.EncodeToken 烘焙的位图令牌）。
// cfg 为 nil 时用"出厂默认配置"（avops 段全零 → L2+ 关、要求确认）。
func newAVOpsTestEnv(t *testing.T, profile string, cfg *config.Config) *avopsTestEnv {
	t.Helper()

	// 驱动目录扫描是相对 CWD 的：切到临时目录，保证"本机没有 rw 档驱动"这个前置条件
	// 在用例里成立（否则仓库里将来放了 .sys 会让 L3 用例静默变成另一条分支）。
	prevWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	prevCfg := config.Get()
	if cfg == nil {
		cfg = &config.Config{}
	}
	config.Set(cfg)
	t.Cleanup(func() { config.Set(prevCfg) })

	mgr := session.New()
	sid := fmt.Sprintf("avops-%d", time.Now().UnixNano())
	info := &types.SessionInfo{
		ID: sid, Hostname: "host", Username: "user",
		OS: "windows", Arch: "386", Status: "active",
		ActiveModules: []string{features.EncodeToken(features.Input{
			Profile: profile, Transport: "tcp", Protocol: "tcp", OS: "windows", Arch: "386",
		})},
	}
	if err := mgr.Add(info); err != nil {
		t.Fatalf("session Add: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Remove(sid) })

	pusher := &fakePusher{}
	tm := task.NewIsolated(mgr)
	s := &Server{cfg: cfg, sessionMgr: mgr, taskMgr: tm, listener: pusher}
	env := &avopsTestEnv{s: s, sess: mgr, tm: tm, pusher: pusher, sid: sid, prevCfg: prevCfg, prevWd: prevWd}
	s.avopsAuditHook = func(ev avopsAuditEvent) {
		env.mu.Lock()
		env.audits = append(env.audits, ev)
		env.mu.Unlock()
	}
	return env
}

// cfgWith 造一个带 avops 段的配置（其余字段保持零值；零值即 fail-closed）。
func cfgWith(l2, l3, l4 bool, requireConfirm bool, defTimeout, maxTimeout int) *config.Config {
	c := &config.Config{}
	c.AVOps.AllowL2 = l2
	c.AVOps.AllowL3 = l3
	c.AVOps.AllowL4 = l4
	c.AVOps.RequireConfirm = &requireConfirm
	c.AVOps.DefaultTimeoutSec = defTimeout
	c.AVOps.MaxTimeoutSec = maxTimeout
	return c
}

func (e *avopsTestEnv) post(t *testing.T, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+e.sid+"/av-ops", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": e.sid})
	rec := httptest.NewRecorder()
	e.s.execAVOpsHandler(rec, req)
	return rec.Code, decodeJSON(t, rec)
}

func (e *avopsTestEnv) getSession(t *testing.T) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+e.sid+"/av-ops", nil)
	req = mux.SetURLVars(req, map[string]string{"id": e.sid})
	rec := httptest.NewRecorder()
	e.s.sessionAVOpsHandler(rec, req)
	return rec.Code, decodeJSON(t, rec)
}

func (e *avopsTestEnv) getCatalog(t *testing.T) (int, map[string]interface{}) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.s.listAVOpsHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/av-ops", nil))
	return rec.Code, decodeJSON(t, rec)
}

// postJSON 便捷构造请求体。
func postJSON(t *testing.T, action string, confirm bool, params map[string]interface{}, timeout int, tier string) string {
	t.Helper()
	m := map[string]interface{}{"action": action, "confirm": confirm, "timeout_sec": timeout}
	if params != nil {
		m["params"] = params
	}
	if tier != "" {
		m["tier"] = tier
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (e *avopsTestEnv) auditEvents() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.audits))
	for _, a := range e.audits {
		out = append(out, a.Event)
	}
	return out
}

func (e *avopsTestEnv) lastAudit(t *testing.T) avopsAuditEvent {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.audits) == 0 {
		t.Fatal("没有审计事件（每个决策都必须留痕）")
	}
	return e.audits[len(e.audits)-1]
}

// checksOf2 把响应里的 checks 数组转成 step → (ok, code)。
func checksOf2(t *testing.T, body map[string]interface{}) map[int]struct {
	OK   bool
	Code string
} {
	t.Helper()
	raw, ok := body["checks"].([]interface{})
	if !ok {
		t.Fatalf("响应缺少 checks：%v", body)
	}
	out := map[int]struct {
		OK   bool
		Code string
	}{}
	for _, it := range raw {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		step := int(m["step"].(float64))
		code, _ := m["code"].(string)
		out[step] = struct {
			OK   bool
			Code string
		}{m["ok"] == true, code}
	}
	return out
}

// ─── 等级目录 ────────────────────────────────────────────────────────────────

// TestAVOpsCatalogDefaultsFailClosed GET /av-ops 必须自解释"当前允许做到哪一级"。
func TestAVOpsCatalogDefaultsFailClosed(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.getCatalog(t)
	if code != 200 || body["ok"] != true {
		t.Fatalf("GET /av-ops = %d %v", code, body)
	}
	tiers, ok := body["tiers"].([]interface{})
	if !ok || len(tiers) != 5 {
		t.Fatalf("tiers = %v, want 5 级", body["tiers"])
	}
	wantAllowed := map[string]bool{"L0": true, "L1": true, "L2": false, "L3": false, "L4": false}
	for _, it := range tiers {
		m := it.(map[string]interface{})
		tier := m["tier"].(string)
		if got := m["allowed"] == true; got != wantAllowed[tier] {
			t.Errorf("默认配置下 %s allowed = %v, want %v", tier, got, wantAllowed[tier])
		}
		if !wantAllowed[tier] {
			if r, _ := m["denied_reason"].(string); strings.TrimSpace(r) == "" {
				t.Errorf("%s 被拒但没给人类可读原因（前端要靠它解释为什么不给按钮）", tier)
			}
		}
		if m["implemented"] == false {
			if n := m["action_count"].(float64); n != 0 {
				t.Errorf("%s 标记为未实现却带了 %v 个动作（会造出点了没反应的假入口）", tier, n)
			}
		}
	}
	if n := body["action_count"].(float64); int(n) != 8 {
		t.Errorf("action_count = %v, want 8（6 条既有链共 8 个动作）", n)
	}
	// 策略回显：require_confirm 必须是正向字段且默认为 true
	pol := body["policy"].(map[string]interface{})
	if pol["allow_l2"] != false || pol["allow_l3"] != false || pol["allow_l4"] != false {
		t.Errorf("默认策略必须全关，实际 %v", pol)
	}
	if pol["require_confirm"] != true {
		t.Errorf("默认策略 require_confirm 必须为 true（零值不得变成免确认），实际 %v", pol)
	}
	if int(pol["default_timeout_sec"].(float64)) != avops.DefaultTimeoutSec {
		t.Errorf("default_timeout_sec = %v, want %d", pol["default_timeout_sec"], avops.DefaultTimeoutSec)
	}
}

// ─── fail-closed：未知动作 / 未知等级 / tier 不符 ─────────────────────────────

func TestAVOpsUnknownActionFailClosed(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	for _, name := range []string{"edr_nuke", "amsi_etw_suppress", "byovd", "exec"} {
		code, body := env.post(t, postJSON(t, name, true, nil, 0, ""))
		if code != 400 || body["code"] != avops.CodeUnknownAction {
			t.Errorf("未知动作 %q = HTTP %d code=%v, want 400 %s", name, code, body["code"], avops.CodeUnknownAction)
		}
	}
	// 未知动作也要留审计（拒绝同样是一个决策）
	ev := env.lastAudit(t)
	if ev.Event != "avops_rejected" || ev.Code != avops.CodeUnknownAction {
		t.Errorf("审计 = %+v, want avops_rejected/%s", ev, avops.CodeUnknownAction)
	}
	if env.pusher.count() != 0 {
		t.Fatal("未知动作竟然下发了任务")
	}
}

func TestAVOpsUnknownTierFailClosed(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 0, "L9"))
	if code != 400 || body["code"] != avops.CodeUnknownTier {
		t.Fatalf("未知 tier = HTTP %d code=%v, want 400 %s", code, body["code"], avops.CodeUnknownTier)
	}
	if env.pusher.count() != 0 {
		t.Fatal("未知等级竟然下发了任务")
	}
}

// TestAVOpsTierMismatchRejected 用低等级冒充高等级必须被拒（防"用 L0 绕过确认"）。
func TestAVOpsTierMismatchRejected(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 0, "L0"))
	if code != 400 || body["code"] != avops.CodeTierMismatch {
		t.Fatalf("tier 不符 = HTTP %d code=%v, want 400 %s", code, body["code"], avops.CodeTierMismatch)
	}
	// 相符时放行到后续步骤（这里因缺 confirm 之外的检查全部通过 → 会真的下发）
	code2, body2 := env.post(t, postJSON(t, "edr_blind", true, nil, 0, "L1"))
	if code2 != 200 || body2["ok"] != true {
		t.Fatalf("tier 相符应放行，实际 HTTP %d %v", code2, body2)
	}
}

// ─── 等级配置开关 / 二次确认 / 能力位 / L3 驱动 ──────────────────────────────

func TestAVOpsL2DisabledByDefaultAndEnabledByConfig(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.post(t, postJSON(t, "edr_kill", true, map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 0, ""))
	if code != 403 || body["code"] != avops.CodeTierDisabled {
		t.Fatalf("默认配置下 L2 = HTTP %d code=%v, want 403 %s", code, body["code"], avops.CodeTierDisabled)
	}
	checks := checksOf2(t, body)
	if c, ok := checks[3]; !ok || c.OK || c.Code != avops.CodeTierDisabled {
		t.Errorf("第 3 步应记录 tier_disabled，实际 %+v", checks[3])
	}
	if env.pusher.count() != 0 {
		t.Fatal("被禁用的等级竟然下发了任务")
	}

	// 打开 allow_l2 后放行
	config.Set(cfgWith(true, false, false, true, 0, 0))
	code2, body2 := env.post(t, postJSON(t, "edr_kill", true, map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 30, ""))
	if code2 != 200 || body2["ok"] != true {
		t.Fatalf("allow_l2=true 后 L2 = HTTP %d %v", code2, body2)
	}
	if got := body2["task_type"]; got != "edr_kill" {
		t.Errorf("task_type = %v, want edr_kill", got)
	}
	if env.pusher.count() != 1 {
		t.Fatalf("下发次数 = %d, want 1", env.pusher.count())
	}
	// 影响评估必须如实写清"会动什么"
	impact := body2["impact"].(map[string]interface{})
	if impact["destructive"] != true || impact["auto_retry"] != false {
		t.Errorf("impact = %v, want destructive/!auto_retry", impact)
	}
	if s, _ := impact["targets"].(string); !strings.Contains(s, "MsMpEng.exe") {
		t.Errorf("impact.targets 应写出具体目标，实际 %q", s)
	}
	// 审计
	ev := env.lastAudit(t)
	if ev.Event != "avops_dispatched" || ev.Action != "edr_kill" || ev.Tier != "L2" || !ev.Confirm {
		t.Errorf("审计 = %+v, want avops_dispatched/edr_kill/L2/confirm", ev)
	}
}

func TestAVOpsMissingConfirmRejected(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.post(t, postJSON(t, "edr_blind", false, nil, 0, ""))
	if code != 409 || body["code"] != avops.CodeConfirmationRequired {
		t.Fatalf("缺 confirm = HTTP %d code=%v, want 409 %s", code, body["code"], avops.CodeConfirmationRequired)
	}
	checks := checksOf2(t, body)
	if c, ok := checks[4]; !ok || c.OK || c.Code != avops.CodeConfirmationRequired {
		t.Errorf("第 4 步应记录 confirmation_required，实际 %+v", checks[4])
	}
	if env.pusher.count() != 0 {
		t.Fatal("缺确认竟然下发了任务")
	}

	// require_confirm=false 时放行（配置放宽是显式行为，且响应里会警告）
	config.Set(cfgWith(false, false, false, false, 0, 0))
	code2, body2 := env.post(t, postJSON(t, "edr_blind", false, nil, 30, ""))
	if code2 != 200 {
		t.Fatalf("require_confirm=false 时应放行，实际 HTTP %d %v", code2, body2)
	}
	warns := fmt.Sprint(body2["warnings"])
	if !strings.Contains(warns, "require_confirm") {
		t.Errorf("放宽项必须在 warnings 里明说，实际 %v", body2["warnings"])
	}
}

func TestAVOpsCapabilityMissingRejected(t *testing.T) {
	// light 档载荷里没有 edr_blind（edr_windows.go 带 windows && !light）
	env := newAVOpsTestEnv(t, features.ProfileLight, nil)
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 0, ""))
	if code != 409 || body["code"] != avops.CodeCapabilityMissing {
		t.Fatalf("能力位缺失 = HTTP %d code=%v, want 409 %s", code, body["code"], avops.CodeCapabilityMissing)
	}
	checks := checksOf2(t, body)
	if c, ok := checks[5]; !ok || c.OK || c.Code != avops.CodeCapabilityMissing {
		t.Errorf("第 5 步应记录 capability_missing，实际 %+v", checks[5])
	}
	// L0（av_detect）在 light 档里也有 → 可下发
	code2, body2 := env.post(t, postJSON(t, "av_detect", false, nil, 30, ""))
	if code2 != 200 {
		t.Fatalf("light 档的 av_detect 应可下发，实际 HTTP %d %v", code2, body2)
	}
}

func TestAVOpsL3WithoutDriverRejected(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))

	// ppl_kill：没有 rw 档驱动 → 明确说"无 rw 档驱动，不可用"
	code, body := env.post(t, postJSON(t, "ppl_kill", true, map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 0, ""))
	if code != 409 || body["code"] != avops.CodeDriverUnavailable {
		t.Fatalf("L3 无驱动 = HTTP %d code=%v, want 409 %s", code, body["code"], avops.CodeDriverUnavailable)
	}
	if e, _ := body["error"].(string); !strings.Contains(e, "无 rw 档驱动") {
		t.Errorf("拒绝文案必须直说「无 rw 档驱动，不可用」，实际 %q", e)
	}

	// byovd_kill：按名字点名的驱动不存在 → 同样拒绝
	code2, body2 := env.post(t, postJSON(t, "byovd_kill", true, map[string]interface{}{
		"pid": float64(1234), "driver": "definitely_missing_driver",
	}, 0, ""))
	if code2 != 409 || body2["code"] != avops.CodeDriverUnavailable {
		t.Fatalf("点名不存在的驱动 = HTTP %d code=%v, want 409 %s", code2, body2["code"], avops.CodeDriverUnavailable)
	}
	if env.pusher.count() != 0 {
		t.Fatal("驱动不可用时竟然下发了任务")
	}

	// L3 关闭时：先被等级闸门拦住（而不是驱动检查）
	config.Set(&config.Config{})
	code3, body3 := env.post(t, postJSON(t, "ppl_kill", true, map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 0, ""))
	if code3 != 403 || body3["code"] != avops.CodeTierDisabled {
		t.Fatalf("L3 默认禁用 = HTTP %d code=%v, want 403 %s", code3, body3["code"], avops.CodeTierDisabled)
	}
}

// TestAVOpsByovdLoadSelfcheckAndBase64 分级入口的 byovd_load 不允许成为"绕过加载前自检的后门"。
func TestAVOpsByovdLoadSelfcheckAndBase64(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))

	// 非法 base64：明确报参数错误，不静默当成"没给驱动"
	code, body := env.post(t, postJSON(t, "byovd_load", true, map[string]interface{}{
		"driver_b64": "!!!not-base64!!!", "service_name": "demo",
	}, 0, ""))
	if code != 400 || body["code"] != avops.CodeParamsInvalid {
		t.Fatalf("非法 base64 = HTTP %d code=%v, want 400 %s", code, body["code"], avops.CodeParamsInvalid)
	}

	// 缺 service_name：必填参数校验
	code2, body2 := env.post(t, postJSON(t, "byovd_load", true, map[string]interface{}{
		"driver_b64": base64.StdEncoding.EncodeToString([]byte("fake-sys")),
	}, 0, ""))
	if code2 != 400 || body2["code"] != avops.CodeParamsInvalid {
		t.Fatalf("缺 service_name = HTTP %d code=%v, want 400 %s", code2, body2["code"], avops.CodeParamsInvalid)
	}

	// 自检未通过（manifest 声明了不一致的 sha256）→ 硬拒。
	// 造一个临时驱动目录：同一目录里 manifest 声明 demo.sys 的 sha256 与实际不符。
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/drivers", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/drivers/demo.sys", []byte("real-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"drivers":[{"file":"demo.sys","name":"demo","purpose":"kill","device":"\\\\.\\demo","ioctl":"0x222048","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`
	if err := os.WriteFile(dir+"/drivers/manifest.json", []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	code3, body3 := env.post(t, postJSON(t, "byovd_load", true, map[string]interface{}{
		"driver_b64":   base64.StdEncoding.EncodeToString([]byte("real-bytes")),
		"service_name": "demo", "name": "demo",
	}, 0, ""))
	if !drivers.SelfCheckSupported() {
		// 非 Windows 平台（CI 的 Linux runner）：加载前自检**根本无法执行**（没有 WinVerifyTrust），
		// 所以这里按平台设计不会返回 driver_selfcheck_failed，而是"给明确警告后仍放行"。
		// 这条断言同样有意义：它证明"自检不可用"不会被静默当成"自检通过" —— 否则在 Linux 上
		// 托管的控制端会看起来和 Windows 一样安全（CI 上暴露出来的正是这个假设）。
		if code3 != 200 {
			t.Fatalf("非 Windows 平台自检不可用时按设计应放行并给警告，实际 HTTP %d code=%v body=%v",
				code3, body3["code"], body3)
		}
		if !warningsContainText(body3, "非 Windows") {
			t.Fatalf("非 Windows 平台必须给出「不做驱动自检」的明确警告，实际 warnings=%v", body3["warnings"])
		}
		t.Log("非 Windows 平台：已断言「自检不可用 → 明确警告」而不是静默通过")
		return
	}
	if code3 != 400 || body3["code"] != avops.CodeDriverSelfcheckFailed {
		t.Fatalf("哈希不符应硬拒 = HTTP %d code=%v, want 400 %s（body=%v）",
			code3, body3["code"], avops.CodeDriverSelfcheckFailed, body3)
	}
}

// warningsContainText 判断响应里的 warnings[]（[]interface{} of string）是否含某段文字。
func warningsContainText(body map[string]interface{}, want string) bool {
	raw, ok := body["warnings"].([]interface{})
	if !ok {
		return false
	}
	for _, w := range raw {
		if s, ok := w.(string); ok && strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// ─── 会话可用性判定（排障入口）───────────────────────────────────────────────

func TestAVOpsSessionAvailability(t *testing.T) {
	// light 档 + 默认配置：能量出来的只有 L0
	env := newAVOpsTestEnv(t, features.ProfileLight, nil)
	code, body := env.getSession(t)
	if code != 200 || body["ok"] != true {
		t.Fatalf("GET /sessions/{id}/av-ops = %d %v", code, body)
	}
	raw, ok := body["actions"].([]interface{})
	if !ok || len(raw) != 8 {
		t.Fatalf("actions = %v, want 8", body["actions"])
	}
	byAction := map[string]map[string]interface{}{}
	for _, it := range raw {
		m := it.(map[string]interface{})
		byAction[m["name"].(string)] = m
	}
	// L0 可用且无原因
	if a := byAction["av_detect"]; a["allowed"] != true || len(a["reasons"].([]interface{})) != 0 {
		t.Errorf("av_detect 应 allowed 且无 reasons，实际 %v", a)
	}
	// L2 被配置禁用
	k := byAction["edr_kill"]
	if k["allowed"] != false || !hasReasonCode(k, avops.CodeTierDisabled) {
		t.Errorf("edr_kill 应因 tier_disabled 被拒，实际 %v", k["reasons"])
	}
	// L1 能力位缺失（light 档没有 edr_blind）
	b := byAction["edr_blind"]
	if b["allowed"] != false || !hasReasonCode(b, avops.CodeCapabilityMissing) {
		t.Errorf("edr_blind 应因 capability_missing 被拒，实际 %v", b["reasons"])
	}
	// 需要确认也必须被显式列出：GET 要把 reasons 一次列全（排障时最烦"修一个冒一个"）
	if !hasReasonCode(b, avops.CodeConfirmationRequired) {
		t.Errorf("edr_blind 的 reasons 应列出 confirmation_required，实际 %v", b["reasons"])
	}
	// L3 无 rw 档驱动
	p := byAction["ppl_kill"]
	reasons := fmt.Sprint(p["reasons"])
	if p["allowed"] != false || !strings.Contains(reasons, "无 rw 档驱动") {
		t.Errorf("ppl_kill 应因驱动不可用被拒且说明无 rw 档，实际 %v", p["reasons"])
	}
	// 汇总与驱动块
	sum := body["summary"].(map[string]interface{})
	if int(sum["allowed"].(float64))+int(sum["blocked"].(float64)) != 8 {
		t.Errorf("summary 不闭合：%v", sum)
	}
	drv := body["driver"].(map[string]interface{})
	if drv["rw_available"] != false {
		t.Errorf("临时 CWD 下不应有 rw 档驱动，实际 %v", drv)
	}
}

// hasReasonCode 判断 reasons 里是否包含某个机器可读码（GET 要一次列全，不能只看第一条）。
func hasReasonCode(action map[string]interface{}, code string) bool {
	reasons, ok := action["reasons"].([]interface{})
	if !ok {
		return false
	}
	for _, it := range reasons {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		if s, _ := m["code"].(string); s == code {
			return true
		}
	}
	return false
}

func TestAVOpsSessionNotFound(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/nope/av-ops", strings.NewReader(postJSON(t, "av_detect", false, nil, 0, "")))
	req = mux.SetURLVars(req, map[string]string{"id": "nope"})
	rec := httptest.NewRecorder()
	env.s.execAVOpsHandler(rec, req)
	if rec.Code != 404 {
		t.Fatalf("会话不存在 = %d, want 404", rec.Code)
	}
	// 复用仓库 helper 的既有响应体（与其它会话级路由同一口径）
	if !strings.Contains(rec.Body.String(), "session not found") {
		t.Errorf("404 响应体应沿用仓库口径，实际 %s", rec.Body.String())
	}
}

func TestAVOpsInactiveSessionRejected(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	// 造一个"存在但不在线"的会话：status=asleep 且最近心跳已远超判活窗口。
	// 注意 session.Add 会把 Session.LastSeen 置为 now（新品必然"活着"），
	// 所以这里显式把 LastSeen 推到过去 —— 否则测的是"刚上线的会话"，与本用例无关。
	sid := env.sid + "-asleep"
	if err := env.sess.Add(&types.SessionInfo{
		ID: sid, Hostname: "h", Username: "u", OS: "windows", Status: "asleep",
		ActiveModules: []string{features.EncodeToken(features.Input{
			Profile: features.ProfileFull, OS: "windows", Arch: "386",
		})},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.sess.Remove(sid) })
	sess, err := env.sess.Get(sid)
	if err != nil {
		t.Fatal(err)
	}
	sess.LastSeen = time.Now().Add(-time.Hour)
	if sess.IsAlive() {
		t.Fatal("前置条件不成立：会话仍被判为存活，用例测不到「非 active 被拒」")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sid+"/av-ops", strings.NewReader(postJSON(t, "av_detect", false, nil, 0, "")))
	req = mux.SetURLVars(req, map[string]string{"id": sid})
	rec := httptest.NewRecorder()
	env.s.execAVOpsHandler(rec, req)
	if rec.Code != 409 {
		t.Fatalf("非 active 会话 = %d, want 409（body=%s）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), avops.CodeSessionInactive) {
		t.Errorf("应给出机器可读 code=%s，实际 %s", avops.CodeSessionInactive, rec.Body.String())
	}

	// GET 排障入口：所有动作都带 session_inactive 原因
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sid+"/av-ops", nil)
	req2 = mux.SetURLVars(req2, map[string]string{"id": sid})
	rec2 := httptest.NewRecorder()
	env.s.sessionAVOpsHandler(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("GET 排障入口 = %d, want 200", rec2.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec2.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, it := range body["actions"].([]interface{}) {
		m := it.(map[string]interface{})
		if m["allowed"] == true {
			t.Errorf("非 active 会话下 %s 不应 allowed", m["name"])
		}
		if !strings.Contains(fmt.Sprint(m["reasons"]), avops.CodeSessionInactive) {
			t.Errorf("%s 的 reasons 应包含 session_inactive，实际 %v", m["name"], m["reasons"])
		}
	}
}

// ─── 显式超时 ────────────────────────────────────────────────────────────────

func TestAVOpsTimeoutValidation(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, false, false, true, 30, 60))
	// 超上限 → 拒绝（不截断）
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 61, ""))
	if code != 400 || body["code"] != avops.CodeTimeoutInvalid {
		t.Fatalf("超上限 = HTTP %d code=%v, want 400 %s", code, body["code"], avops.CodeTimeoutInvalid)
	}
	// 负数 → 拒绝
	code2, body2 := env.post(t, postJSON(t, "edr_blind", true, nil, -1, ""))
	if code2 != 400 || body2["code"] != avops.CodeTimeoutInvalid {
		t.Fatalf("负数 = HTTP %d code=%v, want 400 %s", code2, body2["code"], avops.CodeTimeoutInvalid)
	}
	// 0 → 用默认值，并在 checks 里回显生效值
	code3, body3 := env.post(t, postJSON(t, "edr_blind", true, nil, 0, ""))
	if code3 != 200 {
		t.Fatalf("0 应回落到默认超时，实际 HTTP %d %v", code3, body3)
	}
	if checks := fmt.Sprint(body3["checks"]); !strings.Contains(checks, "显式超时 30 秒") {
		t.Errorf("checks 应回显生效超时 30 秒，实际 %v", body3["checks"])
	}
	if imp := body3["impact"].(map[string]interface{}); int(imp["timeout_sec"].(float64)) != 30 {
		t.Errorf("impact.timeout_sec = %v, want 30", imp["timeout_sec"])
	}
}

// TestAVOpsTimeoutWatchdog 显式超时必须变成服务端可判定的结论（task 进入 timeout 终态），
// 这也是"破坏性任务禁止自动重试"的第二条独立保证。
func TestAVOpsTimeoutWatchdog(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, false, false, true, 1, 60))
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 1, ""))
	if code != 200 {
		t.Fatalf("下发失败：HTTP %d %v", code, body)
	}
	taskID := uint64(body["task_id"].(float64))

	deadline := time.Now().Add(5 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		if tk, err := env.tm.Get(taskID); err == nil && tk != nil {
			status = tk.Status
			if status == task.StatusTimeout {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != task.StatusTimeout {
		t.Fatalf("超时看门狗未把任务收口，状态 = %q, want %q", status, task.StatusTimeout)
	}
	// 超时也要留审计
	found := false
	env.mu.Lock()
	for _, ev := range env.audits {
		if ev.Event == "avops_timeout" && ev.TaskID == taskID {
			found = true
		}
	}
	env.mu.Unlock()
	if !found {
		t.Error("超时未写审计事件 avops_timeout")
	}
}

// ─── 下发后的语义：禁止自动重投递 / 审计不含凭据 ─────────────────────────────

// TestAVOpsDispatchedTaskIsNotAutoReplayed L1 动作下发后，任务虽在 sent 状态，
// 但**不参与**服务端任何自动重投递（TCP 重连补发 / HTTP 轮询重新入队）。
func TestAVOpsDispatchedTaskIsNotAutoReplayed(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	code, body := env.post(t, postJSON(t, "edr_blind", true, nil, 30, ""))
	if code != 200 {
		t.Fatalf("下发失败：HTTP %d %v", code, body)
	}
	taskID := uint64(body["task_id"].(float64))
	// 假 pusher 只记录，任务仍停在 pending；先推进到 sent（= 已派发未回结果）
	if _, err := env.tm.GetNext(env.sid); err != nil {
		t.Fatalf("GetNext: %v", err)
	}
	if n := len(env.tm.ListReplayable(env.sid)); n != 0 {
		t.Fatalf("破坏性任务仍会被重连补发：%d 条", n)
	}
	if requeued, refused := env.tm.RequeueSentEx(env.sid, 0); requeued != 0 || refused != 1 {
		t.Fatalf("破坏性任务重投递门未生效：requeued=%d refused=%d", requeued, refused)
	}
	// 对照：L0 只读任务允许重投递（重跑一次侦察没有副作用）
	code2, body2 := env.post(t, postJSON(t, "av_detect", false, nil, 30, ""))
	if code2 != 200 {
		t.Fatalf("L0 下发失败：HTTP %d %v", code2, body2)
	}
	l0id := uint64(body2["task_id"].(float64))
	if l0id == taskID {
		t.Fatal("两次下发拿到了同一个 task id")
	}
	if _, err := env.tm.GetNext(env.sid); err != nil {
		t.Fatalf("GetNext: %v", err)
	}
	if requeued, _ := env.tm.RequeueSentEx(env.sid, 0); requeued != 1 {
		t.Fatalf("L0 只读任务应允许自动重投递，实际 requeued=%d", requeued)
	}
}

// TestAVOpsAuditCarriesNoCredentialMaterial 审计/日志里不得出现驱动字节等凭据类内容。
func TestAVOpsAuditCarriesNoCredentialMaterial(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))

	// 用一段可识别的字节当驱动内容（非法 base64 会在解码前被拒，这里用合法 base64 走到自检）
	marker := "SECRET-DRIVER-BYTES-MARKER"
	blob := base64.StdEncoding.EncodeToString([]byte(marker))
	code, body := env.post(t, postJSON(t, "byovd_load", true, map[string]interface{}{
		"driver_b64": blob, "service_name": "svc",
	}, 30, ""))
	// 结果不重要（本机可能因自检/警告产生不同结论），重点是**审计里不能出现内容**
	if code == 200 {
		t.Logf("下发成功（driver 自检无硬错误）: %v", body["checks"])
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	for _, ev := range env.audits {
		if strings.Contains(ev.Detail, marker) || strings.Contains(ev.Detail, blob) {
			t.Fatalf("审计事件泄露了驱动字节：%+v", ev)
		}
		if strings.Contains(ev.Detail, "driver_b64") && strings.Contains(ev.Detail, marker) {
			t.Fatalf("审计事件泄露了驱动内容：%+v", ev)
		}
	}
}

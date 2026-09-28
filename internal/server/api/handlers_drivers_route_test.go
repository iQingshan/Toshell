package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"toshell/internal/common/avops"
	"toshell/internal/common/features"
	"toshell/internal/server/drivers"
)

// ─── 驱动选路 / 台账 的接口级用例（v1.4.0 S6 P0-1）────────────────────────────
//
// 这些用例把"下发路径真的接上了 drivers.Route 与驱动台账"钉住：
//   - ppl_kill 自动挑 rw 档、byovd_kill 自动挑 kill 档（含档位不符的拒绝）；
//   - byovd_unload 在请求没给服务名时从台账解析（服务端重启后的清场路径）；
//   - GET /api/v1/drivers/ledger 给出可执行的清场指引；
//   - avops 动作表与 drivers 的档位需求表不漂移。

// writeAPIDriverDir 在**当前工作目录**下铺一个 drivers/ 目录（用例已把 CWD 切到临时目录）。
func writeAPIDriverDir(t *testing.T, manifest string, files ...string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := filepath.Join(cwd, "drivers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("建驱动目录: %v", err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("fake-sys-"+f), 0o600); err != nil {
			t.Fatalf("写驱动: %v", err)
		}
	}
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatalf("写 manifest: %v", err)
		}
	}
}

// isolatedLedger 给测试环境注入一个隔离的台账文件（不写仓库的 data/drivers/）。
func isolatedLedger(t *testing.T, env *avopsTestEnv) *drivers.Ledger {
	t.Helper()
	l := drivers.NewLedger(filepath.Join(t.TempDir(), "loaded.json"))
	env.s.driverLedger = l
	return l
}

// TestAVOpsPPLKillAutoRoutesToRWProfile purpose 分档真正驱动选路：
// 目录里同时有 kill 档与 rw 档时，ppl_kill 必须挑 rw 档（而不是"第一个驱动"）。
func TestAVOpsPPLKillAutoRoutesToRWProfile(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"aaa_kill.sys","name":"aaa_kill","purpose":"kill","device":"\\\\.\\aaa","ioctl":"0x222048"},
		{"file":"zzz_rw.sys","name":"zzz_rw","purpose":"rw"}
	]}`, "aaa_kill.sys", "zzz_rw.sys")

	code, body := env.post(t, postJSON(t, "ppl_kill", true,
		map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 0, ""))
	if code != 200 {
		t.Fatalf("有 rw 档时 ppl_kill 应放行，实际 HTTP %d %v", code, body)
	}
	drv, ok := body["driver"].(map[string]interface{})
	if !ok {
		t.Fatalf("响应缺少 driver 段（选路过程必须可回显）：%v", body)
	}
	if drv["name"] != "zzz_rw" || drv["purpose"] != "rw" || drv["source"] != drivers.RouteSourceCatalog {
		t.Fatalf("ppl_kill 未按 rw 档选路：%v", drv)
	}
	if env.pusher.count() != 1 {
		t.Fatalf("下发次数 = %d, want 1", env.pusher.count())
	}
}

// TestAVOpsByovdKillNamedProfilePurposeMismatch 点名了档位不符的驱动必须拒绝（不静默替换）。
func TestAVOpsByovdKillNamedProfilePurposeMismatch(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"kill.sys","name":"killdrv","purpose":"kill","device":"\\\\.\\kill","ioctl":"0x222048"},
		{"file":"rw.sys","name":"rwdrv","purpose":"rw"}
	]}`, "kill.sys", "rw.sys")

	code, body := env.post(t, postJSON(t, "byovd_kill", true,
		map[string]interface{}{"pid": float64(1234), "driver": "rwdrv"}, 0, ""))
	if code != 409 || body["code"] != avops.CodeDriverUnavailable {
		t.Fatalf("点名 rw 档做 byovd_kill = HTTP %d code=%v, want 409 %s", code, body["code"], avops.CodeDriverUnavailable)
	}
	if e, _ := body["error"].(string); !strings.Contains(e, "kill") || !strings.Contains(e, "rw") {
		t.Errorf("拒绝原因应写清「点名的驱动是 rw 档、本动作要 kill 档」，实际 %q", e)
	}
	if env.pusher.count() != 0 {
		t.Fatal("档位不符时不应下发")
	}

	// 不点名时按档位自动挑 kill 档 → 放行
	code2, body2 := env.post(t, postJSON(t, "byovd_kill", true,
		map[string]interface{}{"pid": float64(1234)}, 0, ""))
	if code2 != 200 {
		t.Fatalf("自动选路应放行，实际 HTTP %d %v", code2, body2)
	}
	drv := body2["driver"].(map[string]interface{})
	if drv["name"] != "killdrv" || drv["source"] != drivers.RouteSourceCatalog {
		t.Fatalf("byovd_kill 未挑到 kill 档：%v", drv)
	}
}

// TestAVOpsByovdLoadRegistersPurposeFromManifest 加载后按 manifest 声明的档位登记：
// 一个 rw 档驱动加载后，ppl_kill 必须能自动选到它（而不是永远只认 kill）。
func TestAVOpsByovdLoadRegistersPurposeFromManifest(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	isolatedLedger(t, env)
	raw := []byte("fake-rw-driver-bytes")
	writeAPIDriverDir(t, `{"drivers":[{"file":"rw.sys","name":"rwdrv","purpose":"rw","device":"\\\\.\\rw","ioctl":"0x222050","sha256":"`+
		sha256HexOf(raw)+`"}]}`, "rw.sys")

	// 同字节上传：哈希一致 → 自检无硬错；档位应取自 manifest（rw）
	code, resp := env.post(t, postJSON(t, "byovd_load", true, map[string]interface{}{
		"driver_b64": base64.StdEncoding.EncodeToString(raw), "service_name": "rwsvc", "name": "rwdrv",
	}, 0, ""))
	if code != 200 {
		t.Fatalf("byovd_load 应放行，实际 HTTP %d %v", code, resp)
	}
	drv := resp["driver"].(map[string]interface{})
	if drv["purpose"] != "rw" {
		t.Fatalf("加载应按 manifest 声明登记 rw 档，实际 %v", drv)
	}
	// 台账里必须记下这条加载（服务端重启后的清场依据）
	pending := env.s.driverLedgerOf().PendingForSession(env.sid)
	if len(pending) != 1 || pending[0].ServiceName != "rwsvc" || pending[0].Purpose != "rw" {
		t.Fatalf("台账未记录加载：%+v", pending)
	}

	// 加载后 ppl_kill 应能按 rw 档选到本会话登记的驱动（source=session）
	code2, resp2 := env.post(t, postJSON(t, "ppl_kill", true,
		map[string]interface{}{"processes": []string{"MsMpEng.exe"}}, 0, ""))
	if code2 != 200 {
		t.Fatalf("登记的 rw 档应让 ppl_kill 可用，实际 HTTP %d %v", code2, resp2)
	}
	if d := resp2["driver"].(map[string]interface{}); d["source"] != drivers.RouteSourceSession {
		t.Fatalf("ppl_kill 未用本会话登记的 rw 档：%v", d)
	}
}

// TestAVOpsByovdUnloadResolvesServiceFromLedger 请求没给 service_name 时，
// 从**服务端台账**解析（这正是"服务端重启后清场"的落点：内存里的登记已经没了）。
func TestAVOpsByovdUnloadResolvesServiceFromLedger(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	led := isolatedLedger(t, env)
	if err := led.RecordLoad(drivers.LedgerEntry{
		SessionID: env.sid, ServiceName: "leftover", DriverName: "leftover",
		Device: `\\.\leftover`, IOCTL: 0x222048, Purpose: "kill", LoadTaskID: 3,
	}); err != nil {
		t.Fatal(err)
	}
	// 前置条件：内存里没有该会话的档案（模拟服务端重启后的状态）
	if _, ok := env.s.recallSessionDriver(env.sid); !ok {
		t.Fatal("前置条件不成立：台账应能恢复出档案（这是重启恢复的一部分）")
	}
	if err := env.postUnload(t, ""); err != nil {
		t.Fatal(err)
	}
}

// postUnload 发一条不带 service_name 的 byovd_unload，并断言服务名来自台账。
func (e *avopsTestEnv) postUnload(t *testing.T, wantDriver string) error {
	t.Helper()
	code, body := e.post(t, postJSON(t, "byovd_unload", true, nil, 0, ""))
	if code != 200 {
		return fmt.Errorf("byovd_unload 应从台账解析出服务名并放行，实际 HTTP %d %v", code, body)
	}
	if body["task_type"] != "byovd_unload" {
		return fmt.Errorf("task_type = %v", body["task_type"])
	}
	drv, _ := body["driver"].(map[string]interface{})
	if drv["service"] != "leftover" {
		return fmt.Errorf("应从台账解析出 service=leftover，实际 %v", drv)
	}
	if drv["source"] != drivers.RouteSourceServiceName {
		return fmt.Errorf("source = %v, want %s", drv["source"], drivers.RouteSourceServiceName)
	}
	// 卸载后台账里该条不应再算残留
	if n := len(e.s.driverLedgerOf().Pending()); n != 0 {
		return fmt.Errorf("卸载后台账 pending = %d, want 0", n)
	}
	return nil
}

// TestAVOpsByovdUnloadWithoutAnyServiceRejected 三个来源都没有服务名时必须**明确拒绝**
// （而不是下发一个注定失败的任务）。
func TestAVOpsByovdUnloadWithoutAnyServiceRejected(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	isolatedLedger(t, env)

	code, body := env.post(t, postJSON(t, "byovd_unload", true, nil, 0, ""))
	if code != 400 || body["code"] != avops.CodeParamsInvalid {
		t.Fatalf("缺 service_name = HTTP %d code=%v, want 400 %s", code, body["code"], avops.CodeParamsInvalid)
	}
	if e, _ := body["error"].(string); !strings.Contains(e, "service_name") || !strings.Contains(e, "台账") {
		t.Errorf("拒绝文案应说明服务名从哪些来源取，实际 %q", e)
	}
	if env.pusher.count() != 0 {
		t.Fatal("缺服务名时不应下发任务")
	}
}

// TestDriverLedgerHandlerCleanupPlan GET /api/v1/drivers/ledger：
// 在线/离线两种残留都要给出可执行指引，counts 要闭合。
func TestDriverLedgerHandlerCleanupPlan(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	led := isolatedLedger(t, env)
	// 一条残留属于当前在线会话，一条属于已消失的会话（植入端重启后 session id 会变）
	if err := led.RecordLoad(drivers.LedgerEntry{SessionID: env.sid, ServiceName: "svc_online", DriverName: "a", Purpose: "kill", LoadTaskID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := led.RecordLoad(drivers.LedgerEntry{SessionID: "gone-session", ServiceName: "svc_offline", DriverName: "b", Purpose: "rw", LoadTaskID: 2}); err != nil {
		t.Fatal(err)
	}
	// 已清场的一条：不应出现在 pending/cleanup 里
	if err := led.RecordLoad(drivers.LedgerEntry{SessionID: env.sid, ServiceName: "svc_cleared", DriverName: "c", Purpose: "kill", LoadTaskID: 3}); err != nil {
		t.Fatal(err)
	}
	if err := led.RecordUnload(env.sid, "svc_cleared", 4); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	env.s.driverLedgerHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/drivers/ledger", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /drivers/ledger = %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	counts := body["counts"].(map[string]interface{})
	if int(counts["total"].(float64)) != 3 || int(counts["pending"].(float64)) != 2 ||
		int(counts["pending_online"].(float64)) != 1 || int(counts["pending_offline"].(float64)) != 1 {
		t.Fatalf("counts 不闭合：%v", counts)
	}
	cleanup := body["cleanup"].([]interface{})
	if len(cleanup) != 2 {
		t.Fatalf("cleanup 应只含 2 条残留：%v", cleanup)
	}
	var online, offline map[string]interface{}
	for _, it := range cleanup {
		m := it.(map[string]interface{})
		if m["service_name"] == "svc_online" {
			online = m
		} else {
			offline = m
		}
	}
	if online == nil || offline == nil {
		t.Fatalf("cleanup 内容不符：%v", cleanup)
	}
	if online["blocked"] != false || offline["blocked"] != true {
		t.Fatalf("blocked 判定错误：online=%v offline=%v", online["blocked"], offline["blocked"])
	}
	for _, want := range []string{"byovd_unload", "confirm", "svc_online"} {
		if !strings.Contains(online["how"].(string), want) {
			t.Errorf("how 缺少 %q：%v", want, online["how"])
		}
	}
	// 已经下发过卸载的那条不能混进 pending/cleanup
	if strings.Contains(fmt.Sprint(body["pending"]), "svc_cleared") {
		t.Error("已清场的条目不应出现在 pending 里")
	}
	if strings.Contains(fmt.Sprint(body["entries"]), "svc_cleared") == false {
		t.Error("已清场的条目仍应保留在 entries 里（可追溯）")
	}
}

// TestAVOpsSessionPreviewShowsRoutingAndSignature 可用性预览必须能看出
// "会挑哪个驱动"与"签名声明情况"（缺签名/声明未签名要能一眼看出来）。
func TestAVOpsSessionPreviewShowsRoutingAndSignature(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, nil)
	// 注意 zzz_bare 的命名：它与 killdrv 同为 kill 档，按"档位专一度 → 档案名"的确定性顺序
	// 应排在 killdrv 之后（所以预览里挑中的是 killdrv），这里刻意用名字把顺序钉住。
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"kill.sys","name":"killdrv","purpose":"kill","device":"\\\\.\\kill","ioctl":"0x222048","signed":"Contoso Ltd."},
		{"file":"rw.sys","name":"rwdrv","purpose":"rw"},
		{"file":"bare.sys","name":"zzz_bare","purpose":"kill","device":"\\\\.\\bare","ioctl":"0x222049","signed":false}
	]}`, "kill.sys", "rw.sys", "bare.sys")

	code, body := env.getSession(t)
	if code != 200 {
		t.Fatalf("GET /sessions/{id}/av-ops = %d", code)
	}
	drv := body["driver"].(map[string]interface{})
	selected := drv["selected"].(map[string]interface{})
	killView, _ := selected["kill"].(map[string]interface{})
	if killView == nil || killView["name"] != "killdrv" {
		t.Fatalf("预览未给出会被挑中的 kill 档驱动：%v", selected["kill"])
	}
	if killView["declared"] != "signed" || killView["declared_signer"] != "Contoso Ltd." {
		t.Fatalf("预览未带签名声明：%v", killView)
	}
	if !strings.Contains(fmt.Sprint(killView["verify_hint"]), "/verify") {
		t.Errorf("声明已签名时必须指向实测接口：%v", killView["verify_hint"])
	}
	rwView, _ := selected["rw"].(map[string]interface{})
	if rwView == nil || rwView["declared"] != "" || !strings.Contains(fmt.Sprint(rwView["warning"]), "未声明") {
		t.Fatalf("缺签名声明必须能看出来：%v", selected["rw"])
	}
	sigs := drv["signatures"].(map[string]interface{})
	if int(sigs["declared_signed"].(float64)) != 1 || int(sigs["undeclared"].(float64)) != 1 || int(sigs["declared_unsigned"].(float64)) != 1 {
		t.Fatalf("签名声明汇总错误：%v", sigs)
	}
}

// TestDriverRestartRestoresProfileAndOffersCleanup 服务端进程重启的**端到端**判定：
// 新 Server 实例（内存全空、只剩台账文件）应能 ① 恢复会话档案供 bypass 使用，
// ② 在可用性预览里给出残留清场指引。
func TestDriverRestartRestoresProfileAndOffersCleanup(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	path := filepath.Join(t.TempDir(), "loaded.json")

	// 第一次运行：加载了驱动并记进台账
	first := drivers.NewLedger(path)
	if err := first.RecordLoad(drivers.LedgerEntry{
		SessionID: env.sid, ServiceName: "restarted_svc", DriverName: "restarted",
		Device: `\\.\restarted`, IOCTL: 0x222048, Purpose: "kill", LoadTaskID: 5,
	}); err != nil {
		t.Fatal(err)
	}

	// 模拟服务端重启：换一个"全新"的 Server（同一个会话仍在，内存档案为空）
	restarted := &Server{cfg: env.s.cfg, sessionMgr: env.sess, taskMgr: env.tm, listener: env.pusher}
	restarted.driverLedger = drivers.NewLedger(path)
	env.s = restarted
	if restarted.sessionDrivers != nil {
		t.Fatal("前置条件不成立：新 Server 的内存档案应为空")
	}

	// ① 台账恢复档案：byovd_kill 不点名也能用回重启前加载的驱动
	code, body := env.post(t, postJSON(t, "byovd_kill", true, map[string]interface{}{"pid": float64(99)}, 0, ""))
	if code != 200 {
		t.Fatalf("重启后应按台账恢复档案并放行，实际 HTTP %d %v", code, body)
	}
	drv := body["driver"].(map[string]interface{})
	if drv["name"] != "restarted" || drv["source"] != drivers.RouteSourceSession {
		t.Fatalf("应从台账恢复出的档案选路：%v", drv)
	}

	// ② 预览里给出残留与清场指引
	code2, preview := env.getSession(t)
	if code2 != 200 {
		t.Fatalf("GET 预览 = %d", code2)
	}
	ledgerView, ok := preview["driver_ledger"].(map[string]interface{})
	if !ok {
		t.Fatalf("预览缺少 driver_ledger 段：%v", preview)
	}
	if !strings.Contains(fmt.Sprint(ledgerView["pending"]), "restarted_svc") {
		t.Fatalf("预览应列出残留驱动：%v", ledgerView["pending"])
	}
	if !strings.Contains(fmt.Sprint(ledgerView["cleanup"]), "byovd_unload") {
		t.Fatalf("预览应给出可执行的清场指引：%v", ledgerView["cleanup"])
	}
}

// TestLegacyRoutesUseSharedRouting 既有 /edr/* 路由也必须走同一份选路：
// 档位不符明确拒绝、卸载可从台账解析、ppl_kill 保留句柄窃取路线但回显 rw 档缺失。
func TestLegacyRoutesUseSharedRouting(t *testing.T) {
	env := newAVOpsTestEnv(t, features.ProfileFull, cfgWith(false, true, false, true, 0, 0))
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"kill.sys","name":"killdrv","purpose":"kill","device":"\\\\.\\kill","ioctl":"0x222048"},
		{"file":"rw.sys","name":"rwdrv","purpose":"rw"}
	]}`, "kill.sys", "rw.sys")

	// ① byovd-kill 点名 rw 档 → 409 + 中文原因（旧行为是"用上它，然后失败"）
	rec := env.legacyPost(t, "/edr/byovd-kill", `{"pid":1234,"driver":"rwdrv"}`)
	if rec.Code != 409 {
		t.Fatalf("点名档位不符 = %d, want 409（body=%s）", rec.Code, rec.Body.String())
	}
	var kv map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &kv)
	if kv["code"] != drivers.RouteCodeNamedPurposeMismatch {
		t.Fatalf("应回机器可读 code=%s，实际 %v", drivers.RouteCodeNamedPurposeMismatch, kv["code"])
	}
	if !strings.Contains(fmt.Sprint(kv["error"]), "kill") {
		t.Errorf("拒绝原因应写明需要 kill 档：%v", kv["error"])
	}

	// ② byovd-unload 不给服务名 → 从台账解析（既有路由也能清场）
	led := isolatedLedger(t, env)
	if err := led.RecordLoad(drivers.LedgerEntry{SessionID: env.sid, ServiceName: "legacy_leftover", DriverName: "x", Purpose: "kill", LoadTaskID: 1}); err != nil {
		t.Fatal(err)
	}
	rec2 := env.legacyPost(t, "/edr/byovd-unload", `{}`)
	if rec2.Code != 200 {
		t.Fatalf("既有卸载路由应从台账解析服务名，实际 %d %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "legacy_leftover") {
		t.Errorf("响应应回显解析出的服务名：%s", rec2.Body.String())
	}

	// ③ ppl-kill：**保留**句柄窃取路线（仍 200），但必须回显"没有 rw 档"的警告。
	//    这里把 manifest 改成只剩 kill 档（rw.sys 不再有 purpose 声明 → 不参与选路）。
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"kill.sys","name":"killdrv","purpose":"kill","device":"\\\\.\\kill","ioctl":"0x222048"}
	]}`, "kill.sys")
	rec3 := env.legacyPost(t, "/edr/ppl-kill", `{"processes":["MsMpEng.exe"]}`)
	if rec3.Code != 200 {
		t.Fatalf("既有 ppl-kill 路由必须保留句柄窃取路线（仍可下发），实际 %d %s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(rec3.Body.String(), "无可用 rw 档驱动") {
		t.Errorf("应回显无 rw 档的警告：%s", rec3.Body.String())
	}

	// ④ 老 manifest（只写 device/ioctl、没写 purpose）+ 点名 → 必须继续可用（既有语义），
	//    但响应里要给出"请补 purpose"的提示。
	writeAPIDriverDir(t, `{"drivers":[
		{"file":"old.sys","name":"olddrv","device":"\\\\.\\old","ioctl":"0x222077"}
	]}`, "old.sys")
	rec4 := env.legacyPost(t, "/edr/byovd-kill", `{"pid":1234,"driver":"olddrv"}`)
	if rec4.Code != 200 {
		t.Fatalf("点名未声明 purpose 的老档案应继续可用，实际 %d %s", rec4.Code, rec4.Body.String())
	}
	if !strings.Contains(rec4.Body.String(), "purpose") {
		t.Errorf("应提示补 purpose：%s", rec4.Body.String())
	}
}

// legacyPost 发一条既有 /edr/* 路由的请求（httptest + mux 变量）。
func (e *avopsTestEnv) legacyPost(t *testing.T, suffix, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+e.sid+suffix, strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": e.sid})
	rec := httptest.NewRecorder()
	switch {
	case strings.Contains(suffix, "byovd-kill"):
		e.s.byovdKillHandler(rec, req)
	case strings.Contains(suffix, "byovd-unload"):
		e.s.byovdUnloadHandler(rec, req)
	case strings.Contains(suffix, "ppl-kill"):
		e.s.pplKillHandler(rec, req)
	default:
		t.Fatalf("未支持的既有路由：%s", suffix)
	}
	return rec
}

// TestRequirementTableCoversAVOpsActions 守护"动作表"与"档位需求表"不漂移：
// 分级入口里每个 L3 动作都必须在 drivers 的档位需求表里登记（否则选路会 fail-closed 拒绝，
// 表现为"按钮点了没反应"）。
func TestRequirementTableCoversAVOpsActions(t *testing.T) {
	have := map[string]bool{}
	for _, r := range drivers.Requirements() {
		have[r.Action] = true
	}
	l3 := 0
	for _, a := range avops.Actions() {
		if a.Tier != avops.TierL3 {
			continue
		}
		l3++
		if !have[a.Name] {
			t.Errorf("L3 动作 %s 没有对应的档位需求（drivers.Requirements），选路会直接拒绝", a.Name)
		}
	}
	if l3 != 4 {
		t.Fatalf("L3 动作数 = %d, want 4（byovd_load/unload/kill + ppl_kill）", l3)
	}
	// 需求表里的动作名也必须都是真实动作（防错别字）
	for _, r := range drivers.Requirements() {
		if _, ok := avops.Lookup(r.Action); !ok {
			t.Errorf("档位需求表里的动作 %q 不在分级动作表里", r.Action)
		}
	}
}

// sha256HexOf 测试用小工具：算十六进制小写 sha256（与 drivers 包内部口径一致）。
func sha256HexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"toshell/internal/common/types"
	"toshell/internal/server/auth"
	"toshell/internal/server/config"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 植入端兼容端点（审计 H1/M1/M4 回归）──────────────────────────────────────
//
// 这些用例守护三层防护的实际行为：
//   1) 路由层 auth.Middleware：未认证 → 401，且任务状态一点不改；
//   2) handler 层归属校验：SessionID 与任务归属不符 → 403，任务仍 pending；
//   3) 心跳会话绑定：只写自己那条会话，dead 会话不能被心跳复活；
//   4) MaxBytesReader：32 MiB body → 413；
//   5) 回归：payload 载荷下载仍然免认证。

const implantTestAPIKey = "test-implant-api-key"

// resetImplantNotifyLimiter 清空按 IP 的通知限频表（全局变量，测试间隔离）。
func resetImplantNotifyLimiter() {
	implantNotifyMu.Lock()
	implantNotifyLast = map[string]time.Time{}
	implantNotifyMu.Unlock()
}

// newImplantTestServer 构造一个带认证 + 会话 + 独立任务管理器的 Server，并装配真实路由。
func newImplantTestServer(t *testing.T) (*Server, *session.Manager, *task.Manager, string) {
	t.Helper()

	sessMgr := session.New()
	sid := "sess-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	_ = sessMgr.Remove(sid) // 同名单测重复运行（-count=2）时先清理
	if err := sessMgr.Add(&types.SessionInfo{
		ID: sid, Hostname: "host-1", Username: "user-1", OS: "windows", Status: "active",
	}); err != nil {
		t.Fatalf("session add: %v", err)
	}

	tm := task.NewIsolated(sessMgr)

	cfg := &config.Config{}
	cfg.Auth = config.AuthConfig{
		Enabled:       true,
		JWTEnabled:    true,
		JWTKey:        "test-implant-jwt-key",
		JWTExpire:     1,
		APIKeyEnabled: true,
		APIKeys:       []string{implantTestAPIKey},
		AdminUsername: "admin",
		AdminPassword: "admin",
	}
	// webGate 每次请求都读 config.Get()：把全局配置钉在本次测试的 cfg 上
	// （cfg.Web 为零值 → 防护关闭，专门测 auth 层；两条链路互不掩盖）。
	prevCfg := config.Get()
	config.Set(cfg)
	t.Cleanup(func() { config.Set(prevCfg) })

	s := &Server{
		router:     mux.NewRouter(),
		sessionMgr: sessMgr,
		taskMgr:    tm,
		auth:       auth.New(&cfg.Auth),
		cfg:        cfg,
		wsHub:      NewWSHub(),
	}
	s.setupRoutes()
	return s, sessMgr, tm, sid
}

func doImplantRequest(s *Server, method, path, body string, withKey bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if withKey {
		req.Header.Set("X-API-Key", implantTestAPIKey)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func resultBody(sid string, taskID uint64, exitCode int32, output, errMsg string) string {
	return `{"SessionID":"` + sid + `","TaskID":` + strconv.FormatUint(taskID, 10) +
		`,"ExitCode":` + strconv.Itoa(int(exitCode)) +
		`,"Output":"` + output + `","Error":"` + errMsg + `"}`
}

// 未认证打三个端点必须 401，且任务状态/输出一点不改（H1 的核心 PoC）。
func TestImplantCompatEndpointsRequireAuth(t *testing.T) {
	s, _, tm, sid := newImplantTestServer(t)

	tk, err := tm.Create(sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create task: %v", err)
	}

	cases := []struct {
		name string
		path string
		body string
	}{
		{"result", "/api/v1/implant/result", resultBody(sid, tk.ID, 0, "FORGED-BY-UNAUTH", "")},
		{"heartbeat", "/api/v1/implant/heartbeat", `{"SessionID":"` + sid + `","CPUUsage":99.5,"Modules":["PWNED"]}`},
		{"register", "/api/v1/implant/register", `{"SessionID":"` + sid + `","Hostname":"fake"}`},
	}
	for _, tc := range cases {
		rec := doImplantRequest(s, http.MethodPost, tc.path, tc.body, false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: 未认证应 401，实际 %d body=%s", tc.name, rec.Code, rec.Body.String())
		}
	}

	got, err := tm.Get(tk.ID)
	if err != nil || got == nil {
		t.Fatalf("Get task: %v", err)
	}
	if got.Status != task.StatusPending {
		t.Errorf("未认证结果请求不应改任务状态：status=%q want pending", got.Status)
	}
	if got.Output != "" {
		t.Errorf("未认证结果请求不应写入 output：%q", got.Output)
	}
}

// 带合法凭据、但 SessionID 不是任务归属会话：403，任务仍 pending（不能被他人“认领”）。
func TestImplantResultRejectsForeignSession(t *testing.T) {
	s, sessMgr, tm, sid := newImplantTestServer(t)

	other := sid + "-other"
	if err := sessMgr.Add(&types.SessionInfo{ID: other, Hostname: "other", Status: "active"}); err != nil {
		t.Fatalf("add other session: %v", err)
	}

	tk, err := tm.Create(sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create task: %v", err)
	}

	body := resultBody(other, tk.ID, 0, "FORGED-BY-OTHER-SESSION", "")
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/result", body, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨会话伪造应 403，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	got, err := tm.Get(tk.ID)
	if err != nil || got == nil {
		t.Fatalf("Get task: %v", err)
	}
	if got.Status != task.StatusPending {
		t.Errorf("归属不符时任务必须保持 pending，实际 %q", got.Status)
	}
	if got.Output != "" {
		t.Errorf("归属不符时不得写入 output，实际 %q", got.Output)
	}
}

// 带合法凭据 + 正确归属：正常完成（不能把正常路径堵死），且失败结果保留 output/exit。
func TestImplantResultOwnedSessionHappyPath(t *testing.T) {
	s, _, tm, sid := newImplantTestServer(t)

	tkOK, err := tm.Create(sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create task: %v", err)
	}
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/result",
		resultBody(sid, tkOK.ID, 0, "hello-from-owner", ""), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确归属应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := tm.Get(tkOK.ID)
	if got.Status != task.StatusCompleted || got.Output != "hello-from-owner" {
		t.Fatalf("任务未正常完成：status=%q output=%q", got.Status, got.Output)
	}

	// 失败结果同样要保留植入端回传的 output/exit_code（v1.4.0 S6 的既有语义）。
	tkFail, err := tm.Create(sid, task.TaskParams{TaskType: task.TaskTypeCommand})
	if err != nil {
		t.Fatalf("Create task: %v", err)
	}
	rec = doImplantRequest(s, http.MethodPost, "/api/v1/implant/result",
		resultBody(sid, tkFail.ID, 7, "tool said why it failed", "exit code 7"), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确归属的失败结果应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	gotFail, _ := tm.Get(tkFail.ID)
	if gotFail.Status != task.StatusFailed {
		t.Errorf("status=%q want failed", gotFail.Status)
	}
	if gotFail.ExitCode != 7 || gotFail.Output != "tool said why it failed" {
		t.Errorf("失败结果丢了 output/exit_code：exit=%d output=%q", gotFail.ExitCode, gotFail.Output)
	}
}

// 心跳带错误 SessionID：404，且原会话的 CPU/ActiveModules 不被覆盖（M1 的全局污染）。
func TestImplantHeartbeatWrongSessionDoesNotTouchOthers(t *testing.T) {
	s, sessMgr, _, sid := newImplantTestServer(t)

	sess, err := sessMgr.Get(sid)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	sess.Info.CPUUsage = 1
	sess.Info.ActiveModules = []string{"SAFE-MODULE"}

	body := `{"SessionID":"no-such-session","CPUUsage":99.5,"MemoryUsed":123456789,"Modules":["PWNED"]}`
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/heartbeat", body, true)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
		t.Fatalf("错误 SessionID 应 404/400，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	sess2, _ := sessMgr.Get(sid)
	if sess2.Info.CPUUsage != 1 {
		t.Errorf("CPU 被跨会话覆盖：%v want 1", sess2.Info.CPUUsage)
	}
	if !reflect.DeepEqual(sess2.Info.ActiveModules, []string{"SAFE-MODULE"}) {
		t.Errorf("ActiveModules 被跨会话覆盖：%v", sess2.Info.ActiveModules)
	}
}

// 心跳只写“自己那条”：会话 B 的心跳不能改会话 A 的指标（M1 跨会话污染）。
func TestImplantHeartbeatOnlyUpdatesOwnSession(t *testing.T) {
	s, sessMgr, _, sidA := newImplantTestServer(t)

	sidB := sidA + "-b"
	if err := sessMgr.Add(&types.SessionInfo{ID: sidB, Hostname: "host-b", Status: "active"}); err != nil {
		t.Fatalf("add session b: %v", err)
	}

	sessA, _ := sessMgr.Get(sidA)
	sessA.Info.CPUUsage = 1
	sessA.Info.ActiveModules = []string{"A-ONLY"}

	body := `{"SessionID":"` + sidB + `","CPUUsage":42.5,"MemoryUsed":4096,"Modules":["B-MODULE"]}`
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/heartbeat", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法心跳应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	sessA2, _ := sessMgr.Get(sidA)
	if sessA2.Info.CPUUsage != 1 || !reflect.DeepEqual(sessA2.Info.ActiveModules, []string{"A-ONLY"}) {
		t.Errorf("会话 A 被 B 的心跳污染：cpu=%v modules=%v", sessA2.Info.CPUUsage, sessA2.Info.ActiveModules)
	}
	sessB, _ := sessMgr.Get(sidB)
	if sessB.Info.CPUUsage != 42.5 || !reflect.DeepEqual(sessB.Info.ActiveModules, []string{"B-MODULE"}) {
		t.Errorf("会话 B 自身未更新：cpu=%v modules=%v", sessB.Info.CPUUsage, sessB.Info.ActiveModules)
	}
}

// 已 dead 的会话发心跳：必须拒绝，状态不能回到 active，指标也不能被写入。
func TestImplantHeartbeatCannotReviveDeadSession(t *testing.T) {
	s, sessMgr, _, sid := newImplantTestServer(t)

	sess, _ := sessMgr.Get(sid)
	sess.Info.Status = "dead"
	sess.Info.ActiveModules = []string{"ORIGINAL"}

	body := `{"SessionID":"` + sid + `","CPUUsage":88,"Modules":["REVIVED"]}`
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/heartbeat", body, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dead 会话心跳应 409，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	sess2, _ := sessMgr.Get(sid)
	if sess2.Info.Status == "active" {
		t.Error("dead 会话被心跳复活成 active（审计 M1）")
	}
	if !reflect.DeepEqual(sess2.Info.ActiveModules, []string{"ORIGINAL"}) {
		t.Errorf("dead 会话的 ActiveModules 被写：%v", sess2.Info.ActiveModules)
	}
}

// 注册端点正常路径：带凭据 + SessionID → 200，会话存在且信息更新。
func TestImplantRegisterAuthenticatedHappyPath(t *testing.T) {
	s, sessMgr, _, sid := newImplantTestServer(t)
	resetImplantNotifyLimiter()

	body := `{"SessionID":"` + sid + `","Hostname":"renamed-host","Username":"renamed-user","OS":"windows","Arch":"amd64"}`
	rec := doImplantRequest(s, http.MethodPost, "/api/v1/implant/register", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("带凭据注册应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	sess, err := sessMgr.Get(sid)
	if err != nil || sess == nil {
		t.Fatalf("Get session: %v", err)
	}
	if sess.Info.Hostname != "renamed-host" || sess.Info.Username != "renamed-user" {
		t.Errorf("注册信息未刷新：host=%q user=%q", sess.Info.Hostname, sess.Info.Username)
	}
}

// 通知限频：同一 IP 每分钟最多一次（M1 的通知轰炸）。
func TestImplantRegisterNotifyRateLimitedPerIP(t *testing.T) {
	resetImplantNotifyLimiter()
	defer resetImplantNotifyLimiter()

	if !allowImplantRegisterNotify("10.0.0.1") {
		t.Fatal("首个通知应放行")
	}
	if allowImplantRegisterNotify("10.0.0.1") {
		t.Error("同一 IP 每分钟只应放行一次通知")
	}
	if !allowImplantRegisterNotify("10.0.0.2") {
		t.Error("不同 IP 不应互相限频")
	}
}

// 32 MiB body 必须 413，而不是被完整读入后返回 200（M4）。
func TestImplantCompatEndpointsRejectOversizedBody(t *testing.T) {
	s, _, _, sid := newImplantTestServer(t)
	big := strings.Repeat("A", 32<<20)

	cases := []struct {
		name string
		path string
		body string
	}{
		{"register", "/api/v1/implant/register", `{"SessionID":"` + sid + `"}` + big},
		{"heartbeat", "/api/v1/implant/heartbeat", `{"SessionID":"` + sid + `"}` + big},
		{"result", "/api/v1/implant/result", `{"SessionID":"` + sid + `"}` + big},
	}
	for _, tc := range cases {
		rec := doImplantRequest(s, http.MethodPost, tc.path, tc.body, true)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: 32 MiB body 应 413，实际 %d body=%s", tc.name, rec.Code, rec.Body.String())
		}
	}
}

// 回归：/api/v1/implant/payload/ 仍然免认证可下载（产品设计，不能被 auth 误伤）。
func TestImplantPayloadStaysUnauthenticated(t *testing.T) {
	s, _, _, _ := newImplantTestServer(t)
	dir := t.TempDir()
	s.cfg.Implant.OutputDir = dir
	if err := os.WriteFile(filepath.Join(dir, "build-test.bin"), []byte("PAYLOAD-BYTES"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	rec := doImplantRequest(s, http.MethodGet, "/api/v1/implant/payload/file:build-test.bin", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("payload 免认证下载应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "PAYLOAD-BYTES" {
		t.Errorf("载荷内容不对：%q", rec.Body.String())
	}
}

// webGate 豁免必须只剩 payload/uac 两个前缀（其余 /api/v1/implant/ 子路径不再豁免）。
func TestImplantExemptPrefixesNarrowed(t *testing.T) {
	want := []string{"/api/v1/implant/payload/", "/api/v1/implant/uac/"}
	if !reflect.DeepEqual(implantExemptPrefixes, want) {
		t.Fatalf("implantExemptPrefixes = %v, want %v", implantExemptPrefixes, want)
	}
}

// 开启 webGate（Basic 模式）后：payload/uac 仍免认证；其余 implant 子路径不再豁免；
// 且 Basic 只过 webGate 这一层，管理 API 仍必须再带 JWT/API Key（两层独立）。
func TestImplantWebGateExemptionNarrowed(t *testing.T) {
	s, _, _, _ := newImplantTestServer(t)

	hash, err := auth.HashPassword("gatepass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	cfg := config.Get()
	cfg.Web.BasicAuthEnabled = true
	cfg.Web.BasicAuthUser = "gate"
	cfg.Web.BasicAuthPassword = hash
	cfg.Web.UnauthMode = "basic"
	config.Set(cfg)

	dir := t.TempDir()
	s.cfg.Implant.OutputDir = dir
	if err := os.WriteFile(filepath.Join(dir, "build-test.bin"), []byte("PAYLOAD-AFTER-WEBGATE"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// payload 免认证（webGate 豁免命中）
	if rec := doImplantRequest(s, http.MethodGet, "/api/v1/implant/payload/file:build-test.bin", "", false); rec.Code != http.StatusOK {
		t.Errorf("payload 应免认证可下载，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	// uac 前缀也不在 auth 之后（不存在 token → 404，而不是 401）
	if rec := doImplantRequest(s, http.MethodGet, "/api/v1/implant/uac/nonexistent", "", false); rec.Code != http.StatusNotFound {
		t.Errorf("uac 应豁免 webGate（404 而非 401），实际 %d", rec.Code)
	}
	// 其余 /api/v1/implant/ 子路径不再豁免 webGate
	if rec := doImplantRequest(s, http.MethodGet, "/api/v1/implant/unknown-subpath", "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("未知 implant 子路径应被 webGate 拦成 401，实际 %d", rec.Code)
	}
	// 管理 API 同理需要凭据
	if rec := doImplantRequest(s, http.MethodGet, "/api/v1/sessions", "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("sessions 无凭据应 401，实际 %d", rec.Code)
	}
	// Basic 只过 webGate，不能替代 auth.Middleware（/sessions 仍需 API Key）
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.SetBasicAuth("gate", "gatepass")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Basic 凭据不应绕过 auth.Middleware（sessions 仍应 401），实际 %d", rec.Code)
	}
	// Basic + API Key：两层都过
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.SetBasicAuth("gate", "gatepass")
	req.Header.Set("X-API-Key", implantTestAPIKey)
	rec = httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Basic + API Key 应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
}

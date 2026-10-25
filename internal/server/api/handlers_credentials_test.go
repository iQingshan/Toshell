package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 凭据下发入口：能力边界与错误语义 ─────────────────────────────────────
//
// Linux 会话上凭据收集只会在植入端得到一个失败任务（features_unix.go 返回
// "credentials collection only supported on Windows"）。服务端在**下发前**就用
// 中文明确拒绝，前端拿到的是可展示的原文，而不是一个转圈到超时的空任务。

// newCredentialsTestServer 构造只接了会话/任务/假推送的最小 Server。
//
// 注意：session.New() 是进程级单例，因此会话 id 必须带上用例名（否则并行/重复
// 用例会撞 "session already exists"）。
func newCredentialsTestServer(t *testing.T, sid, osName string) (*Server, *fakePusher) {
	t.Helper()
	sessMgr := session.New()
	if err := sessMgr.Add(&types.SessionInfo{
		ID: sid, Hostname: "host-" + osName, Username: "user", OS: osName, Status: "active",
	}); err != nil {
		t.Fatalf("session.Add: %v", err)
	}
	tm := task.NewIsolated(sessMgr)
	pusher := &fakePusher{}
	s := &Server{cfg: &config.Config{}, sessionMgr: sessMgr, taskMgr: tm, listener: pusher}
	return s, pusher
}

// postCredentials 走真实 handler + mux 路径参数。
func postCredentials(t *testing.T, s *Server, sid, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sid+"/credentials", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": sid})
	rec := httptest.NewRecorder()
	s.credentialsHandler(rec, req)
	return rec
}

// TestCredentialsHandlerRejectsNonWindows Linux 会话：400 + "该能力仅支持 Windows"，
// 并且**不**创建/下发任务（避免制造一个注定失败、只能等到超时的任务）。
func TestCredentialsHandlerRejectsNonWindows(t *testing.T) {
	sid := "sess-" + t.Name() + "-linux"
	s, pusher := newCredentialsTestServer(t, sid, "linux")

	rec := postCredentials(t, s, sid, `{"action":"all"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Linux 会话下发凭据应 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "该能力仅支持 Windows") {
		t.Fatalf("错误文案必须明确写'该能力仅支持 Windows'，实际 %s", body)
	}
	if !strings.Contains(body, "linux") {
		t.Fatalf("错误文案应带上当前会话操作系统，实际 %s", body)
	}
	if pusher.count() != 0 {
		t.Fatalf("被拒绝的请求不应下发任务，实际下发 %d 个", pusher.count())
	}
}

// TestCredentialsHandlerDispatchesOnWindows Windows 会话：200 + task_id + 轮询提示，
// 任务确实被创建并推送给植入端。
func TestCredentialsHandlerDispatchesOnWindows(t *testing.T) {
	sid := "sess-" + t.Name() + "-windows"
	s, pusher := newCredentialsTestServer(t, sid, "windows")

	rec := postCredentials(t, s, sid, `{"action":"all"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("Windows 会话下发凭据应 200，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, needle := range []string{"task_id", "poll_timeout_sec", "result_hint", "凭据收集任务已下发"} {
		if !strings.Contains(body, needle) {
			t.Errorf("响应缺少 %q：%s", needle, body)
		}
	}
	if pusher.count() != 1 {
		t.Fatalf("应下发 1 个任务，实际 %d", pusher.count())
	}
}

// TestCredentialsHandlerRejectsUnknownAction 未知 action：400 + 支持的取值列表（不是 500）。
func TestCredentialsHandlerRejectsUnknownAction(t *testing.T) {
	sid := "sess-" + t.Name() + "-windows"
	s, pusher := newCredentialsTestServer(t, sid, "windows")

	rec := postCredentials(t, s, sid, `{"action":"nope"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知 action 应 400，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "支持") {
		t.Fatalf("未知 action 的错误应列出支持的取值：%s", rec.Body.String())
	}
	if pusher.count() != 0 {
		t.Fatalf("未知 action 不应下发任务，实际 %d", pusher.count())
	}
}

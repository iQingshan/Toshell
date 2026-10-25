package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toshell/internal/server/auth"
	"toshell/internal/server/config"
)

// 复审计 N2/N4 的回归测试：
//   - 未认证 /api/v1/login 的 32 MiB body → 413，且没有执行密码校验；
//   - 8 KiB 以内的正常登录仍 200；
//   - 首次认证成功删除 data/initial-admin-password.txt，失败（401）保留；
//   - 任务创建 / 批量 / 会话更新的超限 body → 413。

const loginTestRemoteAddr = "192.0.2.10:34567"

func newLoginTestServer() *Server {
	return &Server{auth: auth.New(&config.AuthConfig{
		Enabled:       true,
		JWTEnabled:    true,
		JWTKey:        "test-jwt-key-0123456789abcdefghijklmn",
		JWTExpire:     1,
		AdminUsername: "admin",
		AdminPassword: "correct-password",
	})}
}

// resetLoginLimiter 清空全局失败计数，避免测试间互相影响。
func resetLoginLimiter() {
	loginLimiterMu.Lock()
	loginFails = map[string]loginFailInfo{}
	loginLimiterMu.Unlock()
}

// withTempInitialAdminPassword 把初始口令文件重定向到临时目录，测试绝不碰真实 data/。
func withTempInitialAdminPassword(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), initialAdminPasswordFileName)
	old := initialAdminPasswordPath
	initialAdminPasswordPath = func() string { return path }
	t.Cleanup(func() { initialAdminPasswordPath = old })
	return path
}

func postLogin(t *testing.T, s *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	req.RemoteAddr = loginTestRemoteAddr
	w := httptest.NewRecorder()
	s.loginHandler(w, req)
	return w
}

func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON：%v，body=%q", err, w.Body.String())
	}
	return resp["error"]
}

// TestLoginOversizedBodyReturns413 32 MiB 合法形状 JSON：必须 413（不是 401/200），
// 且不能进入密码校验分支（否则错误口令会被记录成登录失败）。
func TestLoginOversizedBodyReturns413(t *testing.T) {
	resetLoginLimiter()
	path := withTempInitialAdminPassword(t)
	if err := os.WriteFile(path, []byte("correct-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 合法 JSON 形状 + 超长 password：Decoder 必须读到超过 8 KiB 才能结束对象。
	big := `{"username":"admin","password":"` + strings.Repeat("A", 32<<20) + `"}`
	w := postLogin(t, newLoginTestServer(), []byte(big))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("32 MiB 登录体应返回 413，实际 %d，body=%q", w.Code, w.Body.String())
	}
	if msg := errorMessage(t, w); !strings.Contains(msg, "超过") {
		t.Fatalf("413 原因应为中文“请求体超过…上限”，实际 %q", msg)
	}

	// 密码校验没有执行：错误凭据若被校验，会调用 loginRecordFail 记账。
	loginLimiterMu.Lock()
	_, recorded := loginFails[loginKey("admin", "192.0.2.10")]
	loginLimiterMu.Unlock()
	if recorded {
		t.Fatal("返回 413 却记录了登录失败：说明密码校验被执行了，限体没有抢占在最前面")
	}

	// 未认证的失败请求不得删除初始口令文件。
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("413 请求不应删除初始口令文件：%v", err)
	}
}

// TestLoginOversizedTrailingGarbageReturns413 合法 JSON + 32 MiB 尾部垃圾：
// json.Decoder 可能解析完第一个值就返回，必须靠“读干净剩余 body”补上闸门。
func TestLoginOversizedTrailingGarbageReturns413(t *testing.T) {
	resetLoginLimiter()
	withTempInitialAdminPassword(t)

	body := []byte(`{"username":"admin","password":"correct-password"}` + strings.Repeat(" ", 32<<20))
	w := postLogin(t, newLoginTestServer(), body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("合法 JSON + 超大尾部应返回 413，实际 %d，body=%q", w.Code, w.Body.String())
	}
}

// TestLoginSmallBodyStillWorks 8 KiB 以内的正常登录仍 200（限体不能误伤）。
func TestLoginSmallBodyStillWorks(t *testing.T) {
	resetLoginLimiter()
	withTempInitialAdminPassword(t)

	w := postLogin(t, newLoginTestServer(),
		[]byte(`{"username":"admin","password":"correct-password","extra":"兼容字段"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("正常登录应 200，实际 %d，body=%q", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token"] == "" {
		t.Fatal("登录成功但没返回 token")
	}
}

// TestLoginSuccessDeletesInitialAdminPasswordFile 首次认证成功 → 文件被删除。
func TestLoginSuccessDeletesInitialAdminPasswordFile(t *testing.T) {
	resetLoginLimiter()
	path := withTempInitialAdminPassword(t)
	if err := os.WriteFile(path, []byte("correct-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := postLogin(t, newLoginTestServer(), []byte(`{"username":"admin","password":"correct-password"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("正确口令应 200，实际 %d", w.Code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("登录成功后初始口令文件应被删除，Stat err=%v", err)
	}
}

// TestLoginSuccessToleratesMissingFile 配置给的是显式口令时本来就没有文件，
// 删除调用必须容忍 ErrNotExist，不能影响登录。
func TestLoginSuccessToleratesMissingFile(t *testing.T) {
	resetLoginLimiter()
	withTempInitialAdminPassword(t) // 不创建文件

	w := postLogin(t, newLoginTestServer(), []byte(`{"username":"admin","password":"correct-password"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("文件不存在时登录仍应 200，实际 %d，body=%q", w.Code, w.Body.String())
	}
}

// TestLoginFailureKeepsInitialAdminPasswordFile 401 不删除文件。
func TestLoginFailureKeepsInitialAdminPasswordFile(t *testing.T) {
	resetLoginLimiter()
	path := withTempInitialAdminPassword(t)
	const want = "correct-password\n"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	w := postLogin(t, newLoginTestServer(), []byte(`{"username":"admin","password":"wrong-password"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("错误口令应 401，实际 %d", w.Code)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("401 不应删除初始口令文件：%v", err)
	}
	if string(got) != want {
		t.Fatalf("401 不应改写初始口令文件：%q", string(got))
	}
}

// TestAuthenticatedHandlersBodyLimits 认证后的裸 io.ReadAll 入口统一限体：
// 超限 → 413；恰好等于上限的 body 不误伤（继续走 JSON 解析 → 400）。
func TestAuthenticatedHandlersBodyLimits(t *testing.T) {
	cases := []struct {
		name   string
		limit  int64
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"createTask", taskCreateMaxBodyBytes, (*Server).createTaskHandler},
		{"bulkTasks", bulkTasksMaxBodyBytes, (*Server).bulkTasksHandler},
		{"updateSession", sessionUpdateMaxBodyBytes, (*Server).updateSessionHandler},
		{"interactSession", sessionInteractMaxBodyBytes, (*Server).interactSessionHandler},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 超限 1 字节就足以触发 413；不用 32 MiB，测试更快。
			over := bytes.Repeat([]byte(" "), int(tc.limit)+1)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/test", bytes.NewReader(over))
			w := httptest.NewRecorder()
			tc.handle(&Server{}, w, req)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("超限 body 应 413，实际 %d，body=%q", w.Code, w.Body.String())
			}
			if msg := errorMessage(t, w); !strings.Contains(msg, "超过") {
				t.Fatalf("413 原因应为中文“请求体超过…上限”，实际 %q", msg)
			}

			// 恰好等于上限：不应 413（body 不是合法 JSON，预期 400）。
			atLimit := bytes.Repeat([]byte(" "), int(tc.limit))
			req = httptest.NewRequest(http.MethodPost, "/api/v1/test", bytes.NewReader(atLimit))
			w = httptest.NewRecorder()
			tc.handle(&Server{}, w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("恰好等于上限的 body 不应被限体拒绝，预期 400，实际 %d", w.Code)
			}
		})
	}
}

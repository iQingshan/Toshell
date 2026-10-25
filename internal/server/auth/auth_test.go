package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"toshell/internal/server/config"
)

// TestTokenQueryAllowed 覆盖 M6 的路径白名单：
// 只有浏览器 WebSocket 端点允许 ?token=，其余管理接口必须走 Authorization 头。
func TestTokenQueryAllowed(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// ── 白名单：WS 事件流（含实时屏幕帧）与交互式 shell ──
		{"/api/v1/ws/events", true},
		{"/api/v1/sessions/5041edce2618d318/shell", true},
		{"/api/v1/sessions/uuid-with-dash/shell", true},
		{"/api/v1/sessions/abc/shell/", true},
		{"/api/v1/sessions/abc/shell/child", true},

		// ── 非白名单：一律忽略查询串 token（应 401）──
		{"/api/v1/sessions", false},
		{"/api/v1/sessions/", false},
		{"/api/v1/sessions/abc", false},
		{"/api/v1/sessions/abc/other", false},
		{"/api/v1/sessions//shell", false}, // 空会话 id 不放行
		{"/api/v1/sessions/abc/shellx", false},
		{"/api/v1/tasks", false},
		{"/api/v1/tasks/1", false},
		{"/api/v1/settings", false},
		{"/api/v1/builders", false},
		{"/api/v1/logs", false},
		{"/api/v1/ws/events/extra", false},
		{"/api/v1/ws/other", false},
		{"/api/v1/shell", false},
		{"/ws/events", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := tokenQueryAllowed(tc.path); got != tc.want {
			t.Errorf("tokenQueryAllowed(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func newMiddlewareTestAuth(t *testing.T) (*Auth, string) {
	t.Helper()
	a := New(&config.AuthConfig{
		Enabled:       true,
		JWTEnabled:    true,
		JWTKey:        "test-jwt-key-for-middleware-tests-0123456789",
		JWTExpire:     1,
		APIKeyEnabled: true,
		APIKeys:       []string{"test-api-key"},
		AdminUsername: "admin",
		AdminPassword: "$2a$10$abcdefghijklmnopqrstuv",
	})
	token, err := a.GenerateToken("admin", "admin")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return a, token
}

func serveThroughMiddleware(a *Auth, method, target string, header map[string]string) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "handler-reached")
	})
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.Middleware()(next).ServeHTTP(rec, req)
	return rec
}

func withToken(path, token string) string {
	return path + "?token=" + url.QueryEscape(token)
}

// TestMiddlewareIgnoresQueryTokenOnHTTPPaths 是 M6 的核心回归：
//   - 普通 HTTP 接口带 ?token=<有效 JWT> → 401，且响应点名正确用法；
//   - WS 端点带 ?token=<有效 JWT> → 不被这条规则拒绝（交给 WS 升级逻辑处理）；
//   - Authorization: Bearer / X-API-Key 的正常行为不受影响。
func TestMiddlewareIgnoresQueryTokenOnHTTPPaths(t *testing.T) {
	a, token := newMiddlewareTestAuth(t)

	t.Run("sessions query token rejected", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, withToken("/api/v1/sessions", token), nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/sessions?token=... = %d, want 401", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Authorization header") {
			t.Errorf("401 body should name the correct auth method, got %q", rec.Body.String())
		}
	})

	for _, p := range []string{"/api/v1/tasks", "/api/v1/settings", "/api/v1/builders", "/api/v1/logs"} {
		if rec := serveThroughMiddleware(a, http.MethodGet, withToken(p, token), nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s?token=... = %d, want 401", p, rec.Code)
		}
	}

	t.Run("ws events query token allowed", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, withToken("/api/v1/ws/events", token), nil)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/ws/events?token=<valid> must not be rejected by the query-token rule (got 401)")
		}
	})

	t.Run("session shell query token allowed", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, withToken("/api/v1/sessions/abc/shell", token), nil)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/sessions/{id}/shell?token=<valid> must not be rejected (got 401)")
		}
	})

	t.Run("bearer still works", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, "/api/v1/sessions", map[string]string{
			"Authorization": "Bearer " + token,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("Authorization: Bearer = %d, want 200", rec.Code)
		}
	})

	t.Run("api key still works", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, "/api/v1/sessions", map[string]string{
			"X-API-Key": "test-api-key",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("X-API-Key = %d, want 200", rec.Code)
		}
	})

	t.Run("health still open", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, withToken("/api/v1/health", token), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/health?token=... = %d, want 200", rec.Code)
		}
	})

	t.Run("garbage query token also rejected on HTTP path", func(t *testing.T) {
		rec := serveThroughMiddleware(a, http.MethodGet, withToken("/api/v1/sessions", "not-a-jwt"), nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/sessions?token=not-a-jwt = %d, want 401", rec.Code)
		}
	})
}

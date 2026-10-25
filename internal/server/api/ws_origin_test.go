package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── 审计 M8：WebSocket Origin 校验 ─────────────────────────────────────────

// TestOriginAllowed 空 Origin 放行（非浏览器客户端）、同 host 放行、外站拒绝。
func TestOriginAllowed(t *testing.T) {
	newReq := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://c2.example:8080/ws/events", nil)
		r.Host = "c2.example:8080"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}

	allow := []string{
		"",                        // 非浏览器客户端不发 Origin
		"http://c2.example:8080",  // 同源（http）
		"https://c2.example:8080", // 同 host（scheme 不同不构成跨站）
		"http://C2.EXAMPLE:8080",  // host 大小写不敏感
	}
	for _, origin := range allow {
		if !originAllowed(newReq(origin)) {
			t.Errorf("Origin=%q 应放行", origin)
		}
	}

	deny := []string{
		"http://evil.example",
		"http://c2.example", // 端口不同（Host 含端口时要求逐字一致）
		"http://c2.example:9999",
		"https://evil.example/c2.example:8080",
		"null", // sandboxed iframe / file://
		"://bad-origin",
	}
	for _, origin := range deny {
		if originAllowed(newReq(origin)) {
			t.Errorf("Origin=%q 应拒绝", origin)
		}
	}
}

// TestWebSocketUpgradersUseOriginCheck 两个 upgrader 都必须接上同一套判定，
// 防止以后又把某一个改回 CheckOrigin=true。
func TestWebSocketUpgradersUseOriginCheck(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://c2.example:8080/ws/events", nil)
	r.Host = "c2.example:8080"
	r.Header.Set("Origin", "http://evil.example")

	if upgrader.CheckOrigin == nil || wsUpgrader.CheckOrigin == nil {
		t.Fatalf("两个 upgrader 都必须设置 CheckOrigin")
	}
	if upgrader.CheckOrigin(r) {
		t.Errorf("shell WS upgrader 对外站 Origin 必须拒绝")
	}
	if wsUpgrader.CheckOrigin(r) {
		t.Errorf("事件 WS upgrader 对外站 Origin 必须拒绝")
	}

	r.Header.Set("Origin", "http://c2.example:8080")
	if !upgrader.CheckOrigin(r) || !wsUpgrader.CheckOrigin(r) {
		t.Errorf("同 host Origin 应被两个 upgrader 放行")
	}

	r.Header.Del("Origin")
	if !upgrader.CheckOrigin(r) || !wsUpgrader.CheckOrigin(r) {
		t.Errorf("空 Origin（非浏览器客户端）应被两个 upgrader 放行")
	}
}

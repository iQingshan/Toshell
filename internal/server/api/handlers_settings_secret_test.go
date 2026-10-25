package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"toshell/internal/server/config"
)

// TestGetSettingsMasksWebhookSecret 守护审计 L5：GET /settings 不得回显 webhook
// 加签 secret 明文，只给"是否已设置"（secret_set），PUT 侧仍可写。
func TestGetSettingsMasksWebhookSecret(t *testing.T) {
	prev := config.Get()
	t.Cleanup(func() { config.Set(prev) })

	const secret = "webhook-sign-secret-should-not-leak"

	cfg := &config.Config{}
	cfg.Webhook.Secret = secret
	cfg.Webhook.Enabled = true
	cfg.Webhook.URL = "https://example.com/hook"
	config.Set(cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	(&Server{}).getSettingsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /settings = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("GET /settings leaked the webhook secret plaintext")
	}

	var resp SettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settings response: %v\n%s", err, body)
	}
	ns := resp.Notifications
	if got, ok := ns["secret_set"]; !ok || got != true {
		t.Errorf(`notifications.secret_set = %v (present=%v), want true`, got, ok)
	}
	if _, ok := ns["secret"]; ok {
		t.Errorf("notifications still contains a %q field; it must be replaced by secret_set", "secret")
	}
}

// TestGetSettingsWebhookSecretSetFalse 空 secret 时 secret_set 必须是 false（不是缺字段）。
func TestGetSettingsWebhookSecretSetFalse(t *testing.T) {
	prev := config.Get()
	t.Cleanup(func() { config.Set(prev) })

	cfg := &config.Config{}
	cfg.Webhook.Secret = "   "
	config.Set(cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
	(&Server{}).getSettingsHandler(rec, req)

	var resp SettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settings response: %v", err)
	}
	if got, ok := resp.Notifications["secret_set"]; !ok || got != false {
		t.Errorf(`notifications.secret_set = %v (present=%v), want false`, got, ok)
	}
}

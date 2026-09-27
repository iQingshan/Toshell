package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"toshell/internal/common/features"
	"toshell/internal/common/types"
	"toshell/internal/server/session"
)

// callCapabilities 直接调 handler（不经路由/鉴权），覆盖"有上报/无上报"两条路径。
func callCapabilities(t *testing.T, mgr *session.Manager, id string) (int, map[string]interface{}) {
	t.Helper()
	s := &Server{sessionMgr: mgr}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+id+"/capabilities", nil)
	req = mux.SetURLVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	s.sessionCapabilitiesHandler(rec, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON（code=%d）：%s", rec.Code, rec.Body.String())
	}
	return rec.Code, body
}

// newCapSession 注册一个唯一 id 的会话（session.New 是进程级单例，用例必须自清理）。
func newCapSession(t *testing.T, mgr *session.Manager, os string, modules []string) string {
	t.Helper()
	id := fmt.Sprintf("cap-%d", time.Now().UnixNano())
	info := &types.SessionInfo{
		ID: id, Hostname: "PC1", OS: os, Arch: "amd64",
		Status: "active", ActiveModules: modules,
	}
	if err := mgr.Add(info); err != nil {
		t.Fatalf("session Add: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Remove(id) })
	return id
}

// tabsOf 把响应里的 tabs 转成 map[string]bool（JSON 解出来是 map[string]interface{}）。
func tabsOf(t *testing.T, body map[string]interface{}) map[string]bool {
	t.Helper()
	raw, ok := body["tabs"].(map[string]interface{})
	if !ok {
		t.Fatalf("响应缺少 tabs 或类型不对：%v", body["tabs"])
	}
	out := make(map[string]bool, len(raw))
	for k, v := range raw {
		b, _ := v.(bool)
		out[k] = b
	}
	return out
}

func featuresOf(t *testing.T, body map[string]interface{}) []string {
	t.Helper()
	raw, ok := body["features"].([]interface{})
	if !ok {
		t.Fatalf("响应缺少 features 或类型不对：%v", body["features"])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// TestSessionCapabilitiesPrefersReported 载荷上报了能力位 → 必须用上报值，
// **不能**再按 OS 推导：light 载荷在 Windows 上也不该出现注入/插件/内存/中继面板
// （那些文件带 !light，载荷里真的没有，点了只会得到"未包含在精简构建中"）。
func TestSessionCapabilitiesPrefersReported(t *testing.T) {
	mgr := session.New()

	lightToken := features.EncodeToken(features.Input{Profile: "light", OS: "windows", BOF: true})
	fullToken := features.EncodeToken(features.Input{Profile: "full", OS: "windows", BOF: true})

	t.Run("light 上报", func(t *testing.T) {
		id := newCapSession(t, mgr, "Windows 11 x64", []string{lightToken})
		code, body := callCapabilities(t, mgr, id)
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200", code)
		}
		if body["source"] != "reported" {
			t.Fatalf("source = %v, want reported（载荷已上报能力位）", body["source"])
		}
		tabs := tabsOf(t, body)
		for _, bad := range []string{"injection", "bof", "fileless", "screenstream", "persistence", "credentials", "screenshot", "relay"} {
			if tabs[bad] {
				t.Errorf("light 载荷不该有 %q 面板（载荷里没编进去）：%v", bad, tabs)
			}
		}
		for _, must := range []string{"info", "files", "process", "shell", "av"} {
			if !tabs[must] {
				t.Errorf("light 载荷缺少 %q 面板：%v", must, tabs)
			}
		}
		if _, ok := body["source_note"]; ok {
			t.Error("上报路径不该出现 source_note（那是兜底专用说明）")
		}
		// 契约字段不得改名。
		if _, ok := body["tabs"]; !ok {
			t.Error("响应缺少 tabs")
		}
		if _, ok := body["features"]; !ok {
			t.Error("响应缺少 features")
		}
	})

	t.Run("full 上报", func(t *testing.T) {
		id := newCapSession(t, mgr, "Windows 11 x64", []string{fullToken})
		_, body := callCapabilities(t, mgr, id)
		if body["source"] != "reported" {
			t.Fatalf("source = %v, want reported", body["source"])
		}
		tabs := tabsOf(t, body)
		for _, must := range []string{"injection", "bof", "fileless", "screenstream", "persistence", "credentials", "screenshot", "relay", "av"} {
			if !tabs[must] {
				t.Errorf("full 载荷缺少 %q 面板：%v", must, tabs)
			}
		}
	})
}

// TestSessionCapabilitiesFallsBackForLegacyPayload 老载荷（Modules 为空）保持今天的行为：
// 按 OS 推导，并且必须标明这是兜底（source=os_fallback + source_note）。
func TestSessionCapabilitiesFallsBackForLegacyPayload(t *testing.T) {
	mgr := session.New()

	t.Run("windows 老载荷", func(t *testing.T) {
		id := newCapSession(t, mgr, "Windows 10", nil)
		code, body := callCapabilities(t, mgr, id)
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200", code)
		}
		if body["source"] != "os_fallback" {
			t.Fatalf("source = %v, want os_fallback", body["source"])
		}
		note, _ := body["source_note"].(string)
		if note == "" {
			t.Error("兜底路径必须带 source_note（说明未必等于载荷真实能力）")
		}
		tabs := tabsOf(t, body)
		// 与 v1.4.0 之前的输出完全一致（老载荷不能因为这次改动少按钮）。
		wantTabs := []string{
			"info", "files", "process", "shell", "bof", "relay",
			"injection", "persistence", "screenshot", "credentials", "av", "fileless", "screenstream",
		}
		for _, k := range wantTabs {
			if !tabs[k] {
				t.Errorf("兜底 tabs 缺少 %q：%v", k, tabs)
			}
		}
		if len(tabs) != len(wantTabs) {
			t.Errorf("兜底 tabs 多了键：got %v", tabs)
		}
		wantFeatures, _ := features.OSFallback("Windows 10")
		gotFeatures := featuresOf(t, body)
		if len(gotFeatures) != len(wantFeatures) {
			t.Errorf("兜底 features 长度不符：got %d want %d", len(gotFeatures), len(wantFeatures))
		}
	})

	t.Run("linux 老载荷", func(t *testing.T) {
		id := newCapSession(t, mgr, "Linux 6.1", []string{})
		_, body := callCapabilities(t, mgr, id)
		if body["source"] != "os_fallback" {
			t.Fatalf("source = %v, want os_fallback", body["source"])
		}
		tabs := tabsOf(t, body)
		if !tabs["fileless"] || !tabs["bof"] || !tabs["relay"] {
			t.Errorf("linux 兜底应保留旧口径（fileless/bof/relay）：%v", tabs)
		}
		if tabs["injection"] || tabs["credentials"] || tabs["screenshot"] {
			t.Errorf("linux 兜底不该出现 Windows 专属面板：%v", tabs)
		}
	})

	t.Run("非法令牌视为未上报", func(t *testing.T) {
		id := newCapSession(t, mgr, "Windows 10", []string{"cap:v1:zzzzzzzzzzzzzzzz", "bogus"})
		_, body := callCapabilities(t, mgr, id)
		if body["source"] != "os_fallback" {
			t.Fatalf("脏令牌必须兜底，不能显示空面板：source=%v", body["source"])
		}
	})
}

// TestSessionCapabilitiesSessionNotFound 会话不存在仍是 404（路由/错误码语义不变）。
func TestSessionCapabilitiesSessionNotFound(t *testing.T) {
	mgr := session.New()
	s := &Server{sessionMgr: mgr}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/nope/capabilities", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "definitely-not-exist"})
	rec := httptest.NewRecorder()
	s.sessionCapabilitiesHandler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, want 404", rec.Code)
	}
}

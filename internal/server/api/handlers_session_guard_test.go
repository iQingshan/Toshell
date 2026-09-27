package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/session"
)

// TestRequireSessionNotFoundIs404 会话不存在必须是 **404**，不能是 5xx。
//
// 背景（e2e 冒烟长期挂着的观察项）：`task.Manager.Create` 在会话不存在时返回
// `session not found: <id>`，而 handler 一律当 500 返回 —— 客户端输入错误被报成
// 服务端故障：调用方会重试而不是修正 id，监控也会把它计入服务端错误率。
// 路由存在性探测（scripts/e2e_smoke.ps1）明确要求这里返回 4xx。
func TestRequireSessionNotFoundIs404(t *testing.T) {
	mgr := session.New()
	s := &Server{sessionMgr: mgr}

	// 不存在的会话 → 404
	rec := httptest.NewRecorder()
	if s.requireSession(rec, "nope") {
		t.Fatal("会话不存在时 requireSession 应返回 false")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session not found") {
		t.Fatalf("错误体应说明会话不存在，实际 %s", rec.Body.String())
	}

	// 已存在的会话 → 放行（不写响应）。
	//
	// ⚠️ `session.New()` 是**进程级单例**（session.go 的 once），所以用例必须用唯一的会话 id
	// 并在结束时移除：否则 `-count=N` 重跑会撞 "session already exists"，以及把状态泄漏给
	// 同包其它用例。
	id := fmt.Sprintf("guard-%d", time.Now().UnixNano())
	if err := mgr.Add(&types.SessionInfo{ID: id, Hostname: "PC1"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Remove(id) })

	rec2 := httptest.NewRecorder()
	if !s.requireSession(rec2, id) {
		t.Fatal("会话存在时应放行")
	}
	if rec2.Code != http.StatusOK || rec2.Body.Len() != 0 {
		t.Fatalf("放行时不应写响应: code=%d body=%q", rec2.Code, rec2.Body.String())
	}
}

// TestRequireListenerUnavailableIs503 listener 未就绪是"暂时不可用"，用 503（可退避重试），
// 不是 500（真正的内部故障）—— 语义差别会被客户端重试策略与告警口径直接放大。
func TestRequireListenerUnavailableIs503(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	if s.requireListener(rec) {
		t.Fatal("listener 为 nil 时应返回 false")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, want 503", rec.Code)
	}
}

// TestRequireSessionWithoutManagerNoop 精简装配（未接会话管理器，如部分单测）不拦截，
// 交给下游判定，避免把"没装配"当成"会话不存在"。
func TestRequireSessionWithoutManagerNoop(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	if !s.requireSession(rec, "anything") {
		t.Fatal("未装配 sessionMgr 时应放行")
	}
}

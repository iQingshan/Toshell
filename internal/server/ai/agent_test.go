package ai

import (
	"context"
	"testing"

	"toshell/internal/server/mcp"
)

// TestIsRiskyTool 校验影响会话的操作被判定为需审批，而只读/查询类不受限。
//
// ⚠️ 等级的唯一来源是工具注册表（internal/server/mcp）：只有 LevelRead 免审批，
// LevelConfirm/LevelDanger 都要审批。曾经把 remote_download（LevelDanger，外部载荷入口）
// 列在免审批一侧，v1.4.0 起按注册表纠正；delegate 同样按危险级管控（防"委派绕过审批"）。
func TestIsRiskyTool(t *testing.T) {
	risky := []string{"task_submit", "run_command", "file_download", "process_kill", "screenshot", "credentials", "session_kill", "plugin_load", "fileless_exec", "tunnel_start", "remote_download", "plugin_upload", "delegate", "exec"}
	benign := []string{"session_list", "session_context", "intel_query", "attack_suggest", "plugin_list", "tunnel_list", "web_search", "tool_list"}
	for _, n := range risky {
		if !isRiskyTool(n) {
			t.Fatalf("expected %s to be risky", n)
		}
	}
	for _, n := range benign {
		if isRiskyTool(n) {
			t.Fatalf("expected %s to be benign", n)
		}
	}
	// fail-closed：未注册的名字必须按危险处理，不能因为"忘了登记"而免审批。
	for _, n := range []string{"", "not_a_registered_tool", "TASK_SUBMIT"} {
		if !isRiskyTool(n) {
			t.Fatalf("expected unregistered %q to be risky (fail-closed)", n)
		}
	}
	// 注册表里标成非只读的每一个工具都必须被判定为 risky：防止注册表与审批判定脱节。
	var nonRead []string
	for _, def := range mcp.Default().All() {
		if def.Level != mcp.LevelRead {
			nonRead = append(nonRead, def.Name)
		}
	}
	if len(nonRead) == 0 {
		t.Fatal("registry returned no non-read tools; expectation drift")
	}
	for _, n := range nonRead {
		if !isRiskyTool(n) {
			t.Fatalf("registry marks %s non-read but isRiskyTool says benign", n)
		}
	}
}

// TestAgentStatusTransition 校验 run 状态机基本流转。
func TestAgentStatusTransition(t *testing.T) {
	mgr := NewAgentManager(1)
	run := mgr.NewRun(nil, 0)
	if run.Status != AgentQueued {
		t.Fatalf("initial status = %s, want queued", run.Status)
	}
	run.setStatus(AgentRunning)
	if run.Status != AgentRunning {
		t.Fatalf("status = %s, want running", run.Status)
	}
	run.setStatus(AgentDone)
	if run.Status != AgentDone {
		t.Fatalf("status = %s, want done", run.Status)
	}
	if got := mgr.Get(run.ID); got != run {
		t.Fatal("Get should return the same run")
	}
	mgr.Remove(run.ID)
	if mgr.Get(run.ID) != nil {
		t.Fatal("run should be removed")
	}
}

// TestAgentConcurrencySemaphore 校验并发信号量：超出 MaxConcurrent 应阻塞，已取消 ctx 时快速失败。
func TestAgentConcurrencySemaphore(t *testing.T) {
	mgr := NewAgentManager(2)
	if !mgr.Acquire(context.Background()) {
		t.Fatal("first acquire should succeed")
	}
	if !mgr.Acquire(context.Background()) {
		t.Fatal("second acquire should succeed")
	}
	// 已取消的 ctx：Acquire 应立即失败（不会因为满而卡住）
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if mgr.Acquire(cctx) {
		t.Fatal("acquire with cancelled ctx should fail")
	}
	mgr.Release()
	mgr.Release()
}

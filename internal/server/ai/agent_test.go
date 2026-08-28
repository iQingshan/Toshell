package ai

import (
	"context"
	"testing"
)

// TestIsRiskyTool 校验影响会话的操作被判定为需审批，而只读/查询类不受限。
func TestIsRiskyTool(t *testing.T) {
	risky := []string{"task_submit", "run_command", "file_download", "process_kill", "screenshot", "credentials", "session_kill", "plugin_load", "fileless_exec", "tunnel_start"}
	benign := []string{"session_list", "session_context", "intel_query", "attack_suggest", "plugin_list", "tunnel_list", "web_search", "remote_download", "tool_list"}
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

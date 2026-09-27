package api

import (
	"context"
	"testing"
	"time"

	"toshell/internal/server/ai"
	"toshell/internal/server/config"
)

// TestSuspendedLongTaskReleasesAgentSlot 长任务挂起的**收益**断言：挂起期间必须释放
// Agent 并发槽位。
//
// 为什么单独写这条：suspend→resume 的流转已经有端到端用例覆盖（见
// TestAgentLongTaskSuspendAndResumeEndToEnd），但"挂起到底有没有把槽位还回去"没人断言过 ——
// 而这正是整个改造的目的：AgentConcurrency 默认只有 2，一把 credentials(180s) 以前能把
// Agent 卡满三分钟。如果哪天有人在挂起路径上漏掉"退出循环"（例如把挂起实现成"在循环里
// 等事件"），suspend 的用例照样全绿，槽位却被继续占着，问题只会在真实使用中表现为"AI 卡住"。
//
// 这里把并发上限压到 1：挂起后若槽位没释放，第二次 Acquire 必然超时失败。
func TestSuspendedLongTaskReleasesAgentSlot(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	env.s.agentMgr = ai.NewAgentManager(1) // 单槽位：挂起不释放槽位就必然暴露

	llm, _ := newMockSSELLM(t, "credentials", map[string]string{"session_id": env.sid}, "凭据收集完成")
	aiCfg := config.AIConfig{
		Enabled: true, BaseURL: llm.URL, APIKey: "k", Model: "m",
		ConsentPolicy:        "off",
		LongTaskThresholdSec: ai.DefaultLongTaskThresholdSec,
		MaxTurns:             20,
		MaxToolCalls:         40,
		MaxWallclockSec:      900,
	}
	env.s.cfg.AI = aiCfg
	cp := ai.New(aiCfg, env.s)
	env.s.copilot = cp
	env.s.applyLongTaskExecutor(cp)

	run := env.s.agentMgr.NewRun([]ai.Message{{Role: "user", Content: "收集凭据"}}, 0)
	go env.s.runAgentAsync(context.Background(), run)

	// ① 先确认它真的进了等待态（凭据类工具预估 180s ≥ 阈值 150s）
	waitFor(t, 5*time.Second, "run 进入 awaiting_task", func() bool {
		st, _ := run.WaitState()
		return st == ai.AgentWaitTask
	})

	// ② 槽位必须已经还回来：单槽位下能立刻拿到，就证明 runAgentAsync 的 defer 跑完了
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !env.s.agentMgr.Acquire(ctx) {
		st, waitingOn := run.WaitState()
		t.Fatalf("run 已挂起（status=%s waiting_on=%s）却仍占着并发槽位：长任务改造的收益没有兑现",
			st, waitingOn)
	}
	env.s.agentMgr.Release()

	// ③ 挂起不占槽位 → 第二个 run 能在同一个槽位上跑起来并同样挂起（并发上限 1 也能推进）
	llm2, _ := newMockSSELLM(t, "file_download",
		map[string]string{"session_id": env.sid, "path": "C:\\Windows\\System32\\config\\SAM"}, "下载完成")
	cp2 := ai.New(config.AIConfig{
		Enabled: true, BaseURL: llm2.URL, APIKey: "k", Model: "m",
		ConsentPolicy: "off", LongTaskThresholdSec: ai.DefaultLongTaskThresholdSec,
	}, env.s)
	env.s.copilot = cp2
	env.s.applyLongTaskExecutor(cp2)
	run2 := env.s.agentMgr.NewRun([]ai.Message{{Role: "user", Content: "下载文件"}}, 0)
	go env.s.runAgentAsync(context.Background(), run2)
	waitFor(t, 5*time.Second, "第二个 run 也能挂起", func() bool {
		st, _ := run2.WaitState()
		return st == ai.AgentWaitTask
	})
}

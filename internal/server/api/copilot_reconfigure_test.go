package api

import (
	"testing"

	"toshell/internal/server/config"
)

// TestReconfigureCopilotReinjectsLongTask 热更新重建 Copilot 时必须重新注入长任务通道。
//
// 这条路径容易被忽略：`s.copilot == nil`（= 启动时 AI 未启用，之后在设置页启用）会**新建**
// 一个 Copilot，而注入是构造后的显式动作。漏掉不会报任何错 —— 表现只是"分钟级工具又变成
// 同步等待、并发槽位被占满"，只有重启服务端才会恢复（结果外置存储此前踩过同一个坑，
// 所以两处注入现在都在同一分支里）。
func TestReconfigureCopilotReinjectsLongTask(t *testing.T) {
	cfg := &config.Config{}
	cfg.AI.LongTaskThresholdSec = config.DefaultLongTaskThresholdSec
	s := &Server{cfg: cfg}

	if s.copilot != nil {
		t.Fatal("前置条件不成立：这里要测的正是「从未构造过 Copilot」的重建分支")
	}
	s.ReconfigureCopilot(cfg.AI)

	if s.copilot == nil {
		t.Fatal("ReconfigureCopilot 应重建 Copilot")
	}
	if !s.copilot.LongTaskEnabled() {
		t.Fatal("重建后的 Copilot 没有长任务通道：长工具会静默退回同步等待（并发槽位被占满）")
	}
}

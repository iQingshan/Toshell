package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
	"toshell/internal/common/types"
)

type Database struct {
	db   *sql.DB
	lock sync.RWMutex
}

var db *Database

// New 初始化数据库连接。当前仅支持 SQLite：
// 此前 postgres 分支既未导入驱动、也未组装 DSN（Host/Port/Username/Password/SSLMode
// 从未被使用），属不可用分支，现统一为 SQLite-only，消除误导与隐性错误。
func New(dbType, connectionString string) (*Database, error) {
	if dbType != "" && dbType != "sqlite" {
		return nil, fmt.Errorf("unsupported database type: %q (only \"sqlite\" is supported)", dbType)
	}

	database := &Database{}
	var err error
	database.db, err = sql.Open("sqlite", connectionString)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for better concurrent performance
	database.db.Exec("PRAGMA journal_mode=WAL")
	database.db.Exec("PRAGMA synchronous=NORMAL")

	if err = database.initTables(); err != nil {
		return nil, err
	}

	db = database
	return database, nil
}

func Get() *Database {
	return db
}

// SQL 暴露底层连接，供**同一进程内的专用存储层**使用（当前是 internal/server/agentstore：
// Agent 的 run/step/tool_call/result 四张表 CRUD）。
//
// 约定：调用方**不得**关闭它，也不要在事务外做长耗时操作；连接池与生命周期由本包管理。
// 之所以不在本包直接写这些 CRUD：Agent 存储逻辑有自己的一套状态机语义与测试，
// 放在专用包里既能单独测（`go test ./internal/server/agentstore/`），也不会把本文件撑成几千行。
func (d *Database) SQL() *sql.DB {
	if d == nil {
		return nil
	}
	return d.db
}

func (d *Database) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			username TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			pid INTEGER,
			ip_addresses TEXT,
			mac_addresses TEXT,
			domain TEXT,
			process_name TEXT,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			status TEXT NOT NULL,
			listener TEXT,
		remote_addr TEXT,
		cpu_usage REAL,
		memory_used INTEGER,
		active_modules TEXT,
		comment TEXT
	)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			command TEXT NOT NULL,
			args TEXT,
			execute_type TEXT,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			sent_at INTEGER,
			completed_at INTEGER,
			output TEXT,
			error TEXT,
			exit_code INTEGER,
			timeout INTEGER,
			FOREIGN KEY (session_id) REFERENCES sessions(id)
		)`,
		`CREATE TABLE IF NOT EXISTS listeners (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			protocol TEXT NOT NULL,
			bind_addr TEXT NOT NULL,
			bind_port INTEGER NOT NULL,
			public_addr TEXT,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			connections INTEGER DEFAULT 0,
			options TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			level TEXT NOT NULL,
			component TEXT NOT NULL,
			message TEXT NOT NULL,
			session_id TEXT,
			task_id INTEGER,
			source_ip TEXT,
			user TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS custom_templates (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			category TEXT NOT NULL,
			tasks_json TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS implants (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			format TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			protocol TEXT NOT NULL,
			server_url TEXT,
			size INTEGER DEFAULT 0,
			sha256 TEXT,
			filename TEXT,
			created_at INTEGER NOT NULL,
			options_json TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_session_id ON tasks(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_implants_created ON implants(created_at)`,
	}

	// v1.4.0：Agent 长任务可靠性的四张表（DDL 见 agent_schema.go）。
	// 全部 CREATE ... IF NOT EXISTS，对既有库幂等，不做破坏性 DDL。
	queries = append(queries, AgentSchemaStatements...)

	// v1.4.1：隧道/代理持久化（DDL 见 tunnel_schema.go）。
	// 让 SOCKS5 代理在服务端重启后能按库自动恢复，而不是只剩内存态。
	queries = append(queries, TunnelSchemaStatements...)

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return err
		}
	}

	// Migrations for existing databases
	// sessions.comment was added later; add it if missing
	if err := d.migrateAddColumn("sessions", "comment", "TEXT"); err != nil {
		return err
	}
	// listeners.public_addr was added later; add it if missing
	if err := d.migrateAddColumn("listeners", "public_addr", "TEXT"); err != nil {
		return err
	}

	return nil
}

// migrateAddColumn adds a column to an existing table if it does not exist.
func (d *Database) migrateAddColumn(table, column, definition string) error {
	rows, err := d.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = d.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

func (d *Database) CreateSession(session *types.SessionInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	ipJSON, _ := json.Marshal(session.IPAddresses)
	macJSON, _ := json.Marshal(session.MACAddresses)
	modulesJSON, _ := json.Marshal(session.ActiveModules)

	_, err := d.db.Exec(`
		INSERT INTO sessions (id, hostname, username, os, arch, pid, ip_addresses, mac_addresses, domain, process_name, first_seen, last_seen, status, listener, remote_addr, cpu_usage, memory_used, active_modules, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, session.ID, session.Hostname, session.Username, session.OS, session.Arch, session.PID, string(ipJSON), string(macJSON), session.Domain, session.ProcessName, session.FirstSeen.Unix(), session.LastSeen.Unix(), session.Status, session.Listener, session.RemoteAddr, session.CPUUsage, session.MemoryUsed, string(modulesJSON), session.Comment)

	return err
}

func (d *Database) GetSession(id string) (*types.SessionInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	var session types.SessionInfo
	var ipJSON, macJSON, modulesJSON string
	var firstSeen, lastSeen int64

	err := d.db.QueryRow(`
		SELECT id, hostname, username, os, arch, pid, ip_addresses, mac_addresses, domain, process_name, first_seen, last_seen, status, listener, remote_addr, cpu_usage, memory_used, active_modules, comment
		FROM sessions WHERE id = ?
	`, id).Scan(&session.ID, &session.Hostname, &session.Username, &session.OS, &session.Arch, &session.PID, &ipJSON, &macJSON, &session.Domain, &session.ProcessName, &firstSeen, &lastSeen, &session.Status, &session.Listener, &session.RemoteAddr, &session.CPUUsage, &session.MemoryUsed, &modulesJSON, &session.Comment)

	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(ipJSON), &session.IPAddresses)
	json.Unmarshal([]byte(macJSON), &session.MACAddresses)
	json.Unmarshal([]byte(modulesJSON), &session.ActiveModules)
	session.FirstSeen = time.Unix(firstSeen, 0)
	session.LastSeen = time.Unix(lastSeen, 0)

	return &session, nil
}

func (d *Database) UpdateSession(session *types.SessionInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	ipJSON, _ := json.Marshal(session.IPAddresses)
	macJSON, _ := json.Marshal(session.MACAddresses)
	modulesJSON, _ := json.Marshal(session.ActiveModules)

	_, err := d.db.Exec(`
		UPDATE sessions SET hostname=?, username=?, os=?, arch=?, pid=?, ip_addresses=?, mac_addresses=?, domain=?, process_name=?, last_seen=?, status=?, listener=?, remote_addr=?, cpu_usage=?, memory_used=?, active_modules=?, comment=?
		WHERE id = ?
	`, session.Hostname, session.Username, session.OS, session.Arch, session.PID, string(ipJSON), string(macJSON), session.Domain, session.ProcessName, session.LastSeen.Unix(), session.Status, session.Listener, session.RemoteAddr, session.CPUUsage, session.MemoryUsed, string(modulesJSON), session.Comment, session.ID)

	return err
}

func (d *Database) ListSessions() ([]*types.SessionInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, arch, pid, ip_addresses, mac_addresses, domain, process_name, first_seen, last_seen, status, listener, remote_addr, cpu_usage, memory_used, active_modules, comment
		FROM sessions ORDER BY first_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*types.SessionInfo
	for rows.Next() {
		var session types.SessionInfo
		var ipJSON, macJSON, modulesJSON string
		var firstSeen, lastSeen int64

		err := rows.Scan(&session.ID, &session.Hostname, &session.Username, &session.OS, &session.Arch, &session.PID, &ipJSON, &macJSON, &session.Domain, &session.ProcessName, &firstSeen, &lastSeen, &session.Status, &session.Listener, &session.RemoteAddr, &session.CPUUsage, &session.MemoryUsed, &modulesJSON, &session.Comment)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(ipJSON), &session.IPAddresses)
		json.Unmarshal([]byte(macJSON), &session.MACAddresses)
		json.Unmarshal([]byte(modulesJSON), &session.ActiveModules)
		session.FirstSeen = time.Unix(firstSeen, 0)
		session.LastSeen = time.Unix(lastSeen, 0)

		sessions = append(sessions, &session)
	}

	return sessions, nil
}

func (d *Database) DeleteSession(id string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

// UpdateSessionComment updates only the comment of a session.
func (d *Database) UpdateSessionComment(id, comment string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("UPDATE sessions SET comment = ? WHERE id = ?", comment, id)
	return err
}

// ─── 任务输出落库上限（task.output_max_bytes）────────────────────────────
//
// 历史缺陷：这里曾把任务输出/错误**写死**截断到 500 字节。凭据分段结果
// （browser/wifi/rdp/lsa 的 JSON，正常几十 KB）入库后只剩开头几百字节，
// 重启/回读时界面看着"凭据根本没拿到"。现在上限由配置 task.output_max_bytes
// 决定（默认 256 KiB），并且截断点写一条**可解析**的显式标注（含原始字节数），
// 不再静默丢内容。

// DefaultTaskContentMaxBytes 任务输出/错误入库的默认上限（256 KiB）。
//
// 与 config.DefaultTaskOutputMaxBytes 同值：database 不能 import config
// （依赖方向是 config → logging → database），因此只能各写一份常量；
// 两边的注释互相指向，修改时请成对修改。
const DefaultTaskContentMaxBytes = 256 << 10

var (
	// taskContentMaxBytes 当前生效的入库上限（字节）。进程启动时由 api 层按
	// config.task.output_max_bytes 写入（见 api.applyTaskOutputLimit）。
	taskContentMaxBytes atomic.Int64
	// taskTruncatedRe 匹配本文件写入的截断标注，供 api/前端判定 truncated 与原始字节数。
	taskTruncatedRe = regexp.MustCompile(`\[输出已截断 truncated=true：原始 (\d+) 字节`)
)

func init() { taskContentMaxBytes.Store(DefaultTaskContentMaxBytes) }

// SetTaskContentMaxBytes 设置任务输出/错误入库上限（<=0 回落默认值，而不是"不限制"）。
func SetTaskContentMaxBytes(n int) {
	if n <= 0 {
		n = DefaultTaskContentMaxBytes
	}
	taskContentMaxBytes.Store(int64(n))
}

// TaskContentMaxBytes 返回当前生效的入库上限（字节）。
func TaskContentMaxBytes() int { return int(taskContentMaxBytes.Load()) }

// truncateTaskContent 将任务输出/错误截断到当前入库上限，避免大文本撑爆数据库。
//
// 截断必须**显式**：返回文本末尾带"原始 N 字节 / 入库上限 M 字节"的标注
// （TaskContentTruncated 可反解），绝不让调用方以为这就是完整结果。
func truncateTaskContent(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	// 从末尾逐字节回退，避免截断点落在多字节 UTF-8 字符中间产生乱码
	cut := s[:maxLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + fmt.Sprintf("\n...[输出已截断 truncated=true：原始 %d 字节，入库上限 %d 字节（task.output_max_bytes）；"+
		"完整结果请按结果外置句柄用 result_read 回读]", len(s), maxLen)
}

// TaskContentTruncated 判断一段入库文本是否被本包截断过，并返回原始字节数。
// 未被截断返回 (false, 0)；被截断但原始长度解析失败返回 (true, 0)。
func TaskContentTruncated(s string) (bool, int) {
	m := taskTruncatedRe.FindStringSubmatch(s)
	if m == nil {
		return false, 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 {
		return true, 0
	}
	return true, n
}

func (d *Database) CreateTask(task *types.TaskInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	argsJSON, _ := json.Marshal(task.Args)

	_, err := d.db.Exec(`
		INSERT INTO tasks (session_id, command, args, execute_type, status, created_at, sent_at, completed_at, output, error, exit_code, timeout)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, task.SessionID, task.Command, string(argsJSON), task.ExecuteType, task.Status, task.CreatedAt.Unix(), taskTimeUnix(task.SentAt), taskTimeUnix(task.CompletedAt), truncateTaskContent(task.Output, TaskContentMaxBytes()), truncateTaskContent(task.Error, TaskContentMaxBytes()), task.ExitCode, task.Timeout)

	return err
}

// taskTimeUnix 把可空时间写成 sqlite INTEGER（Unix 秒），nil 写 NULL。
//
// 为什么不能直接把 *time.Time 交给驱动（既有缺陷）：modernc 驱动会把 time.Time
// 编码成 TEXT，而读取侧一直按 int64 扫描 sent_at/completed_at —— 只要任务被
// UpdateTask 写过（sent/completed），重启后按 id 回读就会 "converting string to
// int64" 失败，任务被判成 not found，看着像"结果丢了"。
func taskTimeUnix(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.Unix()
}

// taskTimeUnixOf 把库里读到的 sent_at/completed_at 归一成 Unix 秒。
// 同时兼容历史上被写成 TEXT/RFC3339 的老行（不修老库，但也不让它读不出来）。
func taskTimeUnixOf(v interface{}) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int64:
		return x
	case float64:
		return int64(x)
	case []byte:
		return taskTimeUnixOf(string(x))
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Unix()
			}
		}
		return 0
	case time.Time:
		return x.Unix()
	}
	return 0
}

// scanTask 按固定列顺序读一行 tasks（Get/List 共用），时间列走兼容解析。
func scanTask(scan func(dest ...interface{}) error) (*types.TaskInfo, error) {
	var task types.TaskInfo
	var argsJSON string
	var createdAt int64
	var sentAtRaw, completedAtRaw interface{}

	if err := scan(&task.ID, &task.SessionID, &task.Command, &argsJSON, &task.ExecuteType, &task.Status,
		&createdAt, &sentAtRaw, &completedAtRaw, &task.Output, &task.Error, &task.ExitCode, &task.Timeout); err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(argsJSON), &task.Args)
	task.CreatedAt = time.Unix(createdAt, 0)
	if sentAt := taskTimeUnixOf(sentAtRaw); sentAt > 0 {
		task.SentAt = new(time.Time)
		*task.SentAt = time.Unix(sentAt, 0)
	}
	if completedAt := taskTimeUnixOf(completedAtRaw); completedAt > 0 {
		task.CompletedAt = new(time.Time)
		*task.CompletedAt = time.Unix(completedAt, 0)
	}
	return &task, nil
}

func (d *Database) GetTask(id uint64) (*types.TaskInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	return scanTask(d.db.QueryRow(`
		SELECT id, session_id, command, args, execute_type, status, created_at, sent_at, completed_at, output, error, exit_code, timeout
		FROM tasks WHERE id = ?
	`, id).Scan)
}

func (d *Database) UpdateTask(task *types.TaskInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		UPDATE tasks SET status=?, sent_at=?, completed_at=?, output=?, error=?, exit_code=?
		WHERE id=?
	`, task.Status, taskTimeUnix(task.SentAt), taskTimeUnix(task.CompletedAt), truncateTaskContent(task.Output, TaskContentMaxBytes()), truncateTaskContent(task.Error, TaskContentMaxBytes()), task.ExitCode, task.ID)

	return err
}

func (d *Database) ListTasks() ([]*types.TaskInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, session_id, command, args, execute_type, status, created_at, sent_at, completed_at, output, error, exit_code, timeout
		FROM tasks ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*types.TaskInfo
	for rows.Next() {
		task, err := scanTask(rows.Scan)
		if err != nil {
			continue
		}
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// CountTasks 从数据库聚合统计全量任务（跨重启真实数据）
func (d *Database) CountTasks() (*types.TaskStats, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	var stats types.TaskStats
	err := d.db.QueryRow(`
		SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) AS completed,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed,
			COALESCE(SUM(CASE WHEN status = 'timeout' THEN 1 ELSE 0 END), 0) AS timeout,
			COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) AS pending,
			COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) AS running
		FROM tasks
	`).Scan(&stats.Total, &stats.Completed, &stats.Failed, &stats.Timeout, &stats.Pending, &stats.Running)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

func (d *Database) ListTasksBySession(sessionID string) ([]*types.TaskInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, session_id, command, args, execute_type, status, created_at, sent_at, completed_at, output, error, exit_code, timeout
		FROM tasks WHERE session_id = ? ORDER BY created_at DESC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*types.TaskInfo
	for rows.Next() {
		task, err := scanTask(rows.Scan)
		if err != nil {
			continue
		}
		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (d *Database) CreateListener(listener *types.ListenerInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	optionsJSON, _ := json.Marshal(listener.Options)

	_, err := d.db.Exec(`
		INSERT INTO listeners (id, name, type, protocol, bind_addr, bind_port, public_addr, status, created_at, connections, options)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, listener.ID, listener.Name, listener.Type, listener.Protocol, listener.BindAddr, listener.BindPort, listener.PublicAddr, listener.Status, listener.CreatedAt.Unix(), listener.Connections, string(optionsJSON))

	return err
}

func (d *Database) ListListeners() ([]*types.ListenerInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, type, protocol, bind_addr, bind_port, public_addr, status, created_at, connections, options
		FROM listeners ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var listeners []*types.ListenerInfo
	for rows.Next() {
		var listener types.ListenerInfo
		var optionsJSON, publicAddr sql.NullString
		var createdAt int64

		err := rows.Scan(&listener.ID, &listener.Name, &listener.Type, &listener.Protocol, &listener.BindAddr, &listener.BindPort, &publicAddr, &listener.Status, &createdAt, &listener.Connections, &optionsJSON)
		if err != nil {
			continue
		}

		listener.PublicAddr = publicAddr.String
		if optionsJSON.Valid {
			json.Unmarshal([]byte(optionsJSON.String), &listener.Options)
		}
		listener.CreatedAt = time.Unix(createdAt, 0)

		listeners = append(listeners, &listener)
	}

	return listeners, nil
}

func (d *Database) UpdateListener(listener *types.ListenerInfo) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	optionsJSON, _ := json.Marshal(listener.Options)

	_, err := d.db.Exec(`
		UPDATE listeners SET name = ?, type = ?, protocol = ?, bind_addr = ?, bind_port = ?, public_addr = ?, options = ?
		WHERE id = ?
	`, listener.Name, listener.Type, listener.Protocol, listener.BindAddr, listener.BindPort, listener.PublicAddr, string(optionsJSON), listener.ID)

	return err
}

func (d *Database) UpdateListenerStatus(id, status string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("UPDATE listeners SET status = ? WHERE id = ?", status, id)
	return err
}

func (d *Database) DeleteListener(id string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("DELETE FROM listeners WHERE id = ?", id)
	return err
}

func (d *Database) CreateLog(entry *types.LogEntry) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO logs (timestamp, level, component, message, session_id, task_id, source_ip, user)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.Timestamp.Unix(), entry.Level, entry.Component, entry.Message, entry.SessionID, entry.TaskID, entry.SourceIP, entry.User)

	return err
}

func (d *Database) QueryLogs(filter string, limit int) ([]*types.LogEntry, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	query := "SELECT timestamp, level, component, message, session_id, task_id, source_ip, user FROM logs"
	args := []interface{}{}

	if filter != "" {
		query += " WHERE " + filter
	}

	query += " ORDER BY timestamp DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*types.LogEntry
	for rows.Next() {
		var entry types.LogEntry
		var timestamp int64

		err := rows.Scan(&timestamp, &entry.Level, &entry.Component, &entry.Message, &entry.SessionID, &entry.TaskID, &entry.SourceIP, &entry.User)
		if err != nil {
			continue
		}

		entry.Timestamp = time.Unix(timestamp, 0)
		logs = append(logs, &entry)
	}

	return logs, nil
}

// ─── Custom Templates ──────────────────────────────────────────────────────

type CustomTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	TasksJSON   string `json:"tasks_json"`
	CreatedAt   int64  `json:"created_at"`
}

func (d *Database) CreateCustomTemplate(tmpl *CustomTemplate) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO custom_templates (id, name, description, category, tasks_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, tmpl.ID, tmpl.Name, tmpl.Description, tmpl.Category, tmpl.TasksJSON, tmpl.CreatedAt)
	return err
}

func (d *Database) ListCustomTemplates() ([]*CustomTemplate, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`SELECT id, name, description, category, tasks_json, created_at FROM custom_templates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*CustomTemplate
	for rows.Next() {
		var t CustomTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Category, &t.TasksJSON, &t.CreatedAt); err != nil {
			continue
		}
		templates = append(templates, &t)
	}
	return templates, nil
}

func (d *Database) UpdateCustomTemplate(id, name, description, category, tasksJSON string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		UPDATE custom_templates SET name = ?, description = ?, category = ?, tasks_json = ? WHERE id = ?
	`, name, description, category, tasksJSON, id)
	return err
}

func (d *Database) DeleteCustomTemplate(id string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("DELETE FROM custom_templates WHERE id = ?", id)
	return err
}

// ─── Implants ──────────────────────────────────────────────────────────────

type StoredImplant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Format      string `json:"format"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Protocol    string `json:"protocol"`
	ServerURL   string `json:"server_url"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Filename    string `json:"filename"`
	CreatedAt   int64  `json:"created_at"`
	OptionsJSON string `json:"options_json,omitempty"`
}

func (d *Database) CreateImplant(imp *StoredImplant) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO implants (id, name, format, os, arch, protocol, server_url, size, sha256, filename, created_at, options_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, imp.ID, imp.Name, imp.Format, imp.OS, imp.Arch, imp.Protocol, imp.ServerURL, imp.Size, imp.SHA256, imp.Filename, imp.CreatedAt, imp.OptionsJSON)
	return err
}

func (d *Database) ListImplants() ([]*StoredImplant, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`SELECT id, name, format, os, arch, protocol, server_url, size, sha256, filename, created_at FROM implants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var implants []*StoredImplant
	for rows.Next() {
		var imp StoredImplant
		if err := rows.Scan(&imp.ID, &imp.Name, &imp.Format, &imp.OS, &imp.Arch, &imp.Protocol, &imp.ServerURL, &imp.Size, &imp.SHA256, &imp.Filename, &imp.CreatedAt); err != nil {
			continue
		}
		implants = append(implants, &imp)
	}
	return implants, nil
}

func (d *Database) GetImplant(id string) (*StoredImplant, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	var imp StoredImplant
	err := d.db.QueryRow(`SELECT id, name, format, os, arch, protocol, server_url, size, sha256, filename, created_at FROM implants WHERE id = ?`, id).
		Scan(&imp.ID, &imp.Name, &imp.Format, &imp.OS, &imp.Arch, &imp.Protocol, &imp.ServerURL, &imp.Size, &imp.SHA256, &imp.Filename, &imp.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &imp, nil
}

func (d *Database) DeleteImplant(id string) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec("DELETE FROM implants WHERE id = ?", id)
	return err
}

func (d *Database) Close() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.db.Close()
}

func (d *Database) SearchSessions(query string) ([]*types.SessionInfo, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	searchTerm := "%" + strings.ToLower(query) + "%"
	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, arch, pid, ip_addresses, mac_addresses, domain, process_name, first_seen, last_seen, status, listener, remote_addr, cpu_usage, memory_used, active_modules
		FROM sessions 
		WHERE LOWER(hostname) LIKE ? OR LOWER(username) LIKE ? OR LOWER(os) LIKE ? OR LOWER(id) LIKE ?
		ORDER BY first_seen DESC
	`, searchTerm, searchTerm, searchTerm, searchTerm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*types.SessionInfo
	for rows.Next() {
		var session types.SessionInfo
		var ipJSON, macJSON, modulesJSON string
		var firstSeen, lastSeen int64

		err := rows.Scan(&session.ID, &session.Hostname, &session.Username, &session.OS, &session.Arch, &session.PID, &ipJSON, &macJSON, &session.Domain, &session.ProcessName, &firstSeen, &lastSeen, &session.Status, &session.Listener, &session.RemoteAddr, &session.CPUUsage, &session.MemoryUsed, &modulesJSON)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(ipJSON), &session.IPAddresses)
		json.Unmarshal([]byte(macJSON), &session.MACAddresses)
		json.Unmarshal([]byte(modulesJSON), &session.ActiveModules)
		session.FirstSeen = time.Unix(firstSeen, 0)
		session.LastSeen = time.Unix(lastSeen, 0)

		sessions = append(sessions, &session)
	}

	return sessions, nil
}

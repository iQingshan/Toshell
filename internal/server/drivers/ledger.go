// 驱动加载台账：记录"服务端下发过哪些 byovd_load"，并在服务端进程重启后给出**可执行的清场指引**
// （v1.4.0 S6 P0-1 的"进程重启后残留驱动服务清场"）。
//
// ── 先搞清楚"残留"到底可能出现在哪一侧（读代码后的结论）─────────────────────────
//
//	服务端进程重启：内存里的 sessionDrivers（handlers_edr.go）与任务表一起消失，
//	  但**目标机上已加载的内核驱动不会因此卸载**。症状：服务端重启后再想 byovd_kill，
//	  发现"没有可用驱动档案"（登记没了，只能回落到目录 manifest）；也没有任何地方记得
//	  "我在哪些机器上加载过哪些服务"。→ 本台账要解决的就是这一侧。
//	目标机重启：用 handleDrvLoad 创建的是 SERVICE_DEMAND_START（按需启动）的内核服务，
//	  重启不会自动加载它，但**服务注册项与 %SystemRoot%\System32\drivers\<svc>.sys 都还在**
//	  （drv_windows.go 里只有 drv_unload 或下一次同服务的 drv_load 才会删文件）。
//	  → 属于"残留但未运行"，清场仍需按服务名下 byovd_unload。
//	植入端重连：同一个植入端进程的网络闪断重连 → session id 不变，台账条目仍对应在线会话；
//	  植入端进程重启（含目标机重启后重新上线）→ generateSessionID() 按进程启动时间重新生成，
//	  **session id 会变**（implant/main.go），旧条目对应的会话必然不在线。
//	  → 清场只能按 service_name 下发到"该主机当前在线的会话"，不能依赖旧 session id。
//
// ── 为什么选"服务端记账 + 可执行清理指引"，而不是"重启时自动下发清理任务"────────
//
//  1. 服务端**无法枚举目标机服务**（没有这个原语；植入端的 drv_unload 只能按服务名操作），
//     所以"扫一遍目标机把所有可疑驱动服务删掉"这件事在当前架构下做不到 —— 不做假承诺；
//  2. 自动下发是**破坏性动作**：本项目对 L1+ 的既有口径是"不参与任何自动重投递"，
//     服务端重启时静默停止/删除内核服务既无法确认目标机身份（session id 每次都变），
//     又可能在操作员不知情时打断正在进行的工作；
//  3. 因此这里做的是"**有据可依**"的那一半：记账（我下发过什么，落盘、跨重启保留）+
//     把每一条变成可以直接照抄的清理请求（走既有 byovd_unload，不新造任务类型）+ 明确的
//     人工确认口径。判定的纯逻辑（哪些条目算残留、在线与否、指引怎么写）都能单测。
//
// ⚠️ 如实标注：台账记录的是"**服务端创建过相应的加载/卸载任务**"（含推送失败、仍留在队列里的），
// 不是"目标机执行成功了"。执行结果只有目标机知道（服务端不持有该原语），所以每条都带
// LoadTaskID 供核对，且文案里明确写出这一边界。
package drivers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultLedgerPath 台账默认落盘位置。
//
// 放在 data/drivers/ 下的理由：与驱动目录同源（运维只需要看一个地方），
// 且 data/ 已是运行时数据目录（.gitignore 里 data/* 不入库，运行时产物不会被提交）。
// 文件名刻意不叫 manifest.json（那是驱动目录的清单），避免与操作员放的文件混淆。
const DefaultLedgerPath = "data/drivers/loaded.json"

// ledgerNote 写进落盘文件的语义说明（谁打开这个文件都该知道它记的是什么）。
const ledgerNote = "本文件是服务端创建过的 byovd_load / byovd_unload 任务台账（跨重启保留）：" +
	"条目=『服务端创建过相应任务』，不代表目标机执行成功（服务端无法枚举目标机服务，执行结果只有任务结果能回答）；" +
	"清场请用 byovd_unload 按 service_name 下发"

// LedgerEntry 一次驱动加载的下发记录。
type LedgerEntry struct {
	SessionID string `json:"session_id"`
	// ServiceName SCM 服务名（= 落盘文件名 %SystemRoot%\System32\drivers\<svc>.sys）—— 清场的键。
	ServiceName string `json:"service_name"`
	DriverName  string `json:"driver_name,omitempty"`
	Device      string `json:"device,omitempty"`
	IOCTL       uint32 `json:"ioctl,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
	// SHA256 / Size 下发时那份驱动字节的实测哈希与大小（便于事后核对目标机上是哪一份）。
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Source 哪条路径下发的：avops（分级入口）/ legacy（既有 /edr/byovd-load）。
	Source string `json:"source,omitempty"`
	// LoadTaskID 加载任务 id（供核对加载结果；服务端重启后任务表不保留，这里等于最后线索）。
	LoadTaskID uint64    `json:"load_task_id,omitempty"`
	LoadedAt   time.Time `json:"loaded_at"`
	// UnloadTaskID / UnloadedAt 非零表示服务端已下发过卸载（**不代表目标机卸载成功**）。
	UnloadTaskID uint64    `json:"unload_task_id,omitempty"`
	UnloadedAt   time.Time `json:"unloaded_at,omitempty"`
}

// Pending 该条目是否"可能仍残留在目标机上"（服务端还没创建过卸载任务）。
func (e LedgerEntry) Pending() bool { return e.UnloadedAt.IsZero() }

// Key 条目标识：同一会话的同一服务名是一次加载（重复加载会覆盖为最新一次）。
func (e LedgerEntry) Key() string {
	return strings.ToLower(strings.TrimSpace(e.SessionID)) + "|" + strings.ToLower(strings.TrimSpace(e.ServiceName))
}

// ledgerFile 落盘结构。
type ledgerFile struct {
	Note    string        `json:"note"`
	SavedAt time.Time     `json:"saved_at"`
	Entries []LedgerEntry `json:"entries"`
}

// Ledger 驱动加载台账（内存 + JSON 落盘，跨服务端重启保留）。
//
// 为什么不用 sqlite：这里只有几十条记录、只在"下发加载/卸载"时写一次，
// 引入一张表与迁移成本不划算；一个 JSON 文件加原子替换就够，且运维能直接打开看。
type Ledger struct {
	path string

	mu      sync.Mutex
	entries map[string]LedgerEntry
	loadErr error
}

// NewLedger 创建台账并立即尝试读盘（path 为空用 DefaultLedgerPath）。
//
// 读盘失败**不算致命**：台账缺失只影响"清场指引的完整性"，不该让服务端起不来。
// 失败原因通过 LoadError 暴露给接口（与 modules.Store 同一口径）。
func NewLedger(path string) *Ledger {
	if strings.TrimSpace(path) == "" {
		path = DefaultLedgerPath
	}
	l := &Ledger{path: path, entries: map[string]LedgerEntry{}}
	l.load()
	return l
}

// Path 台账文件路径（接口回显，便于操作员直接去看）。
func (l *Ledger) Path() string { return l.path }

// LoadError 最近一次读盘错误（nil = 正常或文件还不存在）。
func (l *Ledger) LoadError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadErr
}

// load 读台账文件。文件不存在是正常情况（从未加载过驱动），不算错误。
func (l *Ledger) load() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadErr = nil
	raw, err := os.ReadFile(l.path)
	if err != nil {
		if !os.IsNotExist(err) {
			l.loadErr = err
		}
		return
	}
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		l.loadErr = fmt.Errorf("驱动台账 %s 不是合法 JSON：%w", l.path, err)
		return
	}
	for _, e := range f.Entries {
		if strings.TrimSpace(e.ServiceName) == "" {
			continue // 脏数据（缺服务名 = 无法清场）直接跳过，不让它污染判定
		}
		l.entries[e.Key()] = e
	}
}

// RecordLoad 记录一次加载下发（同会话同服务名覆盖为最新一次，并清掉旧的卸载标记）。
func (l *Ledger) RecordLoad(e LedgerEntry) error {
	if strings.TrimSpace(e.SessionID) == "" || strings.TrimSpace(e.ServiceName) == "" {
		return fmt.Errorf("驱动台账拒绝记录缺 session_id/service_name 的条目（缺失就无法清场）")
	}
	if e.LoadedAt.IsZero() {
		e.LoadedAt = time.Now()
	}
	e.UnloadTaskID = 0
	e.UnloadedAt = time.Time{}
	l.mu.Lock()
	l.entries[e.Key()] = e
	l.mu.Unlock()
	return l.save()
}

// RecordUnload 记录一次卸载下发：把该会话该服务名的条目标记为"已下发卸载"。
// 找不到对应条目时也会**新建**一条（例如服务端重启前加载、重启后才卸载），
// 这样"我最后对它做了什么"仍有记录，而不会静默丢失。
func (l *Ledger) RecordUnload(sessionID, serviceName string, taskID uint64) error {
	svc := strings.TrimSpace(serviceName)
	if svc == "" {
		return fmt.Errorf("驱动台账拒绝记录缺 service_name 的卸载（服务名是清场的键）")
	}
	key := LedgerEntry{SessionID: sessionID, ServiceName: svc}.Key()
	l.mu.Lock()
	e, ok := l.entries[key]
	if !ok {
		// 没有对应的加载记录（例如加载发生在台账文件被删之前）：仍然记一条，
		// 让"我最后对这个服务做过什么"可查；LoadedAt 留零值，避免伪造一个加载时间。
		e = LedgerEntry{SessionID: sessionID, ServiceName: svc, Source: "unload_without_record"}
	}
	e.UnloadTaskID = taskID
	e.UnloadedAt = time.Now()
	l.entries[key] = e
	l.mu.Unlock()
	return l.save()
}

// All 全部条目（排序：加载时间倒序 → 会话 → 服务名；确定性输出便于断言与展示）。
func (l *Ledger) All() []LedgerEntry {
	l.mu.Lock()
	out := make([]LedgerEntry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e)
	}
	l.mu.Unlock()
	sortEntries(out)
	return out
}

// Pending 可能仍残留在目标机上的条目（服务端尚未下发卸载）。
func (l *Ledger) Pending() []LedgerEntry {
	out := make([]LedgerEntry, 0)
	for _, e := range l.All() {
		if e.Pending() {
			out = append(out, e)
		}
	}
	return out
}

// PendingForSession 某会话的残留条目（按加载时间倒序，最可能仍生效的排在最前）。
func (l *Ledger) PendingForSession(sessionID string) []LedgerEntry {
	out := make([]LedgerEntry, 0)
	for _, e := range l.Pending() {
		if strings.EqualFold(strings.TrimSpace(e.SessionID), strings.TrimSpace(sessionID)) {
			out = append(out, e)
		}
	}
	return out
}

// PendingServicesForSession 某会话残留条目的服务名列表（时间倒序，供 byovd_unload 兜底选路）。
func (l *Ledger) PendingServicesForSession(sessionID string) []string {
	out := make([]string, 0)
	for _, e := range l.PendingForSession(sessionID) {
		out = append(out, e.ServiceName)
	}
	return out
}

// ProfileFor 取某会话最近一次"可能仍加载着"的驱动档案（服务端进程重启后的会话档案恢复）。
//
// 为什么需要它：sessionDrivers 在内存里，服务端一重启就没了；而目标机上的驱动还在。
// 恢复这份档案让重启后的 byovd_kill 仍能按档位选到"上次加载的那个驱动"，
// 否则操作员会遇到"什么都没变，却突然说没有可用驱动档案"。
// 调用方必须知道这是**未经目标机确认**的档案（台账记录的是下发，不是加载成功）。
func (l *Ledger) ProfileFor(sessionID string) (Driver, bool) {
	list := l.PendingForSession(sessionID)
	if len(list) == 0 {
		return Driver{}, false
	}
	e := list[0]
	return Driver{
		Name:    firstNonEmpty(strings.TrimSpace(e.DriverName), strings.TrimSpace(e.ServiceName)),
		Service: e.ServiceName,
		Device:  e.Device,
		IOCTL:   e.IOCTL,
		Purpose: e.Purpose,
		SHA256:  e.SHA256,
		Size:    e.Size,
	}, true
}

// save 原子落盘（临时文件 + rename）：避免服务端在写一半时被杀死，留下半个 JSON
// 让下次启动读到"台账损坏"。
func (l *Ledger) save() error {
	l.mu.Lock()
	f := ledgerFile{Note: ledgerNote, SavedAt: time.Now()}
	for _, e := range l.entries {
		f.Entries = append(f.Entries, e)
	}
	path := l.path
	sortEntries(f.Entries)
	l.mu.Unlock()

	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建驱动台账目录 %s 失败：%w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("写驱动台账 %s 失败：%w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// Windows 上 rename 覆盖已存在文件通常没问题；失败时清掉临时文件避免堆积。
		_ = os.Remove(tmp)
		return fmt.Errorf("替换驱动台账 %s 失败：%w", path, err)
	}
	return nil
}

// sortEntries 台账条目的确定性排序：加载时间倒序 → 会话 → 服务名。
// 时间倒序是为了"最近加载的最可能还在"，让清场指引的第一条最有意义。
func sortEntries(list []LedgerEntry) {
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].LoadedAt.Equal(list[j].LoadedAt) {
			return list[i].LoadedAt.After(list[j].LoadedAt)
		}
		if !strings.EqualFold(list[i].SessionID, list[j].SessionID) {
			return strings.ToLower(list[i].SessionID) < strings.ToLower(list[j].SessionID)
		}
		return strings.ToLower(list[i].ServiceName) < strings.ToLower(list[j].ServiceName)
	})
}

// ─── 清场指引（纯逻辑，可单测）───────────────────────────────────────────────

// CleanupStep 一条**可执行**的清场指引。
//
// 刻意复用既有 byovd_unload 动作（不新造任务类型/路由）：清场走的就是卸载那条已验证的链路，
// 新造入口等于多一条需要单独验证、且不需要存在的路径。
type CleanupStep struct {
	SessionID   string `json:"session_id"`
	ServiceName string `json:"service_name"`
	DriverName  string `json:"driver_name,omitempty"`
	LoadedAt    string `json:"loaded_at"`
	LoadTaskID  uint64 `json:"load_task_id,omitempty"`
	// TargetSessionID 建议把清理请求下发到哪个会话（条目所在会话在线时就是它自己）。
	TargetSessionID string `json:"target_session_id"`
	// SessionAlive 台账里的会话当前是否在线。
	SessionAlive bool `json:"session_alive"`
	// Blocked 现在能否直接下发（会话不在线时为 true —— 指引仍然给出，只是需要先等重连）。
	Blocked bool `json:"blocked"`
	// How 可直接照抄的请求（分级入口的 L3 byovd_unload）。
	How string `json:"how"`
	// Reason 为什么要清场 / 当前这条的前置条件。
	Reason string `json:"reason"`
}

// BuildCleanupPlan 纯逻辑：把台账条目变成清场指引。
//
// aliveSessions 由调用方按**当前会话表**构造：键是会话 id（大小写不敏感，本函数两种写法都查），
// 值为该会话是否在线；nil 表示"一个都不在线"。本函数不读会话表、不看当前时间，
// 输入输出都是纯数据，因此可以完整单测。
func BuildCleanupPlan(entries []LedgerEntry, aliveSessions map[string]bool) []CleanupStep {
	steps := make([]CleanupStep, 0, len(entries))
	for _, e := range entries {
		sid := strings.TrimSpace(e.SessionID)
		alive := aliveSessions[sid] || aliveSessions[strings.ToLower(sid)]
		target := e.SessionID
		step := CleanupStep{
			SessionID:       e.SessionID,
			ServiceName:     e.ServiceName,
			DriverName:      e.DriverName,
			LoadTaskID:      e.LoadTaskID,
			TargetSessionID: target,
			SessionAlive:    alive,
			Blocked:         !alive,
			How: fmt.Sprintf(`POST /api/v1/sessions/%s/av-ops `+
				`{"action":"byovd_unload","tier":"L3","confirm":true,"params":{"service_name":"%s"}}`,
				target, e.ServiceName),
		}
		if !e.LoadedAt.IsZero() {
			step.LoadedAt = e.LoadedAt.Format(time.RFC3339)
		}
		base := fmt.Sprintf("服务端在 %s 为该会话创建过 byovd_load 任务（service=%s，task=%d）："+
			"目标机上可能仍注册/运行着该内核服务。台账只记录『服务端创建过加载任务』，"+
			"不代表加载一定成功、也不代表加载没成功（推送失败的任务仍在队列里、心跳取走后照样会执行；以任务结果为准）",
			step.LoadedAt, e.ServiceName, e.LoadTaskID)
		if alive {
			step.Reason = base + "。该会话在线：可直接按 how 下发 byovd_unload（L3 破坏性动作，需 confirm=true），" +
				"它会停止并删除内核服务与 %SystemRoot%\\System32\\drivers\\" + e.ServiceName + ".sys（文件不可恢复）"
		} else {
			step.Reason = base + "。该会话当前**不在线**（植入端进程重启会生成新的 session_id；" +
				"目标机重启后需等植入端重新上线），因此不能直接下发：" +
				"请在该主机当前在线的会话上按同一个 service_name 下发 byovd_unload，" +
				"或等它重连后再按 how 下发。注意目标机重启**不会**清除已注册的内核服务与驱动文件" +
				"（服务是按需启动，不会自启，但注册项与 .sys 仍在），所以这条残留需要显式清场"
		}
		steps = append(steps, step)
	}
	return steps
}

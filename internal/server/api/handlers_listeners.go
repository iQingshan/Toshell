package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/listener"
	"toshell/internal/server/logging"
	"toshell/internal/server/webhook"
)

type CreateListenerRequest struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Protocol   string                 `json:"protocol"`
	BindAddr   string                 `json:"bind_addr"`
	BindPort   int                    `json:"bind_port"`
	PublicAddr string                 `json:"public_addr"`
	Options    map[string]interface{} `json:"options"`
}

type ListenerInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Protocol    string `json:"protocol"`
	BindAddr    string `json:"bind_addr"`
	BindPort    int    `json:"bind_port"`
	PublicAddr  string `json:"public_addr"`
	Status      string `json:"status"`
	Connections int    `json:"connections"`
	CreatedAt   int64  `json:"created_at"`
	Options     string `json:"options,omitempty"`
}

func listToResponse(l *types.ListenerInfo) ListenerInfo {
	opts := ""
	if l.Options.DomainFronting != "" || l.Options.CertFile != "" || l.Options.KeyFile != "" {
		optsBytes, _ := json.Marshal(l.Options)
		opts = string(optsBytes)
	}
	return ListenerInfo{
		ID:          l.ID,
		Name:        l.Name,
		Type:        l.Type,
		Protocol:    l.Protocol,
		BindAddr:    l.BindAddr,
		BindPort:    int(l.BindPort),
		PublicAddr:  l.PublicAddr,
		Status:      l.Status,
		Connections: l.Connections,
		CreatedAt:   l.CreatedAt.Unix(),
		Options:     opts,
	}
}

func (s *Server) listListenersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	listeners, err := db.ListListeners()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 连接数 = 该监听器下当前在线会话数（实时统计，而非 DB 里存的静态值）。
	// 用 ListenerID（= /sessions 的 listener_id）作 key，与监听器记录 ID 对齐。
	sessions := s.sessionMgr.List()
	connByListener := map[string]int{}
	for _, sess := range sessions {
		if sess == nil || sess.Info == nil || sess.Info.ListenerID == "" {
			continue
		}
		connByListener[sess.Info.ListenerID]++
	}

	result := make([]ListenerInfo, 0, len(listeners))
	for _, l := range listeners {
		ri := listToResponse(l)
		if n, ok := connByListener[l.ID]; ok {
			ri.Connections = n
		}
		result = append(result, ri)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"listeners": result,
		"count":     len(result),
	})
}

func (s *Server) createListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CreateListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error":"Name is required"}`, http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		req.Type = "tcp"
	}
	// 类型即通道：tcp → 二进制帧协议；http → HTTP 轮询（可配 TLS 变 HTTPS）；
	// websocket → WebSocket 帧协议；mqtt → MQTT pub/sub（连接内嵌/外部 broker）。
	if req.Type != "tcp" && req.Type != "http" && req.Type != "websocket" && req.Type != "mqtt" {
		http.Error(w, `{"error":"type 仅支持 tcp / http / websocket / mqtt"}`, http.StatusBadRequest)
		return
	}
	if req.Protocol == "" || req.Protocol == "websocket" {
		req.Protocol = "tcp"
	}
	if req.Type == "http" {
		req.Protocol = "http"
	}
	if req.Type == "websocket" {
		req.Protocol = "websocket"
	}
	if req.Type == "mqtt" {
		req.Protocol = "mqtt"
	}

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	// 监听器 options（MQTT broker 地址/主题前缀等）序列化入库
	var optsBytes []byte
	if len(req.Options) > 0 {
		optsBytes, _ = json.Marshal(req.Options)
	}

	listener := &types.ListenerInfo{
		ID:         uuid.New().String(),
		Name:       req.Name,
		Type:       req.Type,
		Protocol:   req.Protocol,
		PublicAddr: req.PublicAddr,
		BindAddr:   req.BindAddr,
		BindPort:   uint16(req.BindPort),
		Status:     "stopped",
		CreatedAt:  time.Now(),
	}
	if len(optsBytes) > 0 {
		if err := json.Unmarshal(optsBytes, &listener.Options); err != nil {
			http.Error(w, `{"error":"invalid options"}`, http.StatusBadRequest)
			return
		}
	}
	// MQTT 默认内嵌 broker：未指定外部 broker 时，用本机内嵌 broker（bind_port 即 broker 端口）
	if req.Type == "mqtt" && !listener.Options.MQTTEmbeddedBroker && listener.Options.MQTTBrokerURL == "" {
		listener.Options.MQTTEmbeddedBroker = true
	}

	if err := db.CreateListener(listener); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Listener created: %s (%s/%s) on %s:%d", listener.ID, listener.Type, listener.Protocol, listener.BindAddr, listener.BindPort)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(listToResponse(listener))
}

// findListener 在数据库中按 ID 查找监听器。
func (s *Server) findListener(id string) (*types.ListenerInfo, error) {
	db := database.Get()
	if db == nil {
		return nil, fmt.Errorf("Database not available")
	}
	listeners, err := db.ListListeners()
	if err != nil {
		return nil, err
	}
	for _, l := range listeners {
		if l.ID == id {
			return l, nil
		}
	}
	return nil, fmt.Errorf("Listener not found")
}

func (s *Server) getListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	listener, err := s.findListener(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(listToResponse(listener))
}

// updateListenerHandler 更新监听器配置。
// 对于默认监听器（ID 以 "default-" 开头），更新会同步写回配置文件，
// 以保证服务重启后配置不丢失。
func (s *Server) updateListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req CreateListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	existing, err := s.findListener(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	if req.Name == "" {
		req.Name = existing.Name
	}
	if req.Type == "" {
		req.Type = existing.Type
	}
	if req.Protocol == "" {
		req.Protocol = existing.Protocol
	}
	if req.BindAddr == "" {
		req.BindAddr = existing.BindAddr
	}
	if req.BindPort <= 0 || req.BindPort > 65535 {
		req.BindPort = int(existing.BindPort)
	}
	if req.PublicAddr == "" {
		req.PublicAddr = existing.PublicAddr
	}

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	updated := &types.ListenerInfo{
		ID:          existing.ID,
		Name:        req.Name,
		Type:        req.Type,
		Protocol:    req.Protocol,
		BindAddr:    req.BindAddr,
		BindPort:    uint16(req.BindPort),
		PublicAddr:  req.PublicAddr,
		Status:      existing.Status,
		Connections: existing.Connections,
		CreatedAt:   existing.CreatedAt,
		Options:     existing.Options,
	}

	if err := db.UpdateListener(updated); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 默认监听器（配置驱动）编辑后同步写回配置文件，避免重启后被重置。
	if strings.HasPrefix(id, "default-") {
		if err := s.syncDefaultListenerConfig(updated); err != nil {
			logging.Warn("api", "Listener %s updated but config sync failed: %v", id, err)
		}
	}

	logging.Info("api", "Listener %s updated: %s (%s/%s) on %s:%d", id, updated.Name, updated.Type, updated.Protocol, updated.BindAddr, updated.BindPort)

	json.NewEncoder(w).Encode(listToResponse(updated))
}

// syncDefaultListenerConfig 将默认监听器的关键参数写回 configs/server.yaml。
func (s *Server) syncDefaultListenerConfig(l *types.ListenerInfo) error {
	if s.cfg == nil {
		return fmt.Errorf("server config unavailable")
	}

	lc := s.cfg.Listener
	lc.Host = l.BindAddr
	lc.Port = l.BindPort
	lc.PublicHost = l.PublicAddr
	lc.Protocol = l.Protocol

	return config.UpdateListenerConfig(s.cfg, lc)
}

func (s *Server) startListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.startListenerByID(id); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Listener %s started", id)
	json.NewEncoder(w).Encode(map[string]string{
		"id":      id,
		"status":  "running",
		"message": "Listener started",
	})
}

// startListenerByID 按 DB 记录真正启动一个监听器（创建 socket 并注册到路由）。
// 幂等：已在运行时则直接返回。供 HTTP handler 与服务重启自动恢复共用。
func (s *Server) startListenerByID(id string) error {
	db := database.Get()
	if db == nil {
		return fmt.Errorf("Database not available")
	}

	rec, err := s.findListener(id)
	if err != nil {
		return err
	}

	router, ok := s.listener.(*listenerRouter)
	if !ok || router == nil {
		return fmt.Errorf("Listener router unavailable")
	}

	// 幂等：已在运行则直接返回成功
	if router.isRunning(id) {
		return nil
	}

	// 构造监听器配置：绑定地址/端口来自 DB 记录；加密密钥/拟态等继承全局配置，
	// 保证与构建载荷时使用的密钥一致（否则植入端无法解密注册帧）。
	// 优先取 config.Get() 热更新后的最新值，回退到启动快照。
	live := s.cfg
	if g := config.Get(); g != nil && g.Listener.EncryptionKey != "" {
		live = g
	}
	lc := &config.ListenerConfig{
		ID:               id,
		Host:             rec.BindAddr,
		Port:             rec.BindPort,
		PublicHost:       rec.PublicAddr,
		Protocol:         rec.Protocol,
		EncryptionKey:    live.Listener.EncryptionKey,
		HeartbeatTimeout: live.Listener.HeartbeatTimeout,
		WriteQueueSize:   live.Listener.WriteQueueSize,
		MimicryProfile:   live.Listener.MimicryProfile,
		FrontDomain:      live.Listener.FrontDomain,
		MimicrySite:      live.Listener.MimicrySite,
		TLSEnabled:       rec.Options.TLSEnabled,
		CertFile:         rec.Options.CertFile,
		KeyFile:          rec.Options.KeyFile,
	}

	// 装配与 main.go 一致的组件回调
	taskResultCB := func(eventType string, taskID uint64, sessionID string, taskType string, exitCode int32, output string, errorMsg string) {
		outputSummary := output
		if len(outputSummary) > 200 {
			outputSummary = outputSummary[:200] + "..."
		}
		s.BroadcastTaskEvent(eventType, taskID, sessionID, taskType, exitCode, outputSummary, errorMsg)
	}
	sessionDeadCB := func(sessionID string) {
		fmt.Printf("[INFO] [server] Session %s disconnected (SOCKS5 kept alive for reconnect)\n", sessionID)
	}
	webhookNotifier := webhook.New(&s.cfg.Webhook)

	var rl *runtimeListener
	switch rec.Type {
	case "http":
		hl, err := listener.NewHTTPListener(lc, s.sessionMgr, s.taskMgr)
		if err != nil {
			return err
		}
		hl.SetOnTaskResult(taskResultCB)
		hl.SetOnSessionDead(sessionDeadCB)
		hl.SetOnSessionOnline(webhookNotifier.NotifyOnline)
		rl = &runtimeListener{id: id, typ: "http", pusher: hl, stop: hl.Stop}
	case "websocket":
		// WebSocket 通道：复用 Listener 实现（TSHL 帧 + AES-GCM，传输层为 WS 升级）。
		// Listener.Start() 依赖 cfg.Enabled 为 true 才真正监听。
		lc.Enabled = true
		wl, err := listener.NewListener(lc, s.sessionMgr, s.taskMgr)
		if err != nil {
			return err
		}
		wl.SetOnTaskResult(taskResultCB)
		wl.SetOnSessionDead(sessionDeadCB)
		wl.SetOnSessionOnline(webhookNotifier.NotifyOnline)
		wl.SetOnScreenFrame(s.BroadcastScreenFrame)
		wlStop := func() { _ = wl.Stop() }
		rl = &runtimeListener{id: id, typ: "websocket", pusher: wl, stop: wlStop}
	case "tcp":
		tl, err := listener.NewTCPListener(lc, s.sessionMgr, s.taskMgr)
		if err != nil {
			return err
		}
		tl.SetOnTaskResult(taskResultCB)
		tl.SetOnSessionDead(sessionDeadCB)
		tl.SetOnSessionOnline(webhookNotifier.NotifyOnline)
		tl.SetOnScreenFrame(s.BroadcastScreenFrame)
		rl = &runtimeListener{id: id, typ: "tcp", pusher: tl, stop: tl.Stop}
	case "mqtt":
		// MQTT 通道：连接 broker（内嵌或外部），主题 pub/sub 承载 TS 帧。
		// broker 地址/主题前缀来自监听器 options（前端创建时填写）。
		lc.MQTTBrokerURL = rec.Options.MQTTBrokerURL
		lc.MQTTTopicPrefix = rec.Options.MQTTTopicPrefix
		lc.MQTTEmbeddedBroker = rec.Options.MQTTEmbeddedBroker
		ml, err := listener.NewMQTTListener(lc, s.sessionMgr, s.taskMgr)
		if err != nil {
			return err
		}
		ml.SetOnTaskResult(taskResultCB)
		ml.SetOnSessionDead(sessionDeadCB)
		ml.SetOnSessionOnline(webhookNotifier.NotifyOnline)
		ml.SetOnScreenFrame(s.BroadcastScreenFrame)
		mlStop := func() { _ = ml.Stop() }
		rl = &runtimeListener{id: id, typ: "mqtt", pusher: ml, stop: mlStop}
	default:
		return fmt.Errorf("unsupported listener type: %s", rec.Type)
	}

	// 真正启动（bind 失败会同步返回错误，而不是误报成功）
	starter, ok := rl.pusher.(interface{ Start() error })
	if !ok {
		return fmt.Errorf("listener does not support Start()")
	}
	if err := starter.Start(); err != nil {
		logging.Error("api", "Failed to start listener %s: %v", id, err)
		return err
	}

	router.register(rl)

	if err := db.UpdateListenerStatus(id, "running"); err != nil {
		return err
	}

	return nil
}

// RestoreRunningListeners 服务重启后自动恢复 DB 中状态为 running 的监听器。
// 由 cmd/server 在启动完成、默认监听器注册后调用：Web 界面创建的监听器
// （非 default-*）重启后 socket 不会自动重建，植入端无法回连，此方法补齐该缺口。
func (s *Server) RestoreRunningListeners() int {
	db := database.Get()
	if db == nil {
		return 0
	}
	all, err := db.ListListeners()
	if err != nil {
		logging.Warn("api", "RestoreRunningListeners: failed to list listeners: %v", err)
		return 0
	}
	restored := 0
	for _, l := range all {
		if l.Status != "running" {
			continue
		}
		// 默认监听器（default-*）由配置文件驱动，main.go 已处理，跳过避免重复绑定
		if strings.HasPrefix(l.ID, "default-") {
			continue
		}
		if err := s.startListenerByID(l.ID); err != nil {
			logging.Error("api", "Restore listener %s (%s) failed: %v", l.ID, l.Name, err)
		} else {
			restored++
			logging.Info("api", "Restored listener %s (%s on %s:%d)", l.ID, l.Name, l.BindAddr, l.BindPort)
		}
	}
	return restored
}

func (s *Server) stopListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	// 停止并注销运行时监听器（真实关闭 socket）
	if router, ok := s.listener.(*listenerRouter); ok && router != nil {
		router.unregister(id)
	}

	if err := db.UpdateListenerStatus(id, "stopped"); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Listener %s stopped", id)
	json.NewEncoder(w).Encode(map[string]string{
		"id":      id,
		"status":  "stopped",
		"message": "Listener stopped",
	})
}

func (s *Server) deleteListenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	// 先停止运行中的实例再删除记录
	if router, ok := s.listener.(*listenerRouter); ok && router != nil {
		router.unregister(id)
	}

	if err := db.DeleteListener(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "Listener %s deleted", id)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Listener deleted",
	})
}

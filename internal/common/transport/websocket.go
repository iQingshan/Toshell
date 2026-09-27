package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/protocol"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 16,
	WriteBufferSize: 1024 * 16,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const (
	WriteWait      = 10 * time.Second
	PongWait       = 60 * time.Second
	PingPeriod     = (PongWait * 9) / 10
	MaxMessageSize = 1024 * 1024 * 10
)

type Conn struct {
	conn    *websocket.Conn
	writeCh chan []byte // 异步写入通道，解耦调用者与 TCP 写入
	mu      sync.RWMutex
	closed  bool
	done    chan struct{} // 通知 writeLoop 停止
	writeWg sync.WaitGroup
	onClose func()
	onError func(error)
}

func NewConn(conn *websocket.Conn) *Conn {
	c := &Conn{
		conn:    conn,
		writeCh: make(chan []byte, 1024), // 大缓冲避免隧道数据阻塞任务
		done:    make(chan struct{}),
	}
	c.writeWg.Add(1)
	go c.writeLoop()
	return c
}

// writeLoop 从 writeCh 中读取数据并向 WebSocket 连接写入
func (c *Conn) writeLoop() {
	defer c.writeWg.Done()
	for {
		select {
		case data, ok := <-c.writeCh:
			if !ok {
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := c.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				if c.onError != nil {
					c.onError(err)
				}
			}
		case <-c.done:
			// 排空剩余数据后退出
			for {
				select {
				case data, ok := <-c.writeCh:
					if !ok {
						return
					}
					c.conn.SetWriteDeadline(time.Now().Add(time.Second))
					c.conn.WriteMessage(websocket.BinaryMessage, data)
				default:
					return
				}
			}
		}
	}
}

func (c *Conn) SetOnClose(f func()) {
	c.onClose = f
}

func (c *Conn) SetOnError(f func(error)) {
	c.onError = f
}

func (c *Conn) ReadMessage() ([]byte, error) {
	_, data, err := c.conn.ReadMessage()
	if err != nil {
		if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			if c.onError != nil {
				c.onError(err)
			}
		}
		return nil, err
	}
	return data, nil
}

func (c *Conn) WriteMessage(data []byte) error {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return fmt.Errorf("connection closed")
	}

	// 非阻塞投递到 writer goroutine，消除调用者互斥等待
	select {
	case c.writeCh <- data:
		return nil
	default:
		// writeCh 满 → 超负荷，直接同步写入作为背压
		c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
		return c.conn.WriteMessage(websocket.BinaryMessage, data)
	}
}

func (c *Conn) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.WriteMessage(data)
}

func (c *Conn) ReadJSON(v interface{}) error {
	data, err := c.ReadMessage()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// 停止 writer goroutine，排空待发送数据
	close(c.done)
	c.writeWg.Wait()

	err := c.conn.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

func (c *Conn) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

type Client struct {
	url        string
	conn       *Conn
	reconnect  bool
	maxRetries int
	interval   time.Duration
	onConnect  func(*Conn)
	onMessage  func([]byte)
	onClose    func()
	onError    func(error)
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

type ClientOption func(*Client)

func WithReconnect(interval time.Duration, maxRetries int) ClientOption {
	return func(c *Client) {
		c.reconnect = true
		c.interval = interval
		c.maxRetries = maxRetries
	}
}

func WithOnConnect(f func(*Conn)) ClientOption {
	return func(c *Client) {
		c.onConnect = f
	}
}

func WithOnMessage(f func([]byte)) ClientOption {
	return func(c *Client) {
		c.onMessage = f
	}
}

func WithOnClose(f func()) ClientOption {
	return func(c *Client) {
		c.onClose = f
	}
}

func WithOnError(f func(error)) ClientOption {
	return func(c *Client) {
		c.onError = f
	}
}

func NewClient(url string, opts ...ClientOption) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		url:       url,
		reconnect: false,
		interval:  5 * time.Second,
		ctx:       ctx,
		cancel:    cancel,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) Connect() error {
	wsConn, _, err := websocket.DefaultDialer.Dial(c.url, nil)
	if err != nil {
		return err
	}

	conn := NewConn(wsConn)
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	conn.SetOnClose(func() {
		if c.reconnect {
			c.reconnectLoop()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})

	conn.SetOnError(func(err error) {
		if c.onError != nil {
			c.onError(err)
		}
	})

	if c.onConnect != nil {
		c.onConnect(conn)
	}

	c.wg.Add(1)
	go c.readLoop()

	return nil
}

func (c *Client) reconnectLoop() {
	retries := 0
	for c.reconnect && (c.maxRetries <= 0 || retries < c.maxRetries) {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.interval):
		}

		if err := c.Connect(); err != nil {
			retries++
			log.Printf("[transport] Reconnect failed: %v (retry %d)\n", err, retries)
			continue
		}
		log.Printf("[transport] Reconnected successfully\n")
		return
	}
}

func (c *Client) readLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil || conn.IsClosed() {
			return
		}

		data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		if c.onMessage != nil {
			c.onMessage(data)
		}
	}
}

func (c *Client) Send(data []byte) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}
	return conn.WriteMessage(data)
}

func (c *Client) SendPacket(packet *protocol.Packet) error {
	data := protocol.EncodePacket(packet)
	return c.Send(data)
}

func (c *Client) Close() error {
	c.reconnect = false
	c.cancel()
	c.wg.Wait()

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil && !c.conn.IsClosed()
}

// ─── 主动探测面收敛（v1.4.0 S5 第 0 步）────────────────────────────────────────
//
// 收敛前（如实记录）：ServeHTTP 对**任意路径**的 GET 都直接尝试升级 ——
// `// 不检查路径，接受所有 WebSocket 连接`。主动探测者随手发一份握手就能在
// `/whatever` 上拿到 101；就算只发一个普通 GET，gorilla 的握手失败也会回
// `400 Bad Request` + `Sec-Websocket-Version: 13` —— 这两个响应都等于对外宣布
// "这台主机上有一个 WebSocket 端点"。
//
// 收敛后，只有同时满足下列全部条件才升级：
//  1. 路径**恰好**是配置的唯一路径（默认 DefaultUpgradePath，见下）；
//  2. 请求路径是**规范形态**（无 `//`、`/./`、尾部斜杠、`..`、百分号编码）；
//  3. Host 若配了白名单，则必须在名单内（空 = 不检查，保持向后兼容）；
//  4. 请求是一份**完整的** WS 握手（Connection/Upgrade/Key/Version 四项齐备）。
//
// 任何一条不满足都写**同一个** http.NotFound：与"这个路径没有处理器"在
// 状态码 / 响应体 / Content-Type / X-Content-Type-Options 上逐字节一致，
// 探测者拿不到"这里有 WS 端点"的任何信号。

// DefaultUpgradePath WebSocket 升级的默认请求路径。
//
// 为什么是 "/"（而不是"看起来更隐蔽"的随机串）：现役植入端在 server_url 不带
// 路径时就是用 "/" 发起握手的（见 internal/server/builder/implant/transport_ws.go
// 的 wsPollRun），构建器生成的 server_url（applyListenerDefaults）同样不带路径。
// **默认值必须与植入端一致**，否则默认配置下现役载荷会全部连不上 —— 这是本步
// 的兼容性硬要求（"默认配置下现役载荷行为不变"）。想要更隐蔽的路径，就同时在
// 这里与植入端 server_url 上改成同一个值（别再靠猜默认值）。
const DefaultUpgradePath = "/"

// 拒绝原因：固定枚举值（便于日志聚合与单测断言，不含任何请求内容）。
const (
	RejectMethod         = "method_not_get"   // 非 GET
	RejectEncodedPath    = "encoded_path"     // 路径含百分号编码（非规范形态）
	RejectPathMismatch   = "path_mismatch"    // 不是配置的唯一路径 / 路径未规范化
	RejectHostNotAllowed = "host_not_allowed" // Host 不在白名单
	RejectNoHandshake    = "not_ws_handshake" // 缺 WS 握手头
	RejectUpgradeFailed  = "upgrade_failed"   // 头齐备但升级仍失败（客户端自身问题）
)

// UpgradePolicy WebSocket 升级准入策略。
type UpgradePolicy struct {
	// Path 唯一允许升级的请求路径（字面比较，大小写敏感）。空值按
	// DefaultUpgradePath 处理（配置没写与被清空都等价于默认路径）。
	Path string
	// HostAllowlist 允许的 Host 列表；空 = 不检查。元素可以是 host 或 host:port：
	// 不含端口时只比主机名（请求侧端口忽略），含端口时要求含端口逐字一致。
	HostAllowlist []string
}

// normalized 把空路径收敛到默认值。
func (p UpgradePolicy) normalized() UpgradePolicy {
	if p.Path == "" {
		p.Path = DefaultUpgradePath
	}
	return p
}

// UpgradeReject 一条被拒绝的升级尝试（只带排障必需的最小字段）。
//
// 刻意**不带**请求头集合：拒绝日志要能回答"是不是有人在扫我"，但记全量头
// 有把 Cookie/Authorization 这类凭据写进日志的风险。
type UpgradeReject struct {
	// Reason 拒绝原因（上面 Reject* 常量之一）。
	Reason string
	// Path 解码后的请求路径（r.URL.Path）。不取 RequestURI：query 里可能有凭据。
	Path string
	// RawPath 非规范编码的原始形态（r.URL.RawPath），通常为空。
	RawPath string
	// Host 请求的 Host 头。
	Host string
	// RemoteIP 对端 IP（已去掉端口）。
	RemoteIP string
	// HandshakeAttempt 该请求是否**看起来在尝试 WS 升级**（带握手特征头）。
	// 调用方据此过滤背景噪声：公网里大量随机路径的普通 GET 不该刷满日志。
	HandshakeAttempt bool
}

// rejectReason 判定请求是否应当被拒（返回空串 = 放行到升级器）。
//
// 关于 r.URL.Path 与 r.URL.EscapedPath() 的选择（本步的关键取舍）：
// net/http 解析请求行时会做一次解码，`/w%73` 与 `/%2fws` 的**解码结果**分别
// 落在 r.URL.Path（"/ws"、"//ws"）上，而"非规范编码"的原始形态留在
// r.URL.RawPath（仅当它不是 Path 的标准编码时才非空）。
//
//	选择 A：按解码后的 r.URL.Path 做字面比较 —— 与 net/http 内部路由、
//	        http.ServeMux、以及"HTTP 路径语义"完全一致（服务端看到的就是它）。
//	选择 B：按 EscapedPath() 比较 —— 等于要求客户端按我们习惯的编码形态发请求，
//	        反而让 `/%77s`、`/ws%2f` 这类变体获得"看起来不等、解码后相等"的
//	        模糊空间。
//
// 因此这里取 A 做等值/规范化判定，并**额外**用 RawPath 把"任何非规范编码"
// 一刀切拒掉（现役植入端与浏览器发起的握手都是普通路径，出现百分号编码只可能
// 是绕过尝试）。这样 `//`、`/./`、`/ws/`、`..`、`%2f`、大小写变形全部拿不到升级。
func rejectReason(r *http.Request, p UpgradePolicy) string {
	if r.Method != http.MethodGet {
		return RejectMethod
	}
	if r.URL.RawPath != "" {
		return RejectEncodedPath
	}
	// 等值 + 规范化双重判定：前者拦大小写/前缀差异（如 /WS、/wss），
	// 后者拦 path.Clean 之后才会相等的变形（//ws、/./ws、/ws/、/ws/../ws）。
	if r.URL.Path != p.Path || path.Clean(r.URL.Path) != r.URL.Path {
		return RejectPathMismatch
	}
	if !hostAllowed(r.Host, p.HostAllowlist) {
		return RejectHostNotAllowed
	}
	if !isCompleteWSHandshake(r) {
		return RejectNoHandshake
	}
	return ""
}

// isCompleteWSHandshake 判断请求是否是一份完整的 WS 握手。
//
// 为什么要自己先判一遍：只要放行给 gorilla 的 Upgrade()，它就会为"像握手但
// 不完整"的请求写 `400` + `Sec-Websocket-Version: 13` —— 这个响应本身就是
// 端点指纹（普通未知路径是 404）。这里提前把所有不完整形态归入普通 404。
func isCompleteWSHandshake(r *http.Request) bool {
	if !websocket.IsWebSocketUpgrade(r) {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key")) == "" {
		return false
	}
	// gorilla 服务端只接受版本 13；其它版本同样按"没有这个端点"处理，
	// 而不是让 gorilla 回 400 + Version 头。
	return strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")) == "13"
}

// looksLikeWSHandshake 判断请求是否带有 WS 握手特征（用于日志噪声过滤）。
func looksLikeWSHandshake(r *http.Request) bool {
	return websocket.IsWebSocketUpgrade(r) ||
		r.Header.Get("Sec-WebSocket-Key") != "" ||
		r.Header.Get("Sec-WebSocket-Version") != "" ||
		r.Header.Get("Sec-WebSocket-Protocol") != ""
}

// hostAllowed 判断 Host 是否通过白名单（空名单 = 不检查）。
//
// 匹配口径（两条，避免"配了端口却不看端口"这种反直觉行为）：
//   - 名单元素不含端口（如 cdn.example.com）→ 只比主机名，请求侧端口忽略
//     （`cdn.example.com`、`cdn.example.com:18777` 都通过）；
//   - 名单元素含端口（如 10.0.0.1:18777）→ 必须逐字一致（含端口），
//     写成带端口的条目就意味着操作员要卡端口。
func hostAllowed(host string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	name := hostOnly(h)
	for _, entry := range allowlist {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if e == h {
			return true
		}
		if hostOnly(e) == e && e == name {
			return true
		}
	}
	return false
}

// hostOnly 去掉 host:port 的端口（无端口时原样返回）。
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// remoteIP 去掉对端地址里的端口。
func remoteIP(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

type Server struct {
	upgrader  websocket.Upgrader
	handlers  map[string]func(*Conn)
	onConnect func(*Conn)
	onMessage func(*Conn, []byte)
	onClose   func(*Conn)
	mu        sync.RWMutex
	// policy 升级准入策略（零值 = 默认路径 + 不检查 Host）。
	policy UpgradePolicy
	// onReject 被拒绝的升级尝试回调（由监听器接到结构化日志）。
	// 放在 transport 层只做"上报"，是否落日志（噪声过滤）由服务端策略决定。
	onReject func(UpgradeReject)
}

func NewServer() *Server {
	return &Server{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024 * 16,
			WriteBufferSize: 1024 * 16,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		handlers: make(map[string]func(*Conn)),
	}
}

// SetUpgradePolicy 设置升级准入策略（路径 + Host 白名单）。
func (s *Server) SetUpgradePolicy(p UpgradePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = p.normalized()
}

// UpgradePolicy 返回当前生效的升级准入策略（已收敛默认值）。
func (s *Server) UpgradePolicy() UpgradePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.normalized()
}

// SetOnUpgradeReject 注册被拒绝的升级尝试回调。
func (s *Server) SetOnUpgradeReject(f func(UpgradeReject)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onReject = f
}

// policySnapshot 取当前策略与拒绝回调（一次加锁取全，避免两次读之间被改）。
func (s *Server) policySnapshot() (UpgradePolicy, func(UpgradeReject)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.normalized(), s.onReject
}

func (s *Server) Handle(path string, handler func(*Conn)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[path] = handler
}

func (s *Server) SetOnConnect(f func(*Conn)) {
	s.onConnect = f
}

func (s *Server) SetOnMessage(f func(*Conn, []byte)) {
	s.onMessage = f
}

func (s *Server) SetOnClose(f func(*Conn)) {
	s.onClose = f
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	policy, onReject := s.policySnapshot()

	if reason := rejectReason(r, policy); reason != "" {
		if onReject != nil {
			onReject(UpgradeReject{
				Reason:           reason,
				Path:             r.URL.Path,
				RawPath:          r.URL.RawPath,
				Host:             r.Host,
				RemoteIP:         remoteIP(r.RemoteAddr),
				HandshakeAttempt: looksLikeWSHandshake(r),
			})
		}
		// 统一走 http.NotFound：与"路径不存在"不可区分（不升级也**不辩解**）。
		http.NotFound(w, r)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// 走到这里说明路径/Host/握手头都齐了，失败原因是客户端自身的问题
		// （例如不支持的 Sec-Websocket-Extensions）。gorilla 已写好响应，不再二次写。
		if onReject != nil {
			onReject(UpgradeReject{
				Reason:           RejectUpgradeFailed,
				Path:             r.URL.Path,
				Host:             r.Host,
				RemoteIP:         remoteIP(r.RemoteAddr),
				HandshakeAttempt: true,
			})
		}
		log.Printf("[transport] WebSocket upgrade failed: %v\n", err)
		return
	}

	wsConn := NewConn(conn)

	wsConn.SetOnClose(func() {
		if s.onClose != nil {
			s.onClose(wsConn)
		}
	})

	if s.onConnect != nil {
		s.onConnect(wsConn)
	}

	go s.handleConnection(wsConn)
}

func (s *Server) handleConnection(conn *Conn) {
	defer conn.Close()

	conn.conn.SetReadLimit(MaxMessageSize)
	conn.conn.SetReadDeadline(time.Time{})

	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				conn.conn.WriteMessage(websocket.PingMessage, nil)
			}
		}
	}()

	for {
		data, err := conn.ReadMessage()
		if err != nil {
			close(done)
			log.Printf("[transport] Read error: %v\n", err)
			break
		}

		if s.onMessage != nil {
			s.onMessage(conn, data)
		}
	}
}

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	WriteWait       = 10 * time.Second
	PongWait        = 60 * time.Second
	PingPeriod      = (PongWait * 9) / 10
	MaxMessageSize  = 1024 * 1024 * 10
)

type Conn struct {
	conn    *websocket.Conn
	writeCh chan []byte         // 异步写入通道，解耦调用者与 TCP 写入
	mu      sync.RWMutex
	closed  bool
	done    chan struct{}       // 通知 writeLoop 停止
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

type Server struct {
	upgrader websocket.Upgrader
	handlers map[string]func(*Conn)
	onConnect func(*Conn)
	onMessage func(*Conn, []byte)
	onClose   func(*Conn)
	mu        sync.RWMutex
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
	if r.Method == http.MethodGet {
		// 不检查路径，接受所有 WebSocket 连接
		conn, err := s.upgrader.Upgrade(w, r, nil)
		if err != nil {
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
		return
	}

	http.NotFound(w, r)
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

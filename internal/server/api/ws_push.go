package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSEvent represents a WebSocket push event.
type WSEvent struct {
	Type    string      `json:"type"`    // "session_online", "session_offline", "task_completed", "task_failed"
	Payload interface{} `json:"payload"` // event data
	Time    int64       `json:"time"`    // unix timestamp (seconds)
}

// WSClient represents a single WebSocket connection.
type WSClient struct {
	conn *websocket.Conn
	send chan []byte
	hub  *WSHub
}

// WSHub manages all WebSocket connections and broadcasts.
type WSHub struct {
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
	mu         sync.RWMutex

	// fanoutObserver 可选的广播扇出观测回调（v1.4.1 屏幕帧投递计数，见
	// screen_stats.go）。nil = 完全走原路径：不额外分配、不打日志、行为不变。
	// 回调在 Hub 事件循环中、**释放 clients 锁之后**同步调用，必须快速且非阻塞。
	fanoutObserver func(message []byte, delivered, dropped int)
}

var wsUpgrader = websocket.Upgrader{
	// 审计 M8：与 shell WS 共用同一套 Origin 判定（空 Origin 放行、
	// 同 host 放行、外站拒绝），不再无条件返回 true。
	CheckOrigin:     originAllowed,
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

// NewWSHub creates a new WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
	}
}

// Run starts the hub's event loop. Must be called as a goroutine.
func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.Lock()
			delivered, dropped := 0, 0
			for client := range h.clients {
				select {
				case client.send <- message:
					delivered++
				default:
					// Client buffer full, drop and disconnect
					close(client.send)
					delete(h.clients, client)
					dropped++
				}
			}
			observer := h.fanoutObserver
			h.mu.Unlock()
			// 锁外调用：观测回调不能反过来拿 h.mu（也不能拖慢扇出）。
			if observer != nil {
				observer(message, delivered, dropped)
			}
		}
	}
}

// Broadcast sends an event to all connected WebSocket clients.
func (h *WSHub) Broadcast(event WSEvent) {
	event.Time = time.Now().Unix()
	data, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("[ERROR] [ws-hub] Failed to marshal event: %v\n", err)
		return
	}
	h.broadcast <- data
}

// ServeWS handles WebSocket upgrade and manages read/write pumps.
func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[ERROR] [ws-hub] WebSocket upgrade failed: %v\n", err)
		return
	}

	client := &WSClient{
		conn: conn,
		send: make(chan []byte, 64),
		hub:  h,
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *WSClient) writePump() {
	defer c.conn.Close()
	for message := range c.send {
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}

// readPump reads messages from the WebSocket connection (keep-alive).
func (c *WSClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(1024)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Send a ping every 30 seconds to keep the connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// SetFanoutObserver 注册广播扇出观测回调（屏幕帧投递计数用；nil = 关闭观测）。
//
// 回调参数：原始广播 JSON、本次成功写入订阅者发送缓冲的次数、因缓冲满被丢弃
// （客户端同时被断开）的次数。回调在 Hub 事件循环里、锁外同步调用，必须非阻塞
// 且不得反向调用 Hub 的写方法（否则会与事件循环互等）。
func (h *WSHub) SetFanoutObserver(fn func(message []byte, delivered, dropped int)) {
	h.mu.Lock()
	h.fanoutObserver = fn
	h.mu.Unlock()
}

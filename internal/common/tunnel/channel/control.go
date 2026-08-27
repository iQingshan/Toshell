package channel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/tunnel/protocol"
)

type ControlChannel struct {
	conn     net.Conn
	encoder  *protocol.Encoder
	decoder  *protocol.Decoder

	sendQueue    chan *protocol.Packet
	sendPriority chan *protocol.Packet
	recvQueue    chan *protocol.Packet

	stopChan chan struct{}
	wg       sync.WaitGroup
	closed   int32

	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	lastHeartbeat     int64
	lastSend          int64

	onHeartbeat func(*protocol.HeartbeatPayload)
	onTunnelReq func(*protocol.TunnelInfo)
	onTunnelAck func(*protocol.TunnelAckPayload)
	onCloseTun  func(uint32)
	onError     func(error)

	writeMu sync.Mutex
	readMu  sync.Mutex

	stats ControlStats
}

type ControlStats struct {
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
}

type ControlOption func(*ControlChannel)

func WithHeartbeatInterval(d time.Duration) ControlOption {
	return func(cc *ControlChannel) {
		cc.heartbeatInterval = d
	}
}

func WithHeartbeatTimeout(d time.Duration) ControlOption {
	return func(cc *ControlChannel) {
		cc.heartbeatTimeout = d
	}
}

func WithSendQueueSize(size int) ControlOption {
	return func(cc *ControlChannel) {
		cc.sendQueue = make(chan *protocol.Packet, size)
	}
}

func WithOnHeartbeat(f func(*protocol.HeartbeatPayload)) ControlOption {
	return func(cc *ControlChannel) {
		cc.onHeartbeat = f
	}
}

func WithOnTunnelReq(f func(*protocol.TunnelInfo)) ControlOption {
	return func(cc *ControlChannel) {
		cc.onTunnelReq = f
	}
}

func WithOnTunnelAck(f func(*protocol.TunnelAckPayload)) ControlOption {
	return func(cc *ControlChannel) {
		cc.onTunnelAck = f
	}
}

func WithOnCloseTunnel(f func(uint32)) ControlOption {
	return func(cc *ControlChannel) {
		cc.onCloseTun = f
	}
}

func WithOnError(f func(error)) ControlOption {
	return func(cc *ControlChannel) {
		cc.onError = f
	}
}

func NewControlChannel(conn net.Conn, opts ...ControlOption) *ControlChannel {
	cc := &ControlChannel{
		conn:              conn,
		encoder:           protocol.NewEncoder(),
		decoder:           protocol.NewDecoder(),
		sendQueue:         make(chan *protocol.Packet, 256),
		sendPriority:      make(chan *protocol.Packet, 16),
		recvQueue:         make(chan *protocol.Packet, 256),
		stopChan:          make(chan struct{}),
		heartbeatInterval: 30 * time.Second,
		heartbeatTimeout:  90 * time.Second,
		lastHeartbeat:     time.Now().UnixMilli(),
		lastSend:          time.Now().UnixMilli(),
	}

	for _, opt := range opts {
		opt(cc)
	}

	return cc
}

func (cc *ControlChannel) Start() {
	cc.wg.Add(3)
	go cc.sendLoop()
	go cc.recvLoop()
	go cc.heartbeatLoop()
}

func (cc *ControlChannel) Stop() {
	if !atomic.CompareAndSwapInt32(&cc.closed, 0, 1) {
		return
	}

	close(cc.stopChan)
	cc.conn.Close()
	cc.wg.Wait()

	close(cc.sendQueue)
	close(cc.sendPriority)
	close(cc.recvQueue)
}

func (cc *ControlChannel) IsClosed() bool {
	return atomic.LoadInt32(&cc.closed) == 1
}

func (cc *ControlChannel) sendLoop() {
	defer cc.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			cc.handleError(fmt.Errorf("sendLoop panic: %v", r))
		}
	}()

	for {
		select {
		case <-cc.stopChan:
			return
		case pkt := <-cc.sendPriority:
			if err := cc.writePacket(pkt); err != nil {
				cc.handleError(err)
				return
			}
		case pkt := <-cc.sendQueue:
			if err := cc.writePacket(pkt); err != nil {
				cc.handleError(err)
				return
			}
		}
	}
}

func (cc *ControlChannel) recvLoop() {
	defer cc.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			cc.handleError(fmt.Errorf("recvLoop panic: %v", r))
		}
	}()

	buf := make([]byte, 64*1024)
	streamDecoder := protocol.NewStreamDecoder(10 * 1024 * 1024)

	for {
		select {
		case <-cc.stopChan:
			return
		default:
		}

		cc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := cc.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if cc.IsClosed() {
				return
			}
			cc.handleError(err)
			return
		}

		atomic.AddUint64(&cc.stats.BytesIn, uint64(n))
		atomic.AddUint64(&cc.stats.PacketsIn, 1)

		packets := streamDecoder.Feed(buf[:n])
		for _, pkt := range packets {
			cc.handlePacket(pkt)
		}
	}
}

func (cc *ControlChannel) heartbeatLoop() {
	defer cc.wg.Done()

	ticker := time.NewTicker(cc.heartbeatInterval)
	defer ticker.Stop()

	checkTicker := time.NewTicker(10 * time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-cc.stopChan:
			return
		case <-ticker.C:
			cc.SendHeartbeat(&protocol.HeartbeatPayload{
				Timestamp: time.Now().UnixMilli(),
			})
		case <-checkTicker.C:
			lastHb := atomic.LoadInt64(&cc.lastHeartbeat)
			if time.Since(time.UnixMilli(lastHb)) > cc.heartbeatTimeout {
				cc.handleError(fmt.Errorf("heartbeat timeout"))
				return
			}
		}
	}
}

func (cc *ControlChannel) writePacket(pkt *protocol.Packet) error {
	cc.writeMu.Lock()
	defer cc.writeMu.Unlock()

	data, err := cc.encoder.Encode(pkt)
	if err != nil {
		return err
	}

	cc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err := cc.conn.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&cc.stats.BytesOut, uint64(n))
	atomic.AddUint64(&cc.stats.PacketsOut, 1)
	atomic.StoreInt64(&cc.lastSend, time.Now().UnixMilli())

	return nil
}

func (cc *ControlChannel) handlePacket(pkt *protocol.Packet) {
	atomic.StoreInt64(&cc.lastHeartbeat, time.Now().UnixMilli())

	switch pkt.Type {
	case protocol.TypeHeartbeat:
		if cc.onHeartbeat != nil {
			hb, err := protocol.UnmarshalHeartbeat(pkt.Payload)
			if err == nil {
				cc.onHeartbeat(hb)
			}
		}

	case protocol.TypeNewTunnel:
		if cc.onTunnelReq != nil {
			info, err := protocol.UnmarshalTunnelInfo(pkt.Payload)
			if err == nil {
				cc.onTunnelReq(info)
			}
		}

	case protocol.TypeTunnelAck:
		if cc.onTunnelAck != nil {
			ack, err := protocol.UnmarshalTunnelAck(pkt.Payload)
			if err == nil {
				cc.onTunnelAck(ack)
			}
		}

	case protocol.TypeCloseTunnel:
		if cc.onCloseTun != nil {
			cc.onCloseTun(pkt.TunnelID)
		}

	case protocol.TypeError:
		if cc.onError != nil {
			errPkt, _ := protocol.UnmarshalError(pkt.Payload)
			cc.handleError(fmt.Errorf("remote error: %s", errPkt.Message))
		}
	}
}

func (cc *ControlChannel) handleError(err error) {
	if cc.onError != nil {
		cc.onError(err)
	}
}

func (cc *ControlChannel) SendPacket(pkt *protocol.Packet) error {
	if cc.IsClosed() {
		return fmt.Errorf("channel closed")
	}

	select {
	case cc.sendQueue <- pkt:
		return nil
	default:
		return fmt.Errorf("send queue full")
	}
}

func (cc *ControlChannel) SendPriority(pkt *protocol.Packet) error {
	if cc.IsClosed() {
		return fmt.Errorf("channel closed")
	}

	select {
	case cc.sendPriority <- pkt:
		return nil
	default:
		return fmt.Errorf("priority queue full")
	}
}

func (cc *ControlChannel) SendHeartbeat(hb *protocol.HeartbeatPayload) error {
	pkt := protocol.NewHeartbeatPacket(0, hb)
	return cc.SendPriority(pkt)
}

func (cc *ControlChannel) NewTunnel(info *protocol.TunnelInfo) error {
	pkt := protocol.NewTunnelPacket(info.ID, info)
	return cc.SendPacket(pkt)
}

func (cc *ControlChannel) CloseTunnel(tunnelID uint32) error {
	pkt := protocol.NewClosePacket(tunnelID)
	return cc.SendPriority(pkt)
}

func (cc *ControlChannel) SendAck(tunnelID uint32, success bool, errMsg string) error {
	pkt := protocol.NewAckPacket(tunnelID, success, errMsg)
	return cc.SendPriority(pkt)
}

func (cc *ControlChannel) SendError(code int, message string) error {
	pkt := protocol.NewErrorPacket(code, message)
	return cc.SendPriority(pkt)
}

func (cc *ControlChannel) GetStats() ControlStats {
	return ControlStats{
		BytesIn:    atomic.LoadUint64(&cc.stats.BytesIn),
		BytesOut:   atomic.LoadUint64(&cc.stats.BytesOut),
		PacketsIn:  atomic.LoadUint64(&cc.stats.PacketsIn),
		PacketsOut: atomic.LoadUint64(&cc.stats.PacketsOut),
	}
}

func (cc *ControlChannel) LastHeartbeat() time.Time {
	return time.UnixMilli(atomic.LoadInt64(&cc.lastHeartbeat))
}

func (cc *ControlChannel) LastSend() time.Time {
	return time.UnixMilli(atomic.LoadInt64(&cc.lastSend))
}

func (cc *ControlChannel) SetOnHeartbeat(f func(*protocol.HeartbeatPayload)) {
	cc.onHeartbeat = f
}

func (cc *ControlChannel) SetOnTunnelReq(f func(*protocol.TunnelInfo)) {
	cc.onTunnelReq = f
}

func (cc *ControlChannel) SetOnTunnelAck(f func(*protocol.TunnelAckPayload)) {
	cc.onTunnelAck = f
}

func (cc *ControlChannel) SetOnCloseTunnel(f func(uint32)) {
	cc.onCloseTun = f
}

func (cc *ControlChannel) SetOnError(f func(error)) {
	cc.onError = f
}

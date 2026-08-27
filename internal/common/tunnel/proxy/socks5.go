package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/tunnel/manager"
	"toshell/internal/common/tunnel/protocol"
)

type SOCKS5Server struct {
	listener       net.Listener
	port           int
	tunnelMgr      *manager.TunnelManager
	sendToImplant  func(tunnelID uint32, pkt *protocol.Packet) error
	sessionID      string

	stopChan chan struct{}
	wg       sync.WaitGroup
	closed   int32

	connectTimeout time.Duration
	idleTimeout    time.Duration

	stats SOCKS5Stats
}

type SOCKS5Stats struct {
	TotalConnections uint64
	ActiveConnections uint64
	BytesIn          uint64
	BytesOut         uint64
}

type SOCKS5Option func(*SOCKS5Server)

func WithConnectTimeout(d time.Duration) SOCKS5Option {
	return func(s *SOCKS5Server) {
		s.connectTimeout = d
	}
}

func WithIdleTimeout(d time.Duration) SOCKS5Option {
	return func(s *SOCKS5Server) {
		s.idleTimeout = d
	}
}

func WithSendToImplant(f func(tunnelID uint32, pkt *protocol.Packet) error) SOCKS5Option {
	return func(s *SOCKS5Server) {
		s.sendToImplant = f
	}
}

func WithSessionID(id string) SOCKS5Option {
	return func(s *SOCKS5Server) {
		s.sessionID = id
	}
}

func NewSOCKS5Server(port int, opts ...SOCKS5Option) *SOCKS5Server {
	s := &SOCKS5Server{
		port:           port,
		tunnelMgr:      manager.NewTunnelManager(),
		stopChan:       make(chan struct{}),
		connectTimeout: 30 * time.Second,
		idleTimeout:    5 * time.Minute,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}
	s.listener = listener

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *SOCKS5Server) Stop() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	s.tunnelMgr.Stop()
	s.wg.Wait()
}

func (s *SOCKS5Server) IsClosed() bool {
	return atomic.LoadInt32(&s.closed) == 1
}

func (s *SOCKS5Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if s.IsClosed() {
				return
			}
			continue
		}

		atomic.AddUint64(&s.stats.TotalConnections, 1)
		atomic.AddUint64(&s.stats.ActiveConnections, 1)

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		conn.Close()
		if atomic.LoadUint64(&s.stats.ActiveConnections) > 0 {
			atomic.AddUint64(&s.stats.ActiveConnections, ^uint64(0))
		}
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	if n < 2 || buf[0] != 0x05 {
		return
	}

	numMethods := int(buf[1])
	if n < 2+numMethods {
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	n, err = conn.Read(buf)
	if err != nil {
		return
	}

	if n < 7 || buf[0] != 0x05 {
		return
	}

	var targetAddr string
	var targetPort uint16

	switch buf[3] {
	case 0x01:
		if n < 10 {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
	case 0x04:
		if n < 22 {
			return
		}
		targetAddr = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			binary.BigEndian.Uint16(buf[4:6]),
			binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]),
			binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]),
			binary.BigEndian.Uint16(buf[14:16]),
			binary.BigEndian.Uint16(buf[16:18]),
			binary.BigEndian.Uint16(buf[18:20]))
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	tunnel, err := s.tunnelMgr.Create(protocol.ProtocolSOCKS5, targetAddr, targetPort, conn)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 注意：必须使用 Create 分配的 tunnel.ID，而不是预取 NextID()。
	// Create 内部用 tm.nextID 自增分配 ID，与 NextID() 的 atomic 计数方式
	// 不一致会差 1，导致握手包/数据包 TunnelID 与隧道实际 ID 错位，
	// 植入端 ACK 回来时 Get(id) 找不到隧道，隧道永远无法激活。
	info := protocol.NewTunnelInfo(tunnel.ID, protocol.ProtocolSOCKS5, targetAddr, targetPort)
	info.SourceAddr, info.SourcePort = parseRemoteAddr(conn.RemoteAddr().String())

	pkt := protocol.NewTunnelPacket(tunnel.ID, info)
	if s.sendToImplant != nil {
		if err := s.sendToImplant(tunnel.ID, pkt); err != nil {
			s.tunnelMgr.Remove(tunnel.ID)
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	}

	select {
	case <-tunnel.IsReady():
		resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if _, err := conn.Write(resp); err != nil {
			s.tunnelMgr.Remove(tunnel.ID)
			return
		}
		conn.SetDeadline(time.Time{})
		s.wg.Add(1)
		go s.proxyLoop(conn, tunnel)

	case <-time.After(s.connectTimeout):
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		s.tunnelMgr.Remove(tunnel.ID)

	case <-s.stopChan:
		s.tunnelMgr.Remove(tunnel.ID)
	}
}

var socksBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64*1024)
	},
}

func (s *SOCKS5Server) proxyLoop(conn net.Conn, tunnel *manager.Tunnel) {
	defer s.wg.Done()
	defer func() {
		if tunnel.GetState() != protocol.TunnelStateClosed {
			s.tunnelMgr.Remove(tunnel.ID)
		}
	}()

	buf := socksBufPool.Get().([]byte)
	defer socksBufPool.Put(buf)

	for {
		select {
		case <-s.stopChan:
			return
		case <-tunnel.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if tunnel.GetState() != protocol.TunnelStateActive {
					continue
				}
				continue
			}
			return
		}

		tunnel.AddBytesIn(uint64(n))
		atomic.AddUint64(&s.stats.BytesIn, uint64(n))

		// 直接从 pool 复制数据，避免保留 buf 引用
		data := make([]byte, n)
		copy(data, buf[:n])

		pkt := protocol.NewDataPacket(tunnel.ID, data)
		if s.sendToImplant != nil {
			if err := s.sendToImplant(tunnel.ID, pkt); err != nil {
				return
			}
		}
	}
}

func (s *SOCKS5Server) HandleData(pkt *protocol.Packet) {
	switch pkt.Type {
	case protocol.TypeTunnelAck:
		ack, err := protocol.UnmarshalTunnelAck(pkt.Payload)
		if err != nil {
			return
		}

		tunnel, ok := s.tunnelMgr.Get(ack.TunnelID)
		if !ok {
			return
		}

		if ack.Success {
			tunnel.SetActive()
		} else {
			tunnel.SetError()
			s.tunnelMgr.Remove(ack.TunnelID)
		}

	case protocol.TypeData:
		tunnel, ok := s.tunnelMgr.Get(pkt.TunnelID)
		if !ok {
			return
		}

		tunnel.AddBytesOut(uint64(len(pkt.Payload)))
		atomic.AddUint64(&s.stats.BytesOut, uint64(len(pkt.Payload)))

		_, err := tunnel.Write(pkt.Payload)
		if err != nil {
			s.tunnelMgr.Remove(pkt.TunnelID)
		}

	case protocol.TypeCloseTunnel:
		s.tunnelMgr.Remove(pkt.TunnelID)
	}
}

func (s *SOCKS5Server) GetTunnelManager() *manager.TunnelManager {
	return s.tunnelMgr
}

func (s *SOCKS5Server) GetPort() int {
	return s.port
}

func (s *SOCKS5Server) GetStats() SOCKS5Stats {
	return SOCKS5Stats{
		TotalConnections:  atomic.LoadUint64(&s.stats.TotalConnections),
		ActiveConnections: atomic.LoadUint64(&s.stats.ActiveConnections),
		BytesIn:          atomic.LoadUint64(&s.stats.BytesIn),
		BytesOut:         atomic.LoadUint64(&s.stats.BytesOut),
	}
}

func (s *SOCKS5Server) SetSendToImplant(f func(tunnelID uint32, pkt *protocol.Packet) error) {
	s.sendToImplant = f
}

func (s *SOCKS5Server) SetSessionID(id string) {
	s.sessionID = id
}

func parseRemoteAddr(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	
	var port uint16
	for _, c := range portStr {
		if c >= '0' && c <= '9' {
			port = port*10 + uint16(c-'0')
		}
	}
	
	return host, port
}

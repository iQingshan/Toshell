package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Server struct {
	listener  *quic.Listener
	tlsConfig *tls.Config
	tunnels   map[uint32]*Tunnel
	mu        sync.RWMutex
	nextID    uint32
	stopChan  chan struct{}
	wg        sync.WaitGroup
	onConnect func(tunnelID uint32, addr string, port uint16) (net.Conn, error)
	stats     ServerStats
	statsMu   sync.RWMutex
}

type ServerStats struct {
	TotalConnections  uint64
	ActiveConnections int64
	BytesIn           uint64
	BytesOut          uint64
}

type Tunnel struct {
	ID         uint32
	TargetConn net.Conn
	Stream     *StreamWrapper
	CreatedAt  time.Time
	BytesIn    uint64
	BytesOut   uint64
	done       chan struct{}
	mu         sync.Mutex
	closed     bool
}

func NewServer(tlsConfig *tls.Config) *Server {
	if tlsConfig == nil {
		tlsConfig = GenerateTLSConfig()
	}
	return &Server{
		tlsConfig: tlsConfig,
		tunnels:   make(map[uint32]*Tunnel),
		stopChan:  make(chan struct{}),
	}
}

func (s *Server) SetOnConnect(fn func(tunnelID uint32, addr string, port uint16) (net.Conn, error)) {
	s.onConnect = fn
}

func (s *Server) Listen(addr string) error {
	listener, err := quic.ListenAddr(addr, s.tlsConfig, &quic.Config{
		MaxIncomingStreams:     MaxIncomingStreams,
		MaxIdleTimeout:         MaxIdleTimeout,
		KeepAlivePeriod:        KeepAlivePeriod,
		EnableDatagrams:        false,
		DisablePathMTUDiscovery: false,
	})
	if err != nil {
		return fmt.Errorf("failed to listen QUIC: %w", err)
	}
	s.listener = listener

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn *quic.Conn) {
	defer s.wg.Done()
	defer conn.CloseWithError(0, "connection closed")

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		s.wg.Add(1)
		go s.handleStream(conn, NewStreamWrapper(stream))
	}
}

func (s *Server) handleStream(conn *quic.Conn, stream *StreamWrapper) {
	defer s.wg.Done()
	defer stream.Close()

	header := make([]byte, 5)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	streamType := header[0]
	tunnelID := binary.BigEndian.Uint32(header[1:5])

	switch streamType {
	case StreamTypeControl:
		s.handleControlStream(conn, stream, tunnelID)
	case StreamTypeData:
		s.handleDataStream(stream, tunnelID)
	}
}

func (s *Server) handleControlStream(conn *quic.Conn, stream *StreamWrapper, tunnelID uint32) {
	defer stream.Close()

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		stream.SetReadDeadline(time.Now().Add(5 * time.Second))

		var msgLen uint16
		if err := binary.Read(stream, binary.BigEndian, &msgLen); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(stream, msg); err != nil {
			return
		}

		msgType := msg[0]
		switch msgType {
		case ControlConnect:
			s.handleConnect(conn, stream, msg[1:])
		case ControlClose:
			s.handleClose(tunnelID)
			return
		case ControlHeartbeat:
			s.handleHeartbeat(stream)
		}
	}
}

func (s *Server) handleConnect(conn *quic.Conn, controlStream *StreamWrapper, data []byte) {
	if len(data) < 7 {
		return
	}

	req := &ConnectRequest{
		TunnelID: binary.BigEndian.Uint32(data[0:4]),
	}
	addrLen := int(binary.BigEndian.Uint16(data[4:6]))
	if len(data) < 6+addrLen+2 {
		return
	}
	req.TargetAddr = string(data[6 : 6+addrLen])
	req.TargetPort = binary.BigEndian.Uint16(data[6+addrLen : 6+addrLen+2])
	if len(data) > 6+addrLen+2 {
		req.Protocol = data[6+addrLen+2]
	}

	var targetConn net.Conn
	var err error

	if s.onConnect != nil {
		targetConn, err = s.onConnect(req.TunnelID, req.TargetAddr, req.TargetPort)
	} else {
		targetConn, err = net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", req.TargetAddr, req.TargetPort),
			DialTimeout)
	}

	resp := &ConnectResponse{
		TunnelID: req.TunnelID,
		Success:  err == nil,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	respData := make([]byte, 7)
	binary.BigEndian.PutUint32(respData[0:4], resp.TunnelID)
	if resp.Success {
		respData[4] = 1
	}
	errLen := min(len(resp.Error), 255)
	respData[5] = byte(errLen)
	respData = append(respData, []byte(resp.Error[:errLen])...)

	msgLen := uint16(len(respData) + 1)
	binary.Write(controlStream, binary.BigEndian, msgLen)
	controlStream.Write([]byte{ControlAck})
	controlStream.Write(respData)

	if err != nil {
		return
	}

	dataStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		targetConn.Close()
		return
	}

	header := make([]byte, 5)
	header[0] = StreamTypeData
	binary.BigEndian.PutUint32(header[1:5], req.TunnelID)
	dataStream.Write(header)

	tunnel := &Tunnel{
		ID:         req.TunnelID,
		TargetConn: targetConn,
		Stream:     NewStreamWrapper(dataStream),
		CreatedAt:  time.Now(),
		done:       make(chan struct{}),
	}

	s.mu.Lock()
	s.tunnels[req.TunnelID] = tunnel
	s.mu.Unlock()

	atomic.AddUint64(&s.stats.TotalConnections, 1)
	atomic.AddInt64(&s.stats.ActiveConnections, 1)

	s.wg.Add(1)
	go s.forwardData(tunnel)
}

func (s *Server) handleClose(tunnelID uint32) {
	s.mu.Lock()
	tunnel, exists := s.tunnels[tunnelID]
	if exists {
		delete(s.tunnels, tunnelID)
	}
	s.mu.Unlock()

	if tunnel != nil {
		tunnel.Close()
		atomic.AddInt64(&s.stats.ActiveConnections, -1)
	}
}

func (s *Server) handleHeartbeat(stream *StreamWrapper) {
	hb := &Heartbeat{
		Timestamp:     time.Now().UnixMilli(),
		ActiveStreams: len(s.tunnels),
		BytesIn:       atomic.LoadUint64(&s.stats.BytesIn),
		BytesOut:      atomic.LoadUint64(&s.stats.BytesOut),
	}

	data := make([]byte, 28)
	binary.BigEndian.PutUint64(data[0:8], uint64(hb.Timestamp))
	binary.BigEndian.PutUint32(data[8:12], uint32(hb.ActiveStreams))
	binary.BigEndian.PutUint64(data[12:20], hb.BytesIn)
	binary.BigEndian.PutUint64(data[20:28], hb.BytesOut)

	msgLen := uint16(len(data) + 1)
	binary.Write(stream, binary.BigEndian, msgLen)
	stream.Write([]byte{ControlHeartbeat})
	stream.Write(data)
}

func (s *Server) handleDataStream(stream *StreamWrapper, tunnelID uint32) {
	s.mu.RLock()
	tunnel, exists := s.tunnels[tunnelID]
	s.mu.RUnlock()

	if !exists || tunnel == nil {
		stream.Close()
		return
	}

	buf := make([]byte, StreamBufferSize)
	for {
		select {
		case <-tunnel.done:
			return
		case <-s.stopChan:
			return
		default:
		}

		stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := stream.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n > 0 && tunnel.TargetConn != nil {
			tunnel.mu.Lock()
			tunnel.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			wn, werr := tunnel.TargetConn.Write(buf[:n])
			tunnel.mu.Unlock()

			if werr != nil {
				return
			}

			atomic.AddUint64(&tunnel.BytesOut, uint64(wn))
			atomic.AddUint64(&s.stats.BytesOut, uint64(wn))
		}
	}
}

func (s *Server) forwardData(tunnel *Tunnel) {
	defer s.wg.Done()
	defer func() {
		tunnel.Close()
		s.mu.Lock()
		delete(s.tunnels, tunnel.ID)
		s.mu.Unlock()
		atomic.AddInt64(&s.stats.ActiveConnections, -1)
	}()

	buf := make([]byte, StreamBufferSize)
	for {
		select {
		case <-tunnel.done:
			return
		case <-s.stopChan:
			return
		default:
		}

		tunnel.mu.Lock()
		if tunnel.TargetConn == nil {
			tunnel.mu.Unlock()
			return
		}
		tunnel.TargetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := tunnel.TargetConn.Read(buf)
		tunnel.mu.Unlock()

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n > 0 {
			tunnel.Stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			wn, werr := tunnel.Stream.Write(buf[:n])
			if werr != nil {
				return
			}

			atomic.AddUint64(&tunnel.BytesIn, uint64(wn))
			atomic.AddUint64(&s.stats.BytesIn, uint64(wn))
		}
	}
}

func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}
	t.closed = true
	close(t.done)

	if t.TargetConn != nil {
		t.TargetConn.Close()
	}
	if t.Stream != nil {
		t.Stream.Close()
	}
}

func (s *Server) Close() error {
	close(s.stopChan)

	s.mu.Lock()
	for _, tunnel := range s.tunnels {
		tunnel.Close()
	}
	s.tunnels = make(map[uint32]*Tunnel)
	s.mu.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()
	return nil
}

func (s *Server) GetStats() ServerStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return ServerStats{
		TotalConnections:  atomic.LoadUint64(&s.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&s.stats.ActiveConnections),
		BytesIn:           atomic.LoadUint64(&s.stats.BytesIn),
		BytesOut:          atomic.LoadUint64(&s.stats.BytesOut),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

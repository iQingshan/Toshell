package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	StreamTypeControl = 0x00
	StreamTypeData    = 0x01

	ControlConnect   = 0x01
	ControlClose     = 0x02
	ControlHeartbeat = 0x03
	ControlAck       = 0x04

	MaxIncomingStreams = 10000
	MaxIdleTimeout     = 30 * time.Second
	KeepAlivePeriod    = 15 * time.Second
	HandshakeTimeout   = 10 * time.Second
	DialTimeout        = 15 * time.Second
	StreamBufferSize   = 64 * 1024
)

type ConnectRequest struct {
	TunnelID   uint32
	TargetAddr string
	TargetPort uint16
	Protocol   byte
}

type ConnectResponse struct {
	TunnelID uint32
	Success  bool
	Error    string
}

type Heartbeat struct {
	Timestamp     int64
	ActiveStreams int
	BytesIn       uint64
	BytesOut      uint64
}

func GenerateTLSConfig() *tls.Config {
	return generateTLSConfig()
}

func GenerateClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"toshell-quic"},
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"toshell-quic"},
	}
}

type StreamWrapper struct {
	stream *quic.Stream
	closed atomic.Bool
}

func NewStreamWrapper(stream *quic.Stream) *StreamWrapper {
	return &StreamWrapper{stream: stream}
}

func (sw *StreamWrapper) Read(p []byte) (n int, err error) {
	if sw.closed.Load() {
		return 0, net.ErrClosed
	}
	return (*sw.stream).Read(p)
}

func (sw *StreamWrapper) Write(p []byte) (n int, err error) {
	if sw.closed.Load() {
		return 0, net.ErrClosed
	}
	return (*sw.stream).Write(p)
}

func (sw *StreamWrapper) Close() error {
	if sw.closed.CompareAndSwap(false, true) {
		return (*sw.stream).Close()
	}
	return nil
}

func (sw *StreamWrapper) SetDeadline(t time.Time) error {
	if sw.closed.Load() {
		return net.ErrClosed
	}
	return (*sw.stream).SetDeadline(t)
}

func (sw *StreamWrapper) SetReadDeadline(t time.Time) error {
	if sw.closed.Load() {
		return net.ErrClosed
	}
	return (*sw.stream).SetReadDeadline(t)
}

func (sw *StreamWrapper) SetWriteDeadline(t time.Time) error {
	if sw.closed.Load() {
		return net.ErrClosed
	}
	return (*sw.stream).SetWriteDeadline(t)
}

func (sw *StreamWrapper) IsClosed() bool {
	return sw.closed.Load()
}

type Client struct {
	conn          *quic.Conn
	controlStream *StreamWrapper
	tlsConfig     *tls.Config
	tunnels       map[uint32]*ClientTunnel
	mu            sync.RWMutex
	stopChan      chan struct{}
	wg            sync.WaitGroup
	stats         ClientStats
	controlMu     sync.Mutex
}

type ClientStats struct {
	TotalConnections  uint64
	ActiveConnections int64
	BytesIn           uint64
	BytesOut          uint64
}

type ClientTunnel struct {
	ID        uint32
	Stream    *StreamWrapper
	LocalConn net.Conn
	CreatedAt time.Time
	BytesIn   uint64
	BytesOut  uint64
	done      chan struct{}
	mu        sync.Mutex
	closed    bool
}

func NewClient(tlsConfig *tls.Config) *Client {
	if tlsConfig == nil {
		tlsConfig = GenerateClientTLSConfig()
	}
	return &Client{
		tlsConfig: tlsConfig,
		tunnels:   make(map[uint32]*ClientTunnel),
		stopChan:  make(chan struct{}),
	}
}

func (c *Client) Connect(addr string) error {
	conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, &quic.Config{
		MaxIdleTimeout:       MaxIdleTimeout,
		KeepAlivePeriod:      KeepAlivePeriod,
		EnableDatagrams:      false,
		HandshakeIdleTimeout: HandshakeTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to connect QUIC server: %w", err)
	}
	c.conn = conn

	controlStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "failed to open control stream")
		return fmt.Errorf("failed to open control stream: %w", err)
	}
	c.controlStream = NewStreamWrapper(controlStream)

	header := make([]byte, 5)
	header[0] = StreamTypeControl
	binary.BigEndian.PutUint32(header[1:5], 0)
	c.controlStream.Write(header)

	c.wg.Add(1)
	go c.heartbeatLoop()

	c.wg.Add(1)
	go c.receiveLoop()

	return nil
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(KeepAlivePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.sendHeartbeat()
		}
	}
}

func (c *Client) sendHeartbeat() {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()

	if c.controlStream == nil || c.controlStream.IsClosed() {
		return
	}

	msgLen := uint16(1)
	binary.Write(c.controlStream, binary.BigEndian, msgLen)
	c.controlStream.Write([]byte{ControlHeartbeat})
}

func (c *Client) receiveLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		stream, err := c.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		c.wg.Add(1)
		go c.handleStream(NewStreamWrapper(stream))
	}
}

func (c *Client) handleStream(stream *StreamWrapper) {
	defer c.wg.Done()
	defer stream.Close()

	header := make([]byte, 5)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	streamType := header[0]
	tunnelID := binary.BigEndian.Uint32(header[1:5])

	if streamType == StreamTypeData {
		c.handleDataStream(stream, tunnelID)
	}
}

func (c *Client) handleDataStream(stream *StreamWrapper, tunnelID uint32) {
	c.mu.RLock()
	tunnel, exists := c.tunnels[tunnelID]
	c.mu.RUnlock()

	if !exists || tunnel == nil {
		stream.Close()
		return
	}

	buf := make([]byte, StreamBufferSize)
	for {
		select {
		case <-tunnel.done:
			return
		case <-c.stopChan:
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

		if n > 0 && tunnel.LocalConn != nil {
			tunnel.mu.Lock()
			tunnel.LocalConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			wn, werr := tunnel.LocalConn.Write(buf[:n])
			tunnel.mu.Unlock()

			if werr != nil {
				return
			}

			atomic.AddUint64(&tunnel.BytesOut, uint64(wn))
			atomic.AddUint64(&c.stats.BytesOut, uint64(wn))
		}
	}
}

func (c *Client) Dial(tunnelID uint32, targetAddr string, targetPort uint16) error {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()

	if c.controlStream == nil || c.controlStream.IsClosed() {
		return fmt.Errorf("control stream closed")
	}

	req := &ConnectRequest{
		TunnelID:   tunnelID,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		Protocol:   0x01,
	}

	addrBytes := []byte(req.TargetAddr)
	data := make([]byte, 7+len(addrBytes))
	binary.BigEndian.PutUint32(data[0:4], req.TunnelID)
	binary.BigEndian.PutUint16(data[4:6], uint16(len(addrBytes)))
	copy(data[6:], addrBytes)
	binary.BigEndian.PutUint16(data[6+len(addrBytes):], req.TargetPort)

	msgLen := uint16(len(data) + 1)
	binary.Write(c.controlStream, binary.BigEndian, msgLen)
	c.controlStream.Write([]byte{ControlConnect})
	c.controlStream.Write(data)

	return nil
}

func (c *Client) WaitForConnect(tunnelID uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		_, exists := c.tunnels[tunnelID]
		c.mu.RUnlock()
		if exists {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for tunnel %d", tunnelID)
}

func (c *Client) CloseTunnel(tunnelID uint32) {
	c.mu.Lock()
	tunnel, exists := c.tunnels[tunnelID]
	if exists {
		delete(c.tunnels, tunnelID)
	}
	c.mu.Unlock()

	if tunnel != nil {
		tunnel.Close()
		atomic.AddInt64(&c.stats.ActiveConnections, -1)
	}

	c.controlMu.Lock()
	if c.controlStream != nil && !c.controlStream.IsClosed() {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, tunnelID)
		msgLen := uint16(len(data) + 1)
		binary.Write(c.controlStream, binary.BigEndian, msgLen)
		c.controlStream.Write([]byte{ControlClose})
		c.controlStream.Write(data)
	}
	c.controlMu.Unlock()
}

func (c *Client) Forward(tunnelID uint32, localConn net.Conn) {
	c.mu.Lock()
	tunnel, exists := c.tunnels[tunnelID]
	if !exists {
		stream, err := c.conn.OpenStreamSync(context.Background())
		if err != nil {
			c.mu.Unlock()
			localConn.Close()
			return
		}

		header := make([]byte, 5)
		header[0] = StreamTypeData
		binary.BigEndian.PutUint32(header[1:5], tunnelID)
		stream.Write(header)

		tunnel = &ClientTunnel{
			ID:        tunnelID,
			Stream:    NewStreamWrapper(stream),
			LocalConn: localConn,
			CreatedAt: time.Now(),
			done:      make(chan struct{}),
		}
		c.tunnels[tunnelID] = tunnel
		atomic.AddUint64(&c.stats.TotalConnections, 1)
		atomic.AddInt64(&c.stats.ActiveConnections, 1)
	} else {
		tunnel.LocalConn = localConn
	}
	c.mu.Unlock()

	c.wg.Add(1)
	go c.forwardLocalToRemote(tunnel)
}

func (c *Client) forwardLocalToRemote(tunnel *ClientTunnel) {
	defer c.wg.Done()
	defer func() {
		tunnel.Close()
		c.mu.Lock()
		delete(c.tunnels, tunnel.ID)
		c.mu.Unlock()
		atomic.AddInt64(&c.stats.ActiveConnections, -1)
	}()

	buf := make([]byte, StreamBufferSize)
	for {
		select {
		case <-tunnel.done:
			return
		case <-c.stopChan:
			return
		default:
		}

		tunnel.mu.Lock()
		if tunnel.LocalConn == nil {
			tunnel.mu.Unlock()
			return
		}
		tunnel.LocalConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := tunnel.LocalConn.Read(buf)
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
			atomic.AddUint64(&c.stats.BytesIn, uint64(wn))
		}
	}
}

func (t *ClientTunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}
	t.closed = true
	close(t.done)

	if t.LocalConn != nil {
		t.LocalConn.Close()
	}
	if t.Stream != nil {
		t.Stream.Close()
	}
}

func (c *Client) Close() error {
	close(c.stopChan)

	c.mu.Lock()
	for _, tunnel := range c.tunnels {
		tunnel.Close()
	}
	c.tunnels = make(map[uint32]*ClientTunnel)
	c.mu.Unlock()

	if c.controlStream != nil {
		c.controlStream.Close()
	}
	if c.conn != nil {
		c.conn.CloseWithError(0, "client closed")
	}

	c.wg.Wait()
	return nil
}

func (c *Client) GetStats() ClientStats {
	return ClientStats{
		TotalConnections:  atomic.LoadUint64(&c.stats.TotalConnections),
		ActiveConnections: atomic.LoadInt64(&c.stats.ActiveConnections),
		BytesIn:           atomic.LoadUint64(&c.stats.BytesIn),
		BytesOut:          atomic.LoadUint64(&c.stats.BytesOut),
	}
}

package manager

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"toshell/internal/common/tunnel/protocol"
)

type TunnelManager struct {
	tunnels  map[uint32]*Tunnel
	mu       sync.RWMutex
	nextID   uint32

	pool     *ConnectionPool

	onCreate func(*Tunnel)
	onClose  func(uint32)

	stats ManagerStats
}

type Tunnel struct {
	ID         uint32
	Protocol   string
	TargetAddr string
	TargetPort uint16
	SourceAddr string
	SourcePort uint16
	State      protocol.TunnelState
	CreatedAt  time.Time
	BytesIn    uint64
	BytesOut   uint64

	conn     net.Conn
	connMu   sync.Mutex
	done     chan struct{}
	ready    chan struct{}
	pool     *ConnectionPool
}

type ManagerStats struct {
	TotalCreated uint64
	TotalClosed  uint64
	ActiveCount  uint64
}

type TunnelManagerOption func(*TunnelManager)

func WithPool(pool *ConnectionPool) TunnelManagerOption {
	return func(tm *TunnelManager) {
		tm.pool = pool
	}
}

func WithOnCreate(f func(*Tunnel)) TunnelManagerOption {
	return func(tm *TunnelManager) {
		tm.onCreate = f
	}
}

func WithOnClose(f func(uint32)) TunnelManagerOption {
	return func(tm *TunnelManager) {
		tm.onClose = f
	}
}

func NewTunnelManager(opts ...TunnelManagerOption) *TunnelManager {
	tm := &TunnelManager{
		tunnels: make(map[uint32]*Tunnel),
		nextID:  1,
	}

	for _, opt := range opts {
		opt(tm)
	}

	if tm.pool == nil {
		tm.pool = NewConnectionPool()
	}

	return tm
}

func (tm *TunnelManager) Create(proto, targetAddr string, targetPort uint16, conn net.Conn) (*Tunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	id := tm.nextID
	tm.nextID++

	tunnel := &Tunnel{
		ID:         id,
		Protocol:   proto,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		State:      protocol.TunnelStatePending,
		CreatedAt:  time.Now(),
		conn:       conn,
		done:       make(chan struct{}),
		ready:      make(chan struct{}),
		pool:       tm.pool,
	}

	tm.tunnels[id] = tunnel

	if conn != nil {
		if _, err := tm.pool.Add(id, conn); err != nil {
			delete(tm.tunnels, id)
			return nil, err
		}
	}

	atomic.AddUint64(&tm.stats.TotalCreated, 1)
	atomic.AddUint64(&tm.stats.ActiveCount, 1)

	if tm.onCreate != nil {
		go tm.onCreate(tunnel)
	}

	return tunnel, nil
}

func (tm *TunnelManager) Get(id uint32) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tunnel, ok := tm.tunnels[id]
	return tunnel, ok
}

func (tm *TunnelManager) Remove(id uint32) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tunnel, ok := tm.tunnels[id]; ok {
		tunnel.Close()
		delete(tm.tunnels, id)

		atomic.AddUint64(&tm.stats.TotalClosed, 1)
		if atomic.LoadUint64(&tm.stats.ActiveCount) > 0 {
			atomic.AddUint64(&tm.stats.ActiveCount, ^uint64(0))
		}

		if tm.onClose != nil {
			go tm.onClose(id)
		}
	}
}

func (tm *TunnelManager) List() []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, tunnel := range tm.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	return tunnels
}

func (tm *TunnelManager) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.tunnels)
}

func (tm *TunnelManager) CloseAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, tunnel := range tm.tunnels {
		tunnel.Close()
	}
	tm.tunnels = make(map[uint32]*Tunnel)
}

func (tm *TunnelManager) Stop() {
	tm.CloseAll()
	if tm.pool != nil {
		tm.pool.Stop()
	}
}

func (tm *TunnelManager) NextID() uint32 {
	return atomic.AddUint32(&tm.nextID, 1) - 1
}

func (tm *TunnelManager) GetStats() ManagerStats {
	return ManagerStats{
		TotalCreated: atomic.LoadUint64(&tm.stats.TotalCreated),
		TotalClosed:  atomic.LoadUint64(&tm.stats.TotalClosed),
		ActiveCount:  uint64(tm.Count()),
	}
}

func (tm *TunnelManager) GetPool() *ConnectionPool {
	return tm.pool
}

func (t *Tunnel) Close() {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.State == protocol.TunnelStateClosed {
		return
	}

	t.State = protocol.TunnelStateClosed

	select {
	case <-t.done:
		return
	default:
		close(t.done)
	}

	if t.conn != nil {
		t.conn.Close()
	}

	if t.pool != nil {
		t.pool.Remove(t.ID)
	}
}

func (t *Tunnel) SetActive() {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.State != protocol.TunnelStateClosed {
		t.State = protocol.TunnelStateActive
		select {
		case <-t.ready:
		default:
			close(t.ready)
		}
	}
}

func (t *Tunnel) SetError() {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	t.State = protocol.TunnelStateError
}

func (t *Tunnel) IsReady() <-chan struct{} {
	return t.ready
}

func (t *Tunnel) Done() <-chan struct{} {
	return t.done
}

func (t *Tunnel) AddBytesIn(n uint64) {
	atomic.AddUint64(&t.BytesIn, n)
}

func (t *Tunnel) AddBytesOut(n uint64) {
	atomic.AddUint64(&t.BytesOut, n)
}

func (t *Tunnel) GetConn() net.Conn {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	return t.conn
}

func (t *Tunnel) SetConn(conn net.Conn) {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	t.conn = conn
}

func (t *Tunnel) GetState() protocol.TunnelState {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	return t.State
}

func (t *Tunnel) GetStats() (bytesIn, bytesOut uint64, duration time.Duration) {
	return atomic.LoadUint64(&t.BytesIn), atomic.LoadUint64(&t.BytesOut), time.Since(t.CreatedAt)
}

func (t *Tunnel) Write(data []byte) (int, error) {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn == nil || t.State == protocol.TunnelStateClosed {
		return 0, fmt.Errorf("tunnel closed")
	}

	t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err := t.conn.Write(data)
	if err != nil {
		t.State = protocol.TunnelStateError
		return n, err
	}

	atomic.AddUint64(&t.BytesOut, uint64(n))
	return n, nil
}

func (t *Tunnel) Read(buf []byte) (int, error) {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn == nil || t.State == protocol.TunnelStateClosed {
		return 0, fmt.Errorf("tunnel closed")
	}

	t.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := t.conn.Read(buf)
	if err != nil {
		return n, err
	}

	atomic.AddUint64(&t.BytesIn, uint64(n))
	return n, nil
}

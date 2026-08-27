package manager

import (
	"fmt"
	"net"
	"sync"
	"time"

	"toshell/internal/common/tunnel/protocol"
)

type ConnectionPool struct {
	connections map[uint32]*PoolEntry
	mu          sync.RWMutex

	maxConnections int
	idleTimeout    time.Duration
	maxIdleTime    time.Duration

	onEvict func(uint32)

	stopChan chan struct{}
	wg       sync.WaitGroup
}

type PoolEntry struct {
	ID         uint32
	Conn       net.Conn
	LastActive time.Time
	BytesIn    uint64
	BytesOut   uint64
	State      protocol.ConnState
	CreatedAt  time.Time
	mu         sync.Mutex
	done       chan struct{}
}

type PoolOption func(*ConnectionPool)

func WithMaxConnections(max int) PoolOption {
	return func(p *ConnectionPool) {
		p.maxConnections = max
	}
}

func WithIdleTimeout(d time.Duration) PoolOption {
	return func(p *ConnectionPool) {
		p.idleTimeout = d
	}
}

func WithMaxIdleTime(d time.Duration) PoolOption {
	return func(p *ConnectionPool) {
		p.maxIdleTime = d
	}
}

func WithOnEvict(f func(uint32)) PoolOption {
	return func(p *ConnectionPool) {
		p.onEvict = f
	}
}

func NewConnectionPool(opts ...PoolOption) *ConnectionPool {
	p := &ConnectionPool{
		connections:    make(map[uint32]*PoolEntry),
		maxConnections: 10000,
		idleTimeout:    5 * time.Minute,
		maxIdleTime:    30 * time.Minute,
		stopChan:       make(chan struct{}),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.wg.Add(1)
	go p.cleanupLoop()

	return p
}

func (p *ConnectionPool) Add(id uint32, conn net.Conn) (*PoolEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.connections) >= p.maxConnections {
		return nil, fmt.Errorf("connection pool full")
	}

	entry := &PoolEntry{
		ID:         id,
		Conn:       conn,
		LastActive: time.Now(),
		State:      protocol.ConnStateActive,
		CreatedAt:  time.Now(),
		done:       make(chan struct{}),
	}

	p.connections[id] = entry
	return entry, nil
}

func (p *ConnectionPool) Get(id uint32) (*PoolEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.connections[id]
	return entry, ok
}

func (p *ConnectionPool) Remove(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.connections[id]; ok {
		entry.Close()
		delete(p.connections, id)
		if p.onEvict != nil {
			go p.onEvict(id)
		}
	}
}

func (p *ConnectionPool) GetAll() []*PoolEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entries := make([]*PoolEntry, 0, len(p.connections))
	for _, entry := range p.connections {
		entries = append(entries, entry)
	}
	return entries
}

func (p *ConnectionPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.connections)
}

func (p *ConnectionPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, entry := range p.connections {
		entry.Close()
	}
	p.connections = make(map[uint32]*PoolEntry)
}

func (p *ConnectionPool) Stop() {
	close(p.stopChan)
	p.wg.Wait()
	p.CloseAll()
}

func (p *ConnectionPool) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

func (p *ConnectionPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	for id, entry := range p.connections {
		if entry.State == protocol.ConnStateClosed {
			delete(p.connections, id)
			if p.onEvict != nil {
				go p.onEvict(id)
			}
			continue
		}

		idleTime := now.Sub(entry.LastActive)
		if idleTime > p.maxIdleTime {
			entry.Close()
			delete(p.connections, id)
			if p.onEvict != nil {
				go p.onEvict(id)
			}
		}
	}
}

func (e *PoolEntry) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State == protocol.ConnStateClosed {
		return
	}

	e.State = protocol.ConnStateClosed
	select {
	case <-e.done:
		return
	default:
		close(e.done)
	}

	if e.Conn != nil {
		e.Conn.Close()
	}
}

func (e *PoolEntry) UpdateActivity() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.LastActive = time.Now()
}

func (e *PoolEntry) AddBytesIn(n uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.BytesIn += n
	e.LastActive = time.Now()
}

func (e *PoolEntry) AddBytesOut(n uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.BytesOut += n
	e.LastActive = time.Now()
}

func (e *PoolEntry) SetState(state protocol.ConnState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.State = state
}

func (e *PoolEntry) IsClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.State == protocol.ConnStateClosed
}

func (e *PoolEntry) Done() <-chan struct{} {
	return e.done
}

func (e *PoolEntry) GetStats() (bytesIn, bytesOut uint64, duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.BytesIn, e.BytesOut, time.Since(e.CreatedAt)
}

type HealthChecker struct {
	interval  time.Duration
	timeout   time.Duration
	checkFunc func(net.Conn) error

	stopChan chan struct{}
	wg       sync.WaitGroup
}

type HealthCheckOption func(*HealthChecker)

func WithHealthCheckInterval(d time.Duration) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.interval = d
	}
}

func WithHealthCheckTimeout(d time.Duration) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.timeout = d
	}
}

func WithHealthCheckFunc(f func(net.Conn) error) HealthCheckOption {
	return func(hc *HealthChecker) {
		hc.checkFunc = f
	}
}

func NewHealthChecker(opts ...HealthCheckOption) *HealthChecker {
	hc := &HealthChecker{
		interval: 60 * time.Second,
		timeout:  10 * time.Second,
		stopChan: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(hc)
	}

	return hc
}

func (hc *HealthChecker) Start(pool *ConnectionPool) {
	hc.wg.Add(1)
	go hc.checkLoop(pool)
}

func (hc *HealthChecker) Stop() {
	close(hc.stopChan)
	hc.wg.Wait()
}

func (hc *HealthChecker) checkLoop(pool *ConnectionPool) {
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopChan:
			return
		case <-ticker.C:
			hc.checkAll(pool)
		}
	}
}

func (hc *HealthChecker) checkAll(pool *ConnectionPool) {
	entries := pool.GetAll()

	for _, entry := range entries {
		if entry.State != protocol.ConnStateActive {
			continue
		}

		if err := hc.check(entry.Conn); err != nil {
			pool.Remove(entry.ID)
		}
	}
}

func (hc *HealthChecker) check(conn net.Conn) error {
	if hc.checkFunc != nil {
		return hc.checkFunc(conn)
	}

	// 默认健康检查：尝试探测连接状态而不破坏数据流
	// 通过检查连接是否 close 来判断
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return nil
	}

	// 使用 MSG_PEEK 的方式检查连接，或者使用 syscall
	// 简单方案：检查连接是否可写（不可写意味着断开）
	_ = tcpConn.SetWriteDeadline(time.Now().Add(hc.timeout))
	_, err := tcpConn.Write([]byte{})
	if err != nil {
		return err
	}
	tcpConn.SetWriteDeadline(time.Time{})

	return nil
}

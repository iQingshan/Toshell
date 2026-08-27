// Package optimized 提供对标 NPS 的高性能隧道中继实现。
// 核心设计原则：
//   1. io.CopyBuffer + 协程池 → 零 channel 开销的数据拷贝
//   2. Snappy 流压缩 → 比 gzip 快 10 倍的实时压缩
//   3. 令牌桶限速 → 单连接带宽控制
//   4. sync.Pool 缓冲区分级 → 减少 GC 压力
//   5. 批量帧写入 → 减少系统调用
package optimized

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"toshell/pkg/goroutine"
	"toshell/pkg/rate"
)

// ─── 常量 ──────────────────────────────────────────────────────────────────────

const (
	DefaultReadBufSize   = 64 * 1024  // 64KB 读缓冲
	DefaultWriteBufSize  = 64 * 1024  // 64KB 写缓冲
	DefaultBatchSize     = 32 * 1024  // 32KB 批量写入阈值
	DefaultBatchInterval = 5 * time.Millisecond // 批量窗口
)

// ─── Buffer Pool 分级管理（对标 NPS PoolSize 设计） ──────────────────────────

var (
	// BigBufPool 64KB 读写缓冲池
	BigBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, DefaultReadBufSize)
		},
	}

	// CopyBufPool 32KB io.Copy 缓冲池
	CopyBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}

	// SmallBufPool 8KB 小数据缓冲池
	SmallBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8*1024)
		},
	}
)

// ─── 高性能中继器（对标 NPS CopyWaitGroup + gost transport） ──────────────────

// RelayConfig 中继配置。
type RelayConfig struct {
	Rate      *rate.Rate     // 限速器（nil = 不限速）
	IsSnappy  bool           // 是否 Snappy 压缩
	FlowStats *FlowStats     // 流量统计（可选）
	Timeout   time.Duration  // 读写超时
}

// FlowStats 流量统计。
// 使用 atomic.Uint64 以保证在 32 位(386)构建下 8 字节对齐，避免 atomic 操作 panic。
type FlowStats struct {
	BytesIn  atomic.Uint64
	BytesOut atomic.Uint64
}

func (fs *FlowStats) AddIn(n uint64)  { fs.BytesIn.Add(n) }
func (fs *FlowStats) AddOut(n uint64) { fs.BytesOut.Add(n) }
func (fs *FlowStats) GetIn() uint64   { return fs.BytesIn.Load() }
func (fs *FlowStats) GetOut() uint64  { return fs.BytesOut.Load() }

// Relay 高性能双向中继，对标 NPS CopyWaitGroup。
// conn1: 隧道侧连接
// conn2: 外部侧连接
func Relay(conn1, conn2 net.Conn, cfg *RelayConfig) {
	if cfg == nil {
		cfg = &RelayConfig{}
	}

	// TCP 优化
	OptimizeTCPConn(conn1)
	OptimizeTCPConn(conn2)

	// 使用协程池进行双向拷贝（对标 NPS CopyConnsPool）
	goroutine.CopyBidirectional(
		&connWrapper{Conn: conn1, timeout: cfg.Timeout},
		&connWrapper{Conn: conn2, timeout: cfg.Timeout},
		cfg.Rate,
	)
}

// RelayOneWay 高性能单向中继（仅 conn1 → conn2）。
func RelayOneWay(dst, src net.Conn, cfg *RelayConfig) (int64, error) {
	if cfg == nil {
		cfg = &RelayConfig{}
	}

	OptimizeTCPConn(dst)
	OptimizeTCPConn(src)

	return goroutine.CopyOneWay(
		&connWrapper{Conn: dst, timeout: cfg.Timeout},
		&connWrapper{Conn: src, timeout: cfg.Timeout},
		cfg.Rate,
	)
}

// ─── connWrapper：带超时的连接包装 ─────────────────────────────────────────

type connWrapper struct {
	net.Conn
	timeout time.Duration
}

func (cw *connWrapper) Read(b []byte) (int, error) {
	if cw.timeout > 0 {
		cw.Conn.SetReadDeadline(time.Now().Add(cw.timeout))
	}
	return cw.Conn.Read(b)
}

func (cw *connWrapper) Write(b []byte) (int, error) {
	if cw.timeout > 0 {
		cw.Conn.SetWriteDeadline(time.Now().Add(cw.timeout))
	}
	return cw.Conn.Write(b)
}

// ─── 批量写入器（对标 NPS 批处理，减少帧头开销） ──────────────────────────────

// BatchWriter 批量写入器，累积数据到阈值后一次性写入。
type BatchWriter struct {
	writer   func([]byte) error
	buf      []byte
	capacity int
	interval time.Duration
	timer    *time.Timer
	mu       sync.Mutex
	closed   int32
}

// NewBatchWriter 创建批量写入器。
func NewBatchWriter(writer func([]byte) error, capacity int, interval time.Duration) *BatchWriter {
	if capacity <= 0 {
		capacity = DefaultBatchSize
	}
	if interval <= 0 {
		interval = DefaultBatchInterval
	}
	bw := &BatchWriter{
		writer:   writer,
		buf:      make([]byte, 0, capacity),
		capacity: capacity,
		interval: interval,
	}
	return bw
}

// Write 写入数据到缓冲区，达到阈值自动刷新。
func (bw *BatchWriter) Write(data []byte) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if atomic.LoadInt32(&bw.closed) == 1 {
		return io.ErrClosedPipe
	}

	// 如果单次数据超过容量，先刷新再直接写入
	if len(data) >= bw.capacity {
		if len(bw.buf) > 0 {
			if err := bw.flushLocked(); err != nil {
				return err
			}
		}
		return bw.writer(data)
	}

	bw.buf = append(bw.buf, data...)

	// 达到阈值，刷新
	if len(bw.buf) >= bw.capacity {
		return bw.flushLocked()
	}

	// 启动定时器（如果没有）
	if bw.timer == nil {
		bw.timer = time.AfterFunc(bw.interval, func() {
			bw.mu.Lock()
			if len(bw.buf) > 0 && atomic.LoadInt32(&bw.closed) == 0 {
				bw.flushLocked()
			}
			bw.mu.Unlock()
		})
	}

	return nil
}

// Flush 强制刷新缓冲区。
func (bw *BatchWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked()
}

func (bw *BatchWriter) flushLocked() error {
	if len(bw.buf) == 0 {
		return nil
	}
	data := make([]byte, len(bw.buf))
	copy(data, bw.buf)
	bw.buf = bw.buf[:0]
	if bw.timer != nil {
		bw.timer.Stop()
		bw.timer = nil
	}
	return bw.writer(data)
}

// Close 关闭批量写入器，刷新剩余数据。
func (bw *BatchWriter) Close() error {
	atomic.StoreInt32(&bw.closed, 1)
	bw.mu.Lock()
	defer bw.mu.Unlock()
	if bw.timer != nil {
		bw.timer.Stop()
		bw.timer = nil
	}
	return bw.flushLocked()
}

// ─── TCP 连接优化 ────────────────────────────────────────────────────────────

func OptimizeTCPConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)        // 禁用 Nagle 算法
		tcpConn.SetKeepAlive(true)       // 开启 KeepAlive
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(256 * 1024)  // 256KB 读缓冲
		tcpConn.SetWriteBuffer(256 * 1024) // 256KB 写缓冲
	}
}

// ─── 全局初始化 ──────────────────────────────────────────────────────────────

func init() {
	goroutine.InitPool()
}

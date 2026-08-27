package channel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type DataChannel struct {
	tunnelID uint32
	conn     net.Conn

	sendChan chan []byte
	recvChan chan []byte

	writeMu sync.Mutex
	readMu  sync.Mutex

	bytesIn  uint64
	bytesOut uint64

	done    chan struct{}
	closed  int32
	onClose func()

	// 指针持有：sync.Pool 含 noCopy 锁，值拷贝会被 go vet 标记且存在隐患
	bufPool *sync.Pool
}

type DataChannelOption func(*DataChannel)

func WithBufferSize(size int) DataChannelOption {
	return func(dc *DataChannel) {
		dc.sendChan = make(chan []byte, size)
		dc.recvChan = make(chan []byte, size)
	}
}

func WithOnClose(f func()) DataChannelOption {
	return func(dc *DataChannel) {
		dc.onClose = f
	}
}

var dataBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 64*1024)
	},
}

func NewDataChannel(conn net.Conn, tunnelID uint32, opts ...DataChannelOption) *DataChannel {
	dc := &DataChannel{
		tunnelID: tunnelID,
		conn:     conn,
		sendChan: make(chan []byte, 1000),
		recvChan: make(chan []byte, 1000),
		done:     make(chan struct{}),
		bufPool: dataBufPool,
	}

	for _, opt := range opts {
		opt(dc)
	}

	return dc
}

func (dc *DataChannel) Start() {
	go dc.readLoop()
}

func (dc *DataChannel) readLoop() {
	buf := dc.bufPool.Get().([]byte)
	defer dc.bufPool.Put(buf)

	for {
		select {
		case <-dc.done:
			return
		default:
		}

		dc.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := dc.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			dc.Close()
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			atomic.AddUint64(&dc.bytesIn, uint64(n))

			select {
			case dc.sendChan <- data:
			case <-dc.done:
				return
			}
		}
	}
}

func (dc *DataChannel) SendData(data []byte) error {
	if dc.IsClosed() {
		return fmt.Errorf("channel closed")
	}

	select {
	case dc.recvChan <- data:
		return nil
	case <-dc.done:
		return fmt.Errorf("channel closed")
	}
}

func (dc *DataChannel) ReadData() ([]byte, bool) {
	select {
	case data := <-dc.sendChan:
		return data, true
	case <-dc.done:
		return nil, false
	}
}

func (dc *DataChannel) writeLoop() {
	for {
		select {
		case <-dc.done:
			return
		case data := <-dc.recvChan:
			dc.writeMu.Lock()
			dc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, err := dc.conn.Write(data)
			dc.writeMu.Unlock()

			if err != nil {
				dc.Close()
				return
			}

			atomic.AddUint64(&dc.bytesOut, uint64(n))
		}
	}
}

func (dc *DataChannel) WriteDirect(data []byte) (int, error) {
	if dc.IsClosed() {
		return 0, fmt.Errorf("channel closed")
	}

	dc.writeMu.Lock()
	defer dc.writeMu.Unlock()

	dc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err := dc.conn.Write(data)
	if err != nil {
		dc.Close()
		return n, err
	}

	atomic.AddUint64(&dc.bytesOut, uint64(n))
	return n, nil
}

func (dc *DataChannel) Close() {
	if !atomic.CompareAndSwapInt32(&dc.closed, 0, 1) {
		return
	}

	select {
	case <-dc.done:
		return
	default:
		close(dc.done)
	}

	dc.conn.Close()

	if dc.onClose != nil {
		dc.onClose()
	}
}

func (dc *DataChannel) IsClosed() bool {
	return atomic.LoadInt32(&dc.closed) == 1
}

func (dc *DataChannel) TunnelID() uint32 {
	return dc.tunnelID
}

func (dc *DataChannel) BytesIn() uint64 {
	return atomic.LoadUint64(&dc.bytesIn)
}

func (dc *DataChannel) BytesOut() uint64 {
	return atomic.LoadUint64(&dc.bytesOut)
}

func (dc *DataChannel) SetOnClose(f func()) {
	dc.onClose = f
}

func (dc *DataChannel) Done() <-chan struct{} {
	return dc.done
}

type DataChannelManager struct {
	channels map[uint32]*DataChannel
	mu       sync.RWMutex

	onData    func(tunnelID uint32, data []byte)
	notifyCh  chan struct{} // 事件通知通道，替代轮询
}

func NewDataChannelManager() *DataChannelManager {
	return &DataChannelManager{
		channels: make(map[uint32]*DataChannel),
		notifyCh: make(chan struct{}, 1), // buffered 以避免阻塞
	}
}

func (dm *DataChannelManager) Add(dc *DataChannel) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.channels[dc.TunnelID()] = dc

	// 为新通道设置回调：数据到达时通知
	origClose := dc.onClose
	dc.SetOnClose(func() {
		if origClose != nil {
			origClose()
		}
		// 通知管理器有新事件
		select {
		case dm.notifyCh <- struct{}{}:
		default:
		}
	})
}

func (dm *DataChannelManager) Get(tunnelID uint32) (*DataChannel, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	dc, ok := dm.channels[tunnelID]
	return dc, ok
}

func (dm *DataChannelManager) Remove(tunnelID uint32) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dc, ok := dm.channels[tunnelID]; ok {
		dc.Close()
		delete(dm.channels, tunnelID)
	}
}

func (dm *DataChannelManager) CloseAll() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, dc := range dm.channels {
		dc.Close()
	}
	dm.channels = make(map[uint32]*DataChannel)
}

func (dm *DataChannelManager) SendData(tunnelID uint32, data []byte) error {
	dm.mu.RLock()
	dc, ok := dm.channels[tunnelID]
	dm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("tunnel %d not found", tunnelID)
	}

	return dc.SendData(data)
}

func (dm *DataChannelManager) SetOnData(f func(tunnelID uint32, data []byte)) {
	dm.onData = f
}

func (dm *DataChannelManager) notify() {
	select {
	case dm.notifyCh <- struct{}{}:
	default:
	}
}

// StartPolling 使用事件驱动 + 低频率轮询混合模式，减少 CPU 占用
func (dm *DataChannelManager) StartPolling(stopChan <-chan struct{}) {
	go func() {
		// 快速通道：事件驱动
		// 保底轮询：50ms 一次（原来 10ms，减少 5 倍 CPU 占用）
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				return
			case <-dm.notifyCh:
				dm.pollAll()
			case <-ticker.C:
				dm.pollAll()
			}
		}
	}()
}

func (dm *DataChannelManager) pollAll() {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if dm.onData == nil {
		return
	}

	for _, dc := range dm.channels {
		if data, ok := dc.ReadData(); ok {
			dm.onData(dc.TunnelID(), data)
		}
	}
}

func (dm *DataChannelManager) Count() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return len(dm.channels)
}

func (dm *DataChannelManager) List() []uint32 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	ids := make([]uint32, 0, len(dm.channels))
	for id := range dm.channels {
		ids = append(ids, id)
	}
	return ids
}

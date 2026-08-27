// Package rate 提供令牌桶限速器，对标 NPS lib/rate，用于隧道级带宽控制。
package rate

import (
	"sync/atomic"
	"time"
)

// Rate 令牌桶限速器，使用原子操作实现无锁高性能。
type Rate struct {
	bucketSize        int64 // 桶容量（bytes）
	bucketSurplusSize int64 // 当前可用（bytes）
	bucketAddSize     int64 // 每秒补充量（bytes/s）
	stopChan          chan struct{}
	running           int32
}

// NewRate 创建一个限速器。
// addSize: 每秒补充的字节数。0 表示不限速。
func NewRate(addSize int64) *Rate {
	if addSize <= 0 {
		return nil
	}
	r := &Rate{
		bucketSize:        addSize * 2, // 桶容量为 2 倍的补充量，允许突发
		bucketSurplusSize: addSize,     // 初始满桶
		bucketAddSize:     addSize,
		stopChan:          make(chan struct{}),
	}
	r.Start()
	return r
}

// Start 启动 token 补充协程。
func (r *Rate) Start() {
	if r == nil || !atomic.CompareAndSwapInt32(&r.running, 0, 1) {
		return
	}
	go r.refillLoop()
}

// Stop 停止限速器。
func (r *Rate) Stop() {
	if r == nil || !atomic.CompareAndSwapInt32(&r.running, 1, 0) {
		return
	}
	close(r.stopChan)
}

// Get 获取 size 字节的令牌。如果没有足够的令牌，会阻塞等待。
// 对标 NPS Rate.Get()，使用自旋+短暂等待代替长时间阻塞。
func (r *Rate) Get(size int64) {
	if r == nil || size <= 0 {
		return
	}

	// 快速路径：令牌充足
	if atomic.LoadInt64(&r.bucketSurplusSize) >= size {
		atomic.AddInt64(&r.bucketSurplusSize, -size)
		return
	}

	// 慢速路径：等待令牌补充
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if atomic.LoadInt64(&r.bucketSurplusSize) >= size {
			atomic.AddInt64(&r.bucketSurplusSize, -size)
			return
		}
		select {
		case <-ticker.C:
		case <-r.stopChan:
			return
		}
	}
}

// refillLoop 每秒补充令牌。
func (r *Rate) refillLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if res := r.bucketSize - atomic.LoadInt64(&r.bucketSurplusSize); res > 0 {
				add := r.bucketAddSize
				if add > res {
					add = res
				}
				atomic.AddInt64(&r.bucketSurplusSize, add)
			}
		case <-r.stopChan:
			return
		}
	}
}

// Available 返回当前可用字节数。
func (r *Rate) Available() int64 {
	if r == nil {
		return 1<<63 - 1 // 不限速
	}
	return atomic.LoadInt64(&r.bucketSurplusSize)
}

// SetRate 动态调整速率（bytes/s）。0 表示不限速。
func (r *Rate) SetRate(bytesPerSec int64) {
	if r == nil {
		return
	}
	atomic.StoreInt64(&r.bucketAddSize, bytesPerSec)
	atomic.StoreInt64(&r.bucketSize, bytesPerSec*2)
}

// GetRate 获取当前速率（bytes/s）。
func (r *Rate) GetRate() int64 {
	if r == nil {
		return 0
	}
	return atomic.LoadInt64(&r.bucketAddSize)
}

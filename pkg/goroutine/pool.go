// Package goroutine 提供协程池，对标 NPS ants 协程池设计，
// 在高并发隧道场景下消除 goroutine 创建/销毁开销。
package goroutine

import (
	"io"
	"sync"
	"sync/atomic"
	"toshell/pkg/rate"

	"github.com/panjf2000/ants/v2"
)

// ─── 协程池全局变量 ──────────────────────────────────────────────────────────

var (
	// ConnCopyPool 单路连接拷贝池（200K 容量），对标 NPS connCopyPool
	ConnCopyPool *ants.PoolWithFunc

	// CopyConnsPool 双向连接拷贝池（100K 容量），对标 NPS CopyConnsPool
	CopyConnsPool *ants.PoolWithFunc

	initOnce sync.Once
)

// ─── 数据结构 ────────────────────────────────────────────────────────────────

type connGroup struct {
	dst  io.ReadWriteCloser
	src  io.ReadWriteCloser
	wg   *sync.WaitGroup
	n    *int64
	rate *rate.Rate
	isSnappy bool
}

type ConnPair struct {
	Conn1    io.ReadWriteCloser // 隧道侧
	Conn2    io.ReadWriteCloser // 外部侧
	Rate     *rate.Rate
	IsSnappy bool
}

// ─── 初始化 ──────────────────────────────────────────────────────────────────

func InitPool() {
	initOnce.Do(func() {
		var err error
		ConnCopyPool, err = ants.NewPoolWithFunc(200000, copyConnGroupTask,
			ants.WithNonblocking(false),
			ants.WithPreAlloc(true),
		)
		if err != nil {
			panic("failed to create ConnCopyPool: " + err.Error())
		}

		CopyConnsPool, err = ants.NewPoolWithFunc(100000, copyConnsTask,
			ants.WithNonblocking(false),
			ants.WithPreAlloc(true),
		)
		if err != nil {
			panic("failed to create CopyConnsPool: " + err.Error())
		}
	})
}

// ─── 任务函数 ────────────────────────────────────────────────────────────────

func copyConnGroupTask(v interface{}) {
	cg := v.(connGroup)
	n, err := copyBufferPooled(cg.dst, cg.src, cg.rate)
	if err != nil {
		cg.dst.Close()
		cg.src.Close()
	}
	if cg.n != nil {
		atomic.StoreInt64(cg.n, n)
	}
	cg.wg.Done()
}

func copyConnsTask(v interface{}) {
	pair := v.(ConnPair)
	wg := new(sync.WaitGroup)
	wg.Add(2)
	var in, out int64

	// conn2 → conn1: 外部数据流入隧道
	_ = ConnCopyPool.Invoke(connGroup{
		dst:  pair.Conn1,
		src:  pair.Conn2,
		wg:   wg,
		n:    &in,
		rate: pair.Rate,
	})

	// conn1 → conn2: 隧道数据流出到外部
	_ = ConnCopyPool.Invoke(connGroup{
		dst:  pair.Conn2,
		src:  pair.Conn1,
		wg:   wg,
		n:    &out,
		rate: pair.Rate,
	})

	wg.Wait()
}

// ─── 高性能拷贝（对标 NPS common.CopyBuffer） ─────────────────────────────────

const copyBufSize = 32 << 10 // 32KB copy buffer

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, copyBufSize)
		return &b
	},
}

func copyBufferPooled(dst io.Writer, src io.Reader, rt *rate.Rate) (int64, error) {
	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	buf := *bufPtr

	if rt == nil {
		return io.CopyBuffer(dst, src, buf)
	}

	// 带限速的拷贝
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			rt.Get(int64(nr))
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

// ─── 便捷函数 ────────────────────────────────────────────────────────────────

// CopyBidirectional 双向拷贝，使用协程池，对标 NPS CopyWaitGroup。
// conn1: 隧道侧连接（如 mux 连接）
// conn2: 外部侧连接（如 SOCKS5 客户端连接）
// flow: 流量统计（可选）
func CopyBidirectional(conn1, conn2 io.ReadWriteCloser, rt *rate.Rate) {
	wg := new(sync.WaitGroup)
	wg.Add(1)

	err := CopyConnsPool.Invoke(ConnPair{
		Conn1: conn1,
		Conn2: conn2,
		Rate:  rt,
	})
	if err != nil {
		// 池满时降级为直接拷贝
		copyBidirectionalFallback(conn1, conn2, rt)
		return
	}
	wg.Wait()

	conn1.Close()
	conn2.Close()
}

func copyBidirectionalFallback(conn1, conn2 io.ReadWriteCloser, rt *rate.Rate) {
	wg := new(sync.WaitGroup)
	wg.Add(2)
	var in, out int64

	go func() {
		defer wg.Done()
		in, _ = copyBufferPooled(conn1, conn2, rt)
		conn1.Close()
	}()

	go func() {
		defer wg.Done()
		out, _ = copyBufferPooled(conn2, conn1, rt)
		conn2.Close()
	}()

	wg.Wait()
	_ = in
	_ = out
}

// CopyOneWay 单路拷贝，当只需要单向拷贝时使用。
func CopyOneWay(dst io.ReadWriteCloser, src io.ReadWriteCloser, rt *rate.Rate) (int64, error) {
	return copyBufferPooled(dst, src, rt)
}

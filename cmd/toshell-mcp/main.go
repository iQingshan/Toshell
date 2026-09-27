// Command toshell-mcp 是 ToShell 对外 MCP 的 **stdio 桥**。
//
// 外部 MCP 客户端（Claude Desktop / Cursor / Cline / 自研 Agent）只会用 stdio 起子进程、
// 逐行收发 JSON-RPC；而 ToShell 的 MCP 服务端是 HTTP 端点（默认
// http://127.0.0.1:18082/mcp）。本程序把两者接起来：
//
//	stdin(一行一条 JSON-RPC) ──▶ POST http://127.0.0.1:18082/mcp ──▶ 服务端
//	stdout(协议响应)          ◀── JSON / SSE                        ◀──
//
// 三条硬约束：
//  1. **stdout 只出现协议数据**。任何日志、警告、错误、启动横幅都走 stderr——
//     stdio 桥最常见的事故就是把一句 "connected to ..." 写到 stdout，客户端直接解析失败。
//  2. **会话头要透传**。服务端在 initialize 响应里用 `Mcp-Session-Id` 下发会话 id，
//     之后每个请求都必须带上，否则服务端按协议回 400。
//  3. **失败必须回一个 JSON-RPC 错误**，不能让客户端一直等响应（否则 UI 卡死在"思考中"）。
//
// 用法：
//
//	toshell-mcp --url http://127.0.0.1:18082/mcp --token <TOKEN>
//	TOSHELL_MCP_URL=... TOSHELL_MCP_TOKEN=... toshell-mcp
//
// Claude Desktop 配置片段（claude_desktop_config.json）：
//
//	{
//	  "mcpServers": {
//	    "toshell": {
//	      "command": "C:\\\\path\\\\to\\\\toshell-mcp.exe",
//	      "args": ["--url", "http://127.0.0.1:18082/mcp"],
//	      "env": { "TOSHELL_MCP_TOKEN": "<与 configs/server.yaml 的 mcp.token 一致>" }
//	    }
//	  }
//	}
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultURL = "http://127.0.0.1:18082/mcp"

	// maxResponseBytes 单次响应上限（外置结果会走句柄，正常响应很小；
	// 留 64 MiB 给"服务端没配结果外置"的情况，同时避免被超大响应打爆内存）。
	maxResponseBytes = 64 << 20

	// maxRequestLineBytes 单行 stdin 上限。
	maxRequestLineBytes = 8 << 20

	clientName = "toshell-mcp"
)

func main() {
	os.Exit(run())
}

func run() int {
	// 日志一律 stderr：stdout 是协议通道。
	lg := log.New(os.Stderr, "["+clientName+"] ", log.LstdFlags)

	fs := flag.NewFlagSet(clientName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr) // -h / 参数错误也走 stderr
	var (
		urlFlag      = fs.String("url", envOr("TOSHELL_MCP_URL", defaultURL), "ToShell MCP HTTP 端点（env: TOSHELL_MCP_URL）")
		tokenFlag    = fs.String("token", envOr("TOSHELL_MCP_TOKEN", ""), "MCP 访问令牌（env: TOSHELL_MCP_TOKEN）")
		insecureFlag = fs.Bool("insecure", false, "跳过 TLS 证书校验（仅调试用，存在中间人风险）")
		timeoutFlag  = fs.Duration("timeout", 0, "单次 HTTP 请求超时（0=不限；工具调用可能很久，默认不限）")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s：把 MCP stdio 客户端桥接到 ToShell 的 HTTP MCP 端点\n\n", clientName)
		fmt.Fprintf(os.Stderr, "用法：%s [选项]\n\n选项：\n", clientName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n令牌也可以放在环境变量 TOSHELL_MCP_TOKEN 里（推荐，避免出现在进程命令行）。\n")
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		lg.Printf("[ERROR] 不接受位置参数: %v", fs.Args())
		fs.Usage()
		return 2
	}

	endpoint := strings.TrimSpace(*urlFlag)
	token := strings.TrimSpace(*tokenFlag)
	if token == "" {
		// fail-closed：没有令牌连上去也只会收获 401，不如立刻说清楚怎么配。
		lg.Printf("[ERROR] 未提供访问令牌。请设置环境变量 TOSHELL_MCP_TOKEN，" +
			"或用 --token <TOKEN>（值需与 configs/server.yaml 的 mcp.token 一致）")
		return 2
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		lg.Printf("[ERROR] 非法的 --url %q（需要 http:// 或 https:// 开头的完整 MCP 端点）", endpoint)
		return 2
	}

	if *insecureFlag {
		lg.Printf("[WARN] ============================================================")
		lg.Printf("[WARN] --insecure 已开启：将**跳过 TLS 证书校验**，任何能劫持网络的人")
		lg.Printf("[WARN] 都能读到你的 MCP 令牌并冒充服务端。仅限本机调试/自签名测试使用。")
		lg.Printf("[WARN] ============================================================")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		lg.Printf("[WARN] 目标 %s 是明文 HTTP 且非回环地址：令牌会以明文经过网络。"+
			"建议只连 127.0.0.1，或用 https + 反向代理。", u.Host)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0, // 工具调用可能很久，不设响应头超时
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	if *insecureFlag {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 —— 用户显式开启
	}

	b := &bridge{
		url:     endpoint,
		token:   token,
		client:  &http.Client{Transport: transport, Timeout: *timeoutFlag},
		lg:      lg,
		out:     bufio.NewWriter(os.Stdout),
		session: "",
	}
	defer b.flush()

	lg.Printf("[INFO] 桥接就绪：stdio ⇄ %s（stdout 只输出协议数据，日志走 stderr）", endpoint)
	return b.loop(os.Stdin)
}

// bridge stdio ↔ HTTP 的桥。
type bridge struct {
	url    string
	token  string
	client *http.Client
	lg     *log.Logger

	outW    sync.Mutex // stdout 写锁（保留并发扩展位；当前为顺序处理）
	out     *bufio.Writer
	session string
}

func (b *bridge) flush() {
	b.outW.Lock()
	defer b.outW.Unlock()
	_ = b.out.Flush()
}

// loop 逐行读 stdin，转发到 HTTP MCP 端点，把响应写 stdout。
//
// 处理是**顺序**的（一个请求走完再读下一行）：实现简单、响应顺序可预期、
// 不会出现"会话 id 还没拿到就发下一个请求"的竞态。代价是长任务调用期间
// 后续请求会排队——对 C2 的工具体验可接受，已知限制。
func (b *bridge) loop(in io.Reader) int {
	br := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := readLine(br, maxRequestLineBytes)
		if len(line) > 0 {
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				b.handle(trimmed)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				b.lg.Printf("[INFO] stdin 关闭，退出")
				return 0
			}
			b.lg.Printf("[ERROR] 读取 stdin 失败: %v", err)
			return 1
		}
	}
}

// handle 转发一条 JSON-RPC 消息。
func (b *bridge) handle(line []byte) {
	// 先取出请求 id / 是否通知：HTTP 失败时要能回一个"带正确 id 的错误"。
	id, isNote := peekRequestMeta(line)

	req, err := http.NewRequest(http.MethodPost, b.url, bytes.NewReader(line))
	if err != nil {
		b.lg.Printf("[ERROR] 构造请求失败: %v", err)
		b.emitError(id, isNote, -32603, "toshell-mcp: 构造 HTTP 请求失败: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// MCP Streamable HTTP 客户端应同时声明两种可接受的响应类型。
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("User-Agent", clientName)
	if b.session != "" {
		req.Header.Set("Mcp-Session-Id", b.session)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		b.lg.Printf("[ERROR] 请求 %s 失败: %v", b.url, err)
		b.emitError(id, isNote, -32000, "toshell-mcp: 无法连接 MCP 服务端 "+b.url+"："+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 会话头：initialize 之后每个请求都要带。
	if sid := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); sid != "" {
		b.session = sid
		b.lg.Printf("[DEBUG] 会话 id 已更新: %s", sid)
	}

	ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if strings.HasPrefix(ct, "text/event-stream") {
		b.consumeSSE(resp.Body, id, isNote, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		b.lg.Printf("[ERROR] 读取响应失败: %v", err)
		b.emitError(id, isNote, -32000, "toshell-mcp: 读取响应失败: "+err.Error())
		return
	}
	if len(body) > maxResponseBytes {
		b.emitError(id, isNote, -32000, fmt.Sprintf("toshell-mcp: 响应超过 %d 字节上限", maxResponseBytes))
		return
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		// 202/204：通知的正常结局，无响应体。
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		b.lg.Printf("[ERROR] 服务端返回 %d 且响应体为空", resp.StatusCode)
		b.emitError(id, isNote, -32000, fmt.Sprintf("toshell-mcp: 服务端返回 HTTP %d 且无响应体", resp.StatusCode))
		return
	}

	// 规范：写回 stdout 的必须是**一行一条**合法 JSON。
	if !b.emitJSON(trimmed) {
		b.lg.Printf("[ERROR] 服务端响应不是 JSON-RPC 消息（HTTP %d，前 200 字节: %s）",
			resp.StatusCode, preview(trimmed, 200))
		b.emitError(id, isNote, -32000,
			fmt.Sprintf("toshell-mcp: 服务端返回了非 JSON-RPC 响应（HTTP %d），已拦截以免污染协议流；详见 stderr", resp.StatusCode))
	}
}

// consumeSSE 处理 SSE 响应（部分 MCP 服务端对 POST 也回 text/event-stream）。
func (b *bridge) consumeSSE(r io.Reader, id json.RawMessage, isNote bool, status int) {
	br := bufio.NewReaderSize(r, 64<<10)
	var data []string
	emitted := 0
	flushEvent := func() {
		if len(data) == 0 {
			return
		}
		payload := strings.TrimSpace(strings.Join(data, "\n"))
		data = data[:0]
		if payload == "" {
			return
		}
		if b.emitJSON([]byte(payload)) {
			emitted++
		} else {
			b.lg.Printf("[WARN] 忽略非 JSON 的 SSE 数据: %s", preview([]byte(payload), 200))
		}
	}
	for {
		line, err := readLine(br, maxResponseBytes)
		trimmed := strings.TrimSpace(string(line))
		switch {
		case trimmed == "":
			flushEvent() // 空行 = 事件结束
		case strings.HasPrefix(trimmed, ":"):
			// 注释/保活行，丢弃
		case strings.HasPrefix(trimmed, "data:"):
			data = append(data, strings.TrimPrefix(trimmed, "data:"))
		default:
			// event:/id:/retry: 等字段对桥无意义
		}
		if err != nil {
			flushEvent()
			if !errors.Is(err, io.EOF) {
				b.lg.Printf("[ERROR] 读取 SSE 流失败: %v", err)
			}
			break
		}
	}
	if emitted == 0 && !isNote {
		b.lg.Printf("[WARN] SSE 流结束但没有可转发的消息（HTTP %d）", status)
		b.emitError(id, isNote, -32000, "toshell-mcp: SSE 响应中没有有效的 JSON-RPC 消息")
	}
}

// emitJSON 校验并写出一条 JSON-RPC 消息（压缩成单行）。
func (b *bridge) emitJSON(raw []byte) bool {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return false
	}
	// 只接受对象或数组（JSON-RPC 2.0 的两种合法外形）。
	c := bytes.TrimSpace(compact.Bytes())
	if len(c) == 0 || (c[0] != '{' && c[0] != '[') {
		return false
	}
	b.outW.Lock()
	defer b.outW.Unlock()
	_, _ = b.out.Write(c)
	_ = b.out.WriteByte('\n')
	_ = b.out.Flush()
	return true
}

// emitError 把一个桥自身的失败回成 JSON-RPC 错误，避免客户端一直等。
// 通知（无 id）不需要响应，只记 stderr。
func (b *bridge) emitError(id json.RawMessage, isNote bool, code int, msg string) {
	if isNote {
		return
	}
	if len(bytes.TrimSpace(id)) == 0 {
		id = json.RawMessage("null")
	}
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": msg,
			"data":    map[string]interface{}{"code": "bridge_error", "source": clientName},
		},
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = b.emitJSON(raw)
}

// peekRequestMeta 取出 JSON-RPC 请求的 id 与"是否通知"。
// 解析失败时按"有 id、非通知"处理（宁可多回一个错误，也不让客户端挂着）。
func peekRequestMeta(line []byte) (json.RawMessage, bool) {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return json.RawMessage("null"), false
	}
	id := bytes.TrimSpace(probe.ID)
	return probe.ID, len(id) == 0 || string(id) == "null"
}

// readLine 读一行（宽容 CRLF），带长度上限，避免超长行把内存打爆。
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > max {
			return buf[:max], fmt.Errorf("单行超过 %d 字节上限", max)
		}
		if err == nil {
			return buf, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // 行还没结束，继续读
		}
		return buf, err // io.EOF 等：把已读到的部分交回调用方
	}
}

func preview(b []byte, n int) string {
	s := strings.ReplaceAll(string(b), "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// isLoopbackHost 判断是否回环地址（用于"明文令牌过网"告警）。
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

package transport

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ─── WebSocket 主动探测面收敛（v1.4.0 S5 第 0 步）的单测 ──────────────────────
//
// 这里刻意**用裸 TCP 写请求行**（而不是 gorilla 的 Dialer）：探测者的手法就是
// 直接拼 `//ws`、`/./ws`、`/ws%2f`、`WS` 这类变形，标准客户端会在发出去之前
// 就把它们规范化掉，用客户端测等于测不到真正的攻击面。

// wsHandshakeHeaders 一份最小可用的 WS 握手头（四项齐备）。
var wsHandshakeHeaders = []string{
	"Connection: Upgrade",
	"Upgrade: websocket",
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
	"Sec-WebSocket-Version: 13",
}

type rawResponse struct {
	Status int
	Proto  string
	Header http.Header
	Body   string
}

// rawGET 向 addr 发一条裸 HTTP/1.1 GET 请求（请求行原样发出，不做任何规范化）。
func rawGET(t *testing.T, addr, target, host string, headers []string) rawResponse {
	t.Helper()
	return rawReq(t, addr, http.MethodGet, target, host, headers)
}

// rawReq 向 addr 发一条裸 HTTP/1.1 请求（请求行原样发出，不做任何规范化）。
func rawReq(t *testing.T, addr, method, target, host string, headers []string) rawResponse {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response for %q: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return rawResponse{Status: resp.StatusCode, Proto: resp.Proto, Header: resp.Header, Body: string(body)}
}

// hostPort 去掉 httptest 监听地址里的端口（用作 Host 头）。
func hostPort(t *testing.T, addr string) string {
	t.Helper()
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	return h
}

// TestWSUpgradeOnlyOnConfiguredPath 是本次收敛的核心断言：
// 只有配置的那一条**规范**路径能拿到 101，其它形态（`//`、`/./`、尾部斜杠、
// `..`、百分号编码、大小写变形、无关路径）一律 404，且**绝不放行到升级器**。
func TestWSUpgradeOnlyOnConfiguredPath(t *testing.T) {
	srv := NewServer()
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws"})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	host := hostPort(t, addr)

	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"配置路径", "/ws", http.StatusSwitchingProtocols},
		{"配置路径带查询串", "/ws?token=abc", http.StatusSwitchingProtocols},
		{"双斜杠", "//ws", http.StatusNotFound},
		{"点斜杠", "/./ws", http.StatusNotFound},
		{"尾部斜杠", "/ws/", http.StatusNotFound},
		{"中间路径回溯", "/ws/../ws", http.StatusNotFound},
		{"大小写变形", "/WS", http.StatusNotFound},
		{"大小写变形混写", "/Ws", http.StatusNotFound},
		{"百分号编码斜杠", "/ws%2f", http.StatusNotFound},
		{"百分号编码字母", "/%77s", http.StatusNotFound},
		{"百分号编码全大写", "/%2Fws", http.StatusNotFound},
		{"前缀更长的路径", "/wss", http.StatusNotFound},
		{"根路径", "/", http.StatusNotFound},
		{"无关路径", "/unknown", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rawGET(t, addr, tc.target, host, wsHandshakeHeaders)
			if got.Status != tc.want {
				t.Fatalf("target=%q status=%d want=%d", tc.target, got.Status, tc.want)
			}
			if tc.want == http.StatusNotFound {
				// 拒绝必须是普通 404，不能带任何"WS 端点"线索。
				if v := got.Header.Get("Sec-WebSocket-Version"); v != "" {
					t.Fatalf("404 响应不应带 Sec-WebSocket-Version（gorilla 的 400 指纹），got %q", v)
				}
				if got.Header.Get("Upgrade") != "" {
					t.Fatalf("404 响应不应带 Upgrade 头")
				}
			}
		})
	}
}

// TestWSRejectIndistinguishableFromPlainNotFound 证明"被拒绝的握手"与"普通
// 未知路径"在状态码/响应体/关键响应头上完全一致（探测者无法据此区分）。
func TestWSRejectIndistinguishableFromPlainNotFound(t *testing.T) {
	srv := NewServer()
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws"})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 参照物：一台"什么都没有"的服务器对同一路径的响应。
	ref := httptest.NewServer(http.NotFoundHandler())
	defer ref.Close()

	addr := ts.Listener.Addr().String()
	host := hostPort(t, addr)
	refAddr := ref.Listener.Addr().String()
	refHost := hostPort(t, refAddr)

	// 参照响应的 Host 不同会体现在响应里吗？不会（Go 不回显 Host）。为严谨起见
	// 两边都用各自的 host，只比较与"端点是否存在"有关的部分。
	want := rawGET(t, refAddr, "/ws", refHost, nil)
	if want.Status != http.StatusNotFound {
		t.Fatalf("参照服务器应为 404，got %d", want.Status)
	}

	probes := []struct {
		name    string
		method  string
		target  string
		headers []string
	}{
		{"错误路径+完整握手", http.MethodGet, "/nope", wsHandshakeHeaders},
		{"错误路径+无握手头", http.MethodGet, "/nope", nil},
		{"正确路径+无握手头", http.MethodGet, "/ws", nil},
		{"正确路径+只有Connection/Upgrade", http.MethodGet, "/ws", []string{"Connection: Upgrade", "Upgrade: websocket"}},
		{"正确路径+缺Key", http.MethodGet, "/ws", []string{"Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13"}},
		{"正确路径+旧版本号", http.MethodGet, "/ws", []string{"Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version: 8"}},
		{"路径变形+完整握手", http.MethodGet, "/ws%2f", wsHandshakeHeaders},
		{"非GET", http.MethodPost, "/ws", wsHandshakeHeaders},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			got := rawReq(t, addr, p.method, p.target, host, p.headers)
			if got.Status != want.Status {
				t.Fatalf("status=%d，普通 404=%d", got.Status, want.Status)
			}
			if got.Body != want.Body {
				t.Fatalf("body=%q，普通 404=%q", got.Body, want.Body)
			}
			for _, h := range []string{"Content-Type", "X-Content-Type-Options", "Content-Length"} {
				if got.Header.Get(h) != want.Header.Get(h) {
					t.Fatalf("响应头 %s=%q，普通 404=%q", h, got.Header.Get(h), want.Header.Get(h))
				}
			}
			if got.Proto != want.Proto {
				t.Fatalf("协议=%q，普通 404=%q", got.Proto, want.Proto)
			}
		})
	}
}

// TestWSDefaultPathStillWorks 钉住"默认路径不变"这条兼容性硬要求：
// 不做任何策略配置时，"/" 必须仍能升级（现役植入端在 server_url 不带路径时
// 就是用 "/" 握手的），而其它路径必须被拒。
func TestWSDefaultPathStillWorks(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	if got := srv.UpgradePolicy().Path; got != DefaultUpgradePath {
		t.Fatalf("默认策略路径=%q，want %q", got, DefaultUpgradePath)
	}
	if DefaultUpgradePath != "/" {
		t.Fatalf("默认路径必须与现役植入端一致（%q）：改它等于默认配置下所有载荷掉线", DefaultUpgradePath)
	}

	addr := ts.Listener.Addr().String()
	host := hostPort(t, addr)

	// 用真实 gorilla 客户端升级，等价于植入端的握手。
	url := "ws://" + addr + "/"
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("默认路径 %q 必须仍能升级：%v", DefaultUpgradePath, err)
	}
	_ = conn.Close()

	if got := rawGET(t, addr, "/other", host, wsHandshakeHeaders); got.Status != http.StatusNotFound {
		t.Fatalf("非默认路径应 404，got %d", got.Status)
	}
}

// TestWSHostAllowlist Host 白名单：空名单不拦（向后兼容）；非空时非名单 Host
// 即使路径与握手都对也必须 404。
func TestWSHostAllowlist(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	// 空名单：任意 Host 都放行（默认配置的现役行为）。
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws"})
	if got := rawGET(t, addr, "/ws", "any.example.com", wsHandshakeHeaders); got.Status != http.StatusSwitchingProtocols {
		t.Fatalf("空 Host 名单不应拦截，got %d", got.Status)
	}

	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws", HostAllowlist: []string{"cdn.example.com"}})
	cases := []struct {
		name string
		host string
		want int
	}{
		{"名单内", "cdn.example.com", http.StatusSwitchingProtocols},
		{"名单内大小写不敏感", "CDN.Example.COM", http.StatusSwitchingProtocols},
		{"名单内带端口", "cdn.example.com:18777", http.StatusSwitchingProtocols},
		{"名单外", "evil.example.com", http.StatusNotFound},
		{"名单外但同后缀", "cdn.example.com.evil.net", http.StatusNotFound},
		{"空 Host", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rawGET(t, addr, "/ws", tc.host, wsHandshakeHeaders)
			if got.Status != tc.want {
				t.Fatalf("host=%q status=%d want=%d", tc.host, got.Status, tc.want)
			}
		})
	}

	// 名单元素写成 host:port：含端口条目要卡端口，不含端口条目只卡主机名。
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws", HostAllowlist: []string{"10.0.0.1:18777"}})
	for _, tc := range []struct {
		host string
		want int
	}{
		{"10.0.0.1:18777", http.StatusSwitchingProtocols},
		{"10.0.0.1:9999", http.StatusNotFound},
		{"10.0.0.1", http.StatusNotFound},
		{"10.0.0.2", http.StatusNotFound},
	} {
		if got := rawGET(t, addr, "/ws", tc.host, wsHandshakeHeaders); got.Status != tc.want {
			t.Fatalf("host=%q status=%d want=%d", tc.host, got.Status, tc.want)
		}
	}
}

// TestWSUpgradeRejectCallback 拒绝回调要把"路径 / Host / 原因 / 远端 IP"四要素
// 交给上层，并按"是否像握手尝试"标注，供上层做日志噪声过滤。
func TestWSUpgradeRejectCallback(t *testing.T) {
	srv := NewServer()
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws", HostAllowlist: []string{"cdn.example.com"}})

	var got []UpgradeReject
	srv.SetOnUpgradeReject(func(r UpgradeReject) { got = append(got, r) })

	ts := httptest.NewServer(srv)
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	// 1) 无关路径 + 无握手头（背景噪声：标记为非握手尝试）
	rawGET(t, addr, "/favicon.ico", "cdn.example.com", nil)
	// 2) 无关路径 + 完整握手（扫描器：标记为握手尝试）
	rawGET(t, addr, "/socket.io", "cdn.example.com", wsHandshakeHeaders)
	// 3) 正确路径 + Host 不在名单
	rawGET(t, addr, "/ws", "evil.example.com", wsHandshakeHeaders)
	// 4) 正确路径 + 编码变形
	rawGET(t, addr, "/%77s", "cdn.example.com", wsHandshakeHeaders)
	// 5) 正确路径 + 缺握手头
	rawGET(t, addr, "/ws", "cdn.example.com", nil)

	if len(got) != 5 {
		t.Fatalf("拒绝回调应被调用 5 次，got %d：%+v", len(got), got)
	}

	wantReasons := []string{
		RejectPathMismatch,
		RejectPathMismatch,
		RejectHostNotAllowed,
		RejectEncodedPath,
		RejectNoHandshake,
	}
	for i, want := range wantReasons {
		if got[i].Reason != want {
			t.Errorf("第 %d 次拒绝原因=%q，want %q", i+1, got[i].Reason, want)
		}
		if got[i].RemoteIP == "" {
			t.Errorf("第 %d 次拒绝缺少远端 IP", i+1)
		}
		if got[i].Host == "" && i != 0 {
			t.Errorf("第 %d 次拒绝缺少 Host", i+1)
		}
	}
	if got[0].HandshakeAttempt {
		t.Errorf("无握手头的普通 GET 不应被标成握手尝试（会被日志噪声过滤掉）")
	}
	if got[4].HandshakeAttempt {
		t.Errorf("缺握手头的请求不应被标成握手尝试")
	}
	for _, i := range []int{1, 2, 3} {
		if !got[i].HandshakeAttempt {
			t.Errorf("第 %d 次（带握手特征）应被标成握手尝试", i+1)
		}
	}
	if got[3].RawPath == "" {
		t.Errorf("编码变形应记录 RawPath（原始编码形态）")
	}
}

// TestWSHostOverrideViaGorillaDialer 证明植入端 front_domain 依赖的机制成立：
// gorilla 的 Dialer 允许通过 requestHeader 里的 "Host" 键覆盖 Host 头（而不是
// 塞进普通 Header），于是"TLS SNI 用前置域 + HTTP Host 用前置域"可以同时成立。
// 这条是植入端与 HTTP 通道口径对齐的基础。
func TestWSHostOverrideViaGorillaDialer(t *testing.T) {
	srv := NewServer()
	srv.SetUpgradePolicy(UpgradePolicy{Path: "/ws", HostAllowlist: []string{"cdn.example.com"}})

	seenHost := make(chan string, 1)
	srv.SetOnUpgradeReject(func(r UpgradeReject) { seenHost <- r.Host })

	ts := httptest.NewServer(srv)
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	hdr := http.Header{}
	hdr.Set("Host", "cdn.example.com")
	conn, _, err := dialer.Dial("ws://"+addr+"/ws", hdr)
	if err != nil {
		t.Fatalf("带 Host 覆盖的握手应成功（Host 名单内）：%v", err)
	}
	_ = conn.Close()

	// 反证：同一路径、Host 不覆盖 → 连的是 127.0.0.1，名单里没有 → 404。
	if conn2, _, err2 := dialer.Dial("ws://"+addr+"/ws", nil); err2 == nil {
		_ = conn2.Close()
		t.Fatalf("Host 不在名单内时不应升级成功")
	}
	select {
	case h := <-seenHost:
		if !strings.Contains(h, "127.0.0.1") {
			t.Fatalf("拒绝记录里的 Host 应是不在名单内的 127.0.0.1，got %q", h)
		}
	default:
		t.Fatalf("Host 不在名单时应产生一条拒绝记录")
	}
}

// TestHostAllowedUnit 归一化比较的边界（纯函数）。
func TestHostAllowedUnit(t *testing.T) {
	if !hostAllowed("anything", nil) {
		t.Fatal("空名单必须放行（向后兼容）")
	}
	if hostAllowed("", []string{"a"}) {
		t.Fatal("空 Host 在非空名单下必须拒绝")
	}
	if !hostAllowed("[::1]:8080", []string{"::1"}) {
		t.Fatal("IPv6 去端口后应匹配")
	}
	if hostAllowed("a.com", []string{"", "  "}) {
		t.Fatal("空白名单元素应被忽略，不应意外匹配")
	}
}

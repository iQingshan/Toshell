// socks5proxy 是本地直连版 SOCKS5 代理（RFC 1928），不经过隧道。
// 用于独立验证 SOCKS5 协议流程（握手 / CONNECT / 响应构造 / 双向 relay）；
// 隧道版实现在 internal/common/tunnel/tunnel.go 的 SOCKS5Server。
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	socksVersion5     = 0x05
	methodNoAuth      = 0x00
	cmdConnect        = 0x01
	atypIPv4          = 0x01
	atypDomain        = 0x03
	atypIPv6          = 0x04
	repSuccess        = 0x00
	repGeneralFailure = 0x01
	repHostUnreach    = 0x04
	repCmdNotSupport  = 0x07
	repAtypNotSupport = 0x08
)

type ProxyServer struct {
	listener net.Listener
	running  bool
	clients  map[net.Conn]bool
	mu       sync.RWMutex
}

func main() {
	addr := "127.0.0.1:1080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	proxy := &ProxyServer{
		clients: make(map[net.Conn]bool),
		running: true,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 Proxy Server started on %s", addr)

	go proxy.acceptLoop(listener)

	select {}
}

func (p *ProxyServer) acceptLoop(listener net.Listener) {
	for p.running {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		p.mu.Lock()
		p.clients[conn] = true
		p.mu.Unlock()

		log.Printf("New connection from %s", conn.RemoteAddr())
		go p.handleConnection(conn)
	}
}

func (p *ProxyServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer func() {
		p.mu.Lock()
		delete(p.clients, conn)
		p.mu.Unlock()
	}()

	// 1. 方法协商：[VER, NMETHODS, METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("Read method header failed: %v", err)
		return
	}
	if header[0] != socksVersion5 {
		log.Printf("Unsupported version: %d", header[0])
		conn.Write([]byte{socksVersion5, 0xFF})
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if nmethods > 0 {
		if _, err := io.ReadFull(conn, methods); err != nil {
			log.Printf("Read methods failed: %v", err)
			return
		}
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == methodNoAuth {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{socksVersion5, 0xFF})
		log.Printf("No acceptable auth method")
		return
	}
	if _, err := conn.Write([]byte{socksVersion5, methodNoAuth}); err != nil {
		return
	}

	// 2. 请求：[VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		log.Printf("Read request header failed: %v", err)
		return
	}
	if reqHeader[0] != socksVersion5 {
		log.Printf("Bad request version: %d", reqHeader[0])
		return
	}
	if reqHeader[2] != 0x00 { // RSV 必须为 0
		socksReply(conn, repGeneralFailure)
		return
	}

	host, port, ok := parseTarget(conn, reqHeader[3])
	if !ok {
		return
	}

	switch reqHeader[1] {
	case cmdConnect:
		p.handleConnect(conn, host, port)
	case 0x02:
		socksReply(conn, repCmdNotSupport)
		log.Printf("BIND not supported")
	case 0x03:
		socksReply(conn, repCmdNotSupport)
		log.Printf("UDP ASSOCIATE not supported")
	default:
		socksReply(conn, repCmdNotSupport)
		log.Printf("Unknown command: 0x%02x", reqHeader[1])
	}
}

// parseTarget 按 ATYP 读取目标地址，返回 host 与 port。
func parseTarget(conn net.Conn, atyp byte) (host string, port uint16, ok bool) {
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, false
		}
		host = net.IP(ip).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, false
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, false
		}
		host = string(domain)
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, false
		}
		host = net.IP(ip).String()
	default:
		socksReply(conn, repAtypNotSupport)
		log.Printf("Unsupported ATYP: 0x%02x", atyp)
		return "", 0, false
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, false
	}
	return host, binary.BigEndian.Uint16(portBuf), true
}

func (p *ProxyServer) handleConnect(conn net.Conn, host string, port uint16) {
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("CONNECT request to %s", targetAddr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		socksReply(conn, repHostUnreach)
		return
	}
	defer targetConn.Close()

	// 成功响应：VER REP RSV ATYP BND.ADDR(4) BND.PORT(2) = 10 字节。
	// BND.ADDR 用本地监听地址（本机视角 127.0.0.1），BND.PORT 用 0 即可，
	// 浏览器只关心 REP 字段。
	bndIP := net.ParseIP("0.0.0.0").To4()
	resp := []byte{socksVersion5, repSuccess, 0x00, atypIPv4,
		bndIP[0], bndIP[1], bndIP[2], bndIP[3], 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		log.Printf("Write success reply failed: %v", err)
		return
	}
	log.Printf("Connected to %s", targetAddr)

	p.relay(conn, targetConn)
}

// socksReply 发送带指定 REP 的错误响应（ATYP=IPv4, BND=0.0.0.0:0）。
func socksReply(conn net.Conn, rep byte) {
	resp := []byte{socksVersion5, rep, 0x00, atypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		log.Printf("Write reply failed: %v", err)
	}
}

// relay 双向复制：任一侧 EOF/错误即关闭两侧连接（简单代理语义，
// 不做半关闭；隧道版在 tunnel.go relay 中实现了半关闭排空语义）。
func (p *ProxyServer) relay(clientConn, targetConn net.Conn) {
	defer clientConn.Close()

	errChan := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(dst, src, buf)
		if err != nil && !isClosedErr(err) {
			log.Printf("Relay error: %v", err)
		}
		errChan <- struct{}{}
	}

	go cp(targetConn, clientConn)
	go cp(clientConn, targetConn)

	<-errChan
	_ = targetConn.Close()
	<-errChan
	log.Printf("Relay closed: %s <-> %s", clientConn.RemoteAddr(), targetConn.RemoteAddr())
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "EOF")
}

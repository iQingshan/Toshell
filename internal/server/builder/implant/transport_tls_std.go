//go:build transport_http && light

package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ─── HTTP 通道 TLS 客户端：标准库实现（light 精简档）──────────────────
//
// 与 transport_tls_utls.go 二选一：light 档裁剪 uTLS（约 3MB 体积），
// 用标准库 crypto/tls 建立 TLS 连接。SNI 仍使用拟态域名（域前置生效），
// 传输内容由 AES-GCM 保护，不引入额外依赖。JA3 指纹为 Go 标准库特征。

var (
	stdOnce sync.Once
	stdInst *http.Client
)

// httpSharedClient 返回复用的 HTTP 客户端（light 档：标准库 TLS）。
func httpSharedClient() *http.Client {
	stdOnce.Do(func() {
		front := strings.TrimSpace(frontDomain)
		if front == "" {
			if u, err := url.Parse(httpBaseURL(serverAddr)); err == nil && u.Hostname() != "" {
				front = u.Hostname()
			}
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		stdInst = &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, err := dialer.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					tconn := tls.Client(conn, &tls.Config{
						ServerName:         front,
						InsecureSkipVerify: true,
					})
					if err := tconn.HandshakeContext(ctx); err != nil {
						conn.Close()
						return nil, err
					}
					return tconn, nil
				},
			},
			Timeout: 45 * time.Second,
		}
	})
	return stdInst
}

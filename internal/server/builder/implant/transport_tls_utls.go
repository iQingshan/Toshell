//go:build transport_http && !light

package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ─── HTTP 通道 TLS 客户端：uTLS 实现（full 档，JA3 拟态）──────────────
//
// 与 transport_tls_std.go 二选一：full 档启用 uTLS，把 TLS ClientHello
// 伪装成真实 Chrome 指纹（JA3），避免 Go 标准库 TLS 的典型指纹被 NDR/WAF
// 识别。SNI 与 HTTP Host 头使用拟态域名（域前置）。

var (
	utlsOnce sync.Once
	utlsInst *http.Client
)

// httpSharedClient 返回复用的 HTTP 客户端（full 档：uTLS Chrome 指纹）。
func httpSharedClient() *http.Client {
	utlsOnce.Do(func() {
		front := strings.TrimSpace(frontDomain)
		if front == "" {
			if u, err := url.Parse(httpBaseURL(serverAddr)); err == nil && u.Hostname() != "" {
				front = u.Hostname()
			}
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		utlsInst = &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, err := dialer.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					uconn := utls.UClient(conn, &utls.Config{
						ServerName:         front,
						InsecureSkipVerify: true,
					}, utls.HelloChrome_102)
					if err := uconn.HandshakeContext(ctx); err != nil {
						conn.Close()
						return nil, err
					}
					return uconn, nil
				},
			},
			Timeout: 45 * time.Second,
		}
	})
	return utlsInst
}

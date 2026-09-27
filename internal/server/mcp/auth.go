package mcp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ─── 鉴权与来源校验 ──────────────────────────────────────────────────
//
// 对外 MCP 是**远程代码执行的入口**，鉴权必须 fail-closed：
//   - 未配置 token → 服务端拒绝启动（见 server.go New/Start，绝不"无鉴权裸奔"）；
//   - token 用常量时间比较（crypto/subtle），比较的是 SHA-256 摘要而不是原文——
//     摘要长度固定，既避免长度侧信道，也不需要在内存里散落多份 token 明文；
//   - 可选 allow_cidrs：来源不在白名单按**未认证**处理（401），不告诉对方"是网段策略拒绝的"，
//     避免泄漏"这个端口确实存在 MCP 策略"；
//   - allowed_origins：带 Origin 头的请求做白名单校验，默认只放行同源；
//     无 Origin 头（本地 stdio 桥、curl、脚本）放行。
//
// 关于 allow_cidrs 的实现来源：项目里已有一份等价写法在
// `internal/server/auth/webgate.go`（WebGate + clientIP，含"裸 IP 补掩码"的容错）。
// 但那个包里的 `clientIP` 是**未导出**的，从 mcp 包无法复用，且 webgate 的
// TrustProxyHeaders 语义（信任 X-Forwarded-For）在这里是**危险的**：XFF 可伪造，
// 若信任它，攻击者加一个 `X-Forwarded-For: 127.0.0.1` 就能绕过 CIDR 白名单。
// 所以这里**照抄其判断口径**（ParseCIDR → 裸 IP 补 /32 或 /128 → IPNet.Contains），
// 但只取直连 RemoteAddr，不读任何转发头。

// tokenAuthenticator 令牌 + 来源 + Origin 校验器。
type tokenAuthenticator struct {
	tokenID  string
	tokenSum [sha256.Size]byte

	nets    []*net.IPNet
	origins map[string]bool // 全小写
}

// newTokenAuthenticator 构造校验器。invalidCIDRs / invalidOrigins 返回无法解析的条目，
// 由调用方按 fail_closed 决定"启动失败"还是"告警忽略"。
func newTokenAuthenticator(token string, cidrs, origins []string) (a *tokenAuthenticator, invalidCIDRs, invalidOrigins []string) {
	a = &tokenAuthenticator{
		tokenSum: sha256.Sum256([]byte(token)),
		origins:  make(map[string]bool, len(origins)),
	}
	// token_id 只用于审计关联：取摘要前 8 字节（16 hex）。高熵 token 不可反推；
	// 就算泄漏也只是"能识别是同一个令牌"，不构成凭据。
	a.tokenID = "tok_" + hex.EncodeToString(a.tokenSum[:])[:8]

	nets, badNets := parseCIDRs(cidrs)
	a.nets = nets

	for _, raw := range origins {
		o := strings.ToLower(strings.TrimSpace(raw))
		if o == "" {
			continue
		}
		if u, err := url.Parse(o); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			invalidOrigins = append(invalidOrigins, raw)
			continue
		}
		a.origins[o] = true
	}
	return a, badNets, invalidOrigins
}

// parseCIDRs 解析 CIDR 列表，兼容"裸 IP"写法（补成 /32 或 /128）。
// 口径与 internal/server/auth/webgate.go 的 allow_cidrs 保持一致。
func parseCIDRs(list []string) (nets []*net.IPNet, invalid []string) {
	for _, raw := range list {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			if _, n, err := net.ParseCIDR(ip.String() + "/" + strconv.Itoa(bits)); err == nil {
				nets = append(nets, n)
				continue
			}
		}
		invalid = append(invalid, raw)
	}
	return nets, invalid
}

// TokenID 审计用的令牌指纹（非凭据本身）。
func (a *tokenAuthenticator) TokenID() string {
	if a == nil {
		return ""
	}
	return a.tokenID
}

// AllowRemote 来源网段校验。未配置 allow_cidrs 时放行。
func (a *tokenAuthenticator) AllowRemote(ip net.IP) bool {
	if a == nil || len(a.nets) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckToken 校验 Bearer / X-MCP-Token。常量时间比较（对 SHA-256 摘要）。
func (a *tokenAuthenticator) CheckToken(r *http.Request) bool {
	if a == nil {
		return false
	}
	provided := bearerToken(r.Header.Get("Authorization"))
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-MCP-Token"))
	}
	if provided == "" {
		return false
	}
	sum := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(sum[:], a.tokenSum[:]) == 1
}

// bearerToken 解析 `Bearer <token>`（scheme 大小写不敏感）。
// 刻意不接受 `?token=` 查询串：URL 会进浏览器历史、反代日志与 Referer，
// 令牌走查询串等于半公开（对比 auth.Middleware 的 ?token= 兼容写法，这里更严）。
func bearerToken(header string) string {
	h := strings.TrimSpace(header)
	if h == "" {
		return ""
	}
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// CheckOrigin 跨域来源校验：
//   - 无 Origin 头 → 放行（本地 stdio 桥、curl、Python 客户端都不带 Origin）；
//   - allowed_origins 显式命中 → 放行；
//   - 否则只放行同源（Origin 与请求 Host + 协议一致）；
//   - `Origin: null`（file:// / 沙箱 iframe）在显式白名单外一律拒绝。
func (a *tokenAuthenticator) CheckOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if a != nil && a.origins[strings.ToLower(origin)] {
		return true
	}
	return sameOrigin(origin, r)
}

// sameOrigin 判断 Origin 是否与请求自身同源。
// 方案（http/https）按 r.TLS 推断：非 TLS 连接上声明 https 的 Origin 视为跨域。
func sameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	if r.TLS != nil {
		return strings.EqualFold(u.Scheme, "https")
	}
	return strings.EqualFold(u.Scheme, "http")
}

// clientIP 取直连来源 IP（只信 RemoteAddr，不读 X-Forwarded-For）。
// 与 internal/server/auth/webgate.go 的 clientIP 口径一致（不含转发头分支）。
func clientIP(r *http.Request) net.IP {
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return net.IPv4zero
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	return net.IPv4zero
}

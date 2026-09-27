package api

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"toshell/internal/server/config"
)

func testServer(publicHost, tlsCert string, apiPort uint16) *Server {
	cfg := &config.Config{}
	cfg.Listener.PublicHost = publicHost
	cfg.Server.TLSCert = tlsCert
	if tlsCert != "" {
		cfg.Server.TLSKey = "key"
	}
	cfg.Server.APIPort = apiPort
	return &Server{cfg: cfg}
}

// 回归：ops 用 localhost 打开控制台时，不能再生成 localhost 的下载地址。
func TestResolveDownloadTargetPrefersPublicHost(t *testing.T) {
	s := testServer("https://c2.example.com", "cert.pem", 18081)
	r := httptest.NewRequest(http.MethodPost, "http://localhost:18081/api/v1/builders", nil)

	got := s.resolveDownloadTarget(r, "http://localhost:8080", "")
	if got.Base != "https://c2.example.com" {
		t.Fatalf("base = %q, want https://c2.example.com", got.Base)
	}
	if got.Warning != "" {
		t.Fatalf("unexpected warning: %q", got.Warning)
	}
}

// 未配置 public_host 时，按控制台实际访问地址解析（反代域名/X-Forwarded-Host）。
func TestResolveDownloadTargetUsesConsoleHost(t *testing.T) {
	s := testServer("", "", 18081)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/api/v1/implants/stored/x/oneliner", nil)
	r.Host = "c2.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "cdn.example.com, c2.example.com")

	got := s.resolveDownloadTarget(r, "", "")
	if got.Base != "https://cdn.example.com" {
		t.Fatalf("base = %q, want https://cdn.example.com", got.Base)
	}
}

// 内网直连：用载荷 server_url 的主机名 + API 端口。
func TestResolveDownloadTargetUsesServerURLHost(t *testing.T) {
	s := testServer("", "", 18081)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/v1/builders", nil)

	got := s.resolveDownloadTarget(r, "http://10.0.0.9:8080", "")
	if got.Base != "http://10.0.0.9:18081" {
		t.Fatalf("base = %q, want http://10.0.0.9:18081", got.Base)
	}
}

// 显式 download_host 覆盖自动解析，支持带路径前缀的反代地址。
func TestResolveDownloadTargetOverride(t *testing.T) {
	s := testServer("https://ignored.example.com", "", 18081)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/v1/builders", nil)

	got := s.resolveDownloadTarget(r, "", "https://front.example.com/api-proxy/")
	if got.Base != "https://front.example.com/api-proxy" {
		t.Fatalf("base = %q", got.Base)
	}
	if got.Warning != "" {
		t.Fatalf("unexpected warning: %q", got.Warning)
	}
}

// 所有地址都是回环时必须给出 warning，让前端提示运维去配置公网地址。
func TestResolveDownloadTargetWarnsOnLoopback(t *testing.T) {
	s := testServer("", "", 18081)
	r := httptest.NewRequest(http.MethodPost, "http://localhost:18081/api/v1/builders", nil)

	// 环境里存在可用的内网 IPv4 时会兜底到内网地址，但同样必须带 warning；
	// 若没有任何可用网卡则回退 localhost。
	got := s.resolveDownloadTarget(r, "http://localhost:8080", "")
	if got.Warning == "" {
		t.Fatalf("expected warning, got base=%q", got.Base)
	}
	if isLoopbackHost(got.Host) && !strings.Contains(got.Warning, "localhost") {
		t.Fatalf("loopback fallback should mention localhost: %q", got.Warning)
	}
}

func TestNormalizeDownloadBase(t *testing.T) {
	cases := []struct {
		raw      string
		scheme   string
		apiPort  int
		wantBase string
		wantOK   bool
	}{
		{"", "http", 18081, "", false},
		{"localhost", "http", 18081, "", false},
		{"127.0.0.1:18081", "http", 18081, "", false},
		{"c2.example.com", "http", 18081, "http://c2.example.com:18081", true},
		{"c2.example.com", "https", 443, "https://c2.example.com", true},
		{"c2.example.com:8443", "https", 18081, "https://c2.example.com:8443", true},
		{"https://c2.example.com/", "http", 18081, "https://c2.example.com", true},
	}
	for _, c := range cases {
		base, _, ok := normalizeDownloadBase(c.raw, c.scheme, c.apiPort)
		if ok != c.wantOK || base != c.wantBase {
			t.Errorf("normalizeDownloadBase(%q,%q,%d) = (%q,%v), want (%q,%v)",
				c.raw, c.scheme, c.apiPort, base, ok, c.wantBase, c.wantOK)
		}
	}
}

// 一键上线：Windows/Linux 各给出多套变体，且都指向解析出的下载地址、不含 localhost。
func TestOneLinerVariants(t *testing.T) {
	dl := "https://c2.example.com:8443/api/v1/implant/payload/build-1"

	windows := windowsOneLiners(dl)
	if len(windows) < 5 {
		t.Fatalf("windows variants = %d, want >= 5", len(windows))
	}
	for _, v := range windows {
		if v.Name == "" || v.Command == "" || v.Desc == "" {
			t.Fatalf("incomplete variant: %+v", v)
		}
		if !strings.Contains(v.Command, dl) && !strings.Contains(decodeEncCommand(t, v.Command), dl) {
			t.Fatalf("variant %q does not reference the download url", v.Name)
		}
		if strings.Contains(v.Command, "localhost") || strings.Contains(v.Command, "127.0.0.1") {
			t.Fatalf("variant %q leaked a loopback address", v.Name)
		}
	}

	linux := linuxOneLiners(dl)
	if len(linux) < 5 {
		t.Fatalf("linux variants = %d, want >= 5", len(linux))
	}
	for _, v := range linux {
		if !strings.Contains(v.Command, dl) {
			t.Fatalf("variant %q does not reference the download url", v.Name)
		}
		if strings.Contains(v.Command, "localhost") {
			t.Fatalf("variant %q leaked loopback", v.Name)
		}
	}
}

// decodeEncCommand 解开 powershell -enc 的内层脚本，便于断言命令内容；
// 非 -enc 命令原样返回。
//
// 一条命令里可能出现多个 `-enc `，其中部分是**模板占位符**（例如 mshta 骨架里的
// `powershell -w hidden -nop -enc <注入器Base64>`，由操作员手工填入），对占位符做
// Base64 解码必然失败。所以这里从头扫描所有 `-enc ` 出现位置，只对**能成功解码成
// UTF-16LE 文本**的片段做展开，一个都没有时原样返回（保持"扫原文"的语义）。
func decodeEncCommand(t *testing.T, cmd string) string {
	t.Helper()
	var out strings.Builder
	rest := cmd
	decodedAny := false
	for {
		idx := strings.Index(rest, "-enc ")
		if idx < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:idx+len("-enc ")])
		rest = rest[idx+len("-enc "):]
		// 取到下一个空白/引号/分号为止的候选串（Base64 里不会出现这些字符）
		end := strings.IndexAny(rest, " \"';\n\r\t)")
		cand := rest
		if end >= 0 {
			cand = rest[:end]
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cand))
		if err != nil || len(raw) < 2 || len(raw)%2 != 0 {
			continue // 占位符/非 Base64：保留原文，继续往后找
		}
		u16 := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		out.WriteString(string(utf16.Decode(u16)))
		rest = rest[len(cand):]
		decodedAny = true
	}
	if !decodedAny {
		return cmd
	}
	return out.String()
}

func TestSupportsOneLiner(t *testing.T) {
	cases := []struct {
		os, format string
		want       bool
	}{
		{"windows", "exe", true},
		{"windows", "raw", true},
		{"windows", "dll", false},
		{"windows", "shellcode", false},
		{"linux", "bin", true},
		{"linux", "exe", true},
		{"linux", "so", false},
		{"darwin", "exe", false},
	}
	for _, c := range cases {
		if got := supportsOneLiner(c.os, c.format); got != c.want {
			t.Errorf("supportsOneLiner(%q,%q) = %v, want %v", c.os, c.format, got, c.want)
		}
	}
}

// https 请求（控制台自身走 TLS）解析出的基址也必须是 https。
func TestRequestDownloadBaseTLSScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://c2.example.com/api/v1/builders", nil)
	r.TLS = &tls.ConnectionState{}
	base, host, ok := requestDownloadBase(r)
	if !ok || base != "https://c2.example.com" || host != "c2.example.com" {
		t.Fatalf("got base=%q host=%q ok=%v", base, host, ok)
	}
}

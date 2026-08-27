// Package mimicry 提供 C2 监听器的"流量拟态"能力。
//
// 核心思想：让 HTTP C2 监听器在响应头、状态码与响应体上模仿某个真实的互联网服务，
// 使扫描器、蓝队或安全设备的探测请求得到"看似合法"的内容，从而降低监听器被识别为
// C2 的概率；同时 C2 端点的响应也套用一组中性的头部整形，避免"自定义二进制协议"过于突兀。
package mimicry

import (
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Profile 描述一个拟态模板。
type Profile struct {
	Name string `json:"name"`

	// 响应整形（应用于 C2 端点与诱饵响应，二者都安全）
	ServerHeader   string            `json:"server_header,omitempty"`   // 例如 "cloudflare" / "nginx"
	NeutralHeaders map[string]string `json:"neutral_headers,omitempty"` // 中性头（nosniff、STS 等）

	// 诱饵专用头（仅 decoy 使用；如 Cache-Control，不能套在 C2 响应上）
	DecoyHeaders map[string]string `json:"decoy_headers,omitempty"`

	// 诱饵（decoy）：非 C2 路径 / 解密失败 / 探测请求命中时返回的内容
	DecoyStatus      int    `json:"decoy_status"`       // 默认 200
	DecoyContentType string `json:"decoy_content_type"` // 默认 text/plain
	DecoyBody        string `json:"decoy_body"`         // 诱饵响应体
	DecoyPath        string `json:"decoy_path"`         // 对外宣称的典型路径（仅文档/自述用途）
}

var (
	mu       sync.RWMutex
	profiles = map[string]*Profile{}
)

func init() {
	Register(defaultCDN())
	Register(defaultAPI())
	Register(defaultStream())
}

// Register 注册一个拟态模板（按名称，大小写不敏感）。
func Register(p *Profile) {
	if p == nil || p.Name == "" {
		return
	}
	mu.Lock()
	profiles[strings.ToLower(p.Name)] = p
	mu.Unlock()
}

// ByName 按名称查找拟态模板；未命中时返回默认模板。
func ByName(name string) *Profile {
	mu.RLock()
	defer mu.RUnlock()
	if p, ok := profiles[strings.ToLower(name)]; ok {
		return p
	}
	return defaultCDN()
}

// Default 返回默认拟态模板。
func Default() *Profile { return defaultCDN() }

// Names 返回所有已注册模板名称（排序，便于前端展示）。
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(profiles))
	for name := range profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Shape 将中性拟态响应头应用到 w（不写状态码与响应体）。
// 仅应用对任意响应都安全的头，避免把 Cache-Control 等诱饵专用头套到 C2 响应上。
func (p *Profile) Shape(w http.ResponseWriter) {
	if p == nil {
		return
	}
	h := w.Header()
	if p.ServerHeader != "" {
		h.Set("Server", p.ServerHeader)
	}
	for k, v := range p.NeutralHeaders {
		h.Set(k, v)
	}
}

// DecoyHandler 返回诱饵 handler：任何请求都返回拟态的合法内容，
// 用于 C2 监听器的根路由兜底（吞掉所有非 C2 路径的探测）。
func (p *Profile) DecoyHandler() http.Handler {
	if p == nil {
		p = defaultCDN()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Shape(w)
		for k, v := range p.DecoyHeaders {
			w.Header().Set(k, v)
		}

		ct := p.DecoyContentType
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)

		status := p.DecoyStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(p.DecoyBody))
	})
}

// defaultCDN 默认拟态：模拟一个静态 CDN 分发压缩后的 JavaScript 资源包。
// 这是最不易引起怀疑、且与"C2 心跳像拉取静态资源"语义最贴合的选择。
func defaultCDN() *Profile {
	return &Profile{
		Name:         "cdn",
		ServerHeader: "cloudflare",
		NeutralHeaders: map[string]string{
			"X-Content-Type-Options":      "nosniff",
			"Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
			"Access-Control-Allow-Origin": "*",
		},
		DecoyHeaders: map[string]string{
			"Cache-Control": "public, max-age=31536000, immutable",
			"Vary":          "Accept-Encoding",
		},
		DecoyStatus:      200,
		DecoyContentType: "application/javascript; charset=utf-8",
		DecoyPath:        "/assets/app.min.js",
		DecoyBody: "/*! app-bundle v3.2.1 | (c) 2024 Acme Cloud Services | MIT */\n" +
			"(function(g){'use strict';var k=g.__APP__=g.__APP__||{v:'3.2.1',cfg:{api:'https://api.acme-cdn.example/v1',region:'auto',debug:!1}};" +
			"function e(t){return document.getElementById(t)}function l(n,a){var x=document.createElement('script');x.async=!0;x.src=a;x.onload=n;document.head.appendChild(x)}" +
			"k.ready=function(fn){if(document.readyState!=='loading')fn();else document.addEventListener('DOMContentLoaded',fn)};" +
			"k.load=function(n,a){k.ready(function(){l(n,a)})};})(this);\n",
	}
}

// defaultAPI 拟态：模拟一个返回 JSON 的 REST API 服务（未命中路径返回 404 JSON）。
func defaultAPI() *Profile {
	return &Profile{
		Name:         "api",
		ServerHeader: "nginx/1.24.0",
		NeutralHeaders: map[string]string{
			"X-Content-Type-Options": "nosniff",
		},
		DecoyHeaders: map[string]string{
			"Cache-Control": "no-store",
		},
		DecoyStatus:      404,
		DecoyContentType: "application/json; charset=utf-8",
		DecoyPath:        "/api/v1/status",
		DecoyBody:        `{"code":404,"message":"resource not found","request_id":"` + "00000000-0000-0000-0000-000000000000" + `"}`,
	}
}

// defaultStream 拟态：模拟一个视频点播/HLS 流服务（返回 m3u8 播放列表）。
func defaultStream() *Profile {
	return &Profile{
		Name:         "stream",
		ServerHeader: "openresty",
		NeutralHeaders: map[string]string{
			"Accept-Ranges": "bytes",
		},
		DecoyHeaders: map[string]string{
			"Cache-Control": "public, max-age=30",
		},
		DecoyStatus:      200,
		DecoyContentType: "application/vnd.apple.mpegurl",
		DecoyPath:        "/live/index.m3u8",
		DecoyBody: "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:0\n" +
			"#EXTINF:6.000,\nsegment_0000.ts\n#EXTINF:6.000,\nsegment_0001.ts\n#EXT-X-ENDLIST\n",
	}
}

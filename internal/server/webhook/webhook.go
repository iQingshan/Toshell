// Package webhook 提供会话上线事件的通知能力：将新会话上线的信息 POST 到
// 操作员自定义的 URL（企业微信/钉钉/飞书/Slack/Discord 等机器人的 webhook 接口）。
// 仅在上线（新会话注册）时触发，避免高频事件打扰。
//
// 钉钉机器人兼容：钉钉 webhook 要求固定 msgtype 结构（text/markdown），
// 且加签模式需要 timestamp+sign 参数。本包按 URL 自动识别钉钉并发送
// 钉钉 markdown 消息；URL 含 oapi.dingtalk.com 即视为钉钉。非钉钉平台
// 回退发送通用 JSON（event/content/会话字段），企业微信/飞书等亦可直接使用。
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
)

// Notifier 会话上线 webhook 通知器。
// 通知配置在每次发送时从 config.Get() 读取，设置 API 保存或配置文件
// 修改后可立即热生效，无需重启进程（New 的 cfg 仅作初始参考）。
type Notifier struct {
	cfg    *config.WebhookConfig
	client *http.Client
}

// New 创建通知器。cfg 为 nil 或未启用时，NotifyOnline 为空操作。
func New(cfg *config.WebhookConfig) *Notifier {
	return &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// liveCfg 返回当前生效的 webhook 配置（热更新优先，回退初始值）。
func (n *Notifier) liveCfg() *config.WebhookConfig {
	if g := config.Get(); g != nil {
		return &g.Webhook
	}
	return n.cfg
}

// resolveFormat 决定消息格式：显式 dingtalk/generic 优先；
// auto（或空）按 URL 域名识别（oapi.dingtalk.com → dingtalk）。
func resolveFormat(cfg *config.WebhookConfig) string {
	f := strings.ToLower(strings.TrimSpace(cfg.Format))
	if f == "dingtalk" || f == "generic" {
		return f
	}
	// auto 识别
	if strings.Contains(cfg.URL, "oapi.dingtalk.com") {
		return "dingtalk"
	}
	return "generic"
}

// NotifyOnline 在新会话上线时发送通知。仅在启用且仅上线通知时发送。
func (n *Notifier) NotifyOnline(sess *types.SessionInfo) {
	if n == nil || sess == nil {
		return
	}
	cfg := n.liveCfg()
	if cfg == nil || !cfg.Enabled || !cfg.OnlyOnline {
		return
	}
	if cfg.URL == "" {
		return
	}

	fields := map[string]interface{}{
		"event":       "session_online",
		"session_id":  sess.ID,
		"hostname":    sess.Hostname,
		"username":    sess.Username,
		"os":          sess.OS,
		"arch":        sess.Arch,
		"remote_addr": sess.RemoteAddr,
		"timestamp":   time.Now().Unix(),
	}
	payload := buildPayload(cfg, n.renderContent(sess), fields)

	status, respBody, err := postPayload(n.client, cfg, payload)
	if err != nil {
		logging.Warn("webhook", "POST %s failed: %v", cfg.URL, err)
		return
	}
	if status >= 300 {
		logging.Warn("webhook", "POST %s returned status %d body=%s", cfg.URL, status, truncate(respBody, 200))
		return
	}
	logging.Info("webhook", "session_online notification sent for %s (%s@%s)", sess.ID, sess.Username, sess.Hostname)
}

// SendTest 发送一条测试消息到指定 webhook（设置页"发送测试通知"按钮）。
// 返回（HTTP 状态码, 响应体, 错误）。钉钉等平台会返回 {"errcode":0,...} 表示成功。
func SendTest(webhookURL, content, format, secret string) (int, string, error) {
	cfg := &config.WebhookConfig{URL: webhookURL, Content: content, Format: format, Secret: secret}
	if cfg.Content == "" {
		cfg.Content = "ToShell 测试通知: 配置生效 ✅"
	}
	fields := map[string]interface{}{
		"event": "webhook_test", "timestamp": time.Now().Unix(),
	}
	payload := buildPayload(cfg, cfg.Content, fields)
	client := &http.Client{Timeout: 10 * time.Second}
	return postPayload(client, cfg, payload)
}

// buildPayload 按格式构造请求体。
func buildPayload(cfg *config.WebhookConfig, content string, fields map[string]interface{}) []byte {
	if resolveFormat(cfg) == "dingtalk" {
		// 钉钉 markdown 消息
		md := "**ToShell 新会话上线**\n\n"
		md += "> 主机名: " + str(fields["hostname"]) + "\n"
		md += "> 用户: " + str(fields["username"]) + "\n"
		md += "> 系统: " + str(fields["os"]) + "/" + str(fields["arch"]) + "\n"
		md += "> 来源: " + str(fields["remote_addr"]) + "\n"
		md += "> 会话: " + str(fields["session_id"]) + "\n"
		md += "> 时间: " + time.Now().Format("2006-01-02 15:04:05")
		title := "ToShell 会话上线"
		if fields["event"] == "webhook_test" {
			md = content
			title = "ToShell 测试通知"
		}
		p, _ := json.Marshal(map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]interface{}{
				"title": title,
				"text":  md,
			},
			"at": map[string]interface{}{"isAtAll": false},
		})
		return p
	}
	// 通用 JSON：event + content + 会话字段
	payload := map[string]interface{}{"content": content}
	for k, v := range fields {
		payload[k] = v
	}
	p, _ := json.Marshal(payload)
	return p
}

// postPayload 发送请求体并返回（HTTP 状态码, 响应体, 错误）。
// 钉钉加签模式（Secret 非空）自动追加 timestamp+sign 参数。
func postPayload(client *http.Client, cfg *config.WebhookConfig, payload []byte) (int, string, error) {
	target := cfg.URL
	if resolveFormat(cfg) == "dingtalk" && cfg.Secret != "" {
		var err error
		target, err = dingtalkSignedURL(cfg.URL, cfg.Secret)
		if err != nil {
			return 0, "", fmt.Errorf("钉钉加签 URL 构造失败: %v", err)
		}
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ToShell/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// dingtalkSignedURL 为钉钉加签模式追加 timestamp 与 sign 参数。
// 签名算法：sign = base64(HMAC-SHA256(secret, timestamp+"\n"+secret))。
func dingtalkSignedURL(rawURL, secret string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts + "\n" + secret))
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// renderContent 渲染内容模板：替换 {session_id} {hostname} {username} {os} {arch} {remote_addr} {time} 占位符。
func (n *Notifier) renderContent(sess *types.SessionInfo) string {
	tpl := n.liveCfg().Content
	if tpl == "" {
		tpl = "新会话上线: {hostname} ({username}@{os}/{arch}) 来自 {remote_addr}"
	}
	r := strings.NewReplacer(
		"{session_id}", sess.ID,
		"{hostname}", sess.Hostname,
		"{username}", sess.Username,
		"{os}", sess.OS,
		"{arch}", sess.Arch,
		"{remote_addr}", sess.RemoteAddr,
		"{time}", time.Now().Format("2006-01-02 15:04:05"),
	)
	return r.Replace(tpl)
}

// String 返回通知器配置摘要（用于日志/调试）。
func (n *Notifier) String() string {
	if n == nil || n.cfg == nil || !n.cfg.Enabled {
		return "webhook disabled"
	}
	return fmt.Sprintf("webhook enabled -> %s (%s)", n.cfg.URL, resolveFormat(n.cfg))
}

func str(v interface{}) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%v", v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

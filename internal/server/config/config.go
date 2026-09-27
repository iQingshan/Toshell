package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server" json:"server"`
	Listener ListenerConfig `mapstructure:"listener" json:"listener"`
	Implant  ImplantConfig  `mapstructure:"implant" json:"implant"`
	Builder  BuilderConfig  `mapstructure:"builder" json:"builder"`
	Database DatabaseConfig `mapstructure:"database" json:"database"`
	Logging  LoggingConfig  `mapstructure:"logging" json:"logging"`
	Auth     AuthConfig     `mapstructure:"auth" json:"auth"`
	Webhook  WebhookConfig  `mapstructure:"webhook" json:"webhook"`
	AI       AIConfig       `mapstructure:"ai" json:"ai"`
	Web      WebConfig      `mapstructure:"web" json:"web"`
	MCP      MCPConfig      `mapstructure:"mcp" json:"mcp"`
}

// MCPConfig 对外 MCP（Model Context Protocol）服务端配置。
//
// ⚠️ 安全前置：**MCP 客户端一旦连上，就等于拿到调用内部工具的能力**（与内置 AI 副驾驶同一张
// 工具表，其中包含命令执行、注入、载荷构建等）。因此本段默认 `enabled: false`，开启后也
// **只绑回环地址**、**必须配置 token**，且默认**只放行只读工具**（`allowed_tools` 留空即取
// 注册表里的 LevelRead 集合）。不要把 MCP 端点暴露到公网；跨机访问请走堡垒机/SSH 端口转发。
type MCPConfig struct {
	// Enabled 是否启动 MCP 服务端（默认 false）。
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	// Bind 监听地址（默认 127.0.0.1:18082；**不要**设成 0.0.0.0 除非你清楚风险）。
	Bind string `mapstructure:"bind" json:"bind"`
	// Token 访问令牌（必需）。走 `Authorization: Bearer <token>` 或 `X-MCP-Token`；
	// 留空时即使 enabled=true 也会拒绝启动（fail-closed，不允许无鉴权裸奔）。
	Token string `mapstructure:"token" json:"token"`
	// AllowedTools 允许通过 MCP 调用的工具白名单；留空 = 仅只读工具（注册表 LevelRead）。
	AllowedTools []string `mapstructure:"allowed_tools" json:"allowed_tools"`
	// AllowedOrigins 允许的浏览器 Origin（留空 = 拒绝所有带 Origin 的跨域请求）。
	AllowedOrigins []string `mapstructure:"allowed_origins" json:"allowed_origins"`
	// AllowedCIDRs 允许访问 MCP 的来源网段（CIDR 或裸 IP；留空 = 不限制来源）。
	// 注意：**不读 X-Forwarded-For**，避免被伪造绕过；跨机访问请配合堡垒机/端口转发。
	AllowedCIDRs []string `mapstructure:"allow_cidrs" json:"allow_cidrs"`
	// MaxRPM 每 token 每分钟请求上限（**<=0 取默认 60，不是"不限制"**，符合 fail-closed 口径）。
	MaxRPM int `mapstructure:"max_rpm" json:"max_rpm"`
	// MaxConcurrent 同时执行的工具调用上限（<=0 取默认 4）。
	MaxConcurrent int `mapstructure:"max_concurrent" json:"max_concurrent"`
	// MaxPendingHandles 每 token 未读完的外置结果句柄上限（<=0 取默认 32）。
	// 客户端拿了句柄不读、又继续调用，会先撞这道闸（429），不会无上限占盘。
	MaxPendingHandles int `mapstructure:"max_pending_handles" json:"max_pending_handles"`
	// InlineLimit 结果内联上限（字节，默认 8192；超出则外置成句柄）。
	InlineLimit int `mapstructure:"inline_limit" json:"inline_limit"`
	// ResultDir 大结果外置目录（默认 ./data/mcp-results）。
	ResultDir string `mapstructure:"result_dir" json:"result_dir"`
	// ResultTTL 外置结果保留时长（默认 24h，支持 Go duration 字符串）。
	ResultTTL string `mapstructure:"result_ttl" json:"result_ttl"`
	// AuditPath 审计日志路径（JSONL，默认 ./logs/mcp-audit.jsonl）。
	AuditPath string `mapstructure:"audit_path" json:"audit_path"`
	// FailClosed 出错时是否直接拒绝（默认 true；关掉只会放宽，不建议）。
	FailClosed bool `mapstructure:"fail_closed" json:"fail_closed"`
}

// BuilderConfig 构建工具链配置（C 植入端编译所需的 mingw gcc、构建后代码签名等）。
type BuilderConfig struct {
	// MingwGCCPath 指定 mingw-w64 gcc 可执行文件路径（C 植入端编译用），
	// 也可填 gcc 所在目录或用 PATH 中的名字。留空时自动探测：环境变量
	// TOSHELL_MINGW_GCC / CC / MINGW_HOME / MSYS2_ROOT / MINGW_PREFIX →
	// 服务端同目录的便携工具链（如 ./mingw64/bin/gcc.exe）→ 常见安装目录
	// （MSYS2/TDM-GCC/Chocolatey/Scoop）→ PATH 与 Windows 注册表 PATH。
	MingwGCCPath string `mapstructure:"mingw_gcc_path" json:"mingw_gcc_path"`

	// ─── 代码签名（Authenticode，Windows 载荷可选）──────────────────────
	//
	// 为什么需要：装有 360/电脑管家等国产安全软件的主机上，**未签名的新 PE 往往在
	// 进程创建阶段就被拒绝执行并删除**（实测连 Hello-World Go 程序也一样，而微软签名的
	// notepad.exe 副本可正常执行）。签名不是万能的（杀软还会看信誉/行为），但它是
	// "能不能跑起来"这一层的敲门砖。
	//
	// 签名模式（二选一，pfx 优先）：
	//   1) SignPFXPath + SignPFXPassword：用 pfx/证书文件签名；
	//   2) SignThumbprint：用本机证书存储（CurrentUser\My）里该指纹的证书签名。
	// 签名工具优先用 signtool.exe（SignSigntoolPath → PATH → Windows SDK 常见路径），
	// 找不到时自动回退到 PowerShell 的 Set-AuthenticodeSignature（系统自带，无需装 SDK）。
	SignEnabled      bool   `mapstructure:"sign_enabled" json:"sign_enabled"`
	SignPFXPath      string `mapstructure:"sign_pfx_path" json:"sign_pfx_path"`
	SignPFXPassword  string `mapstructure:"sign_pfx_password" json:"-"`
	SignThumbprint   string `mapstructure:"sign_thumbprint" json:"sign_thumbprint"`
	SignTimestampURL string `mapstructure:"sign_timestamp_url" json:"sign_timestamp_url"`
	SignSigntoolPath string `mapstructure:"sign_signtool_path" json:"sign_signtool_path"`
	// SignDescription 写入签名描述（可选，留空用默认）。
	SignDescription string `mapstructure:"sign_description" json:"sign_description"`
	// SignFailClosed 为 true 时"签名失败就丢弃该载荷"（构建报错）；默认 false 只告警并返回未签名产物。
	SignFailClosed bool `mapstructure:"sign_fail_closed" json:"sign_fail_closed"`
}

// WebConfig Web 控制台防护配置（防资产测绘引擎收录、防未授权访问）。
// 注意：只作用于「控制台 + 管理 API」端口；植入端回连（/api/v1/implant/*）
// 与 C2 监听器端口不受影响，否则植入端会失联。
type WebConfig struct {
	// BasicAuthEnabled 开启 HTTP Basic 认证前置门槛（浏览器弹框），
	// 用于阻止测绘引擎（Fofa/Quake/Hunter 等）抓取并收录本资产。
	BasicAuthEnabled bool `mapstructure:"basic_auth_enabled" json:"basic_auth_enabled"`
	// BasicAuthUser Basic 认证用户名。
	BasicAuthUser string `mapstructure:"basic_auth_user" json:"basic_auth_user"`
	// BasicAuthPassword Basic 认证密码的 bcrypt 哈希（不存明文）。
	BasicAuthPassword string `mapstructure:"basic_auth_password" json:"-"`
	// UnauthMode 未认证时的响应方式：
	//   disguise（默认）= 返回 404（对外表现"无此服务"，不留 C2 特征）
	//   basic          = 返回 401 + WWW-Authenticate（浏览器弹出认证框，便于日常使用）
	UnauthMode string `mapstructure:"unauth_mode" json:"unauth_mode"`
	// DecoyTitle 可选：替换控制台首页 <title>，避免默认标题暴露用途。
	DecoyTitle string `mapstructure:"decoy_title" json:"decoy_title"`
	// AllowCIDRs 可选：控制台访问来源白名单（CIDR 列表，如 203.0.113.0/24）。
	// 非空时，不在列表内的来源即使凭据正确也会被拒（用于把控制台限制在运维网段）。
	AllowCIDRs []string `mapstructure:"allow_cidrs" json:"allow_cidrs"`
	// StealthKey 隐蔽入口密钥（非空时启用）：由于 disguise 模式不返回 401 挑战，
	// 浏览器无法弹出认证框，也没有办法把 Basic 凭据带到 JS/CSS 子资源请求上。
	// 设置本密钥后，浏览器访问一次 /__gate?k=<密钥> 即会种下入口 Cookie，
	// 之后整个控制台（含静态资源与 API）凭该 Cookie 通行；
	// 其他任何未持凭据的请求依旧返回 404 伪装，不留 C2 特征。
	StealthKey string `mapstructure:"stealth_key" json:"-"`
	// StealthCookie 入口 Cookie 名（默认 tsh_gate）。
	StealthCookie string `mapstructure:"stealth_cookie" json:"stealth_cookie"`
	// EntryChallenge 是否允许在入口路径 /__gate 上返回 401 挑战（默认 true）：
	// disguise 模式下浏览器不会对 / 弹认证框，但在入口路径上给出挑战后，
	// 浏览器会弹出认证框，输入控制台防护的用户名/密码即可种下入口 Cookie。
	// 只有 /__gate 会给出挑战；其他任何路径（含 /）依旧 404 伪装。
	EntryChallenge bool `mapstructure:"entry_challenge" json:"entry_challenge"`
}

// DefaultLongTaskThresholdSec 长任务挂起的默认预估超时阈值（秒）。
//
// 定义在 config 包而不是 ai 包：viper 默认值（本包）与运行时的策略兜底（ai 包）
// 必须是**同一个数**，而 ai 依赖 config、反向不成立。ai.DefaultLongTaskThresholdSec
// 直接引用本常量，杜绝"注释写 150 / viper 写 120 / 运行时兜底 180"这类历史漂移。
const DefaultLongTaskThresholdSec = 150

// AIConfig AI 副驾驶（LLM 聊天 + 工具调用）配置。
// BaseURL 为 OpenAI 兼容的 chat/completions 端点（如 https://api.deepseek.com/v1）；
// 留空时 AI 副驾驶不可用（前端显示未配置提示）。
type AIConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`   // 是否启用
	BaseURL string `mapstructure:"base_url" json:"base_url"` // OpenAI 兼容端点
	APIKey  string `mapstructure:"api_key" json:"api_key"`   // API Key
	Model   string `mapstructure:"model" json:"model"`       // 模型名（如 deepseek-chat）
	Timeout int    `mapstructure:"timeout" json:"timeout"`   // 单次请求超时（秒），默认 60
	// MaxTurns 工具调用最大轮数（默认 20）。v1.4.0 S2 起三处默认值统一为 20：
	// 本注释、viper.SetDefault、ai 包的运行时兜底（历史上注释写 8 / viper 20 / 前端 8 / 后端 20）。
	MaxTurns int `mapstructure:"max_turns" json:"max_turns"`
	// MaxToolCalls 一次 run 内最多发起多少次工具调用（默认 40）；<=0 时按默认值处理，
	// **不允许**用配置关掉上限（关掉等于把"无限下发命令"的能力交回给模型）。
	MaxToolCalls int `mapstructure:"max_tool_calls" json:"max_tool_calls"`
	// MaxWallclockSec 一次 run 的最长墙钟时间（秒，默认 900）；<=0 时按默认值处理。
	// 它约束的是"真实耗时"而非模型轮次，上游卡住/单步超时也一定会收手。
	MaxWallclockSec int `mapstructure:"max_wallclock_sec" json:"max_wallclock_sec"`
	// ConsentMode 旧键（v1.4.0 S2 起由 ConsentPolicy 取代，保留仅为兼容老配置）：
	// auto=全自动（等价 consent_policy=off）；normal=影响会话的操作需用户同意（等价 graded）。
	// 新的分级语义（只读/confirm/danger）与 delegate 硬兜底见 internal/server/ai 的审批判定。
	ConsentMode string `mapstructure:"consent_mode" json:"consent_mode"`
	// ConsentPolicy 分级审批策略：graded（默认，只读免审 + confirm/danger 需用户同意）/
	// all（含只读在内的一切工具都需同意）/ off（都不问，危险，仅在明确知道后果时使用）。
	// 旧值兼容：auto→off、normal→graded；无法识别的值按 graded 处理并在启动日志里告警。
	ConsentPolicy string `mapstructure:"consent_policy" json:"consent_policy"`
	// AgentConcurrency 异步自主 Agent 的并发上限（同时进行的 run 数），默认 2。
	// 每个 run 独立后台 goroutine，超过上限的任务排队等待。
	AgentConcurrency int `mapstructure:"agent_concurrency" json:"agent_concurrency"`
	// LongTaskThresholdSec 长任务挂起的预估超时阈值（秒，默认 150，见 DefaultLongTaskThresholdSec）。
	//
	// 语义：预估超时 ≥ 该值的工具，在 Agent 内部改走「提交 → 挂起 → 任务完成事件恢复」，
	// 从而**释放并发槽位**（否则一个 credentials 就把槽位占满 180s）。低于阈值的短工具
	// 保持同步等待——挂起它们只会更慢（多一次落库 + 重新进入循环）。
	// <=0 一律回落默认值：配置失误不允许让长任务重新占满槽位。
	LongTaskThresholdSec int `mapstructure:"long_task_threshold_sec" json:"long_task_threshold_sec"`
	// DownloadAllowlist 工具下载域名白名单（空=允许任意公网域名，但仍拒绝内网/回环地址）。
	// 用于限制 remote_download 只能从可信域名拉取，防止被诱导下载到恶意源头。
	DownloadAllowlist []string `mapstructure:"download_allowlist" json:"download_allowlist"`
}

type ServerConfig struct {
	Host           string        `mapstructure:"host" json:"host"`
	Port           uint16        `mapstructure:"port" json:"port"`
	TLSCert        string        `mapstructure:"tls_cert" json:"tls_cert"`
	TLSKey         string        `mapstructure:"tls_key" json:"tls_key"`
	APIHost        string        `mapstructure:"api_host" json:"api_host"`
	APIPort        uint16        `mapstructure:"api_port" json:"api_port"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" json:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout" json:"write_timeout"`
	IdleTimeout    time.Duration `mapstructure:"idle_timeout" json:"idle_timeout"`
	MaxConnections int           `mapstructure:"max_connections" json:"max_connections"`
	// TrustProxyHeaders 仅当服务部署在可信反代（nginx/caddy）之后才设为 true：
	// 登录限速/日志按 X-Forwarded-For 取源 IP；默认 false（直连场景信任该头可被
	// 客户端伪造绕过限速或锁死他人 IP）。
	TrustProxyHeaders bool `mapstructure:"trust_proxy_headers" json:"trust_proxy_headers"`
}

type ListenerConfig struct {
	// ID 监听器标识（DB 记录 ID 或 default-*）；用于会话 → 监听器推送路由。
	ID               string        `mapstructure:"id" json:"id"`
	Enabled          bool          `mapstructure:"enabled" json:"enabled"`
	Host             string        `mapstructure:"host" json:"host"`
	Port             uint16        `mapstructure:"port" json:"port"`
	PublicHost       string        `mapstructure:"public_host" json:"public_host"`
	Protocol         string        `mapstructure:"protocol" json:"protocol"`
	TLSEnabled       bool          `mapstructure:"tls_enabled" json:"tls_enabled"`
	CertFile         string        `mapstructure:"cert_file" json:"cert_file"`
	KeyFile          string        `mapstructure:"key_file" json:"key_file"`
	EncryptionKey    string        `mapstructure:"encryption_key" json:"encryption_key"`
	HeartbeatTimeout time.Duration `mapstructure:"heartbeat_timeout" json:"heartbeat_timeout"`
	WriteQueueSize   int           `mapstructure:"write_queue_size" json:"write_queue_size"`
	// MimicryProfile 选择 HTTP 监听器的流量拟态模板（cdn / api / stream）。
	// 为空或未命中时回退到默认模板 cdn。见 internal/server/mimicry。
	MimicryProfile string `mapstructure:"mimicry_profile" json:"mimicry_profile"`
	// MQTTBrokerURL MQTT 监听器连接的 broker 地址（如 tcp://broker:1883）。
	// 空 = 默认本机 1883（配合内嵌 broker 使用）。
	MQTTBrokerURL string `mapstructure:"mqtt_broker_url" json:"mqtt_broker_url"`
	// MQTTTopicPrefix MQTT 主题前缀（默认 toshell），多实例隔离用。
	MQTTTopicPrefix string `mapstructure:"mqtt_topic_prefix" json:"mqtt_topic_prefix"`
	// MQTTEmbeddedBroker 为 true 时启动内嵌 broker（brokerURL 为空时默认监听本机端口）。
	MQTTEmbeddedBroker bool `mapstructure:"mqtt_embedded_broker" json:"mqtt_embedded_broker"`
	// FrontDomain 域前置拟态域名：植入端 HTTPS 轮询时用作 TLS SNI 与 HTTP Host。
	// 把 C2 服务器部署在 CDN/反代后面后，目标机出站流量表现为访问该合法域名，
	// 可过基于域名的出口白名单。空 = 不使用域前置（SNI/Host 用服务器地址）。
	FrontDomain string `mapstructure:"front_domain" json:"front_domain"`
	// MimicrySite 监听器伪装目标站（完整 URL，如 https://www.example.com）。
	// 非空时，HTTP 监听器对所有非 C2 请求反向代理到该网站，探测者看到的是
	// 与目标站完全一致的响应（页面/资源/404）。空 = 使用静态拟态模板。
	MimicrySite string `mapstructure:"mimicry_site" json:"mimicry_site"`
}

type ImplantConfig struct {
	Interval     uint32 `mapstructure:"interval" json:"interval"`
	Jitter       uint32 `mapstructure:"jitter" json:"jitter"`
	RetryCount   uint32 `mapstructure:"retry_count" json:"retry_count"`
	RetryWait    uint32 `mapstructure:"retry_wait" json:"retry_wait"`
	KillDate     string `mapstructure:"kill_date" json:"kill_date"`
	WorkingHours string `mapstructure:"working_hours" json:"working_hours"`
	OutputDir    string `mapstructure:"output_dir" json:"output_dir"`
	// TemplateDir 指定植入端模板源码目录。为空时依次回退到
	// TOSHELL_IMPLANT_TEMPLATE_DIR 环境变量、exe 同目录的 implant/、
	// 当前目录的 internal/server/builder/implant，方便正式版部署。
	TemplateDir string `mapstructure:"template_dir" json:"template_dir"`
	// 启动随机延迟（秒）：植入端启动后随机休眠 [min,max] 秒，打乱"启动即行为"检测节奏。
	StartupDelayMin int `mapstructure:"startup_delay_min" json:"startup_delay_min"`
	StartupDelayMax int `mapstructure:"startup_delay_max" json:"startup_delay_max"`
}

type DatabaseConfig struct {
	Type     string `mapstructure:"type" json:"type"`
	Path     string `mapstructure:"path" json:"path"`
	Host     string `mapstructure:"host" json:"host"`
	Port     uint16 `mapstructure:"port" json:"port"`
	Username string `mapstructure:"username" json:"username"`
	Password string `mapstructure:"password" json:"password"`
	Database string `mapstructure:"database" json:"database"`
	SSLMode  string `mapstructure:"ssl_mode" json:"ssl_mode"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level" json:"level"`
	Format     string `mapstructure:"format" json:"format"`
	Output     string `mapstructure:"output" json:"output"`
	MaxSize    int    `mapstructure:"max_size" json:"max_size"`
	MaxBackups int    `mapstructure:"max_backups" json:"max_backups"`
	MaxAge     int    `mapstructure:"max_age" json:"max_age"`
	Compress   bool   `mapstructure:"compress" json:"compress"`
}

type AuthConfig struct {
	Enabled       bool     `mapstructure:"enabled" json:"enabled"`
	JWTEnabled    bool     `mapstructure:"jwt_enabled" json:"jwt_enabled"`
	JWTKey        string   `mapstructure:"jwt_key" json:"jwt_key"`
	JWTExpire     int      `mapstructure:"jwt_expire" json:"jwt_expire"`
	APIKeyEnabled bool     `mapstructure:"api_key_enabled" json:"api_key_enabled"`
	APIKeys       []string `mapstructure:"api_keys" json:"api_keys"`
	AdminUsername string   `mapstructure:"admin_username" json:"admin_username"`
	AdminPassword string   `mapstructure:"admin_password" json:"admin_password"`
}

// WebhookConfig 会话上线通知（webhook）配置。
type WebhookConfig struct {
	Enabled    bool   `mapstructure:"enabled" json:"enabled"`         // 是否启用
	URL        string `mapstructure:"url" json:"url"`                 // 通知目标 URL（企业微信/钉钉/飞书/Slack 等机器人 webhook）
	Content    string `mapstructure:"content" json:"content"`         // 内容模板，支持 {session_id} {hostname} {username} {os} {arch} {remote_addr} {time}
	OnlyOnline bool   `mapstructure:"only_online" json:"only_online"` // 仅上线通知（true 时只在会话上线时发送）
	// Format 消息格式：auto（按 URL 自动识别平台）/ dingtalk（钉钉 markdown）/
	// feishu（飞书、Lark）/ wecom（企业微信）/ slack / discord /
	// generic（通用 JSON，自建接收端）。空 = auto。
	Format string `mapstructure:"format" json:"format"`
	// Secret 机器人加签密钥。钉钉：timestamp+sign 查询参数；
	// 飞书：body 内 timestamp+sign（HMAC-SHA256）。使用关键字模式可留空。
	Secret string `mapstructure:"secret" json:"secret"`
}

var GlobalConfig *Config

// 配置热更新订阅者：Apply 成功后会依次调用（副本迭代，回调内再注册安全）。
var (
	onChangeMu sync.RWMutex
	onChange   []func(*Config)
)

// OnChange 注册配置热更新回调。回调在配置被重新应用后执行，
// 触发来源：配置文件被外部修改（viper WatchConfig 自动重载）或
// 通过设置 API 保存（Save）。可用于通知各组件（listener/auth 等）热生效。
func OnChange(cb func(*Config)) {
	onChangeMu.Lock()
	onChange = append(onChange, cb)
	onChangeMu.Unlock()
}

func fireOnChange() {
	onChangeMu.RLock()
	cbs := make([]func(*Config), len(onChange))
	copy(cbs, onChange)
	onChangeMu.RUnlock()
	for _, cb := range cbs {
		cb(GlobalConfig)
	}
}

// Apply 从 viper 重新读取并应用当前配置，通知所有订阅者。
// 供外部修改配置文件后的自动重载（WatchConfig）与设置 API 保存后调用。
func Apply() error {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return err
	}
	GlobalConfig = &cfg
	fireOnChange()
	return nil
}

// Save 批量应用配置项（key 为 viper 路径，如 "listener.mimicry_profile"），
// 原子写回配置文件并立即热生效。
//
// 写入语义（重要）：采用「读-改-写 + 原子替换」而不是 viper.WriteConfig()：
//  1. 把配置文件读成 YAML 节点树（保留注释、字段顺序与缩进）；
//  2. 只修改传入的 key，其余内容原样保留；
//  3. 写同目录临时文件 → fsync → rename 覆盖（避免截断写入导致配置损坏/丢凭据）。
func Save(updates map[string]interface{}) error {
	if err := Persist(updates); err != nil {
		return err
	}
	// 用文件内容同步 viper 内存态（比逐个 viper.Set 更贴近磁盘真实值）
	if err := viper.ReadInConfig(); err != nil {
		for k, v := range updates {
			viper.Set(k, v)
		}
	}
	return Apply()
}

// configFilePath 记录本次进程实际使用的配置文件绝对路径（Load 时确定）。
var configFilePath string

// ConfigPath 返回当前生效的配置文件绝对路径（空 = 未使用配置文件）。
func ConfigPath() string { return configFilePath }

// resolveConfigPath 解析配置文件路径：显式 -config 优先，其次 viper 实际读到的文件，
// 最后回退到 ./configs/server.yaml（首个启动目录）。返回绝对路径。
func resolveConfigPath(explicit string) string {
	p := strings.TrimSpace(explicit)
	if p == "" {
		if used := viper.ConfigFileUsed(); used != "" {
			p = used
		}
	}
	if p == "" {
		p = filepath.Join("configs", "server.yaml")
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// Persist 把 updates 原子写回配置文件：只改传入的 key，其余字段与注释原样保留。
// 文件不存在时会创建（含父目录），因此首次启动生成的凭据也能真正落盘。
func Persist(updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	path := configFilePath
	if path == "" {
		path = resolveConfigPath("")
	}
	if strings.HasSuffix(path, ".yaml.example") || strings.HasSuffix(path, ".yml.example") {
		// 兜底：绝不写入示例文件（否则会污染模板并可能泄露真实密钥）
		path = strings.TrimSuffix(path, ".example")
	}
	doc, err := loadYAMLDoc(path)
	if err != nil {
		return err
	}
	for k, v := range updates {
		if strings.HasPrefix(k, "_") {
			continue // 内部字段（如 _new_api_key）只回传前端，不落盘
		}
		if err := setYAMLPath(doc, k, v); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
	}
	return writeYAMLAtomic(path, doc)
}

// loadYAMLDoc 读取 YAML 文件为节点树；文件不存在时返回空映射文档。
func loadYAMLDoc(path string) (*yaml.Node, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newEmptyYAMLDoc(), nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0] == nil {
		return newEmptyYAMLDoc(), nil
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return newEmptyYAMLDoc(), nil
	}
	return &doc, nil
}

// newEmptyYAMLDoc 构造「空映射」文档节点。
func newEmptyYAMLDoc() *yaml.Node {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
}

// setYAMLPath 在节点树中设置 "a.b.c" 路径的值为 v；中间层级缺失时自动创建映射。
func setYAMLPath(doc *yaml.Node, dotted string, v interface{}) error {
	parts := strings.Split(dotted, ".")
	root := doc.Content[0]
	cur := root
	for i, part := range parts {
		last := i == len(parts)-1
		// 在映射中查找 key
		idx := -1
		for j := 0; j+1 < len(cur.Content); j += 2 {
			if cur.Content[j].Value == part {
				idx = j
				break
			}
		}
		if last {
			valNode, err := encodeYAMLValue(v)
			if err != nil {
				return err
			}
			if idx >= 0 {
				cur.Content[idx+1] = valNode
			} else {
				cur.Content = append(cur.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, valNode)
			}
			return nil
		}
		if idx >= 0 && cur.Content[idx+1].Kind == yaml.MappingNode {
			cur = cur.Content[idx+1]
			continue
		}
		child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if idx >= 0 {
			cur.Content[idx+1] = child // 叶子与中间层级冲突时以中间映射为准
		} else {
			cur.Content = append(cur.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, child)
		}
		cur = child
	}
	return nil
}

// encodeYAMLValue 把 Go 值编码为 YAML 节点（保留类型：整数/布尔/字符串/序列）。
func encodeYAMLValue(v interface{}) (*yaml.Node, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tmp yaml.Node
	if err := yaml.Unmarshal(b, &tmp); err != nil {
		return nil, err
	}
	if len(tmp.Content) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}, nil
	}
	return tmp.Content[0], nil
}

// writeYAMLAtomic 原子写回：同目录临时文件 → fsync → rename 覆盖。
// 任一步失败都不会破坏原文件（这是「配置写坏导致凭据丢失」的根治手段）。
func writeYAMLAtomic(path string, doc *yaml.Node) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	mode := os.FileMode(0o600)
	if st, serr := os.Stat(path); serr == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".server.yaml.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows 上 rename 到已存在文件会失败：先移除目标再重试。
		if rmErr := os.Remove(path); rmErr == nil {
			if err2 := os.Rename(tmpName, path); err2 == nil {
				return nil
			}
		}
		cleanup()
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func Load(configPath string) (*Config, error) {
	viper.SetConfigType("yaml")

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("server")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("/etc/toshell/")
	}

	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.api_port", 8081)
	viper.SetDefault("server.read_timeout", 30*time.Second)
	viper.SetDefault("server.write_timeout", 30*time.Second)
	viper.SetDefault("server.idle_timeout", 120*time.Second)
	viper.SetDefault("server.max_connections", 1000)

	viper.SetDefault("listener.enabled", true)
	viper.SetDefault("listener.host", "0.0.0.0")
	viper.SetDefault("listener.port", 8080)
	viper.SetDefault("listener.protocol", "websocket")
	viper.SetDefault("listener.tls_enabled", false)
	viper.SetDefault("listener.cert_file", "")
	viper.SetDefault("listener.key_file", "")
	viper.SetDefault("listener.encryption_key", "")
	viper.SetDefault("listener.write_queue_size", 500)
	viper.SetDefault("listener.mimicry_profile", "cdn")

	viper.SetDefault("implant.interval", 60)
	// 抖动默认 20%（不是 10%）：与「生成载荷」能力接口对外声明的默认值、
	// 以及服务端在请求未指定时的回退值保持**同一套口径**。三处曾经不一致
	// （配置默认 10 / 接口声明 20 / 构建回退 20），用户看到的默认值和实际烘焙
	// 进载荷的值对不上，排查起来很费劲。
	viper.SetDefault("implant.jitter", 20)
	viper.SetDefault("implant.retry_count", 3)
	viper.SetDefault("implant.retry_wait", 5)
	viper.SetDefault("implant.output_dir", "./implants")
	viper.SetDefault("implant.startup_delay_min", 2)
	viper.SetDefault("implant.startup_delay_max", 10)

	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.path", "./data/toshell.db")

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")

	viper.SetDefault("auth.enabled", true)
	viper.SetDefault("auth.jwt_enabled", true)
	viper.SetDefault("auth.jwt_key", "")
	viper.SetDefault("auth.jwt_expire", 24)
	viper.SetDefault("auth.api_key_enabled", true)

	viper.SetDefault("webhook.enabled", false)
	viper.SetDefault("webhook.url", "")
	viper.SetDefault("webhook.content", "")
	viper.SetDefault("webhook.only_online", true)

	// Web 控制台防护（防资产测绘/未授权访问）
	viper.SetDefault("web.basic_auth_enabled", false)
	viper.SetDefault("web.basic_auth_user", "toshell")
	viper.SetDefault("web.basic_auth_password", "")
	// 默认 basic：未认证返回 401 挑战 → 浏览器弹出认证框，前端仍可正常使用。
	// disguise（404 伪装）更隐蔽，但浏览器不会弹框，需在 URL 里携带凭据
	// （https://user:pass@host/）才能进入前端，适合纯 API/CLI 场景。
	viper.SetDefault("web.unauth_mode", "basic")
	viper.SetDefault("web.decoy_title", "")
	viper.SetDefault("web.allow_cidrs", []string{})
	// 隐蔽入口（disguise 模式下浏览器进入控制台的唯一方式）
	viper.SetDefault("web.stealth_key", "")
	viper.SetDefault("web.stealth_cookie", "tsh_gate")
	// 入口路径 /__gate 上返回 401 挑战，让浏览器能弹认证框（仅该路径；/ 仍 404）
	viper.SetDefault("web.entry_challenge", true)

	viper.SetDefault("ai.enabled", false)
	viper.SetDefault("ai.base_url", "")
	viper.SetDefault("ai.api_key", "")
	viper.SetDefault("ai.model", "deepseek-chat")
	viper.SetDefault("ai.timeout", 60)
	// 三处上限的默认值：20 轮 / 40 次工具调用 / 900 秒墙钟。
	viper.SetDefault("ai.max_turns", 20)
	viper.SetDefault("ai.max_tool_calls", 40)
	viper.SetDefault("ai.max_wallclock_sec", 900)
	// 审批策略默认 graded。这里**故意留空串**而不是写 "graded"：老配置往往只写了旧键
	// ai.consent_mode，空串才能让 ai 包的 effectiveConsentPolicy 回落到旧值映射
	// （auto→off / normal→graded）；若在此写死 "graded"，旧键会被默认值盖掉而失效。
	viper.SetDefault("ai.consent_policy", "")
	viper.SetDefault("ai.agent_concurrency", 2)
	// 长任务挂起阈值：与 ai.DefaultLongTaskThresholdSec 同一个常量（单一来源）。
	viper.SetDefault("ai.long_task_threshold_sec", DefaultLongTaskThresholdSec)

	// ── 对外 MCP 服务端（默认整体关闭；开启后也只绑回环 + 需 token + 只放行只读工具）──
	viper.SetDefault("mcp.enabled", false)
	viper.SetDefault("mcp.bind", "127.0.0.1:18082")
	viper.SetDefault("mcp.token", "")
	viper.SetDefault("mcp.allowed_tools", []string{})
	viper.SetDefault("mcp.allowed_origins", []string{})
	viper.SetDefault("mcp.allow_cidrs", []string{})
	viper.SetDefault("mcp.max_rpm", 120)
	viper.SetDefault("mcp.max_concurrent", 4)
	viper.SetDefault("mcp.max_pending_handles", 32)
	viper.SetDefault("mcp.inline_limit", 8192)
	viper.SetDefault("mcp.result_dir", "./data/mcp-results")
	viper.SetDefault("mcp.result_ttl", "24h")
	viper.SetDefault("mcp.audit_path", "./logs/mcp-audit.jsonl")
	viper.SetDefault("mcp.fail_closed", true)

	viper.SetEnvPrefix("TOSHELL")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// 记录本次进程实际使用的配置文件绝对路径（写回凭据/设置时使用）
	configFilePath = resolveConfigPath(configPath)

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	GlobalConfig = &config

	// 配置热更新：监听配置文件变化（外部编辑或设置 API 写回），
	// 自动重新加载并通知订阅者，运行中无需重启进程。
	viper.WatchConfig()
	viper.OnConfigChange(func(_ fsnotify.Event) {
		if err := Apply(); err != nil {
			// 配置可能处于半写入状态，忽略本次并保留旧配置，下次变化再试。
			return
		}
	})

	return &config, nil
}

func Get() *Config {
	if GlobalConfig == nil {
		GlobalConfig = &Config{}
	}
	return GlobalConfig
}

func Set(config *Config) {
	GlobalConfig = config
}

// UpdateListenerConfig 将监听器运行参数同步写回配置文件（供 Web 编辑默认监听器使用）。
// 走 Save 的原子读-改-写路径，只改动 listener.* 这几项，其余字段与注释保留。
// 返回写回后的当前生效配置。
func UpdateListenerConfig(cfg *Config, lc ListenerConfig) error {
	updates := map[string]interface{}{
		"listener.enabled":     lc.Enabled,
		"listener.host":        lc.Host,
		"listener.port":        lc.Port,
		"listener.public_host": lc.PublicHost,
		"listener.protocol":    lc.Protocol,
	}
	if err := Save(updates); err != nil {
		return err
	}
	cfg.Listener = lc
	return nil
}

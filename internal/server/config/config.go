package config

import (
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server" json:"server"`
	Listener ListenerConfig `mapstructure:"listener" json:"listener"`
	Implant  ImplantConfig  `mapstructure:"implant" json:"implant"`
	Database DatabaseConfig `mapstructure:"database" json:"database"`
	Logging  LoggingConfig  `mapstructure:"logging" json:"logging"`
	Auth     AuthConfig     `mapstructure:"auth" json:"auth"`
	Webhook  WebhookConfig  `mapstructure:"webhook" json:"webhook"`
	AI       AIConfig       `mapstructure:"ai" json:"ai"`
}

// AIConfig AI 副驾驶（LLM 聊天 + 工具调用）配置。
// BaseURL 为 OpenAI 兼容的 chat/completions 端点（如 https://api.deepseek.com/v1）；
// 留空时 AI 副驾驶不可用（前端显示未配置提示）。
type AIConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`     // 是否启用
	BaseURL string `mapstructure:"base_url" json:"base_url"`   // OpenAI 兼容端点
	APIKey  string `mapstructure:"api_key" json:"api_key"`     // API Key
	Model   string `mapstructure:"model" json:"model"`         // 模型名（如 deepseek-chat）
	Timeout int    `mapstructure:"timeout" json:"timeout"`     // 单次请求超时（秒），默认 60
	MaxTurns int   `mapstructure:"max_turns" json:"max_turns"` // 工具调用最大轮数，默认 8
	// ConsentMode 权限模式：auto=全自动（默认，工具直接执行）；
	// normal=影响会话的操作（命令下发/文件/进程/凭据/截屏/隧道/插件等）执行前需用户同意，
	// 任务流(delegate/剧本)除外。读取/查询类工具不拦截。
	ConsentMode string `mapstructure:"consent_mode" json:"consent_mode"`
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
	// Format 消息格式：auto（按 URL 自动识别，钉钉用钉钉 markdown，其它通用 JSON）/
	// dingtalk（强制钉钉 markdown）/ generic（通用 JSON）。空 = auto。
	Format string `mapstructure:"format" json:"format"`
	// Secret 钉钉加签密钥（安全设置里的"加签"Secret）。仅在钉钉格式且非空时启用
	// timestamp+sign 加签；使用关键字模式留空即可。
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
// 写回配置文件并立即热生效（WriteConfig 同时会触发 WatchConfig 自动重载）。
// 返回写回后的生效配置。
func Save(updates map[string]interface{}) error {
	for k, v := range updates {
		viper.Set(k, v)
	}
	if err := viper.WriteConfig(); err != nil {
		return err
	}
	return Apply()
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
	viper.SetDefault("implant.jitter", 10)
	viper.SetDefault("implant.retry_count", 3)
	viper.SetDefault("implant.retry_wait", 5)
	viper.SetDefault("implant.output_dir", "./implants")
	viper.SetDefault("implant.startup_delay_min", 5)
	viper.SetDefault("implant.startup_delay_max", 30)

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

	viper.SetDefault("ai.enabled", false)
	viper.SetDefault("ai.base_url", "")
	viper.SetDefault("ai.api_key", "")
	viper.SetDefault("ai.model", "deepseek-chat")
	viper.SetDefault("ai.timeout", 60)
	viper.SetDefault("ai.max_turns", 20)

	viper.SetEnvPrefix("TOSHELL")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

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
// 返回写回后的当前生效配置。
func UpdateListenerConfig(cfg *Config, lc ListenerConfig) error {
	viper.Set("listener.enabled", lc.Enabled)
	viper.Set("listener.host", lc.Host)
	viper.Set("listener.port", lc.Port)
	viper.Set("listener.public_host", lc.PublicHost)
	viper.Set("listener.protocol", lc.Protocol)
	if err := viper.WriteConfig(); err != nil {
		return err
	}
	cfg.Listener = lc
	return nil
}

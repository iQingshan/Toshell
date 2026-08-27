package types

import (
	"time"
)

type SessionInfo struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	PID           uint32    `json:"pid"`
	ProcessName   string    `json:"process_name"`
	ProcessPath   string    `json:"process_path"` // 🔴 新增：Agent 自身的完整磁盘路径
	IPAddresses   []string  `json:"ip_addresses"`
	MACAddresses  []string  `json:"mac_addresses"`
	Domain        string    `json:"domain"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	Listener      string    `json:"listener"`
	ListenerID    string    `json:"listener_id,omitempty"` // 所属监听器 ID（DB 记录或 default-*）；用于多监听器推送路由
	RemoteAddr    string    `json:"remote_addr"`
	ParentRelay   string    `json:"parent_relay,omitempty"` // 中继链的父中继主机名（直连为空）
	CPUUsage      float32   `json:"cpu_usage"`
	MemoryUsed    uint64    `json:"memory_used"`
	ActiveModules []string  `json:"active_modules"`
	Comment       string    `json:"comment,omitempty"`
}

type TaskInfo struct {
	ID          uint64     `json:"id"`
	SessionID   string     `json:"session_id"`
	TaskType    string     `json:"task_type"`
	Command     string     `json:"command"`
	Args        []string   `json:"args"`
	ExecuteType string     `json:"execute_type"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output      string     `json:"output,omitempty"`
	Error       string     `json:"error,omitempty"`
	ExitCode    int32      `json:"exit_code"`
	Timeout     uint32     `json:"timeout"`
	Path        string     `json:"path,omitempty"`
	PID         uint32     `json:"pid,omitempty"`
	Data        string     `json:"data,omitempty"`
	// 传输进度（大文件下载/上传）：0-100 百分比
	Progress int `json:"progress,omitempty"`
}

// TaskStats 任务聚合统计（基于数据库全量任务）
type TaskStats struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Timeout   int `json:"timeout"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
}

// RelayNode 表示一个正在监听的中继节点（供前端"选择中继会话"）。
type RelayNode struct {
	SessionID string `json:"session_id"`
	Hostname  string `json:"hostname"`
	Addr      string `json:"addr"` // 中继监听地址，如 0.0.0.0:9999
	Host      string `json:"host"` // 可达 IP（从 RemoteAddr 提取）
	Port      string `json:"port"` // 监听端口（从 addr 提取）
}

type ListenerInfo struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Protocol    string          `json:"protocol"`
	BindAddr    string          `json:"bind_addr"`
	BindPort    uint16          `json:"bind_port"`
	PublicAddr  string          `json:"public_addr"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	Connections int             `json:"connections"`
	Options     ListenerOptions `json:"options"`
}

type ListenerOptions struct {
	DomainFronting string            `json:"domain_fronting"`
	CertFile       string            `json:"cert_file"`
	KeyFile        string            `json:"key_file"`
	UserAgent      string            `json:"user_agent"`
	Headers        map[string]string `json:"headers"`
	Jitter         uint32            `json:"jitter"`
	Interval       uint32            `json:"interval"`
	TLSEnabled     bool              `json:"tls_enabled"`
	// MQTT 监听器专用：broker 地址（tcp://host:1883）与主题前缀
	MQTTBrokerURL   string `json:"mqtt_broker_url"`
	MQTTTopicPrefix string `json:"mqtt_topic_prefix"`
	// MQTTEmbeddedBroker 内嵌 broker 开关
	MQTTEmbeddedBroker bool `json:"mqtt_embedded_broker"`
}

type ImplantConfig struct {
	ServerURL    string   `json:"server_url"`
	Protocol     string   `json:"protocol"`
	HostKey      string   `json:"host_key"`
	Interval     uint32   `json:"interval"`
	Jitter       uint32   `json:"jitter"`
	RetryCount   uint32   `json:"retry_count"`
	RetryWait    uint32   `json:"retry_wait"`
	KillDate     string   `json:"kill_date"`
	WorkingHours string   `json:"working_hours"`
	Modules      []string `json:"modules"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
	SessionID string    `json:"session_id,omitempty"`
	TaskID    uint64    `json:"task_id,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	User      string    `json:"user,omitempty"`
}

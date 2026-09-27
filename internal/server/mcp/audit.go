package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── 结构化审计 ──────────────────────────────────────────────────────
//
// 目标：每一次工具调用（放行、拒绝、限流、执行失败）都留下**一行 JSONL**，
// 事后能回答"谁、什么时候、从哪里、调了什么工具、参数长什么样、多久、多大、成没成"。
//
// 两条硬约束：
//  1. **不落参数原文**。参数里经常带凭据（密码、hash、token、cookie）、目标口令、
//     载荷配置，原样写日志等于把凭据抄进一个长期保留的文件。这里只落
//     `args_keys`（参数名列表）+ `args_digest`（可关联的摘要，敏感键的值不参与摘要）。
//  2. **不复用 internal/server/logging**。它用 `fmt.Sprintf` 拼 `message` 字段且不转义，
//     把 JSON 塞进去会产出**非法 JSON**。所以审计自己写文件/自己写 stderr。
//
// 落盘策略：`audit_path` 已配置 → 以 O_APPEND 追加写该文件（0600）；
// 未配置 → 只写 stderr（仍是一行一条 JSONL），并在启动日志里明确告警——
// 不静默丢弃审计，但也不偷偷往工作目录里堆文件。

// AuditRecord 一条工具调用审计记录，字段顺序即 JSONL 输出顺序（便于人工/脚本阅读）。
type AuditRecord struct {
	TS          string   `json:"ts"`
	CallID      string   `json:"call_id"`
	Tool        string   `json:"tool"`
	Level       string   `json:"level"`
	ArgsDigest  string   `json:"args_digest"`
	ArgsKeys    []string `json:"args_keys"`
	Status      string   `json:"status"`
	ErrorCode   string   `json:"error_code"`
	DurationMS  int64    `json:"duration_ms"`
	RemoteAddr  string   `json:"remote_addr"`
	Client      string   `json:"client"`
	TokenID     string   `json:"token_id"`
	ResultBytes int      `json:"result_bytes"`
	Truncated   bool     `json:"truncated"`
}

// AuditSink 可选的上层镜像接口：由接线方（api/DB 层）实现，把审计同时写进数据库。
// **保持最小**：单方法、单参数、单返回值，mcp 包不 import database，避免反向依赖。
//
// 注意：Write 在请求路径上同步调用，实现必须快（或自己内部排队）；
// 它返回错误只会被记进 stderr，不会影响工具调用结果（审计落盘才是权威记录）。
type AuditSink interface {
	WriteMCPAudit(rec AuditRecord) error
}

// redactedMarker 敏感参数的替代值：只标记"这里有个敏感值"，不透露长度与内容。
const redactedMarker = "<redacted>"

// sensitiveKeyHints 命中即视为敏感参数名（大小写不敏感的子串匹配）。
// 宁可多脱敏：脱敏只是少一点检索能力，漏脱敏是不可逆的凭据泄漏。
var sensitiveKeyHints = []string{
	"pass", "pwd", "secret", "token", "key", "cred", "cookie", "auth",
	"hash", "sign", "session", "bearer", "jwt", "apikey", "api_key",
}

// IsSensitiveKey 判断参数名是否敏感（导出以便上层复用同一套口径）。
func IsSensitiveKey(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" {
		return false
	}
	for _, h := range sensitiveKeyHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// ArgsKeys 返回排序后的参数名列表（永不为 nil，保证 JSON 里是 [] 而不是 null）。
func ArgsKeys(args map[string]string) []string {
	out := make([]string, 0, len(args))
	for k := range args {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ArgsDigest 计算参数摘要，用于把"同一次调用"和"不同调用"区分开。
//
// 口径（也是脱敏口径）：
//   - 参数名明文参与摘要（便于排查是哪个参数变了）；
//   - **敏感键的值一律替换为 `<redacted>`**，即摘要里不含敏感值的任何信息——
//     连 SHA-256 都不给：对弱口令/短 token 做哈希是可以离线爆破的；
//   - 其余值的摘要用带长度前缀的规范化串联（长度前缀避免 `a=bc` 与 `ab=c` 撞车）。
//
// 因此 args_digest **不是**参数的忠实指纹：只改密码时摘要不变，这是刻意的取舍。
func ArgsDigest(args map[string]string) string {
	h := sha256.New()
	for _, k := range ArgsKeys(args) {
		v := args[k]
		if IsSensitiveKey(k) {
			v = redactedMarker
		}
		fmt.Fprintf(h, "%d:%s=%d:%s\x00", len(k), k, len(v), v)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// AuditLogger 审计写入器（文件 + 可选 DB 镜像）。零值不可用，请用 NewAuditLogger。
type AuditLogger struct {
	mu    sync.Mutex
	w     io.Writer
	f     *os.File
	path  string
	lines uint64
	sink  AuditSink
	lg    *log.Logger
}

// NewAuditLogger 打开审计输出。path 为空时退化为 stderr（并告警），不返回错误。
func NewAuditLogger(path string, lg *log.Logger) (*AuditLogger, error) {
	a := &AuditLogger{lg: lg}
	p := strings.TrimSpace(path)
	if p == "" {
		a.w = os.Stderr
		if lg != nil {
			lg.Printf("[WARN] [mcp] 未配置 audit_path：审计只写 stderr，不会落盘；生产环境请显式配置（否则重启即丢）")
		}
		return a, nil
	}
	if dir := filepath.Dir(p); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mcp: 创建审计目录失败: %w", err)
		}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("mcp: 打开审计文件失败: %w", err)
	}
	a.f, a.w, a.path = f, f, p
	return a, nil
}

// Path 返回审计文件路径（空字符串表示只写 stderr）。
func (a *AuditLogger) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

// SetSink 注入可选的上层镜像（DB）。允许传 nil 关闭镜像。
func (a *AuditLogger) SetSink(s AuditSink) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.sink = s
	a.mu.Unlock()
}

// Write 写一行审计。任何失败都只记 stderr，不 panic、不返回错误：
// 审计失败不能把工具调用一起拖挂（但对失败本身必须吵）。
func (a *AuditLogger) Write(rec AuditRecord) {
	if a == nil {
		return
	}
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.ArgsKeys == nil {
		rec.ArgsKeys = []string{}
	}
	if rec.Status == "" {
		rec.Status = StatusError
	}
	line, err := json.Marshal(rec)
	if err != nil {
		if a.lg != nil {
			a.lg.Printf("[ERROR] [mcp] 审计记录序列化失败: %v", err)
		}
		return
	}

	a.mu.Lock()
	_, werr := a.w.Write(append(line, '\n'))
	if werr == nil {
		a.lines++
	}
	sink := a.sink
	a.mu.Unlock()

	if werr != nil && a.lg != nil {
		a.lg.Printf("[ERROR] [mcp] 审计写入失败: %v", werr)
	}
	if sink != nil {
		if err := sink.WriteMCPAudit(rec); err != nil && a.lg != nil {
			a.lg.Printf("[ERROR] [mcp] 审计镜像(DB)失败 call_id=%s: %v", rec.CallID, err)
		}
	}
}

// Lines 已写入的记录数（自检/测试用）。
func (a *AuditLogger) Lines() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lines
}

// Close 关闭审计文件（stderr 模式为 no-op，幂等）。
func (a *AuditLogger) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	a.w = io.Discard
	return err
}

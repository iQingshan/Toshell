// Package intel 从任务输出中提取结构化情报（IP/账号/哈希/路径等），
// 供跨会话聚合、攻击面图谱（future）与 AI 副驾驶（future）使用。
package intel

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Item 一条提取的情报。
type Item struct {
	SessionID string    `json:"session_id"`
	TaskID    uint64    `json:"task_id"`
	Kind      string    `json:"kind"`   // ip / account / hash / path / domain / url
	Value     string    `json:"value"`  // 提取值（规范化）
	Context   string    `json:"context"` // 来源任务上下文摘要
	CreatedAt time.Time `json:"created_at"`
}

// Store 内存情报库（跨会话聚合去重）。持久化可选（SQLite 表）。
type Store struct {
	mu    sync.RWMutex
	items map[string]*Item // key: kind|value（去重）
}

var (
	store     *Store
	storeOnce sync.Once
)

// Get 返回全局情报库单例。
func Get() *Store {
	storeOnce.Do(func() {
		store = &Store{items: make(map[string]*Item)}
	})
	return store
}

var (
	reIP        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDomain    = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	reNTLMHash  = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reSHA1Hash  = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reAccount   = regexp.MustCompile(`\b(?:[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+)\b`)
	reSharePath = regexp.MustCompile(`\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+`)
	reURL       = regexp.MustCompile(`https?://[^\s"']+`)
)

// Extract 从任务输出提取情报并入库，返回本次新增条数。
func (s *Store) Extract(sessionID string, taskID uint64, taskType, output string) int {
	if output == "" {
		return 0
	}
	added := 0
	add := func(kind, value, ctx string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := kind + "|" + value
		s.mu.Lock()
		if _, exists := s.items[key]; !exists {
			s.items[key] = &Item{
				SessionID: sessionID, TaskID: taskID, Kind: kind, Value: value,
				Context:   ctx,
				CreatedAt: time.Now(),
			}
			added++
		}
		s.mu.Unlock()
	}

	ctx := taskType
	if len(output) > 120 {
		ctx = taskType + ": " + output[:120]
	} else {
		ctx = taskType + ": " + output
	}

	for _, m := range reIP.FindAllString(output, -1) {
		// 过滤明显非公网/回环
		if strings.HasPrefix(m, "127.") || strings.HasPrefix(m, "0.") || strings.HasPrefix(m, "255.") {
			continue
		}
		add("ip", m, ctx)
	}
	for _, m := range reDomain.FindAllString(output, -1) {
		if strings.Contains(m, " ") {
			continue
		}
		add("domain", strings.ToLower(m), ctx)
	}
	// 32 位十六进制：优先按 NTLM 哈希（排除纯数字/明显非哈希）
	for _, m := range reNTLMHash.FindAllString(output, -1) {
		if len(m) == 32 && containsLetter(m) {
			add("hash_ntlm", strings.ToUpper(m), ctx)
		}
	}
	for _, m := range reSHA1Hash.FindAllString(output, -1) {
		if len(m) == 40 {
			add("hash_sha1", strings.ToUpper(m), ctx)
		}
	}
	for _, m := range reAccount.FindAllString(output, -1) {
		add("account", m, ctx)
	}
	for _, m := range reSharePath.FindAllString(output, -1) {
		add("share", m, ctx)
	}
	for _, m := range reURL.FindAllString(output, -1) {
		add("url", m, ctx)
	}
	return added
}

func containsLetter(s string) bool {
	for _, c := range s {
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			return true
		}
	}
	return false
}

// List 返回全部情报（按时间倒序）。
func (s *Store) List() []Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Item, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, *it)
	}
	// 简单排序：时间倒序
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// ListByKind 按类型查询（如 "ip" / "account"）。
func (s *Store) ListByKind(kind string) []Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Item
	for _, it := range s.items {
		if it.Kind == kind {
			out = append(out, *it)
		}
	}
	return out
}

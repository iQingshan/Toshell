package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ResultStore：把超出内联上限的工具结果**外置落盘**，只把摘要 + 句柄放进上下文，
// 需要细节时按 offset/limit 分页回读。这样既省 token，也避免"每轮重复注入长结果"。
//
// 目录布局：`<dir>/<YYYYMMDD>/<16位随机hex>.bin`，句柄形如 `20260927/ab12cd34ef567890`。
// 安全：句柄是外部输入（模型/客户端可回传），因此**严格白名单校验**（日期 + hex），
// 任何不合规的句柄一律拒绝，杜绝 `../` 路径穿越。
type ResultStore struct {
	dir string
	ttl time.Duration
	// MaxTotal 目录容量上限（字节）；超出时 GC 会从最旧的文件开始删。0 = 不限制。
	MaxTotal int64

	mu sync.Mutex
}

// handleRe 句柄白名单：`YYYYMMDD/16~64 位小写 hex`。
var handleRe = regexp.MustCompile(`^\d{8}/[0-9a-f]{16,64}$`)

// ErrBadHandle 句柄格式非法（含路径穿越企图）。
var ErrBadHandle = errors.New("mcp: invalid result handle")

// ErrHandleNotFound 句柄不存在（可能已被 GC）。
var ErrHandleNotFound = errors.New("mcp: result handle not found")

// NewResultStore 创建/复用结果目录。dir 为空时返回 nil（调用方需容忍 nil：退化为内联截断）。
func NewResultStore(dir string, ttl time.Duration) (*ResultStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mcp: create result dir: %w", err)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &ResultStore{dir: dir, ttl: ttl, MaxTotal: 512 << 20}, nil
}

// Dir 返回结果目录（审计/界面展示用）。
func (s *ResultStore) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Put 落盘一份结果，返回句柄与总字节数。
func (s *ResultStore) Put(_ string, raw []byte) (string, int, error) {
	if s == nil {
		return "", 0, errors.New("mcp: result store disabled")
	}
	day := time.Now().Format("20060102")
	dst := filepath.Join(s.dir, day)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", 0, fmt.Errorf("mcp: create day dir: %w", err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", 0, fmt.Errorf("mcp: rand: %w", err)
	}
	name := hex.EncodeToString(id[:])
	if err := os.WriteFile(filepath.Join(dst, name+".bin"), raw, 0o600); err != nil {
		return "", 0, fmt.Errorf("mcp: write result: %w", err)
	}
	return day + "/" + name, len(raw), nil
}

// Get 分页回读：offset 为字节偏移，limit<=0 表示"到结尾"（但单次仍受 maxChunk 限制）。
func (s *ResultStore) Get(handle string, offset, limit int) ([]byte, int, error) {
	if s == nil {
		return nil, 0, errors.New("mcp: result store disabled")
	}
	path, err := s.resolve(handle)
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrHandleNotFound
		}
		return nil, 0, fmt.Errorf("mcp: read result: %w", err)
	}
	total := len(data)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	const maxChunk = 256 << 10 // 单次回读上限，避免一次把外部结果全塞回上下文
	if limit <= 0 || limit > maxChunk {
		limit = maxChunk
	}
	end := offset + limit
	if end > total {
		end = total
	}
	chunk := make([]byte, end-offset)
	copy(chunk, data[offset:end])
	return chunk, total, nil
}

// Tail 取末尾 n 字节（看任务输出的结尾很常用）。
func (s *ResultStore) Tail(handle string, n int) ([]byte, int, error) {
	path, err := s.resolve(handle)
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrHandleNotFound
		}
		return nil, 0, fmt.Errorf("mcp: read result: %w", err)
	}
	total := len(data)
	if n <= 0 || n > total {
		n = total
	}
	const maxChunk = 256 << 10
	if n > maxChunk {
		n = maxChunk
	}
	chunk := make([]byte, n)
	copy(chunk, data[total-n:])
	return chunk, total, nil
}

// resolve 把句柄解析为绝对路径，并做白名单 + 目录逃逸双重校验。
func (s *ResultStore) resolve(handle string) (string, error) {
	h := strings.TrimSpace(handle)
	if !handleRe.MatchString(h) {
		return "", ErrBadHandle
	}
	day, name := h[:8], h[9:]
	path := filepath.Join(s.dir, day, name+".bin")
	// 双保险：解析后必须仍在结果目录内。
	base, err := filepath.Abs(s.dir)
	if err != nil {
		return "", fmt.Errorf("mcp: abs dir: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("mcp: abs path: %w", err)
	}
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", ErrBadHandle
	}
	return abs, nil
}

// GC 清理过期结果，并在超过 MaxTotal 时从最旧开始删。返回删除的文件数。
func (s *ResultStore) GC() (int, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type entry struct {
		path string
		size int64
		mod  time.Time
	}
	var all []entry
	days, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	for _, d := range days {
		if !d.IsDir() || !regexp.MustCompile(`^\d{8}$`).MatchString(d.Name()) {
			continue
		}
		dayDir := filepath.Join(s.dir, d.Name())
		files, err := os.ReadDir(dayDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".bin") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			all = append(all, entry{path: filepath.Join(dayDir, f.Name()), size: info.Size(), mod: info.ModTime()})
		}
	}

	removed := 0
	deadline := time.Now().Add(-s.ttl)
	keep := all[:0]
	for _, e := range all {
		if e.mod.Before(deadline) {
			if os.Remove(e.path) == nil {
				removed++
			}
			continue
		}
		keep = append(keep, e)
	}
	all = keep

	if s.MaxTotal > 0 {
		var total int64
		for _, e := range all {
			total += e.size
		}
		if total > s.MaxTotal {
			sort.Slice(all, func(i, j int) bool { return all[i].mod.Before(all[j].mod) })
			for _, e := range all {
				if total <= s.MaxTotal {
					break
				}
				if os.Remove(e.path) == nil {
					total -= e.size
					removed++
				}
			}
		}
	}
	return removed, nil
}

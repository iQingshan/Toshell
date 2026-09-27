package modules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultTokenTTL 一次性 token 的默认有效期。
//
// 为什么是"一次性 + 短时效"而不是"把 base64 塞进任务参数"：
//   - 内联 base64 会把模块字节写进 tasks 表、任务列表接口、SSE 事件与审计日志 ——
//     一份多 MB 的二进制在 sqlite 里反复膨胀，且**任何能读任务列表的人都能拿到模块**，
//     与"操作员显式批准某次下发"的授权语义完全脱钩；
//   - 一次性 token 把授权收敛成一个短命凭据：只对某个会话、某个模块有效，用过即废、
//     过期即废。即使 token 泄露（日志/抓包/内存），也无法再次下发，且能立刻定位到
//     "谁在用已用过的 token"（token_reused 是明确的攻击/故障信号）。
//   - 2 分钟足够覆盖一次真实下发（下发是同步的：签 token → 推二进制 → 推任务），
//     又短到让"事后重放"没有窗口。
const DefaultTokenTTL = 2 * time.Minute

// Token 是一次性下发凭据。
type Token struct {
	Value     string    `json:"token"`
	SessionID string    `json:"session_id"`
	ModuleID  string    `json:"module_id"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	ABI       uint32    `json:"abi"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// Expired 判断 token 是否已过期。
func (t *Token) Expired(now time.Time) bool { return !now.Before(t.ExpiresAt) }

// Used 判断 token 是否已被核销。
func (t *Token) Used() bool { return !t.UsedAt.IsZero() }

// Store 是模块注册表 + token 签发/核销的内存实现。
//
// 为什么 token 只在内存里（不落盘）：一次性凭据的语义就是"这次下发"。落盘会引入
// "服务端重启后旧 token 还能用"的窗口，收益（跨重启重放下发）几乎不存在。代价是
// 服务端重启会让在途 token 失效 —— 那是**正确**行为（重试一次即可）。
type Store struct {
	dir string

	mu       sync.Mutex
	manifest *Manifest
	tokens   map[string]*Token

	// ttl 默认 DefaultTokenTTL；测试里改小以免 sleep。
	ttl time.Duration
	// now 可注入时钟（token 过期判定必须可测，不允许靠 sleep 真实时间）。
	now func() time.Time

	// loadErr 记录最近一次清单加载失败（观测用：handler 会在健康检查/列表接口里回显）。
	loadErr error
}

// NewStore 创建注册表；dir 为空时用 DefaultDir。不立即读盘（懒加载 + Reload）。
func NewStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{
		dir:    dir,
		tokens: make(map[string]*Token),
		ttl:    DefaultTokenTTL,
		now:    time.Now,
	}
}

// Dir 模块目录。
func (s *Store) Dir() string { return s.dir }

// SetTokenTTL 修改 token 有效期（测试用；生产保持默认）。
func (s *Store) SetTokenTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = d
}

// SetClock 注入时钟（测试用）。
func (s *Store) SetClock(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}

// Reload 重新读清单（模块被重新构建/替换后调用；也用于启动时加载）。
func (s *Store) Reload() error {
	m, err := LoadManifestFile(s.dir)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadErr = err
	if err != nil {
		return err
	}
	s.manifest = m
	return nil
}

// LoadError 返回最近一次清单加载错误（nil = 正常）。
func (s *Store) LoadError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadErr
}

// manifestLocked 保证 manifest 已加载一次（懒加载）。
func (s *Store) manifestLocked() (*Manifest, error) {
	if s.manifest != nil {
		return s.manifest, nil
	}
	m, err := LoadManifestFile(s.dir)
	if err != nil {
		s.loadErr = err
		return nil, err
	}
	s.manifest = m
	s.loadErr = nil
	return m, nil
}

// List 返回清单里的全部模块条目（按 id 排序，稳定输出便于断言与展示）。
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.manifestLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(m.Modules))
	copy(out, m.Modules)
	return out, nil
}

// Lookup 按 id 查模块条目（第 2 步：模块已登记且在 manifest 中）。
func (s *Store) Lookup(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.manifestLocked()
	if err != nil {
		return Entry{}, err
	}
	e, ok := m.Find(id)
	if !ok {
		return Entry{}, &Error{Code: CodeModuleNotRegistered, HTTP: 404,
			Message: fmt.Sprintf("模块 %q 未登记在 %s 中（先在模块目录里放入模块并写进清单，或调用模块构建器）",
				id, filepath.Join(s.dir, ManifestName))}
	}
	return e, nil
}

// ReadVerified 读出模块字节并做硬校验（第 3 步：sha256 与实际字节一致）。
//
// 这是唯一允许把模块字节交给下发的入口：读文件 → 校验大小 → 校验 sha256。
// 顺序刻意是"先读后校验再返回"，绝不会出现"校验失败也把字节返回给调用方"的中间态。
func (s *Store) ReadVerified(id string) (Entry, []byte, error) {
	e, err := s.Lookup(id)
	if err != nil {
		return Entry{}, nil, err
	}
	path := filepath.Join(s.dir, e.File)
	// 兜底防穿越（Validate 已经拦过，这里是"清单被内存中篡改"这类不可能路径的第二道闸）。
	if filepath.Base(path) != e.File {
		return Entry{}, nil, NewError(500, CodeManifestInvalid, "模块文件名 %q 非法", e.File)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Entry{}, nil, &Error{Code: CodeModuleFileMissing, HTTP: 500,
				Message: fmt.Sprintf("模块 %s 的文件不存在：%s（清单已登记但文件被删/被移动）", e.ID, path)}
		}
		return Entry{}, nil, fmt.Errorf("读取模块文件 %s 失败: %w", path, err)
	}
	if err := e.VerifyBytes(raw); err != nil {
		return Entry{}, nil, err
	}
	return e, raw, nil
}

// IssueToken 为 (会话, 模块) 签发一次性 token。
func (s *Store) IssueToken(sessionID, moduleID string) (*Token, error) {
	return s.issueToken(sessionID, moduleID, "")
}

// IssueTokenFor 签发 token 并绑定期望哈希（handler 在 ReadVerified 之后调用，
// 把"已经校验过的那份字节"的哈希写进 token，避免校验与下发之间被换文件 ——
// TOCTOU：校验用一份、下发用另一份。绑定哈希后植入端会发现不符并硬拒）。
func (s *Store) IssueTokenFor(sessionID string, e Entry) (*Token, error) {
	return s.issueToken(sessionID, e.ID, e.SHA256)
}

func (s *Store) issueToken(sessionID, moduleID, sha string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.manifestLocked()
	if err != nil {
		return nil, err
	}
	e, ok := m.Find(moduleID)
	if !ok {
		return nil, &Error{Code: CodeModuleNotRegistered, HTTP: 404,
			Message: fmt.Sprintf("模块 %q 未登记在清单中，无法签发下发凭据", moduleID)}
	}
	if sha == "" {
		sha = e.SHA256
	}

	now := s.now()
	s.purgeExpiredLocked(now)

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("生成一次性 token 失败: %w", err)
	}
	tok := &Token{
		// 128 位随机：token 会出现在审计日志里，必须是不可猜测的（否则拿到日志的人
		// 可以在有效期内抢先"用掉"一次下发）。用 hex 而不是 base64url，便于肉眼比对。
		Value:     hex.EncodeToString(buf),
		SessionID: sessionID,
		ModuleID:  e.ID,
		SHA256:    sha,
		Size:      e.Size,
		ABI:       e.ABI,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.tokens[tok.Value] = tok
	return tok, nil
}

// ConsumeToken 核销 token：**同一个 token 只能成功一次**。
//
// 校验顺序与错误码刻意区分四种失败，因为它们指向完全不同的处置：
//   - token_not_found      → 打错/伪造/服务端重启后旧 token（重试一次即可）
//   - token_expired        → 超时（重新发起下发）
//   - token_reused         → **重放/重试**：同一个 token 第二次下发被拒（安全信号，要审计）
//   - token_session_wrong  → 拿 A 会话的凭据去下发到 B 会话（越权尝试，要审计）
func (s *Store) ConsumeToken(value, sessionID, moduleID string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	// 先查再清：过期清理会把条目删掉，如果先清，调用方拿到的是"不存在"而不是"过期"。
	// 这两者对操作员的处置完全不同（一个是"打错了/重启了"，一个是"等太久了"），
	// 所以判定顺序必须保证过期能被明确报出来。
	tok, ok := s.tokens[value]
	if !ok {
		s.purgeExpiredLocked(now)
		return nil, &Error{Code: CodeTokenNotFound, HTTP: 409,
			Message: "一次性 token 不存在：可能拼写错误、已被服务端重启清空，或从未签发过"}
	}
	if tok.Expired(now) {
		delete(s.tokens, value)
		return nil, &Error{Code: CodeTokenExpired, HTTP: 409,
			Message: fmt.Sprintf("一次性 token 已过期（有效期 %s，签发于 %s）：请重新发起下发",
				s.ttl, tok.IssuedAt.Format(time.RFC3339))}
	}
	// 顺手清理其它过期项（当前这个还没过期，不会被误删）。
	s.purgeExpiredLocked(now)
	if tok.Used() {
		return nil, &Error{Code: CodeTokenReused, HTTP: 409,
			Message: fmt.Sprintf("一次性 token 已被使用过（%s）：拒绝重放。同一个凭据只允许下发一次",
				tok.UsedAt.Format(time.RFC3339))}
	}
	if sessionID != "" && tok.SessionID != sessionID {
		return nil, &Error{Code: CodeTokenSessionWrong, HTTP: 409,
			Message: fmt.Sprintf("token 属于会话 %s，不能用于会话 %s", tok.SessionID, sessionID)}
	}
	if moduleID != "" && tok.ModuleID != moduleID {
		return nil, &Error{Code: CodeTokenModuleWrong, HTTP: 409,
			Message: fmt.Sprintf("token 绑定的是模块 %s，不能用于模块 %s", tok.ModuleID, moduleID)}
	}
	tok.UsedAt = now
	return tok, nil
}

// Peek 只读查看 token（不核销）——给测试与审计用。
func (s *Store) Peek(value string) (*Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[value]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// purgeExpiredLocked 清理过期 token（顺带清掉已核销且过了有效期的记录，避免内存无界增长）。
func (s *Store) purgeExpiredLocked(now time.Time) {
	for k, t := range s.tokens {
		if t.Expired(now) {
			delete(s.tokens, k)
		}
	}
}

// LiveTokens 返回当前未过期且未使用的 token 数（观测/测试用）。
func (s *Store) LiveTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purgeExpiredLocked(now)
	n := 0
	for _, t := range s.tokens {
		if !t.Used() {
			n++
		}
	}
	return n
}

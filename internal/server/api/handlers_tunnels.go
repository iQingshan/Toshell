package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/mux"
	"toshell/internal/common/tunnel"
	"toshell/internal/server/logging"
	"toshell/internal/server/tunnelstore"
)

// ─── 隧道/代理（v1.4.1：库为一等资源）────────────────────────────────────────
//
// v1.4.0 及之前：socks5Servers（内存 map）就是全部真相，服务端一重启代理全丢。
// v1.4.1 起：
//   - 创建 → 先起监听，再落库（tunnels 表），落库失败回滚监听并报错（成功才算成功）；
//   - 列表 → 以库为准，运行态（是否真在监听 / 活动连接 / 认证）与库对账后返回；
//   - 关闭 → 先停监听，再删库（硬删除，理由见 tunnelstore.Delete 的注释）；
//   - 启动 → RestoreTunnels 按库逐条重建监听（见 handlers_tunnels_restore.go）。
//
// 响应字段只增不改：v1.4.0 的 session_id / local_port / tunnels / auth_enabled /
// count / servers 全部保留，v1.4.1 只追加 id / status / listening / restored /
// persisted / protocol / mode / target_addr / remark / last_error / created_at /
// updated_at。口令与用户名**永不回显**（只回 auth_enabled）。

// runtimeTunnels 把某代理当前的活动连接（per-connection 隧道）转成对外 JSON。
// 字段与 v1.4.0 完全一致（id/target_addr/target_port/active/created_at/bytes_in/bytes_out）。
func runtimeTunnels(socks5 *tunnel.SOCKS5Server) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	if socks5 == nil {
		return out
	}
	for _, t := range socks5.GetTunnelManager().ListTunnels() {
		out = append(out, map[string]interface{}{
			"id":          t.ID,
			"target_addr": t.TargetAddr,
			"target_port": t.TargetPort,
			"active":      t.Active,
			"created_at":  t.CreatedAt.Format(time.RFC3339),
			"bytes_in":    t.BytesIn.Load(),
			"bytes_out":   t.BytesOut.Load(),
		})
	}
	return out
}

// tunnelEntry 组装「一条代理」的对外视图（列表用）。
//
//	row    = 库里的行（nil：纯内存实例，无库降级或落库失败）
//	socks5 = 当前运行实例（nil：库里有但此刻没在监听，例如上次恢复失败）
//
// status 采用**运行态优先**对账：真在监听就是 running；否则用库里的状态
// （error 带 last_error），库里也没有就标 stopped。listening 单独给出布尔值，
// 前端不必依赖 status 的字符串含义。
func (s *Server) tunnelEntry(id string, row *tunnelstore.Tunnel, socks5 *tunnel.SOCKS5Server) map[string]interface{} {
	port := 0
	if socks5 != nil {
		port = socks5.GetPort()
	} else if row != nil {
		port = row.LocalPort
	}

	status := "stopped"
	authEnabled := false
	protocol, mode, targetAddr, remark, lastError := "socks5", "dynamic", "", "", ""
	restored := false
	createdAt, updatedAt := "", ""

	if row != nil {
		status = row.Status
		authEnabled = row.AuthEnabled
		protocol, mode, targetAddr = row.Protocol, row.Mode, row.TargetAddr
		remark, lastError, restored = row.Remark, row.LastError, row.Restored
		if row.CreatedAt > 0 {
			createdAt = time.Unix(row.CreatedAt, 0).Format(time.RFC3339)
		}
		if row.UpdatedAt > 0 {
			updatedAt = time.Unix(row.UpdatedAt, 0).Format(time.RFC3339)
		}
	}
	if socks5 != nil {
		status = "running"
		authEnabled = socks5.AuthEnabled()
	}

	// v1.4.3 #16：隧道归属会话（issue 反馈"会话多了只看 session_id 分不清是哪台机器"）。
	// 会话管理器里查不到（进程重启后从库里恢复的代理、或会话已被删除）时，
	// session_alive=false 且 host/user 留空，前端据此显示「已下线」。
	sessionHost, sessionUser, sessionStatus := "", "", ""
	sessionAlive := false
	if info, ierr := s.sessionMgr.GetSessionInfo(id); ierr == nil && info != nil {
		sessionHost, sessionUser = info.Hostname, info.Username
		if st, serr := s.sessionMgr.GetStatus(id); serr == nil {
			sessionStatus = st
			sessionAlive = st == "active"
		}
	}

	return map[string]interface{}{
		// ── v1.4.0 既有字段（原样保留，顺序/命名不变）──
		"session_id":   id,
		"local_port":   port,
		"tunnels":      runtimeTunnels(socks5),
		"auth_enabled": authEnabled,

		// ── v1.4.1 追加字段 ──
		"id":          id,
		"status":      status,
		"listening":   socks5 != nil,
		"restored":    restored,
		"persisted":   row != nil,
		"protocol":    protocol,
		"mode":        mode,
		"target_addr": targetAddr,
		"remark":      remark,
		"last_error":  lastError,
		"created_at":  createdAt,
		"updated_at":  updatedAt,

		// ── v1.4.3 #16 追加字段（只增不改）──
		"session_host":   sessionHost,
		"session_user":   sessionUser,
		"session_status": sessionStatus,
		"session_alive":  sessionAlive,
	}
}

// tunnelDetailResponse 是 ?session_id=xxx 时的旧响应形状 + 追加字段：
// v1.4.0 只回 tunnels/count/local_port/auth_enabled，这里全部保留。
func (s *Server) tunnelDetailResponse(id string, row *tunnelstore.Tunnel, socks5 *tunnel.SOCKS5Server) map[string]interface{} {
	entry := s.tunnelEntry(id, row, socks5)
	tunnels, _ := entry["tunnels"].([]map[string]interface{})
	out := map[string]interface{}{
		"tunnels":      tunnels,
		"count":        len(tunnels),
		"local_port":   entry["local_port"],
		"auth_enabled": entry["auth_enabled"],
	}
	for _, k := range []string{
		"id", "session_id", "status", "listening", "restored", "persisted",
		"protocol", "mode", "target_addr", "remark", "last_error", "created_at", "updated_at",
		// v1.4.3 #16：详情也带上归属会话，前端不用两处逻辑
		"session_host", "session_user", "session_status", "session_alive",
	} {
		out[k] = entry[k]
	}
	return out
}

// runtimeSnapshot 在锁内复制指针（不做任何可能阻塞的调用），锁外再编码响应。
func (s *Server) runtimeSnapshot() map[string]*tunnel.SOCKS5Server {
	s.socks5Mu.RLock()
	defer s.socks5Mu.RUnlock()
	out := make(map[string]*tunnel.SOCKS5Server, len(s.socks5Servers))
	for id, srv := range s.socks5Servers {
		out[id] = srv
	}
	return out
}

// storedTunnels 读库；无库或读失败时返回 nil（列表退回纯内存视图，绝不 500）。
func (s *Server) storedTunnels() []*tunnelstore.Tunnel {
	if s.tunnelStore == nil {
		return nil
	}
	rows, err := s.tunnelStore.List()
	if err != nil {
		logging.Warn("tunnel", "读取 tunnels 表失败，本次列表退回内存视图：%v", err)
		return nil
	}
	return rows
}

func (s *Server) listTunnelsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionID := r.URL.Query().Get("session_id")
	runtime := s.runtimeSnapshot()
	rows := s.storedTunnels()

	if sessionID != "" {
		var row *tunnelstore.Tunnel
		for _, it := range rows {
			if it.ID == sessionID {
				row = it
				break
			}
		}
		if rt := runtime[sessionID]; row != nil || rt != nil {
			json.NewEncoder(w).Encode(s.tunnelDetailResponse(sessionID, row, rt))
			return
		}
		// 兼容 v1.4.0 行为：查询参数给的 id 既不在库里、也没有运行实例时退回整体列表，
		// 避免老客户端拿到空数组就误判"代理全丢了"。
	}

	// 以库为准，再并上「只在内存、没进库」的实例（无库降级 / 落库失败的兜底），
	// 保证列表不会因为库不可用而少显示正在运行的代理。
	servers := make([]map[string]interface{}, 0, len(rows)+len(runtime))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		seen[row.ID] = true
		servers = append(servers, s.tunnelEntry(row.ID, row, runtime[row.ID]))
	}
	for id, rt := range runtime {
		if seen[id] {
			continue
		}
		servers = append(servers, s.tunnelEntry(id, nil, rt))
	}
	// 内存 map 遍历顺序随机：按 session_id 排一下，前端卡片不会每次刷新换位置。
	sort.Slice(servers, func(i, j int) bool {
		return servers[i]["session_id"].(string) < servers[j]["session_id"].(string)
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
	})
}

func (s *Server) createTunnelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// auth_user / auth_pass 可选：留空 = 保持历史行为（无认证）。
	// 口令只用于配置代理监听器与（加密后）落库，绝不写日志、绝不在响应里回显。
	var req struct {
		SessionID string `json:"session_id"`
		LocalPort int    `json:"local_port"`
		AuthUser  string `json:"auth_user"`
		AuthPass  string `json:"auth_pass"`
		Remark    string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	auth := &tunnel.AuthConfig{Username: req.AuthUser, Password: req.AuthPass}
	if err := auth.Validate(); err != nil {
		// 只返回校验结论，不回显口令/用户名内容
		writeJSONError(w, http.StatusBadRequest, "invalid proxy auth: "+err.Error())
		return
	}

	port, err := s.startTunnelPersisted(req.SessionID, req.LocalPort, auth, req.Remark)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"session_id": req.SessionID,
		"local_port": port,
		// 只回显"是否启用认证"，口令绝不回传（连用户名也不回传）
		"auth_enabled": auth.Enabled(),
		"message":      "SOCKS5 proxy started successfully",
		// ── v1.4.1 追加字段 ──
		"id":        req.SessionID,
		"status":    tunnelstore.StatusRunning,
		"restored":  false,
		"persisted": s.tunnelStore != nil,
		"remark":    req.Remark,
	})
}

// startTunnelPersisted 启动代理并落库（HTTP 创建与 MCP tunnel_start 共用入口）。
//
// 落库失败时**回滚监听**再返回错误：宁可这次创建失败，也不留给操作员一个
// "看起来成功、重启就消失"的代理。
func (s *Server) startTunnelPersisted(sessionID string, localPort int, auth *tunnel.AuthConfig, remark string) (int, error) {
	port, err := s.startSOCKS5(sessionID, localPort, auth)
	if err != nil {
		return 0, err
	}
	if s.tunnelStore == nil {
		// 无库降级：代理只在内存里（行为等同 v1.4.0），API 用 persisted=false 明确告知。
		return port, nil
	}
	row := &tunnelstore.Tunnel{
		ID:        sessionID,
		SessionID: sessionID,
		LocalPort: port,
		// SOCKS5 动态代理：目标由客户端每条连接自己指定，故 target_addr 为空。
		Protocol:    "socks5",
		Mode:        "dynamic",
		AuthEnabled: auth != nil && auth.Enabled(),
		Remark:      remark,
		Status:      tunnelstore.StatusRunning,
	}
	if auth != nil {
		row.AuthUser = auth.Username
	}
	var pass string
	if auth != nil {
		pass = auth.Password
	}
	if perr := s.tunnelStore.Upsert(row, pass); perr != nil {
		s.stopSOCKS5(sessionID)
		return 0, fmt.Errorf("代理已回滚：持久化失败: %w", perr)
	}
	return port, nil
}

// closeTunnel 停止代理并删除持久化记录（HTTP DELETE 与 MCP tunnel_stop 共用）。
// 删库失败会把错误传出去，让调用方明确知道"下次重启可能又冒出来"。
func (s *Server) closeTunnel(sessionID string) error {
	s.stopSOCKS5(sessionID)
	if s.tunnelStore == nil {
		return nil
	}
	// 硬删除（而非标记 closed）：见 tunnelstore.Delete 的注释——行语义是"期望存在的代理"。
	return s.tunnelStore.Delete(sessionID)
}

// startSOCKS5 为指定会话启动一个 SOCKS5 隧道代理（HTTP handler 与 MCP 工具共用）。
// auth 可为 nil 或空值：此时代理不启用认证（老调用方行为不变）。
func (s *Server) startSOCKS5(sessionID string, localPort int, auth *tunnel.AuthConfig) (int, error) {
	if auth == nil {
		auth = &tunnel.AuthConfig{}
	}
	if err := auth.Validate(); err != nil {
		return 0, err
	}
	if localPort <= 0 {
		localPort = 1080
	}
	s.socks5Mu.Lock()
	defer s.socks5Mu.Unlock()

	if _, exists := s.socks5Servers[sessionID]; exists {
		return 0, fmt.Errorf("SOCKS5 server already running for this session")
	}
	// 检查端口是否已被其他 session 占用（Windows 上 net.Listen 默认 SO_REUSEADDR，
	// 同端口二次绑定不报错，会导致连接错误分发/隧道串流）。
	for sid, other := range s.socks5Servers {
		if other.GetPort() == localPort {
			return 0, fmt.Errorf("port %d already in use by session %s", localPort, sid)
		}
	}

	socks5 := tunnel.NewSOCKS5Server(localPort)
	socks5.SetSessionID(sessionID)
	socks5.SetSendToImplant(s.sendTunnelPacket)
	socks5.SetAuth(auth.Username, auth.Password)
	if sess, err := s.sessionMgr.Get(sessionID); err == nil && sess != nil {
		sess.SetTunnelHandler(func(p *tunnel.TunnelPacket) { socks5.HandleTunnelData(p) })
	}
	if err := socks5.Start(); err != nil {
		return 0, err
	}
	s.socks5Servers[sessionID] = socks5
	// 安全边界：日志只记录"是否启用认证"，绝不打印用户名/口令。
	logging.Info("api", "SOCKS5 proxy started for session %s on port %d (auth_enabled=%v)", sessionID, socks5.GetPort(), auth.Enabled())
	return socks5.GetPort(), nil
}

// stopSOCKS5 停止指定会话的隧道代理（只动运行态，不碰库）。
func (s *Server) stopSOCKS5(sessionID string) {
	s.socks5Mu.Lock()
	defer s.socks5Mu.Unlock()
	if socks5, ok := s.socks5Servers[sessionID]; ok {
		socks5.Stop()
		delete(s.socks5Servers, sessionID)
	}
}

// RebindTunnelHandler 把「会话下行数据 → 代理」的处理器重新绑到会话上。
//
// 为什么需要它：代理的上行（客户端 → 植入端）靠 s.sendTunnelPacket 直接可达，
// 但下行（植入端 → 客户端）依赖 session.tunnelHandler。服务端重启后会话对象是新的，
// 恢复出来的代理在植入端重连前根本没有 handler，回包会被 DispatchTunnelData 静默丢弃
// （表现为浏览器 ERR_SSL_PROTOCOL_ERROR / 连接挂起）。main.go 在会话上线回调里调用本方法。
func (s *Server) RebindTunnelHandler(sessionID string) {
	s.socks5Mu.RLock()
	socks5 := s.socks5Servers[sessionID]
	s.socks5Mu.RUnlock()
	if socks5 == nil {
		return
	}
	sess, err := s.sessionMgr.Get(sessionID)
	if err != nil || sess == nil {
		return
	}
	sess.SetTunnelHandler(func(p *tunnel.TunnelPacket) { socks5.HandleTunnelData(p) })
	logging.Info("tunnel", "代理回包通道已绑定到会话 %s（端口 %d）", sessionID, socks5.GetPort())
}

func (s *Server) closeTunnelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	// 先停运行态再删库：反序的话，删库成功而 Stop 卡住会留下"库里没有、端口还开着"的僵尸代理。
	if err := s.closeTunnel(sessionID); err != nil {
		logging.Warn("tunnel", "关闭代理后删除隧道记录失败（%s）：%v", sessionID, err)
		writeJSONError(w, http.StatusInternalServerError, "proxy stopped but failed to delete tunnel record: "+err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "SOCKS5 proxy stopped",
	})
}

func (s *Server) sendTunnelPacket(sessionID string, packet []byte) error {
	if s.listener == nil {
		return fmt.Errorf("no listener available")
	}
	return s.listener.SendTunnelRaw(sessionID, packet)
}

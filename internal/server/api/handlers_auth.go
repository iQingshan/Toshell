package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
)

// healthHandler 健康检查。
//
// v1.4.0 S6 附带修复：这里顺带回传"最近一次配置热重载是否成功"。
// 为什么放在 health 里：配置文件写坏时服务端会**静默沿用旧配置**，
// 而操作员唯一的诊断入口就是 health（顶栏状态、运维探针都用它）。
//
// 注意 health 是**未认证可达**的（见 auth 中间件对 /api/v1/health 的放行），
// 所以这里只给 ok/时间/失败次数，**不给错误原文**（错误里含配置文件路径与
// YAML 解析细节）；完整错误原文在已认证的 GET /api/v1/settings 里。
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	reload := config.LastReload()
	body := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"config_reload": map[string]interface{}{
			"ok":       reload.OK,
			"at":       reload.At.Format(time.RFC3339),
			"attempts": reload.Attempts,
			"failures": reload.Failures,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) systemStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	hostname, _ := os.Hostname()

	stats := map[string]interface{}{
		"hostname":   hostname,
		"goroutines": runtime.NumGoroutine(),
		"go_version": runtime.Version(),
		"cpu_count":  runtime.NumCPU(),
		"memory": map[string]interface{}{
			"alloc":       memStats.Alloc / 1024 / 1024,
			"total_alloc": memStats.TotalAlloc / 1024 / 1024,
			"sys":         memStats.Sys / 1024 / 1024,
			"heap_inuse":  memStats.HeapInuse / 1024 / 1024,
		},
		"sessions": map[string]interface{}{
			"total":  s.sessionMgr.Count(),
			"active": len(s.sessionMgr.List()),
		},
		"uptime":    time.Since(s.startTime).String(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(stats)
}

func (s *Server) listLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	limit := r.URL.Query().Get("limit")
	level := r.URL.Query().Get("level")

	maxLogs := 100
	if limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 && n <= 1000 {
			maxLogs = n
		}
	}

	filter := ""
	if level != "" {
		// 安全加固：level 白名单，防 SQL 注入（此前直接拼接 level = 'xxx' OR 1=1 --）
		switch level {
		case "debug", "info", "warn", "error":
			filter = "level = '" + level + "'"
		default:
			http.Error(w, `{"error":"invalid level"}`, http.StatusBadRequest)
			return
		}
	}

	var logs []*types.LogEntry
	db := database.Get()
	if db != nil {
		all, err := db.QueryLogs(filter, maxLogs)
		if err != nil {
			logging.Warn("api", "Failed to query logs: %v", err)
		} else {
			logs = all
		}
	}

	if logs == nil {
		logs = []*types.LogEntry{}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	clientIP := clientIP(r)

	if !s.auth.Config.Enabled {
		token, _ := s.auth.GenerateToken(req.Username, "admin")
		writeLoginLog(s, req.Username, clientIP, true, "auth disabled, login accepted")
		json.NewEncoder(w).Encode(map[string]string{"token": token, "username": req.Username})
		return
	}

	// 登录限速/锁定：按 IP+账号 计数，连续失败达阈值后锁定一段时间，防暴力破解。
	key := loginKey(req.Username, clientIP)
	if loginIsLocked(key) {
		writeLoginLog(s, req.Username, clientIP, false, "too many attempts, locked")
		http.Error(w, `{"error":"Too many failed attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	if s.auth.ValidateCredentials(req.Username, req.Password) {
		loginReset(key)
		token, err := s.auth.GenerateToken(req.Username, "admin")
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		writeLoginLog(s, req.Username, clientIP, true, "login success")
		json.NewEncoder(w).Encode(map[string]string{"token": token, "username": req.Username})
	} else {
		loginRecordFail(key)
		writeLoginLog(s, req.Username, clientIP, false, "invalid credentials")
		http.Error(w, `{"error":"Invalid credentials"}`, http.StatusUnauthorized)
	}
}

// ─── 登录限速 / 锁定 ───────────────────────────────────────────────
// 按 IP+账号 维度统计连续失败；5 次失败（5 分钟窗口内）后锁定 5 分钟。
var (
	loginLimiterMu sync.Mutex
	loginFails     = map[string]loginFailInfo{}
)

type loginFailInfo struct {
	count    int
	firstAt  time.Time
	lockedAt time.Time
}

const (
	maxLoginFails = 5
	loginFailWin  = 5 * time.Minute
	loginLockTime = 5 * time.Minute
)

func loginKey(username, ip string) string {
	return ip + "|" + username
}

func loginIsLocked(key string) bool {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()
	info, ok := loginFails[key]
	if !ok {
		return false
	}
	if !info.lockedAt.IsZero() {
		if time.Since(info.lockedAt) < loginLockTime {
			return true
		}
		delete(loginFails, key) // 锁定期满，清除记录
	}
	return false
}

func loginRecordFail(key string) {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()
	info := loginFails[key]
	if info.count == 0 || time.Since(info.firstAt) > loginFailWin {
		info.count = 1
		info.firstAt = time.Now()
	} else {
		info.count++
	}
	if info.count >= maxLoginFails {
		info.lockedAt = time.Now()
		info.count = 0
	}
	loginFails[key] = info
}

// CleanupLoginLimiter 定期清理过期的登录限速条目，防止 loginFails map 无界增长。
// 由服务器主循环的周期性清理任务调用。
func CleanupLoginLimiter() {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()
	now := time.Now()
	for key, info := range loginFails {
		locked := !info.lockedAt.IsZero() && now.Sub(info.lockedAt) < loginLockTime
		activeWin := info.count > 0 && now.Sub(info.firstAt) < loginFailWin
		if !locked && !activeWin {
			delete(loginFails, key)
		}
	}
}

func loginReset(key string) {
	loginLimiterMu.Lock()
	defer loginLimiterMu.Unlock()
	delete(loginFails, key)
}

// clientIP 返回客户端真实 IP（剥离端口）。
// 安全加固：不再信任 X-Forwarded-For / X-Real-IP —— 客户端可直接伪造这些头，
// 绕过登录限速（刷 XFF 每次换 IP）或锁死他人 IP。直连场景 RemoteAddr 即真实来源；
// 若部署在反代后需限速精确到源 IP，应改由反代统一重写 XFF 并在 server.yaml
// 显式开启 trust_proxy_headers（见 loginHandler 的调用处配置）。
func clientIP(r *http.Request) string {
	// 仅当显式配置信任代理头时才取 XFF（默认关闭，防伪造）
	cfg := config.Get()
	if cfg != nil && cfg.Server.TrustProxyHeaders {
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			if i := strings.Index(ip, ","); i > 0 {
				ip = ip[:i] // 取最左（反代写入的第一个）
			}
			return strings.TrimSpace(ip)
		}
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	// 默认：RemoteAddr（形如 "1.2.3.4:port"），剥离端口
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// writeLoginLog persists a login attempt to the database and console.
func writeLoginLog(s *Server, username, ip string, success bool, detail string) {
	level := "info"
	message := fmt.Sprintf("login attempt user=%s ip=%s %s", username, ip, detail)
	if success {
		logging.Info("auth", "%s", message)
	} else {
		logging.Warn("auth", "%s", message)
		level = "warning"
	}

	db := database.Get()
	if db == nil {
		return
	}
	entry := &types.LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Component: "auth",
		Message:   message,
		SourceIP:  ip,
		User:      username,
	}
	if err := db.CreateLog(entry); err != nil {
		logging.Warn("auth", "Failed to persist login log: %v", err)
	}
}

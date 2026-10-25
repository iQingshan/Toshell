package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
		// v1.4.1：屏幕帧广播投递计数（只追加字段，已有字段语义不变）
		"screen_stream": s.screenStreamStatsSnapshot(),
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

// maxLoginBodyBytes 登录端点（POST /api/v1/login）的请求体上限（审计 N2）。
//
// 登录请求只有 username/password 两个短字段，8 KiB 足够（即使用户名/口令里全是
// 多字节字符也绰绰有余）。/api/v1/login 是**未认证**可达的（auth 中间件对它放行），
// 所以必须最先限体：不设上限时一个 32 MiB 的 body 会被完整读进内存
// （审计实测 RSS 66 MB → 172 MB），构成未认证内存 DoS。
//
// 超限必须回 413；回 401 会被操作员误读成“口令错”，掩盖真正的原因。
const maxLoginBodyBytes = 8 << 10

// writeBodyTooLarge 统一写“请求体超限”的 413 中文原因。
func writeBodyTooLarge(w http.ResponseWriter, limit int64, scope string) {
	writeJSONError(w, http.StatusRequestEntityTooLarge,
		fmt.Sprintf("%s请求体超过 %d 字节上限", scope, limit))
}

// readBodyLimited 在 http.MaxBytesReader 闸门之后读取整个请求体，超限统一回 413。
//
// 为什么不直接用 json.Decoder.Decode：Decoder 解析完第一个 JSON 值就可能返回，
// 后面的超大尾部不会被计入上限（"合法 JSON + 32 MiB 垃圾"照样能走完流程）。
// 这里先整体读入再 Unmarshal，保证任何超过 limit 的 body 都会被明确拒绝。
// scope 只用于中文错误原因（如“创建任务”）。
func readBodyLimited(w http.ResponseWriter, r *http.Request, limit int64, scope string) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
			writeBodyTooLarge(w, limit, scope)
			return nil, false
		}
		writeJSONError(w, http.StatusBadRequest, "读取请求体失败")
		return nil, false
	}
	return body, true
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 未认证端点：先限体，再解码；不要把超大 body 读进内存。
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
			writeBodyTooLarge(w, maxLoginBodyBytes, "登录")
			return
		}
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	// Decode 解析完第一个 JSON 值就可能提前返回；把剩余 body 读干净并要求整体
	// 仍在 8 KiB 内，否则“合法 JSON + 超大尾部”会绕过上面的闸门（也就绕过了
	// 未认证端点的内存边界）。读取错误在响应写出之前处理，不影响正常登录。
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
			writeBodyTooLarge(w, maxLoginBodyBytes, "登录")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "读取请求体失败")
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
		// 认证成功 = 初始明文口令已经用过一次：立即删除落盘文件（审计 N4）。
		// 删除失败只告警，不影响本次登录。
		clearInitialAdminPasswordFile()
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

// ─── 初始管理员明文口令文件（审计 L2/N4） ──────────────────────────
//
// 首次启动（配置里没有显式 admin_password）时，cmd/server/main.go 生成随机口令，
// 把明文写进 data/initial-admin-password.txt，只在日志里给路径。该文件是明文
// 凭据：首次成功登录后必须删除，不能长期留在 data/（备份、卷快照、任意文件读
// 都会放大影响）。

// DataDir 运行时数据目录名（相对进程工作目录）。
// 抽成常量与 cmd/server/main.go 共用，避免“写入用一处、删除用另一处”导致路径漂移。
const DataDir = "data"

// initialAdminPasswordFileName 初始管理员明文口令文件名。
const initialAdminPasswordFileName = "initial-admin-password.txt"

// InitialAdminPasswordPath 返回初始管理员明文口令文件的完整路径。
// cmd/server/main.go 写入与登录成功后的清理都走这里，保证两处完全一致。
func InitialAdminPasswordPath(dataDir string) string {
	return filepath.Join(dataDir, initialAdminPasswordFileName)
}

// initialAdminPasswordPath 是登录成功后要清理的路径。
// 抽成变量是为了让测试注入临时目录，不碰真实的 data/ 目录；生产运行时固定为
// data/initial-admin-password.txt。
var initialAdminPasswordPath = func() string {
	return InitialAdminPasswordPath(DataDir)
}

// clearInitialAdminPasswordFile 在管理员首次认证成功后删除明文口令文件。
//
// 取舍：为什么不是“改密后删”——ToShell 的管理员口令写在配置文件里，改密必须改
// 配置 + 重启；而启动时若配置里已有显式口令，本来就不会写这个文件；若走的是
// 自动生成，重启后配置里也已是哈希。也就是说“首登删文件”覆盖了明文真正被使用的
// 唯一时刻，窗口最小，且不依赖用户是否记得改密。
//
// 失败不影响登录：文件可能早已被手工删除（ErrNotExist 直接忽略），也可能因
// 权限/占用删不掉——那只是残留风险，不能反过来把已通过认证的管理员挡在门外。
func clearInitialAdminPasswordFile() {
	path := initialAdminPasswordPath()
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return // 显式配置口令时启动本就不写文件，或管理员已手工删除。
		}
		logging.Warn("auth", "登录成功但删除初始管理员口令文件失败（%s）：%v；请手工删除", path, err)
		return
	}
	logging.Info("auth", "管理员首次登录成功，已删除初始明文口令文件 %s", path)
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

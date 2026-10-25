package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// originAllowed 校验 WebSocket 握手的 Origin（审计 M8）。
//
// 允许：
//   - Origin 为空：非浏览器客户端（CLI、自动化脚本、植入端）不发 Origin；
//   - Origin 的 host（含端口时逐字一致）与本次请求的 Host 相同：同源页面；
//   - Origin 的 host 与 `X-Forwarded-Host` 相同：控制台部署在反代后面、且反代把
//     Host 改写成后端地址时（例如 nginx `proxy_set_header Host 127.0.0.1:8081;`），
//     浏览器发的 Origin 是外部域名，与 r.Host 永远不相等 —— 不放行这条会让
//     "按文档挂 TLS 反代"的部署直接连不上 WS。
//     安全性：`X-Forwarded-Host` 由反代写入，浏览器无法伪造；非浏览器客户端
//     本来就不发 Origin（走第一条）。因此这条不构成 CSWSH 面的放宽。
//
// 其余一律拒绝。此前两个 upgrader 都写死 CheckOrigin=true，等于放弃浏览器
// 同源这层纵深防御 —— 一旦 token 通过 URL 泄露（M6）并叠加 XSS，攻击者
// 就能从任意站点跨站建立 shell/事件流。
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		// 反代可能写成逗号分隔的链（client, proxy1, proxy2），取最左一跳，
		// 与 Host 比较时忽略大小写。
		if i := strings.Index(fwd, ","); i >= 0 {
			fwd = strings.TrimSpace(fwd[:i])
		}
		if strings.EqualFold(u.Host, fwd) {
			return true
		}
	}
	return false
}

var upgrader = websocket.Upgrader{
	CheckOrigin: originAllowed,
}

type ShellController interface {
	OpenShell(sessionID string, shell string) error
	SendShellInput(sessionID string, data string) error
	CloseShell(sessionID string) error
}

func (s *Server) shellWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	fmt.Printf("[DEBUG] [shell] WebSocket connection request for session: %s\n", sessionID)

	sess, err := s.sessionMgr.Get(sessionID)
	if err != nil {
		fmt.Printf("[ERROR] [shell] Session not found: %s\n", sessionID)
		http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[ERROR] [shell] WebSocket upgrade failed: %v\n", err)
		return
	}
	defer conn.Close()

	// 审计 M8：限制**单个** WebSocket 消息的读取上限。认证用户（或泄露的
	// token）原本可以发任意大帧把服务端内存打满；shell 输入是人工键入/粘贴，
	// 1 MiB 远高于正常单条指令，又小于 16 MiB 的协议帧上限。
	// 注意：既有 SetReadDeadline / pong 逻辑保持不变（此处不涉及）。
	conn.SetReadLimit(1 << 20)

	fmt.Printf("[INFO] [shell] WebSocket connected for session: %s\n", sessionID)

	shellChan := make(chan []byte, 100)
	cwdChan := make(chan string, 10)
	done := make(chan struct{})
	// 每个 shell 连接用唯一 handler key（而非 sessionID）：
	// 同会话并发开多个 shell 时互不覆盖（此前按 sessionID 注册，
	// 第二个连接会覆盖第一个的 handler，且 defer 会把对方的也删掉）。
	handlerID := uuid.NewString()

	sess.AddShellOutputHandler(handlerID, func(data []byte) {
		select {
		case shellChan <- data:
		default:
		}
	})
	defer sess.RemoveShellOutputHandler(handlerID)

	sess.AddShellCWDHandler(handlerID, func(cwd string) {
		select {
		case cwdChan <- cwd:
		default:
		}
	})
	defer sess.RemoveShellCWDHandler(handlerID)

	controller, ok := s.listener.(ShellController)
	if !ok {
		fmt.Printf("[ERROR] [shell] Listener does not implement ShellController\n")
		conn.WriteMessage(1, []byte("[错误: 服务端不支持交互式Shell]"))
		return
	}

	if err := controller.OpenShell(sessionID, ""); err != nil {
		fmt.Printf("[ERROR] [shell] Failed to open shell: %v\n", err)
		conn.WriteMessage(1, []byte(fmt.Sprintf("[错误: 无法打开Shell - %v]", err)))
		return
	}
	defer controller.CloseShell(sessionID)

	fmt.Printf("[INFO] [shell] Shell opened for session: %s\n", sessionID)
	conn.WriteMessage(1, []byte("[Shell已连接，等待输出...]"))

	// CWD 标记消息格式: \x00CWD\x00<目录>；前端据此更新文件浏览器当前目录
	const cwdMarker = "\x00CWD\x00"
	if current := sess.GetShellCWD(); current != "" {
		conn.WriteMessage(1, []byte(cwdMarker+current))
	}

	// 输出 writer goroutine：conn 关闭或 done 触发即退出，
	// 不再永久阻塞泄漏（此前 select 无退出分支，每次 shell 泄漏 1 goroutine）
	go func() {
		defer func() { recover() }() // conn 并发写 panic 兜底
		for {
			select {
			case <-done:
				return
			case data := <-shellChan:
				if err := conn.WriteMessage(1, data); err != nil {
					return
				}
			case cwd := <-cwdChan:
				if err := conn.WriteMessage(1, []byte(cwdMarker+cwd)); err != nil {
					return
				}
			case <-time.After(30 * time.Second):
				// 空闲保活探测：检测 conn 是否已死（WriteMessage 失败即退出）
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()
	defer close(done)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("[INFO] [shell] WebSocket read error: %v\n", err)
			break
		}

		if err := controller.SendShellInput(sessionID, string(msg)); err != nil {
			conn.WriteMessage(1, []byte(fmt.Sprintf("[错误: %v]", err)))
		}
	}

	fmt.Printf("[INFO] [shell] WebSocket handler exiting for session: %s\n", sessionID)
}

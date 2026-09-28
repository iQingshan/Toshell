// Package avops 是「杀软对抗能力分级」（AV-Ops）的**唯一一份真源**（v1.4.0 S6）。
//
// 为什么需要它：v1.4.0 S6 之前，"杀软对抗"不是一个功能而是 6 条互不相干的链
// （av_detect / edr_blind / edr_kill / byovd_* / ppl_kill / process_kill），每条链
// 各自有路由、各自的参数、各自的风险，**没有分级、没有前置检查、没有回滚、没有审计、
// 没有风险回显**。操作员（和前端、脚本、AI）只能靠"发一次试试"来判断某个动作能不能下发。
//
// 本包把这些散落的语义收成三样东西：
//
//  1. **等级（Tier）**：L0 侦察 → L1 用户态温和 → L2 强 → L3 BYOVD → L4 检测面抑制。
//     每一级带 `DefaultEnabled`（L0/L1 默认开，L2+ 默认关）、`ReadOnly`、`Destructive`、
//     `NeedsConfirm`、`NoAutoRetry`。
//  2. **动作表（Action）**：把 6 条链**真实提供**的动作逐个登记 —— 动作名 → 等级 →
//     植入端任务类型 → 必需能力位 → 影响文案。动作名是**对外契约**，只允许新增。
//  3. **策略（Policy）**：服务端配置（allow_l2/l3/l4、确认、超时上限）如何影响放行。
//
// 三条硬规则（全部 fail-closed）：
//
//   - **未知动作一律拒绝**：没登记在动作表里的名字不允许执行，绝不做"看起来像就放过去"的猜测；
//   - **未知等级串归到最高风险并拒绝**：`tier` 字段写错不会退化成"低等级"；
//   - **等级只能由动作决定**：请求里的 `tier` 只用于一致性核对（不符即拒），
//     防止调用方用 `tier=L0` 去绕过 L2+ 的配置开关与二次确认。
//
// 为什么放在 internal/common（而不是 internal/server 下）：
//   - 它是**纯逻辑**（不 import 任何 server 包、不碰网络/文件/DB），因此可以被
//     api（HTTP 入口）、task（重投递策略）、以及单测同时引用，不会形成 server 内部
//     包的循环依赖，也不会把"分级语义"绑死在 HTTP 层上；
//   - 仓库既有的同一取舍见 internal/common/features：能被多层共用的"事实来源"
//     一律放最内层，避免两边各维护一份表、迟早与真相漂移。
//
// ⚠️ 驱动（BYOVD）的**可用性判定**不在这里：它要读本机驱动目录与 manifest，
// 属于服务端 IO（见 internal/server/drivers 的 RWProfile / KillCapableProfile）。
// 本包只管"L3 必须有操作员自备的可用驱动"这条**规则**，具体判定由 api 层调用驱动包完成。
package avops

import (
	"fmt"
	"strings"
)

// ─── 等级 ────────────────────────────────────────────────────────────────────

// Tier 能力等级。取值是对外契约（HTTP 响应/请求体的 tier 字段），只允许新增。
type Tier string

const (
	// TierL0 侦察：只读枚举，不改动目标机任何状态。默认开。
	TierL0 Tier = "L0"
	// TierL1 用户态温和：不改内核、不结束进程，但会改目标进程内存与系统注册表。默认开、需确认。
	TierL1 Tier = "L1"
	// TierL2 强：结束安全软件/任意进程。默认关（配置 avops.allow_l2），需确认。
	TierL2 Tier = "L2"
	// TierL3 BYOVD：加载/卸载/使用操作员自备内核驱动、PPL 清除。默认关、需确认、必须有驱动。
	TierL3 Tier = "L3"
	// TierL4 检测面抑制（AMSI/ETW patch）。默认关、需确认。**本批未落地任何动作**。
	TierL4 Tier = "L4"
)

// TierMeta 一个等级的元数据。
//
// 字段语义（刻意写全，因为它们直接决定"界面要不要二次确认""任务能不能自动重试"）：
//   - DefaultEnabled：**出厂默认**是否允许执行（L0/L1 true；L2/L3/L4 false）。
//     它说明的是"默认配置下的取值"，真正的判定看 Policy.TierAllowed。
//   - ReadOnly：是否只读（不改动目标机状态）。只有 L0 是只读。
//   - Destructive：是否会对目标机造成**不可自动回滚**的副作用。
//
// 关于 Destructive 的口径（重要，别按"只有杀进程才算"去理解）：
// 需求里给的例子是"杀进程/卸载/加载驱动"，但 L1 的 edr_blind **确实**会把系统级
// ETW Autologger 注册表项 Start 置 0（系统级、不自动恢复），并覆盖目标进程 ntdll 的
// .text。把它标成"非破坏性"会让调用方在超时后放心重试、让界面不给二次确认 —— 这正是
// 本项目要防的事故。因此这里的口径是"是否留下不可自动回滚的改动"：宁可保守多警示，
// 也不粉饰。每个动作的影响文案（Action.Impact）会把**具体做了什么**如实写清，
// 不靠一个布尔值表达全部风险。
//   - NeedsConfirm：是否必须 `confirm=true`（L1 起为 true）。
//   - NoAutoRetry：服务端是否禁止**自动**重投递该等级任务（L1 起为 true）。
//     只读的 L0 可以照常重投递（重跑一次侦察没有副作用）。
//   - Implemented：本等级当前是否已有落地动作。L4 目前为 false（详见其 Note）。
type TierMeta struct {
	Tier           Tier   `json:"tier"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	DefaultEnabled bool   `json:"default_enabled"`
	ReadOnly       bool   `json:"read_only"`
	Destructive    bool   `json:"destructive"`
	NeedsConfirm   bool   `json:"needs_confirm"`
	NoAutoRetry    bool   `json:"no_auto_retry"`
	Implemented    bool   `json:"implemented"`
	Note           string `json:"note,omitempty"`
}

// tierList 等级表（顺序 = 风险从低到高；MaxTier 依赖这个顺序）。
var tierList = []TierMeta{
	{
		Tier:           TierL0,
		Name:           "L0 侦察",
		Description:    "只读枚举目标会话上的安全软件与进程，不改动任何状态。",
		DefaultEnabled: true,
		ReadOnly:       true,
		Destructive:    false,
		NeedsConfirm:   false,
		NoAutoRetry:    false,
		Implemented:    true,
	},
	{
		Tier:           TierL1,
		Name:           "L1 用户态温和",
		Description:    "用户态对抗：不结束进程、不加载驱动，但会改目标进程内存与系统注册表（EDR 失明）。",
		DefaultEnabled: true,
		ReadOnly:       false,
		Destructive:    true,
		NeedsConfirm:   true,
		NoAutoRetry:    true,
		Implemented:    true,
	},
	{
		Tier:           TierL2,
		Name:           "L2 强",
		Description:    "结束安全软件或指定进程（taskkill / TerminateProcess）。默认关闭。",
		DefaultEnabled: false,
		ReadOnly:       false,
		Destructive:    true,
		NeedsConfirm:   true,
		NoAutoRetry:    true,
		Implemented:    true,
		Note:           "默认关闭（configs 的 avops.allow_l2=false）；开启后仍需 confirm=true。",
	},
	{
		Tier:           TierL3,
		Name:           "L3 BYOVD",
		Description:    "加载/卸载/使用操作员自备的内核驱动，以及 PPL 清除。默认关闭。",
		DefaultEnabled: false,
		ReadOnly:       false,
		Destructive:    true,
		NeedsConfirm:   true,
		NoAutoRetry:    true,
		Implemented:    true,
		Note:           "驱动仍由操作员自备，项目不内置任何驱动；L3 动作一律要求本机驱动目录里存在对应档位的驱动（rw 档用于 PPL 清除），没有就明确拒绝而不是「试一下」。",
	},
	{
		Tier:           TierL4,
		Name:           "L4 检测面抑制",
		Description:    "检测面抑制（AMSI/ETW patch 等），让目标机上的安全产品看不到后续行为。默认关闭。",
		DefaultEnabled: false,
		ReadOnly:       false,
		Destructive:    true,
		NeedsConfirm:   true,
		NoAutoRetry:    true,
		Implemented:    false,
		Note: "本批（v1.4.0 S6 第一批）**没有**落地任何 L4 动作：植入端目前没有独立的 AMSI/ETW " +
			"抑制任务类型，把 amsi_etw_suppress 之类先写进动作表只会造出一个「点了没反应」的假入口" +
			"（这正是 S4 要修的毛病）。等植入端有了对应实现再补动作；届时 amsi_etw_suppress 会作为" +
			"新动作登记在 L4，并受 configs 的 avops.allow_l4 控制。因此当前 allow_l4=true 也不会" +
			"让任何动作变成可下发。",
	},
}

// Tiers 返回全部等级元数据（按风险从低到高，副本）。
func Tiers() []TierMeta {
	out := make([]TierMeta, len(tierList))
	copy(out, tierList)
	return out
}

// TierOf 解析等级字符串，返回元数据与是否已知。
//
// **fail-closed**：不认识的等级串（拼错、未来版本的等级、空串都算）一律返回**最高风险**
// 等级的元数据并标记 ok=false，由调用方拒绝。这样"写错等级"永远不会退化成"低等级放行"。
func TierOf(s string) (TierMeta, bool) {
	want := Tier(strings.ToUpper(strings.TrimSpace(s)))
	for _, t := range tierList {
		if t.Tier == want {
			return t, true
		}
	}
	return MaxTier(), false
}

// MaxTier 返回最高风险等级（当前 L4）。用于"未知等级归到最高风险"。
func MaxTier() TierMeta {
	return tierList[len(tierList)-1]
}

// TierRank 等级的序数（0 = L0）。未知等级返回 -1。
// 只用于排序/展示，**不要**用它做放行判定（放行一律走 Policy.TierAllowed）。
func TierRank(t Tier) int {
	for i, m := range tierList {
		if m.Tier == t {
			return i
		}
	}
	return -1
}

// ─── 动作表 ──────────────────────────────────────────────────────────────────

// ParamHint 动作参数说明（供前端渲染表单与接口文档使用；**不做类型强校验**，
// 真实校验在 api 层按动作逐个做，因为不同动作的参数形状差别太大）。
type ParamHint struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// Action 一个可下发的对抗动作（对外契约：动作名只允许新增，不允许改名/删除）。
type Action struct {
	Name string `json:"name"`
	Tier Tier   `json:"tier"`
	// TaskType 该动作在植入端的任务类型（**已逐个与 internal/server/builder/implant
	// 的 executeTask switch 核对过**；写错等于造出一个必然失败的任务）。
	TaskType string `json:"task_type"`
	// Capability 该动作要求载荷具备的能力位（internal/common/features 的能力名）。
	Capability string `json:"capability"`
	// Destructive / NeedsConfirm 与所在等级一致（见 Action 表末尾的一致性单测）；
	// 冗余保留是为了让接口响应不必再去查等级表，也为了让"这条动作是不是破坏性"在表里一目了然。
	Destructive  bool `json:"destructive"`
	NeedsConfirm bool `json:"needs_confirm"`
	// Summary 一句话说明"这个动作做什么"。
	Summary string `json:"summary"`
	// Impact 如实的影响评估（不夸大、不粉饰）：会改什么、会不会自动恢复、可能触发什么。
	Impact string `json:"impact"`
	// RequiredParams 必填参数名（缺失即拒）。
	RequiredParams []string `json:"required_params,omitempty"`
	// Params 参数说明。
	Params []ParamHint `json:"params,omitempty"`
	// AutoRetry 该动作是否允许服务端自动重投递（= 等级 NoAutoRetry 取反）。
	AutoRetry bool `json:"auto_retry"`
}

// actionList 动作表 —— 覆盖既有 6 条链（av_detect / edr_blind / edr_kill / byovd_* /
// ppl_kill / process_kill）**实际提供**的动作，动作名与既有路由/任务类型对应关系在
// 每条注释里写明。新增动作前请先读三条失败路径（未知动作/未知等级/等级被禁用）。
var actionList = []Action{
	// ── L0 侦察 ─────────────────────────────────────────────────────────────
	{
		Name:     "av_detect",
		Tier:     TierL0,
		TaskType: "av_detect",
		// 既有链：植入端 main.go 的 case "av_detect" → detectSecurityProducts()
		// （tasklist.exe 枚举进程），结果由服务端 avdetect 包与指纹库比对。
		Capability:   "av_detect",
		Destructive:  false,
		NeedsConfirm: false,
		Summary:      "枚举目标会话上的安全软件（进程枚举 + 服务端指纹库比对）。",
		Impact: "只读：创建一次 tasklist.exe 子进程枚举进程名并与服务端指纹库比对，" +
			"不改动任何进程、文件、注册表或驱动。副作用仅为这一次进程枚举本身" +
			"（会短暂出现一个 tasklist.exe 子进程，属正常系统行为）。",
		AutoRetry: true,
	},
	// ── L1 用户态温和 ───────────────────────────────────────────────────────
	{
		Name:     "edr_blind",
		Tier:     TierL1,
		TaskType: "edr_blind",
		// 既有链：POST /sessions/{id}/edr/blind → CreateEDRBlind → case "edr_blind"
		// → edr_windows.go handleEDRBlind（ntdll 脱钩 + ETW patch + Autologger 清理）。
		Capability:   "edr_blind",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "EDR 失明：ntdll 脱钩 + ETW patch + ETW Autologger 清理。",
		Impact: "会修改目标会话进程自身的内存：用磁盘上的干净 ntdll.dll 覆盖已加载 ntdll 的 .text" +
			"（抹掉 EDR 的用户态 hook），并把 EtwEventWrite/EtwWriteEx patch 成提前返回；" +
			"另外以管理员权限把已知 EDR 的 ETW Autologger 注册表项 Start 置 0 —— " +
			"**这是系统级改动且不会自动恢复**（目标机的 ETW 日志/EDR 数据源会持续缺失）。" +
			"不结束任何进程、不加载任何驱动。可能触发安全软件的主动防御告警。",
		AutoRetry: false,
	},
	// ── L2 强 ───────────────────────────────────────────────────────────────
	{
		Name:     "edr_kill",
		Tier:     TierL2,
		TaskType: "edr_kill",
		// 既有链：POST /sessions/{id}/edr/kill → CreateEDRKill → handleEDRKill
		// （taskkill /F /IM <name>）。
		Capability:   "edr_kill",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "按进程名强制结束安全软件/EDR 进程（未指定时用植入端内置清单，当前 36 项）。",
		Impact: "会用 taskkill /F /IM 强制结束目标机上**进程名匹配**的安全软件/EDR 进程。" +
			"未指定 processes 时使用植入端内置清单（见 internal/server/builder/implant/edr_windows.go " +
			"的 defaultAVProcesses，当前 36 个进程名），实际命中几个取决于目标机当时运行了哪些产品，" +
			"服务端无法预先给出确定数字。后果：这些产品的实时防护立即失效；" +
			"可能触发自保护对抗、主动防御告警，内核组件被强杀时可能导致目标机不稳定甚至重启。" +
			"被结束的进程不会自动恢复。",
		Params: []ParamHint{
			{Name: "processes", Type: "array", Required: false, Description: "要结束的进程名列表；留空 = 用植入端内置安全软件清单（36 项）"},
		},
		AutoRetry: false,
	},
	{
		Name:     "process_kill",
		Tier:     TierL2,
		TaskType: "process_kill",
		// 既有链：DELETE /sessions/{id}/processes/{pid} → CreateProcessKill →
		// case "process_kill" → killProcess(pid)。放进分级表是因为它是"结束进程"这条
		// 能力里最容易误用的一条：PID 填错就会杀掉无关进程。
		Capability:   "process_kill",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "强制结束目标机上指定 PID 的进程。",
		Impact: "会强制结束目标机上**指定 PID** 的进程（TerminateProcess / 进程终止 API）。" +
			"若该 PID 属于安全软件或系统关键进程，后果与 L2 的进程击杀相同" +
			"（实时防护失效、可能触发自保护对抗或目标机不稳定/重启）；" +
			"被杀进程不会自动恢复。**PID 是会复用的**：请先用 process_list 确认再下发。",
		RequiredParams: []string{"pid"},
		Params: []ParamHint{
			{Name: "pid", Type: "integer", Required: true, Description: "目标进程 PID（先用 process_list 确认，PID 会复用）"},
		},
		AutoRetry: false,
	},
	// ── L3 BYOVD（驱动由操作员自备）────────────────────────────────────────
	{
		Name:     "byovd_load",
		Tier:     TierL3,
		TaskType: "byovd_load",
		// 既有链：POST /sessions/{id}/edr/byovd-load → CreateBYOVDLoad → handleDrvLoad
		// （写 %SystemRoot%\System32\drivers\<svc>.sys + SCM 创建/启动内核服务）。
		Capability:   "byovd_load",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "把操作员自备的 .sys 写入系统驱动目录并以内核服务启动（BYOVD 加载）。",
		Impact: "会把请求里携带的 .sys（driver_b64）写入目标机 " +
			`%SystemRoot%\System32\drivers\<service_name>.sys` + " 并以内核服务启动 —— " +
			"**这是加载内核驱动**：加载成功即获得内核态能力，可直接导致蓝屏或触发安全软件告警；" +
			"未签名/在微软易受攻击驱动黑名单里的驱动会被内核代码完整性（HVCI 等）**静默拒绝**" +
			"（不会有任何弹窗）。同名旧服务会被停止并删除旧驱动文件（不可恢复）。" +
			"驱动由操作员自备，项目不内置任何驱动；请自行确认来源与授权。",
		RequiredParams: []string{"driver_b64", "service_name"},
		Params: []ParamHint{
			{Name: "driver_b64", Type: "string", Required: true, Description: "操作员自备 .sys 的 base64 内容"},
			{Name: "service_name", Type: "string", Required: true, Description: "SCM 服务名（决定落盘文件名与设备名）"},
			{Name: "device_name", Type: "string", Required: false, Description: "设备名（留空按服务名推断 \\\\.\\<svc>）"},
			{Name: "name", Type: "string", Required: false, Description: "驱动档案名：用于在 manifest.json 里找期望 sha256 与声明签名者做加载前自检（留空则只能给「未声明哈希」的警告）"},
			{Name: "purpose", Type: "string", Required: false, Description: "驱动档位 kill/rw/both（v1.4.0 S6）：留空用 manifest 声明，两边都没有按 kill 兜底；登记后决定后续 byovd_kill / ppl_kill 能否自动选到它"},
		},
		AutoRetry: false,
	},
	{
		Name:     "byovd_unload",
		Tier:     TierL3,
		TaskType: "byovd_unload",
		// 既有链：POST /sessions/{id}/edr/byovd-unload → CreateBYOVDUnload → handleDrvUnload。
		Capability:   "byovd_load", // 与 load/kill 同一个编译单元 drv_windows.go（windows && !light）
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "停止并删除目标机上的内核服务与驱动文件（BYOVD 卸载/清场）。",
		Impact: "会停止并删除目标机上指定 service_name 的内核服务，并删除对应的 .sys 驱动文件。" +
			"若该驱动仍被其它组件使用，停止服务可能导致目标机不稳定；" +
			"**删除的驱动文件不可恢复**（需要重新上传）。",
		// v1.4.0 S6 P0-1：service_name **不再列为必填** —— 选路会依次尝试
		// 请求 → 本会话登记的驱动档案 → 服务端加载台账（drivers.Ledger）。
		// 清场恰恰发生在"会话换了一个、服务端也重启过"的场景，那时操作员手上未必记得服务名，
		// 而服务端台账里有记录；把必填去掉，这条清场路径才真正可用（选路仍会在三者都空时明确拒绝）。
		Params: []ParamHint{
			{Name: "service_name", Type: "string", Required: false, Description: "要停止并删除的内核服务名；留空时按本会话登记的档案 → 服务端加载台账（GET /api/v1/drivers/ledger）解析"},
		},
		AutoRetry: false,
	},
	{
		Name:     "byovd_kill",
		Tier:     TierL3,
		TaskType: "byovd_kill",
		// 既有链：POST /sessions/{id}/edr/byovd-kill → CreateBYOVDKill → handleDrvKill
		// （打开驱动设备 + DeviceIoControl 终止 IOCTL）。注意**没有**独立能力位：
		// 实现与 byovd_load 同在 drv_windows.go，因此复用 byovd_load 能力位。
		Capability:   "byovd_load",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "通过已加载的操作员驱动，用其无鉴权终止 IOCTL 结束指定 PID/进程名的进程。",
		Impact: "会打开操作员驱动的设备并对其终止 IOCTL 传入 PID，**由内核驱动结束进程**" +
			"（无需调用方权限）。目标可以是普通杀软/EDR 进程；**对 PPL 保护进程无效**" +
			"（内核句柄检查拦得住，需改用 ppl_kill）。被结束的进程不会自动恢复；" +
			"可能触发自保护对抗与主动防御告警。",
		Params: []ParamHint{
			{Name: "pid", Type: "integer", Required: false, Description: "目标 PID（与 process_name 至少给一个）"},
			{Name: "process_name", Type: "string", Required: false, Description: "目标进程名（与 pid 至少给一个）"},
			{Name: "driver", Type: "string", Required: false, Description: "驱动档案名（来自 GET /api/v1/drivers）；或直接给 device+ioctl"},
			{Name: "device", Type: "string", Required: false, Description: "驱动设备路径，如 \\\\.\\yourdrv"},
			{Name: "ioctl", Type: "string", Required: false, Description: "终止 IOCTL（支持 0x222048 / 十进制 / 数字）"},
		},
		AutoRetry: false,
	},
	{
		Name:     "ppl_kill",
		Tier:     TierL3,
		TaskType: "ppl_kill",
		// 既有链：POST /sessions/{id}/edr/ppl-kill → CreatePPLKill → handlePPLKill。
		// ⚠️ 分级入口对本动作的要求**比既有路由更严**（既有路由保留原语义不动）：
		// 必须有 rw 档驱动才放行，见 api 层的 L3 驱动前置检查。
		Capability:   "ppl_kill",
		Destructive:  true,
		NeedsConfirm: true,
		Summary:      "PPL 清除：结束受保护进程（需要具备内核读写的 rw 档驱动）。",
		Impact: "会对指定进程（未指定时用内置安全软件清单）先尝试直接 TerminateProcess，" +
			"失败则走 NtDuplicateObject 句柄窃取后终止。**无 rw 档驱动时对 PPL 保护进程" +
			"（Defender MsMpEng 等）通常失败** —— 本分级入口因此要求存在 rw 档驱动才放行，" +
			"而不是让操作员" + "「试一下看看」" + "。若成功结束安全软件进程，后果同 L2" +
			"（实时防护失效、可能触发自保护对抗/蓝屏/重启/告警），且不可自动恢复。",
		RequiredParams: []string{"processes"},
		Params: []ParamHint{
			{Name: "processes", Type: "array", Required: true, Description: "要清除的受保护进程名列表（留空会退回内置清单，因此这里显式要求给出目标）"},
		},
		AutoRetry: false,
	},
}

// Actions 返回全部动作（副本）。
func Actions() []Action {
	out := make([]Action, len(actionList))
	copy(out, actionList)
	return out
}

// Lookup 按动作名查表。
//
// 返回 ok=false 有两种情况，调用方都必须拒绝：
//  1. 名字不在表里（未知动作）；
//  2. 表里的动作写了一个**未知等级**（表本身坏了）—— 这种情况下绝不"当作低等级放行"。
func Lookup(name string) (Action, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, a := range actionList {
		if a.Name != n {
			continue
		}
		if _, ok := TierOf(string(a.Tier)); !ok {
			return a, false
		}
		return a, true
	}
	return Action{}, false
}

// ActionsOfTier 返回某等级下的全部动作（按表顺序）。
func ActionsOfTier(t Tier) []Action {
	var out []Action
	for _, a := range actionList {
		if a.Tier == t {
			out = append(out, a)
		}
	}
	return out
}

// ActionByTaskType 按植入端任务类型反查动作（用于"这条任务要不要禁止自动重试"）。
func ActionByTaskType(taskType string) (Action, bool) {
	tt := strings.TrimSpace(taskType)
	for _, a := range actionList {
		if a.TaskType == tt {
			return a, true
		}
	}
	return Action{}, false
}

// Meta 返回动作所在等级的元数据。
func (a Action) Meta() TierMeta {
	m, _ := TierOf(string(a.Tier))
	return m
}

// TaskNoRetry 判断"这个植入端任务类型是否禁止服务端自动重投递"（v1.4.0 S6）。
//
// 判定依据是**任务类型**而不是内存里的标记：task_type 会随任务落 sqlite 并在重启后读回，
// 而挂在内存对象上的标记重启即丢 —— 恰恰是重启恢复那条补发路径最需要它。
//
// 未知任务类型返回 false（**刻意不 fail-closed**）：服务端还有 file_download/file_upload
// 等三十来个任务类型依赖"断线重投递 + 断点续传"才能工作，把未登记类型一律当成不可重试
// 会直接打断大文件传输。这里的取舍是"只对本表明确登记为破坏性的动作收紧"，而不是
// "对一切未知情况收紧"；新增破坏性动作时**必须**登记进动作表，否则它不会被保护 ——
// 这一点由 handlers_avops 的源码扫描单测兜住（新破坏性任务类型不允许绕过本表）。
func TaskNoRetry(taskType string) bool {
	a, ok := ActionByTaskType(taskType)
	if !ok {
		return false
	}
	m, ok := TierOf(string(a.Tier))
	if !ok {
		// 表坏了：按最保守处理（禁止自动重投递）。
		return true
	}
	return m.NoAutoRetry
}

// ─── 策略（服务端配置 → 放行判定）────────────────────────────────────────────

// 默认确认与超时口径。
//
// 为什么默认值写在 avops 而不是只写在 config：config 的 viper 默认值、运行时兜底
// （Normalize）与接口回显必须是**同一个数**（历史教训：同一个人为上限曾在注释/viper/
// 前端/后端四处取不同值），所以常量放在纯逻辑包，config 直接引用。
const (
	// DefaultTimeoutSec timeout_sec 未指定（0）时的默认显式超时。
	DefaultTimeoutSec = 120
	// MaxTimeoutSec 显式超时上限（超过即拒绝，而不是截断 —— 截断会让调用方
	// 以为"我要的 3600 秒生效了"，实际只等 600 秒，是典型的哑失败）。
	MaxTimeoutSec = 600
)

// Policy 服务端配置对 AV-Ops 的影响（纯数据，可由 config.AVOpsConfig 直接映射）。
type Policy struct {
	AllowL2 bool `json:"allow_l2"`
	AllowL3 bool `json:"allow_l3"`
	AllowL4 bool `json:"allow_l4"`
	// SkipConfirm = true 表示"不强制二次确认"（对应配置 avops.require_confirm=false）。
	//
	// 为什么字段是**反向**的（skip 而不是 require）：零值必须落在最严的一侧。
	// 如果写成 `RequireConfirm bool`，那么任何"忘了赋值"的零值 Policy 都会变成
	// "不要求确认"，等于把 L1+ 的二次确认静默关掉 —— 这正是 fail-closed 要防的事。
	// 配置层仍用正向键 `require_confirm`（默认 true），映射到策略时取反（见 api 层）。
	SkipConfirm bool `json:"skip_confirm"`
	// DefaultTimeoutSec / MaxTimeoutSec：见上方常量。<=0 一律回落默认值。
	DefaultTimeoutSec int `json:"default_timeout_sec"`
	MaxTimeoutSec     int `json:"max_timeout_sec"`
}

// DefaultPolicy 出厂默认策略：L2/L3/L4 全关、强制确认、超时 120/600。
//
// 这是 **fail-closed 的落点**：任何"配置没读到/解析失败"的路径都应该回落到它
// （或者干脆回落到零值 —— 两者同效，见 Normalize 的注释），而不是回落到"全开"。
func DefaultPolicy() Policy {
	return Policy{
		AllowL2:           false,
		AllowL3:           false,
		AllowL4:           false,
		SkipConfirm:       false,
		DefaultTimeoutSec: DefaultTimeoutSec,
		MaxTimeoutSec:     MaxTimeoutSec,
	}
}

// Normalize 补齐零值（<=0 一律回落默认值，不允许用配置关掉超时上限）。
func (p Policy) Normalize() Policy {
	if p.DefaultTimeoutSec <= 0 {
		p.DefaultTimeoutSec = DefaultTimeoutSec
	}
	if p.MaxTimeoutSec <= 0 {
		p.MaxTimeoutSec = MaxTimeoutSec
	}
	if p.DefaultTimeoutSec > p.MaxTimeoutSec {
		p.DefaultTimeoutSec = p.MaxTimeoutSec
	}
	return p
}

// TierAllowed 判断该等级在当前策略下是否允许执行；不允许时给出人类可读原因。
//
// 注意 L0/L1 没有开关（默认开、始终允许），但 L1 仍然要过确认这一关（见 CheckConfirm）。
func (p Policy) TierAllowed(t Tier) (bool, string) {
	p = p.Normalize()
	switch t {
	case TierL0, TierL1:
		return true, ""
	case TierL2:
		if p.AllowL2 {
			return true, ""
		}
		return false, "L2（强：结束安全软件/进程）默认禁用：需要服务端配置 avops.allow_l2=true（默认关闭是 fail-closed 的一部分）"
	case TierL3:
		if p.AllowL3 {
			return true, ""
		}
		return false, "L3（BYOVD：加载/卸载/使用操作员自备驱动、PPL 清除）默认禁用：需要服务端配置 avops.allow_l3=true"
	case TierL4:
		if p.AllowL4 {
			return true, ""
		}
		return false, "L4（检测面抑制）默认禁用：需要服务端配置 avops.allow_l4=true"
	}
	// 未知等级：归到最高风险并拒绝。
	return false, fmt.Sprintf("未知等级 %q：按最高风险（%s）处理并拒绝（fail-closed）", string(t), MaxTier().Tier)
}

// ResolveTimeout 归一化显式超时：0 → 默认值；负数/超上限 → 拒绝。
func (p Policy) ResolveTimeout(sec int) (int, error) {
	p = p.Normalize()
	if sec < 0 {
		return 0, NewError(400, CodeTimeoutInvalid, "timeout_sec 不能为负数（%d）", sec)
	}
	if sec == 0 {
		return p.DefaultTimeoutSec, nil
	}
	if sec > p.MaxTimeoutSec {
		return 0, NewError(400, CodeTimeoutInvalid,
			"timeout_sec=%d 超过上限 %d 秒：直接拒绝（而不是截断到上限）—— 截断会让调用方以为自己的取值生效了",
			sec, p.MaxTimeoutSec)
	}
	return sec, nil
}

// ─── 前置检查（纯逻辑部分）────────────────────────────────────────────────────

// CheckAction 解析并校验动作名。这是"未知动作 fail-closed"的唯一落点。
func CheckAction(name string) (Action, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return Action{}, NewError(400, CodeBadRequest, "缺少 action 字段")
	}
	a, ok := Lookup(n)
	if !ok {
		if _, known := actionByName(n); known {
			// 表里存在但等级未知 = 表本身有问题：绝不放行。
			return Action{}, NewError(500, CodeUnknownTier,
				"动作 %s 在分级表里登记了一个未知等级：拒绝执行（fail-closed，请检查 avops 动作表）", n)
		}
		return Action{}, NewError(400, CodeUnknownAction,
			"未知动作 %q：不在分级表里的动作一律不允许执行（fail-closed）。可用动作见 GET /api/v1/av-ops", name)
	}
	return a, nil
}

// actionByName 只按名字找（不校验等级），供 CheckAction 区分"未知动作"与"表坏了"。
func actionByName(name string) (Action, bool) {
	for _, a := range actionList {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

// CheckTierField 核对请求里的 tier 与动作实际等级是否一致。
//
// 为什么需要它：`tier` 字段如果只是"装饰"，调用方就可以写 `tier=L0` 去骗过
// 前端/脚本里基于 tier 的二次确认逻辑；服务端必须**按动作自己的等级**判定，
// 并把不一致当成错误拒绝（而不是"以服务端为准、默默忽略"）—— 后者会让调用方
// 长久地以为自己传的等级生效了。
func CheckTierField(reqTier string, a Action) error {
	s := strings.TrimSpace(reqTier)
	if s == "" {
		return nil // 留空 = 由服务端决定等级（推荐用法）
	}
	m, ok := TierOf(s)
	if !ok {
		return NewError(400, CodeUnknownTier,
			"未知等级 %q：按最高风险 %s 处理并拒绝（fail-closed）", reqTier, m.Tier)
	}
	if m.Tier != a.Tier {
		return NewError(400, CodeTierMismatch,
			"tier 与动作等级不符：action=%s 实际是 %s（%s），请求里写的是 %s。"+
				"服务端一律按动作自己的等级判定，不允许用低等级绕过配置开关与二次确认",
			a.Name, a.Tier, a.Meta().Name, m.Tier)
	}
	return nil
}

// CheckTierAllowed 等级是否被服务端配置允许。
func CheckTierAllowed(p Policy, a Action) error {
	if ok, reason := p.TierAllowed(a.Tier); !ok {
		return NewError(403, CodeTierDisabled, "动作 %s（%s）被服务端配置禁用：%s", a.Name, a.Tier, reason)
	}
	return nil
}

// CheckConfirm 需要确认的动作必须 confirm=true（缺失 → 409 confirmation_required）。
func CheckConfirm(p Policy, a Action, confirm bool) error {
	if !a.NeedsConfirm || p.Normalize().SkipConfirm {
		return nil
	}
	if !confirm {
		return NewError(409, CodeConfirmationRequired,
			"动作 %s（%s，%s）需要二次确认：请在请求体里带 confirm=true。"+
				"破坏性动作不接受隐式确认 —— 缺确认就拒绝，而不是「默认帮操作员确认了」",
			a.Name, a.Tier, a.Meta().Name)
	}
	return nil
}

// CheckCapability 载荷能力位必须包含动作所需能力。
func CheckCapability(a Action, featureList []string, source string) error {
	if a.Capability == "" {
		return nil
	}
	for _, f := range featureList {
		if f == a.Capability {
			return nil
		}
	}
	hint := "该会话的载荷没有上报能力位、当前清单是按 OS 兜底推导的（未必等于载荷真实能力）"
	if source != "" && source != "os_fallback" {
		hint = "能力位来自载荷自报（权威）"
	}
	return NewError(409, CodeCapabilityMissing,
		"该会话的载荷不具备动作 %s 需要的能力 %q（%s）：请用包含该能力的档案重新构建载荷"+
			"（full 档，或对应的 -tags），或改用其它动作。下发到不支持的载荷上只会拿到"+
			"「未包含在本次构建中」", a.Name, a.Capability, hint)
}

// CheckRequiredParams 必填参数校验。
func CheckRequiredParams(a Action, params map[string]interface{}) error {
	for _, k := range a.RequiredParams {
		if !HasParam(params, k) {
			return NewError(400, CodeParamsInvalid, "动作 %s 缺少必填参数 %q", a.Name, k)
		}
	}
	return nil
}

// ─── 参数读取小工具（纯逻辑，便于表驱动单测）─────────────────────────────────

// HasParam 判断参数存在且非空（字符串非空串；数字非 0；数组非空）。
func HasParam(params map[string]interface{}, key string) bool {
	if params == nil {
		return false
	}
	v, ok := params[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) != ""
	case float64:
		return t != 0
	case bool:
		return t
	case []interface{}:
		return len(t) > 0
	case []string:
		return len(t) > 0
	}
	return true
}

// ParamString 取字符串参数（去空白；不存在或类型不符返回空串）。
func ParamString(params map[string]interface{}, key string) string {
	if params == nil {
		return ""
	}
	switch t := params[key].(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	}
	return ""
}

// ParamUint32 取无符号整数参数（兼容 JSON 数字与十进制字符串）。
func ParamUint32(params map[string]interface{}, key string) (uint32, bool) {
	if params == nil {
		return 0, false
	}
	switch t := params[key].(type) {
	case float64:
		if t < 0 || t > 4294967295 || t != float64(uint32(t)) {
			return 0, false
		}
		return uint32(t), true
	case string:
		var n uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err != nil || n > 4294967295 {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}

// ParamStringSlice 取字符串数组参数（兼容 JSON 数组与逗号分隔字符串）。
func ParamStringSlice(params map[string]interface{}, key string) []string {
	if params == nil {
		return nil
	}
	clean := func(in []string) []string {
		var out []string
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	switch t := params[key].(type) {
	case []interface{}:
		var out []string
		for _, v := range t {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return clean(out)
	case []string:
		return clean(t)
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return clean(strings.Split(t, ","))
	}
	return nil
}

// ─── 错误码 ──────────────────────────────────────────────────────────────────

// 错误码：**对外契约**（HTTP 响应的 code 字段、审计日志、前端判断、测试断言都依赖它），
// 只允许新增，不允许改名。命名口径与 internal/server/modules 一致：<对象>_<问题>，小写下划线。
//
// 为什么必须稳定：失败路径的价值在于"可判定"。只有中文文案时，脚本/前端只能做字符串
// 匹配，任何文案微调都会静默破坏它们的判断（S4 的模块接口已经踩过这个坑）。
const (
	// CodeBadRequest 请求体本身不合法（缺字段/JSON 解析失败）。
	CodeBadRequest = "bad_request"
	// CodeUnknownAction 动作不在分级表里（fail-closed）。
	CodeUnknownAction = "unknown_action"
	// CodeUnknownTier 等级串未知（归到最高风险并拒绝），或动作表登记了未知等级。
	CodeUnknownTier = "unknown_tier"
	// CodeTierMismatch 请求里的 tier 与动作实际等级不符（防"低等级绕过确认"）。
	CodeTierMismatch = "tier_mismatch"
	// CodeTierDisabled 该等级被服务端配置禁用（L2+ 默认禁用）。
	CodeTierDisabled = "tier_disabled"
	// CodeConfirmationRequired 需要确认的动作缺少 confirm=true（HTTP 409）。
	CodeConfirmationRequired = "confirmation_required"
	// CodeCapabilityMissing 载荷能力位不含该动作所需能力。
	CodeCapabilityMissing = "capability_missing"
	// CodeDriverUnavailable L3 动作没有可用的操作员自备驱动。
	CodeDriverUnavailable = "driver_unavailable"
	// CodeDriverSelfcheckFailed 操作员自备驱动没有通过加载前自检（哈希不符/易受攻击黑名单等硬错误）。
	// 与既有 byovd_load 路由同一口径：自检有 Errors 一律拒绝下发，没有"警告后继续"。
	CodeDriverSelfcheckFailed = "driver_selfcheck_failed"
	// CodeTimeoutInvalid 显式超时非法（负数/超上限）。
	CodeTimeoutInvalid = "timeout_invalid"
	// CodeParamsInvalid 动作参数不合法（缺必填/类型不符）。
	CodeParamsInvalid = "params_invalid"
	// CodeSessionNotFound 会话不存在（HTTP 404，与全项目同一口径）。
	CodeSessionNotFound = "session_not_found"
	// CodeSessionInactive 会话存在但不在线（HTTP 409）。
	CodeSessionInactive = "session_inactive"
	// CodeTaskCreateFailed 创建任务失败（服务端故障）。
	CodeTaskCreateFailed = "task_create_failed"
	// CodePushFailed 任务下发失败（listener 推送失败）。
	CodePushFailed = "push_failed"
)

// Error 带机器可读码与 HTTP 状态的分级错误。
//
// 把 HTTP 状态挂在错误对象上（而不是在 handler 里 switch 错误码）是为了让
// "哪类失败该返回几"这个决定只有一处：客户端输入错误 → 400、需要确认 → 409、
// 配置禁用/能力缺失/无驱动 → 403/409、服务端故障 → 500。
type Error struct {
	Code    string `json:"code"`
	Message string `json:"error"`
	HTTP    int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

// NewError 构造带码错误。
func NewError(httpStatus int, code, format string, a ...interface{}) *Error {
	return &Error{Code: code, HTTP: httpStatus, Message: fmt.Sprintf(format, a...)}
}

// ErrorCode 从任意 error 提取机器可读码（非 *Error 时返回空串）。
func ErrorCode(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// ErrorHTTP 从任意 error 提取 HTTP 状态（非 *Error 时返回 def）。
func ErrorHTTP(err error, def int) int {
	if e, ok := err.(*Error); ok && e.HTTP != 0 {
		return e.HTTP
	}
	return def
}

// ErrorMessage 从任意 error 提取面向人的文案。
func ErrorMessage(err error) string {
	if e, ok := err.(*Error); ok && e.Message != "" {
		return e.Message
	}
	return err.Error()
}

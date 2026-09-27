// Package modules 是 v1.4.0 S4「内存模块按需加载」的服务端侧：模块注册表 + 一次性 token。
//
// 它只做三件事，且全部是**可单测的纯逻辑 + 本地文件**：
//
//  1. 读 data/modules/manifest.json（模块清单：id/文件/sha256/大小/abi/arch/os/说明）。
//  2. 按 id 取出模块字节并**硬校验** sha256 与大小（哈希不符一律拒绝，见 Verify*）。
//  3. 签发/核销一次性 token（把"授权给谁、哪个模块、多久过期、是否已用过"记在内存里）。
//
// 为什么单独一个包而不是塞进 api handler：
//   - 校验链的 7 条里有 5 条是纯函数（清单解析 / 哈希比对 / 版本握手 / token 生命周期 /
//     架构归一），把它们放进 handler 就只能靠 httptest 间接覆盖；放这里可以直接表驱动单测。
//   - handler 只保留"编排 + HTTP 语义 + 审计日志"，读代码时一眼能看出 9 步的顺序。
//
// 目录约定：data/modules/（与 data/uploads、data/transfers 同一套"运行时产物放 data/ 下"
// 的口径，相对于服务端进程的工作目录）。manifest.json 由模块构建器（builder.BuildModule）
// 写入，也可以由操作员手工维护 —— 只要 sha256/size/abi 与实际文件一致。
package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"toshell/internal/common/moduleabi"
)

// DefaultDir 模块目录（相对服务端工作目录）。
const DefaultDir = "data/modules"

// ManifestName 清单文件名。
const ManifestName = "manifest.json"

// ManifestVersion 清单结构版本。版本不认识时**拒绝加载**（宁可不给操作员模块，
// 也不要用错误的结构解出一份看似正常的清单）。
const ManifestVersion = 1

// Entry 是清单里的一个模块条目。
//
// 字段全部是"事实"而不是"声明"：sha256/size 必须与实际文件一致（加载时硬校验），
// abi/os/arch 必须与模块 PE 头一致（下发前由 pecheck 复核）。
type Entry struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// File 模块文件名（**只允许文件名**，不许含路径分隔符：防止清单被写坏/被篡改后
	// 变成任意文件读取）。
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	ABI    uint32 `json:"abi"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	// Entry 期望的入口导出名（默认 tsh_module_main，留痕用）。
	Entry string `json:"entry,omitempty"`
	// ArgsSchema 参数说明（给操作员看，服务端不校验）。示例模块用的是紧凑格式
	// "reg:<子键>|<值名>"，不是 JSON —— 见 implant_c/module/cred_probe.c 的说明。
	ArgsSchema string `json:"args_schema,omitempty"`
	// Source 模块源码位置（可追溯：模块是从哪份源码编出来的）。
	Source  string `json:"source,omitempty"`
	BuiltAt string `json:"built_at,omitempty"`
	// BuildCmd 复现用构建命令（留痕，便于"服务端更新模块而不重编载荷"的运维流程）。
	BuildCmd string `json:"build_cmd,omitempty"`
}

// Manifest 是 manifest.json 的结构。
type Manifest struct {
	Version     int     `json:"version"`
	GeneratedAt string  `json:"generated_at,omitempty"`
	Modules     []Entry `json:"modules"`
}

// Find 按 id 查条目。
func (m *Manifest) Find(id string) (Entry, bool) {
	id = strings.TrimSpace(id)
	for _, e := range m.Modules {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// ParseManifest 解析并校验清单（纯函数：只吃字节，不碰文件系统）。
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &Error{Code: CodeManifestInvalid, HTTP: 500,
			Message: fmt.Sprintf("模块清单 %s 不是合法 JSON：%v", ManifestName, err)}
	}
	if m.Version != ManifestVersion {
		return nil, &Error{Code: CodeManifestInvalid, HTTP: 500,
			Message: fmt.Sprintf("模块清单版本 %d 不被支持（本服务端只认 %d）", m.Version, ManifestVersion)}
	}
	seen := make(map[string]bool, len(m.Modules))
	for i := range m.Modules {
		e := &m.Modules[i]
		if err := e.Validate(); err != nil {
			return nil, err
		}
		if seen[e.ID] {
			return nil, &Error{Code: CodeManifestInvalid, HTTP: 500,
				Message: fmt.Sprintf("模块清单里 id %q 重复：id 是唯一定位键，重复会让\"下发的是哪个模块\"变得不可判定", e.ID)}
		}
		seen[e.ID] = true
	}
	sort.SliceStable(m.Modules, func(i, j int) bool { return m.Modules[i].ID < m.Modules[j].ID })
	return &m, nil
}

// Validate 校验清单条目的自洽性（纯函数）。
//
// 注意这里**不比对真实文件**：sha256 与文件的一致性属于"硬校验"（见 ReadVerified），
// 需要文件系统参与。这里只保证条目本身没有明显错误（缺字段、路径穿越、哈希格式）。
func (e *Entry) Validate() error {
	bad := func(format string, a ...interface{}) error {
		return &Error{Code: CodeManifestInvalid, HTTP: 500,
			Message: fmt.Sprintf("模块清单条目 %q 不合法：", e.ID) + fmt.Sprintf(format, a...)}
	}
	if strings.TrimSpace(e.ID) == "" {
		return bad("缺少 id")
	}
	if strings.TrimSpace(e.File) == "" {
		return bad("缺少 file")
	}
	// 路径穿越防护：清单是配置，配置被写坏/被篡改都不该变成任意文件读取。
	if e.File != filepath.Base(e.File) || strings.ContainsAny(e.File, `/\:`) || strings.Contains(e.File, "..") {
		return bad("file 只能是模块目录下的文件名（不含路径分隔符/%s）", "..")
	}
	if err := ValidateSHA256(e.SHA256); err != nil {
		return bad("%v", err)
	}
	if e.Size <= 0 {
		return bad("size 必须为正数（当前 %d）", e.Size)
	}
	if e.Size > moduleabi.MaxModuleSize {
		return bad("size %d 超过上限 %d", e.Size, moduleabi.MaxModuleSize)
	}
	if e.ABI != moduleabi.Version {
		// 版本握手（服务端侧）：清单声明的 ABI 与本服务端的 ABI 必须一致。
		// 这里就给结论，而不是等植入端加载后才发现 —— 那时代码已经进了目标进程。
		return &Error{Code: CodeABIMismatch, HTTP: 409,
			Message: fmt.Sprintf("模块 %s 声明 ABI %d，本服务端要求 ABI %d（%s）：拒绝下发，请用匹配版本的工具链重新构建该模块",
				e.ID, e.ABI, moduleabi.Version, moduleabi.TokenPrefix)}
	}
	if strings.TrimSpace(e.Arch) == "" {
		return bad("缺少 arch（模块必须声明目标架构，架构不符会直接崩宿主）")
	}
	if strings.TrimSpace(e.OS) == "" {
		return bad("缺少 os")
	}
	return nil
}

// ValidateSHA256 校验哈希字符串格式（64 位 hex，大小写不敏感）。
func ValidateSHA256(s string) error {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return fmt.Errorf("sha256 必须是 64 位 hex（当前 %d 位：%q）", len(s), s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("sha256 含非 hex 字符：%q", s)
	}
	return nil
}

// VerifyBytes 校验模块字节是否与清单条目一致（纯函数，便于表驱动单测）。
//
// ⚠️ 哈希不符**必须拒绝**，绝不"警告后继续"：
//   - 哈希是服务端对"我要下发的就是操作员批准过的那份二进制"的唯一承诺。允许不一致
//     等于允许任何拿到模块目录写权限的人替换成任意 DLL，而控制台照样显示"已校验通过"；
//   - 植入端还会再算一次（防链路损坏），两次都硬拦，中间没有"降级放行"的口子。
func (e *Entry) VerifyBytes(raw []byte) error {
	if int64(len(raw)) != e.Size {
		return &Error{Code: CodeSizeMismatch, HTTP: 409,
			Message: fmt.Sprintf("模块 %s 大小不符：清单声明 %d 字节，实际文件 %d 字节（模块文件被替换或清单未更新；拒绝下发）",
				e.ID, e.Size, len(raw))}
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, e.SHA256) {
		return &Error{Code: CodeHashMismatch, HTTP: 409,
			Message: fmt.Sprintf("模块 %s sha256 不符：清单 %s，实际 %s（拒绝下发：哈希不符意味着字节不是被批准的那份）",
				e.ID, strings.ToLower(e.SHA256), got)}
	}
	return nil
}

// MatchArch 校验模块架构与会话（宿主植入端）架构是否一致（纯函数）。
//
// 为什么必须硬拦：反射映射只做"按宿主架构跳入口点"，不做指令集翻译；32 位模块进
// 64 位宿主（或反之）不是"执行失败"，而是**宿主进程崩溃**（会话永久掉线）。
// 这与 builder.CheckMemoryExec 的架构判定同一口径，这里是它的前置版本。
func MatchArch(moduleArch, hostArch string) error {
	ma := NormalizeArch(moduleArch)
	ha := NormalizeArch(hostArch)
	if ma == "" {
		return &Error{Code: CodeArchMismatch, HTTP: 409,
			Message: fmt.Sprintf("模块声明的架构 %q 无法识别，拒绝下发", moduleArch)}
	}
	if ha == "" {
		// 会话没上报架构（老载荷/异常注册）：不猜，直接拒绝并说明原因。
		return &Error{Code: CodeArchMismatch, HTTP: 409,
			Message: fmt.Sprintf("会话未上报可用架构（hostArch=%q），无法确认模块 %s 架构是否匹配：拒绝下发", hostArch, moduleArch)}
	}
	if ma != ha {
		return &Error{Code: CodeArchMismatch, HTTP: 409,
			Message: fmt.Sprintf("架构不符：模块是 %s，宿主植入端是 %s；反射映射不做指令集翻译，强行下发会崩宿主", ma, ha)}
	}
	return nil
}

// NormalizeArch 把常见的架构别名归一成 386 / amd64 / arm64（不认识返回 ""）。
// 归一化必须**两边同一套**，否则 "x86" 与 "386" 会被判成不符（误拦）或 "amd64" 与
// "x64" 被判成不符（误拦）—— 这类误拦会逼操作员去改清单，反而制造更松的口径。
func NormalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "386", "x86", "i386", "i486", "i586", "i686", "32", "x32":
		return "386"
	case "amd64", "x64", "x86_64", "x86-64", "64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

// MatchOS 校验模块目标 OS 与会话 OS 是否一致（纯函数）。只做 windows 判定：
// 内存模块当前只支持 Windows（反射加载器 blob_windows.go 就是 windows-only）。
func MatchOS(moduleOS, hostOS string) error {
	if !strings.Contains(strings.ToLower(moduleOS), "windows") {
		return &Error{Code: CodeOSMismatch, HTTP: 409,
			Message: fmt.Sprintf("模块声明的 os=%q 不是 windows：内存模块加载只有 Windows 实现，拒绝下发", moduleOS)}
	}
	if hostOS != "" && !strings.Contains(strings.ToLower(hostOS), "windows") {
		return &Error{Code: CodeOSMismatch, HTTP: 409,
			Message: fmt.Sprintf("会话 os=%q 与模块 os=%q 不符，拒绝下发", hostOS, moduleOS)}
	}
	return nil
}

// LoadManifestFile 从目录读取清单文件（不存在时返回空清单而不是错误：
// 没有模块目录的服务端仍然要能正常工作，只是没有可下发的模块）。
func LoadManifestFile(dir string) (*Manifest, error) {
	path := filepath.Join(dir, ManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Manifest{Version: ManifestVersion, Modules: []Entry{}}, nil
		}
		return nil, fmt.Errorf("读取模块清单 %s 失败: %w", path, err)
	}
	return ParseManifest(data)
}

// WriteManifestFile 原子写回清单（模块构建器用）。
func WriteManifestFile(dir string, m *Manifest) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	m.Version = ManifestVersion
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ManifestName+".tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ManifestName))
}

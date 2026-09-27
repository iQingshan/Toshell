// 加载前自检（BYOVD 驱动的"上机之前先看一眼"）——本文件是平台无关的骨架：
//
//  1. 数据结构：VerifyResult / SignatureStatus / BlocklistStatus；
//  2. 纯逻辑：CompareHash（比对 sha256）、BuildVerifyResult（合并结论）、
//     Summary（生成中文结论）——三者不读盘、不调用任何系统 API，单测可放心调用；
//  3. 平台相关实现分别在 verify_windows.go（WinVerifyTrust + 注册表黑名单提示）与
//     verify_other.go（非 Windows 占位）。
//
// 设计取舍：**不做任何名单内置**。服务端既不下载黑名单，也不在代码里写死任何驱动名，
// 只报告"本机黑名单策略是否启用 + 本机是否装了微软那份名单数据文件"，由内核在
// StartService 阶段做真正的裁决（被拦时报 1275 ERROR_DRIVER_BLOCKED）。
package drivers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// VerifyResult 一次加载前自检的完整结论。
//
// 字段语义（JSON 命名沿用前端既有风格，均为新增字段，不改动既有 Driver 字段）：
//   - SHA256          磁盘上（或接口上传的）驱动字节的实时 sha256；
//   - ManifestSHA256  manifest.json 里声明的期望 sha256（没声明则为空）；
//   - HashOK          两者是否一致（manifest 未声明时视为"未校验"，返回 true + 警告）；
//   - Signed          本机 Authenticode 签名校验是否通过（SignatureChecked=false 时该值无意义）；
//   - Signer          签名者简单显示名（取不到时留空，见 verify_windows.go 的取舍说明）；
//   - Blocklisted     本机是否启用了微软易受攻击驱动黑名单策略（不含名单内容）；
//   - Warnings/Errors Errors 非空 = 必须拒绝下发；Warnings 非空 = 允许下发但需提示风险。
type VerifyResult struct {
	SHA256           string   `json:"sha256"`
	ManifestSHA256   string   `json:"manifest_sha256,omitempty"`
	HashOK           bool     `json:"hash_ok"`
	Signed           bool     `json:"signed"`
	SignatureChecked bool     `json:"signature_checked"`
	Signer           string   `json:"signer,omitempty"`
	Blocklisted      bool     `json:"blocklisted"`
	BlocklistReason  string   `json:"blocklist_reason,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Errors           []string `json:"errors,omitempty"`
}

// SignatureStatus 平台层给出的签名校验结论（纯数据，便于跨平台复用与单测）。
type SignatureStatus struct {
	// Checked 是否真的执行过签名校验（非 Windows、wintrust 不可用、校验超时时为 false）。
	Checked bool
	Signed  bool
	Signer  string
	// TimedOut 本次校验是否因超时放弃（超时结论不会被缓存，下次调用会重试）。
	TimedOut bool
	Warnings []string
	Errors   []string
}

// BlocklistStatus 平台层给出的"易受攻击驱动黑名单"状态。
// Enabled 只表示**本机策略已启用**，驱动是否真的在微软名单里由内核判定，服务端不持有名单数据。
type BlocklistStatus struct {
	Enabled  bool
	Reason   string
	Warnings []string
}

// SignatureTimeout 签名校验的软超时：WinVerifyTrust 在需要下载证书链/吊销列表时可能长时间阻塞，
// 超过该上限就放弃本次结论并给出提示（不会取消已进入的系统调用，见 verify_windows.go 注释）。
const SignatureTimeout = 4 * time.Second

// CompareHash 纯逻辑：比对"实际 sha256"与"manifest 声明的期望 sha256"。
// 返回 (是否一致, 错误列表, 警告列表)。manifest 未声明期望值时不算错误，只给警告。
func CompareHash(actual, expected string) (bool, []string, []string) {
	actual = strings.ToLower(strings.TrimSpace(actual))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if actual == "" {
		return false, []string{"无法计算驱动 sha256：文件读取失败或内容为空"}, nil
	}
	if expected == "" {
		return true, nil, []string{"manifest.json 未声明该驱动的 sha256，跳过一致性校验（建议补上 sha256 字段，防止驱动被替换/损坏而无人察觉）"}
	}
	if actual != expected {
		return false, []string{fmt.Sprintf("sha256 与 manifest 不一致，可能被替换/损坏（实际 %s，manifest 声明 %s）", actual, expected)}, nil
	}
	return true, nil, nil
}

// BuildVerifyResult 纯逻辑：把"哈希比对 + 签名结论 + 黑名单状态"合并成最终判定。
// 不读盘、不调用系统 API，因此单测可以直接喂假数据覆盖各分支。
func BuildVerifyResult(actualSHA, expectedSHA, declaredSigner string, sig SignatureStatus, bl BlocklistStatus) VerifyResult {
	res := VerifyResult{
		SHA256:           strings.ToLower(strings.TrimSpace(actualSHA)),
		ManifestSHA256:   strings.ToLower(strings.TrimSpace(expectedSHA)),
		Signed:           sig.Signed,
		SignatureChecked: sig.Checked,
		Signer:           strings.TrimSpace(sig.Signer),
		Blocklisted:      bl.Enabled,
		BlocklistReason:  bl.Reason,
	}

	ok, errs, warns := CompareHash(actualSHA, expectedSHA)
	res.HashOK = ok
	res.Errors = append(res.Errors, errs...)
	res.Warnings = append(res.Warnings, warns...)

	res.Warnings = append(res.Warnings, sig.Warnings...)
	res.Errors = append(res.Errors, sig.Errors...)
	if sig.Checked && !sig.Signed {
		res.Warnings = append(res.Warnings, "驱动未通过 Authenticode 签名校验：开启签名强制/CI 策略的内核会拒绝加载，杀软也常按「无签名驱动」告警")
	}
	if sig.Signer != "" && declaredSigner != "" && !signerMatches(declaredSigner, sig.Signer) {
		res.Warnings = append(res.Warnings, fmt.Sprintf("manifest 声明的签名者 %q 与本机实测 %q 不一致，请人工核对驱动来源", declaredSigner, sig.Signer))
	}
	res.Warnings = append(res.Warnings, bl.Warnings...)
	return res
}

// signerMatches 纯逻辑：manifest 里的 signed 字段是人工标注（常写简称，如 "Microsoft"），
// 因此双向包含即视为一致，避免因写法差异产生噪声警告。
func signerMatches(declared, measured string) bool {
	d := strings.ToLower(strings.TrimSpace(declared))
	m := strings.ToLower(strings.TrimSpace(measured))
	if d == "" || m == "" {
		return true
	}
	return strings.Contains(m, d) || strings.Contains(d, m)
}

// Summary 生成一句话中文结论，供日志与前端直接展示。
func (r VerifyResult) Summary() string {
	if len(r.Errors) > 0 {
		return "自检未通过：" + strings.Join(r.Errors, "；")
	}
	if len(r.Warnings) > 0 {
		return "自检存在风险（允许加载）：" + strings.Join(r.Warnings, "；")
	}
	if !r.SignatureChecked {
		return "自检完成：sha256 一致，签名状态未校验"
	}
	if r.Signed {
		if r.Signer != "" {
			return "自检通过：sha256 一致，签名有效（" + r.Signer + "）"
		}
		return "自检通过：sha256 一致，签名有效"
	}
	return "自检完成：sha256 一致"
}

// Verify 统一的加载前自检入口：对磁盘上的驱动文件做完整校验。
// 非 Windows 平台直接返回占位结论（见 verify_other.go），不读盘。
func Verify(path string) VerifyResult {
	if !platformSupported {
		return VerifyResult{Warnings: []string{"非 Windows 平台不做驱动自检"}}
	}
	if strings.TrimSpace(path) == "" {
		return VerifyResult{Errors: []string{"驱动路径为空，无法自检"}}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return VerifyResult{Errors: []string{fmt.Sprintf("无法读取驱动文件 %s：%v", path, err)}}
	}
	expected, declared := manifestExpectedFor(path)
	return verifyWithRaw(path, raw, expected, declared)
}

// SelfCheckSupported 本平台是否真的能执行驱动加载前自检（Authenticode 签名校验）。
//
// 为什么要把它导出来：调用方（以及单测）必须能区分两种截然不同的结论 ——
//   - "自检跑过了，没发现问题"；
//   - "**自检根本没跑**（无 WinVerifyTrust 的平台），只给了占位警告"。
//
// 前者可以放行，后者只是"我们无法判断"。把两者混成同一个 `VerifyResult`（都只有 Warnings）
// 会让"在 Linux 上托管的控制端"看起来和 Windows 一样安全 —— 这类"看起来验过了"的哑判定
// 正是 CI 上暴露出来的那次回归（`profile_test.go` 与 byovd_load 的自检用例假设了
// `verifyWithRaw`/`VerifyBytes` 一定会调用签名校验）。
//
// 当前实现：Windows = true（走 WinVerifyTrust）；其它平台 = false（见 verify_other.go）。
// 注意它**不改**放行策略（非 Windows 上仍是"给警告后允许加载"），只把事实暴露出来。
func SelfCheckSupported() bool { return platformSupported }

// verifyWithRaw 用**已读入内存**的驱动字节做自检（List() 已经读过一次，避免二次全文件读取）。
// expectedSHA / declaredSigner 由调用方从 manifest 里取出，同样避免重复解析 manifest.json。
func verifyWithRaw(path string, raw []byte, expectedSHA, declaredSigner string) VerifyResult {
	if !platformSupported {
		return VerifyResult{Warnings: []string{"非 Windows 平台不做驱动自检"}}
	}
	if raw == nil {
		return VerifyResult{Errors: []string{fmt.Sprintf("无法读取驱动文件 %s：内容为空", path)}}
	}
	actual := sha256Hex(raw)
	sig := cachedSignature(path, actual, raw)
	bl := platformBlocklist()
	return BuildVerifyResult(actual, expectedSHA, declaredSigner, sig, bl)
}

// VerifyBytes 校验**接口上传的驱动字节**（byovd_load 的 driver_b64 解码结果）。
//
// 难点：WinVerifyTrust 只能校验磁盘文件，无法校验内存里的字节。因此这里先在服务端
// 驱动目录里找同名驱动：
//   - 找到且 sha256 与上传内容完全一致 → 复用该文件的签名结论（内容一致，结论等价）；
//   - 找到但 sha256 不同 → 不做签名校验并给出警告（上传的不是本地那份，结论不可复用）；
//   - 没找到 → 不做签名校验并给出警告，提示操作员自行确认来源。
//
// manifest 声明的期望 sha256 与上传内容的比对，是这条路径上唯一能硬拦"被替换/损坏"的检查。
func VerifyBytes(name string, raw []byte) VerifyResult {
	if !platformSupported {
		return VerifyResult{Warnings: []string{"非 Windows 平台不做驱动自检"}}
	}
	if raw == nil {
		return VerifyResult{Errors: []string{"驱动内容为空，无法自检"}}
	}
	actual := sha256Hex(raw)
	diskPath, expected, declared := lookupDriver(name)

	var sig SignatureStatus
	switch {
	case diskPath == "":
		sig = SignatureStatus{Warnings: []string{"服务端驱动目录里没有同名驱动，无法对上传内容做签名校验（WinVerifyTrust 只能校验磁盘文件）；请自行确认它是来源合法的已签名驱动"}}
	default:
		diskRaw, err := os.ReadFile(diskPath)
		if err != nil {
			sig = SignatureStatus{Warnings: []string{fmt.Sprintf("无法读取同名驱动 %s 做签名校验：%v", diskPath, err)}}
			break
		}
		diskSHA := sha256Hex(diskRaw)
		if diskSHA != actual {
			sig = SignatureStatus{Warnings: []string{fmt.Sprintf("上传的驱动与 %s 的同名文件 sha256 不同，无法复用其签名结论；请确认上传的确实是预期的已签名驱动", diskPath)}}
			break
		}
		// 内容一致：对该磁盘文件做的签名结论对上传字节同样成立。
		sig = cachedSignature(diskPath, diskSHA, diskRaw)
	}

	bl := platformBlocklist()
	return BuildVerifyResult(actual, expected, declared, sig, bl)
}

// manifestExpectedFor 读取 path 同目录 manifest.json 里该文件的期望 sha256 与声明的签名者。
func manifestExpectedFor(path string) (string, string) {
	return manifestExpectedIn(filepath.Dir(path), filepath.Base(path))
}

// manifestExpectedIn 在 dir/manifest.json 里按文件名或驱动名查找声明。
func manifestExpectedIn(dir, fileName string) (string, string) {
	m := readManifest(dir)
	base := strings.ToLower(strings.TrimSpace(fileName))
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	for _, e := range m.Drivers {
		f := strings.ToLower(strings.TrimSpace(e.File))
		n := strings.ToLower(strings.TrimSpace(e.Name))
		if f == base || (n != "" && n == stem) || (f != "" && strings.TrimSuffix(f, filepath.Ext(f)) == stem) {
			return strings.TrimSpace(e.SHA256), e.Signed
		}
	}
	return "", ""
}

// lookupDriver 按名称（驱动名或文件名）在驱动目录里定位文件，并返回 manifest 声明的期望 sha256 与签名者。
// 只做 stat/解析 manifest，不读 .sys 内容（内容由调用方按需读一次）。
func lookupDriver(name string) (path, expectedSHA, declaredSigner string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", ""
	}
	for _, dir := range SearchDirs() {
		m := readManifest(dir)
		// 1) manifest 里声明的 file/name 命中
		for _, e := range m.Drivers {
			file := strings.TrimSpace(e.File)
			if file == "" {
				continue
			}
			stem := strings.TrimSuffix(file, filepath.Ext(file))
			if !strings.EqualFold(file, name) && !strings.EqualFold(stem, name) &&
				(e.Name == "" || !strings.EqualFold(strings.TrimSpace(e.Name), name)) {
				continue
			}
			p := filepath.Join(dir, file)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, strings.TrimSpace(e.SHA256), e.Signed
			}
		}
		// 2) 直接按文件名命中（name / name.sys）
		for _, cand := range []string{name, name + ".sys"} {
			if !strings.EqualFold(filepath.Ext(cand), ".sys") {
				continue
			}
			p := filepath.Join(dir, cand)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				exp, signer := manifestExpectedIn(dir, filepath.Base(p))
				return p, exp, signer
			}
		}
	}
	return "", "", ""
}

// sha256Hex 计算十六进制小写 sha256。
func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// 签名结论缓存：同一路径 + 同一内容（sha256）只调用一次 WinVerifyTrust。
// 这样 List() 每次都带自检结果也不会反复验签；超时结论不入缓存，下次请求会重试。
const sigCacheLimit = 128

// signatureCheck 是 platformSignature 的间接层：单测里可替换为桩函数，
// 避免 go test 真的去跑 WinVerifyTrust（那会依赖本机证书链与联网吊销检查）。
var signatureCheck = platformSignature

var (
	sigCacheMu sync.Mutex
	sigCache   = map[string]SignatureStatus{}
)

func cachedSignature(path, sha string, raw []byte) SignatureStatus {
	key := strings.ToLower(path) + "|" + strings.ToLower(sha)
	sigCacheMu.Lock()
	if s, ok := sigCache[key]; ok {
		sigCacheMu.Unlock()
		return s
	}
	sigCacheMu.Unlock()

	s := signatureCheck(path, raw)
	if s.TimedOut {
		return s
	}
	sigCacheMu.Lock()
	if len(sigCache) >= sigCacheLimit {
		sigCache = map[string]SignatureStatus{} // 简单粗暴地整体清空，避免无界增长
	}
	sigCache[key] = s
	sigCacheMu.Unlock()
	return s
}

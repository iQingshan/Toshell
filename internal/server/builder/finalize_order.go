package builder

import (
	"fmt"
	"strings"

	"toshell/internal/server/logging"
)

// ─── 交付流水线的"字节加工顺序"契约（v1.4.0 S3 / 计划 §3 D3）─────────────────
//
// 要防的是什么：**白签**（signed=true 但签名其实已失效）。
// 代码签名覆盖的是"签名那一刻的字节"；签名之后再改一个字节（UPX 压缩、PE 资源/图标/
// 版本信息修补、字符串擦除、文本编码）都会让签名失效。而复核（sign.go 的
// verifyWithPowerShell）发生在签名之后、后处理之前，所以白签**从接口上看仍然是
// signed=true**，极难排查 —— 只能靠把顺序写成唯一一份可断言的契约。
//
// 约定（新增任何"改字节"的步骤时照做）：
//  1. 步骤名登记在下面的常量里，并按实际执行顺序出现在 finalizeSteps 的返回里；
//  2. StepSign 必须且只能是最后一个（signOrderWarning 会在运行时拦截）；
//  3. 新增的 PE 资源/图标/版本信息/时间戳修补必须排在 StepUPX 与 StepSign **之前**
//     （UPX 之后再补资源等于把压缩结果改坏；签名之后再动就是白签）。
//
// 这份顺序与 ROADMAP/docs/EVASION.md 的 §"静态降特征"、§"签名顺序约束"一致。
const (
	// StepScrubFingerprint Go 构建期指纹（buildinfo 魔数 / Go build ID / 锚定窗口内版本串）。
	StepScrubFingerprint = "scrub_fingerprint"
	// StepScrubVersion 全文件 Go 版本串（runtime.buildVersion，锚定窗口扫不到的那一份）。
	StepScrubVersion = "scrub_version_string"
	// StepUPX UPX 压缩（仅 Windows exe/bin 且 UPX 可用且开启）。
	StepUPX = "upx"
	// StepEncodeText shellcode 类格式的文本化（hex / base64 交付物）。
	StepEncodeText = "encode_text"
	// StepSign 代码签名。**必须是最后一步**。
	StepSign = "sign"
)

// finalizeSteps 返回本次构建中"会改动交付字节"的步骤名（按执行顺序）。
//
// 纯函数：只看入参，不做 IO —— 这样顺序契约能在 CI 里被表驱动地钉住，
// 而不是靠人读 builder.go 的调用顺序。
//
//	language="c"（mingw C 植入端）→ 没有 Go 运行时指纹可擦
//	format=shellcode/shellcode_bin → 交付物是文本/原始字节，不是 PE，不签名
//	其余 Windows PE 格式（exe/bin/dll/raw）→ 可能签名
func finalizeSteps(language, targetOS, format string, upxEnabled, signEnabled bool) []string {
	steps := make([]string, 0, 5)
	if language != "c" {
		steps = append(steps, StepScrubFingerprint, StepScrubVersion)
	}
	if upxEnabled {
		steps = append(steps, StepUPX)
	}
	if isTextEncodedFormat(format) {
		steps = append(steps, StepEncodeText)
	}
	if signEnabled && isSignableFormat(targetOS, format) {
		steps = append(steps, StepSign)
	}
	return steps
}

// isTextEncodedFormat 交付物是否由"二进制 → 文本"编码而来（编码会改字节，签名无意义）。
func isTextEncodedFormat(format string) bool {
	switch strings.ToLower(format) {
	case "shellcode", "shellcode_bin", "shellcode_hex":
		return true
	default:
		return false
	}
}

// isSignableFormat 该平台/格式是否会走代码签名（与 sign.go 的 signIfNeeded 口径一致：
// 必须是 Windows 上的 PE 类交付物；shellcode 类格式即便 MZ 开头也不签）。
func isSignableFormat(targetOS, format string) bool {
	os := strings.ToLower(strings.TrimSpace(targetOS))
	if os == "" {
		os = "windows" // 与 Build 里的默认目标平台一致
	}
	if os != "windows" {
		return false
	}
	return !isTextEncodedFormat(format)
}

// signOrderWarning 校验"签名必须是最后一步"，违反时返回中文告警（空串=顺序正确）。
//
// 这是运行时的兜底：将来有人把资源修补/加壳挪到签名之后，构建日志里会直接出现
// error 级别告警，而不是等到目标机上发现"签名载荷被拦"再回头排查。
func signOrderWarning(steps []string) string {
	signAt := -1
	for i, s := range steps {
		if s == StepSign {
			signAt = i
			break
		}
	}
	if signAt < 0 {
		return "" // 不签名就没有白签风险
	}
	if signAt == len(steps)-1 {
		return ""
	}
	return fmt.Sprintf("构建流水线顺序被改坏：签名（%s）之后仍有会改动字节的步骤 %v —— "+
		"签名后再改一个字节都会让签名失效（白签，接口仍显示 signed=true）。"+
		"请把新增步骤插到签名与 UPX 之前（约定见 finalize_order.go 顶部注释）。",
		StepSign, steps[signAt+1:])
}

// finalizePipelineSteps 解析本次构建实际生效的步骤（把配置/工具可用性合并进来）。
func (b *Builder) finalizePipelineSteps(opts BuildOptions, targetOS string) []string {
	upx := b.useUPX && opts.UPXEnable && targetOS == "windows" &&
		(opts.Format == "exe" || opts.Format == "bin")
	return finalizeSteps(opts.Language, targetOS, opts.Format, upx, ResolveSignConfig(opts.SignEnabled).Enabled)
}

// logFinalizePipeline 构建开始时打印一次交付流水线，并在顺序被改坏时打 error。
func (b *Builder) logFinalizePipeline(opts BuildOptions, targetOS string) {
	steps := b.finalizePipelineSteps(opts, targetOS)
	if len(steps) == 0 {
		return
	}
	logging.Info("builder", "交付流水线（字节加工顺序，签名必须是最后一步）：%s", strings.Join(steps, " → "))
	if warn := signOrderWarning(steps); warn != "" {
		logging.Error("builder", "%s", warn)
	}
}

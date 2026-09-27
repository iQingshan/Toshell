package builder

import (
	"strings"
	"testing"
)

// ─── 顺序契约：签名必须是最后一步（计划 §3 D3，防"白签"）────────────────────
//
// 这些用例是纯函数级的，不编译任何载荷、不签名、不需要证书，因此 CI 必跑。
// 契约的动机见 finalize_order.go 顶部注释：签名后再改一个字节都会让签名失效，
// 而接口仍会显示 signed=true（复核发生在签名之后、后处理之前），极难排查。

// TestFinalizeStepsSignIsLast 遍历"平台 × 格式 × 开关"的组合，断言不变量：
// **只要出现 sign，它就必须是最后一个步骤**。
func TestFinalizeStepsSignIsLast(t *testing.T) {
	languages := []string{"go", "c"}
	targetOSes := []string{"windows", "linux", "darwin", ""}
	formats := []string{"exe", "bin", "dll", "raw", "shellcode", "shellcode_bin", "so"}
	for _, lang := range languages {
		for _, os := range targetOSes {
			for _, format := range formats {
				for _, res := range []bool{false, true} {
					for _, upx := range []bool{false, true} {
						for _, sign := range []bool{false, true} {
							steps := finalizeSteps(lang, os, format, res, upx, sign)
							warn := signOrderWarning(steps)
							if warn != "" {
								t.Fatalf("顺序契约被违反：lang=%s os=%s format=%s res=%v upx=%v sign=%v steps=%v → %s",
									lang, os, format, res, upx, sign, steps, warn)
							}
							if !sign {
								continue
							}
							if !isSignableFormat(os, format) {
								continue
							}
							if len(steps) == 0 || steps[len(steps)-1] != StepSign {
								t.Fatalf("可签名的组合里 sign 必须是最后一步：lang=%s os=%s format=%s steps=%v",
									lang, os, format, steps)
							}
							// 资源修补（v1.4.0 S3 第二批）：只要出现，就必须排在 upx 与 sign 之前。
							if res {
								if !containsStep(steps, StepResourcePatch) {
									t.Fatalf("res=true 时步骤里必须有 %s：steps=%v", StepResourcePatch, steps)
								}
								if idxStep(steps, StepResourcePatch) > idxStep(steps, StepSign) {
									t.Fatalf("%s 必须排在 %s 之前（签名之后再改字节=白签）：steps=%v",
										StepResourcePatch, StepSign, steps)
								}
								if containsStep(steps, StepUPX) && idxStep(steps, StepResourcePatch) > idxStep(steps, StepUPX) {
									t.Fatalf("%s 必须排在 %s 之前（UPX 之后再补资源会压坏/被压坏）：steps=%v",
										StepResourcePatch, StepUPX, steps)
								}
							}
						}
					}
				}
			}
		}
	}
}

// TestFinalizeStepsOrderWindowsExe 固定一个"全开"组合，钉住具体顺序：
// 指纹擦除 → 版本串擦除 → 资源修补 → UPX → 签名
// （UPX 必须在签名之前，否则压缩会破坏签名；资源修补必须在 UPX 与签名之前，
// 顺序理由见 finalize_order.go 与 patch_resources.go 顶部注释）。
func TestFinalizeStepsOrderWindowsExe(t *testing.T) {
	got := finalizeSteps("go", "windows", "exe", true, true, true)
	want := []string{StepScrubFingerprint, StepScrubVersion, StepResourcePatch, StepUPX, StepSign}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("windows exe 全开顺序 = %v, want %v", got, want)
	}
	// 不开资源时不能凭空多出 pe_resource_patch（它只应在"本次构建真的要打资源"时出现）。
	gotNoRes := finalizeSteps("go", "windows", "exe", false, true, true)
	wantNoRes := []string{StepScrubFingerprint, StepScrubVersion, StepUPX, StepSign}
	if strings.Join(gotNoRes, ",") != strings.Join(wantNoRes, ",") {
		t.Fatalf("未开资源时顺序 = %v, want %v", gotNoRes, wantNoRes)
	}
}

// TestShouldPatchResourcesFormatGate 资源修补只对"按 PE 交付的 Windows 格式"生效：
// shellcode / raw / so / 非 Windows 目标 / C 植入端一律跳过（原因见 shouldPatchResources 注释）。
func TestShouldPatchResourcesFormatGate(t *testing.T) {
	// 一组"确实要求打资源"的选项。
	full := func(format, lang string) BuildOptions {
		return BuildOptions{
			Format: format, Language: lang,
			ResourceCompanyName: "示例科技（授权红队测试）",
			ResourceFileVersion: "1.4.0.0",
			ResourceIconPath:    `C:\icons\app.ico`,
		}
	}
	yes := []struct {
		format, lang string
	}{
		{"exe", "go"}, {"bin", "go"}, {"dll", "go"},
	}
	for _, c := range yes {
		opts := full(c.format, c.lang)
		if !shouldPatchResources(&opts, "windows") {
			t.Errorf("format=%s language=%s 应当打资源", c.format, c.lang)
		}
	}
	no := []struct {
		format, lang, os string
	}{
		{"shellcode", "go", "windows"},     // 文本/裸字节交付，资源会被 donut 转成垃圾
		{"shellcode_bin", "go", "windows"}, // 同上
		{"raw", "go", "windows"},           // 不按 PE 交付
		{"so", "go", "windows"},            // 不是 Windows PE
		{"exe", "go", "linux"},             // ELF 没有 .rsrc
		{"bin", "go", "darwin"},            // Mach-O 没有 .rsrc
		{"exe", "c", "windows"},            // C 植入端走独立管线，本次未接入（见注释）
	}
	for _, c := range no {
		opts := full(c.format, c.lang)
		if shouldPatchResources(&opts, c.os) {
			t.Errorf("format=%s language=%s os=%s 不应打资源", c.format, c.lang, c.os)
		}
	}
	// 零值（默认档）必须完全不触发：这是"默认零行为变化"的第一道断言。
	if shouldPatchResources(&BuildOptions{Format: "exe", Language: "go", OS: "windows"}, "windows") {
		t.Fatal("默认档（未配置任何资源字段）绝不能触发资源修补")
	}
}

// TestFinalizeStepsNonPEFormatsNotSigned shellcode 类交付物是文本/原始字节，不该出现签名步骤。
func TestFinalizeStepsNonPEFormatsNotSigned(t *testing.T) {
	for _, format := range []string{"shellcode", "shellcode_bin"} {
		steps := finalizeSteps("go", "windows", format, false, false, true)
		for _, s := range steps {
			if s == StepSign {
				t.Fatalf("format=%s 不应有签名步骤：%v", format, steps)
			}
		}
		if !containsStep(steps, StepEncodeText) {
			t.Fatalf("format=%s 应有文本编码步骤：%v", format, steps)
		}
	}
}

// TestFinalizeStepsLinuxNotSigned 非 Windows 目标不签名（签名栈只在 Windows 上）。
func TestFinalizeStepsLinuxNotSigned(t *testing.T) {
	steps := finalizeSteps("go", "linux", "exe", false, false, true)
	if containsStep(steps, StepSign) {
		t.Fatalf("linux 产物不应有签名步骤：%v", steps)
	}
}

// TestFinalizeStepsCImplantSkipsGoScrub C 植入端（mingw，无 Go 运行时）不该报"Go 指纹擦除"步骤。
func TestFinalizeStepsCImplantSkipsGoScrub(t *testing.T) {
	steps := finalizeSteps("c", "windows", "exe", false, false, true)
	for _, s := range steps {
		if s == StepScrubFingerprint || s == StepScrubVersion {
			t.Fatalf("C 植入端不该有 Go 指纹擦除步骤：%v", steps)
		}
	}
	if !containsStep(steps, StepSign) {
		t.Fatalf("C 植入端是 Windows PE，签名开启时应有 sign：%v", steps)
	}
}

// TestSignOrderWarningDetectsViolation 守卫本身要能抓到"签名之后还有改字节的步骤"：
// 这里模拟将来有人把 PE 资源修补/加壳挪到签名之后。
func TestSignOrderWarningDetectsViolation(t *testing.T) {
	ok := []string{StepScrubFingerprint, StepUPX, StepSign}
	if w := signOrderWarning(ok); w != "" {
		t.Fatalf("正确顺序被误报：%s", w)
	}
	bad := []string{StepScrubFingerprint, StepSign, "pe_resource_patch"}
	w := signOrderWarning(bad)
	if w == "" {
		t.Fatal("签名之后还有字节加工步骤时必须告警（否则就是白签）")
	}
	if !strings.Contains(w, "pe_resource_patch") {
		t.Fatalf("告警应点名违规步骤，实际：%s", w)
	}
	// 不签名 → 无风险，不该告警
	if w := signOrderWarning([]string{StepScrubFingerprint, StepUPX}); w != "" {
		t.Fatalf("不签名时不该告警：%s", w)
	}
}

func containsStep(steps []string, want string) bool {
	return idxStep(steps, want) >= 0
}

// idxStep 返回步骤在流水线里的下标（-1 = 不存在），用于断言相对顺序。
func idxStep(steps []string, want string) int {
	for i, s := range steps {
		if s == want {
			return i
		}
	}
	return -1
}

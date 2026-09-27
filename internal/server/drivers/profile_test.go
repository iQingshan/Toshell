package drivers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDriverDir 在临时目录里铺一个 drivers/ 目录并切到该目录：
// SearchDirs() 会扫 CWD/drivers 与 data/drivers，切目录是为了不受仓库真实驱动目录影响
// （与 verify_test.go 的 TestListCarriesVerify 同一手法）。
func writeDriverDir(t *testing.T, manifest string, files ...string) {
	t.Helper()
	// 自检里的 Authenticode 校验会真的等本机证书链（SignatureTimeout=4s/文件，且超时结论
	// 不入缓存），既慢又与用例目标无关 —— 换成桩函数（同一手法见 verify_test.go）。
	old := signatureCheck
	signatureCheck = func(string, []byte) SignatureStatus {
		return SignatureStatus{Checked: true, Signed: false}
	}
	t.Cleanup(func() { signatureCheck = old })

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	if err := os.MkdirAll(filepath.Join(dir, "drivers"), 0o700); err != nil {
		t.Fatalf("建目录: %v", err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, "drivers", f), []byte("fake-sys-"+f), 0o600); err != nil {
			t.Fatalf("写入 %s: %v", f, err)
		}
	}
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "drivers", "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatalf("写入 manifest: %v", err)
		}
	}
}

// TestSummarySelectsByPurpose 钉住 purpose 分档的选路口径（v1.4.0 S6 的 L3 前置检查依赖它）：
//
//	kill  → 只被 Kill 选中（rw 不选）；
//	rw    → 只被 RW 选中（Kill 不选：PPL 清除要的是内核读写，不是终止 IOCTL）；
//	both  → 两者都选中（ROADMAP P0-1 声明的第三档）；
//	device/ioctl 缺失的 kill 档 → Kill 不选（选了也发不出终止 IOCTL）。
func TestSummarySelectsByPurpose(t *testing.T) {
	writeDriverDir(t, `{"drivers":[
		{"file":"killer.sys","name":"killer","purpose":"kill","device":"\\\\.\\killer","ioctl":"0x222048"},
		{"file":"rwdrv.sys","name":"rwdrv","purpose":"rw"},
		{"file":"bothdrv.sys","name":"bothdrv","purpose":"both","device":"\\\\.\\both","ioctl":"0x222049"},
		{"file":"vague.sys","name":"vague","purpose":"kill"}
	]}`, "killer.sys", "rwdrv.sys", "bothdrv.sys", "vague.sys")

	sum := Summary()
	if sum.Total != 4 {
		t.Fatalf("Total = %d, want 4（目录里 4 个 .sys）", sum.Total)
	}
	if sum.Kill == nil {
		t.Fatal("Kill 档应命中（killer 或 bothdrv）")
	}
	if sum.Kill.Name != "bothdrv" && sum.Kill.Name != "killer" {
		t.Fatalf("Kill = %q, want killer/bothdrv", sum.Kill.Name)
	}
	if sum.Kill.Name == "vague" {
		t.Fatal("device/ioctl 缺失的 kill 档驱动不应被 Kill 选中")
	}
	if sum.RW == nil {
		t.Fatal("RW 档应命中（rwdrv 或 bothdrv）")
	}
	if sum.RW.Name != "rwdrv" && sum.RW.Name != "bothdrv" {
		t.Fatalf("RW = %q, want rwdrv/bothdrv", sum.RW.Name)
	}
	// Purposes 去重排序（前端据此提示"你放的驱动没写 purpose"）
	if len(sum.Purposes) != 3 {
		t.Fatalf("Purposes = %v, want 3 个档位", sum.Purposes)
	}
	for i := 1; i < len(sum.Purposes); i++ {
		if sum.Purposes[i-1] >= sum.Purposes[i] {
			t.Fatalf("Purposes 未排序去重：%v", sum.Purposes)
		}
	}
	if len(sum.SearchDirs) == 0 {
		t.Fatal("SearchDirs 应非空（排障要告诉操作员把 .sys 放哪）")
	}
}

// TestSummaryCheapPathDoesNotVerify 守护 Summary 的"便宜路径"契约：
// 它必须**不读驱动字节、不算 sha256、不跑签名校验**。
// 用桩函数统计调用次数：Summary 调用前后计数必须不变。
//
// 为什么必须钉住：这个端点会被前端每次刷新页面调用，一旦有人把它改成走 List()，
// 在有 N 个驱动的机器上最坏要 N×4 秒（SignatureTimeout 超时结论不入缓存），
// 直接撞爆 HTTP 写超时 —— 这种回归只有计数断言拦得住。
func TestSummaryCheapPathDoesNotVerify(t *testing.T) {
	writeDriverDir(t, `{"drivers":[{"file":"a.sys","name":"a","purpose":"rw"}]}`, "a.sys")

	calls := 0
	old := signatureCheck
	signatureCheck = func(string, []byte) SignatureStatus {
		calls++
		return SignatureStatus{Checked: true}
	}
	t.Cleanup(func() { signatureCheck = old })

	sum := Summary()
	if calls != 0 {
		t.Fatalf("Summary 触发了 %d 次签名校验，应走便宜路径（不验签、不算哈希）", calls)
	}
	if sum.RW == nil || sum.RW.Name != "a" {
		t.Fatalf("便宜路径仍必须给出档位结论，实际 RW=%v", sum.RW)
	}
	if sum.RW.SHA256 != "" || sum.RW.Verify != nil {
		t.Fatalf("便宜路径不应填 SHA256/Verify（那是 List 的职责）：%+v", sum.RW)
	}
	// List 仍然照旧做完整自检（既有语义不变）
	if !SelfCheckSupported() {
		// 非 Windows 平台：verifyWithRaw 会**短路**（"非 Windows 平台不做驱动自检"），
		// 签名校验这条路径本身不存在，所以"调用计数 > 0"这个断言在这里无法成立。
		// 但不能因此什么都不测：仍要断言 List() **仍然走自检入口**并给出占位结论
		// （将来有人把 List 改成"跳过整段自检"就会被这里拦住）。
		// 这次是 CI（Linux）先抓到的 —— 本机是 Windows，计数断言照过。
		lst := List()
		if len(lst) == 0 || lst[0].Verify == nil {
			t.Fatalf("List() 必须仍然带自检结论，实际 %+v", lst)
		}
		if !strings.Contains(strings.Join(lst[0].Verify.Warnings, "；"), "非 Windows") {
			t.Fatalf("非 Windows 平台应有「不做驱动自检」的占位警告，实际 %+v", *lst[0].Verify)
		}
		return
	}
	if calls == 0 {
		_ = List()
	}
	if calls == 0 {
		t.Fatal("List 必须仍然做签名自检（便宜路径不能把既有自检挤掉）")
	}
}

// TestSummaryWithoutDrivers 没有对应档位驱动时必须为 nil ——
// 这是 L3 前置检查"无 rw 档驱动，不可用"的数据来源，不能"猜一个默认值"。
func TestSummaryWithoutDrivers(t *testing.T) {
	// 只有 kill 档
	writeDriverDir(t, `{"drivers":[{"file":"killer.sys","name":"killer","purpose":"kill","device":"\\\\.\\killer","ioctl":"0x222048"}]}`, "killer.sys")
	sum := Summary()
	if sum.RW != nil {
		t.Fatalf("只有 kill 档驱动时 RW 不应命中，实际 %q", sum.RW.Name)
	}
	if sum.Kill == nil {
		t.Fatal("kill 档驱动齐全时 Kill 应命中")
	}

	// 只有 rw 档
	writeDriverDir(t, `{"drivers":[{"file":"rwdrv.sys","name":"rwdrv","purpose":"rw"}]}`, "rwdrv.sys")
	sum = Summary()
	if sum.RW == nil {
		t.Fatal("rw 档驱动存在时 RW 应命中")
	}
	if sum.Kill != nil {
		t.Fatalf("只有 rw 档驱动时 Kill 不应命中，实际 %q", sum.Kill.Name)
	}
	if _, ok := KillProfile(); ok {
		t.Fatal("只有 rw 档驱动时既有 KillProfile 也不应命中")
	}

	// 空目录
	writeDriverDir(t, "")
	sum = Summary()
	if sum.Total != 0 || sum.Kill != nil || sum.RW != nil {
		t.Fatalf("空目录应给出零值摘要，实际 %+v", sum)
	}
}

package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toshell/internal/server/config"
)

// 构建标签直接决定哪些免杀/对抗代码进入载荷，改错很难在功能测试里暴露，
// 因此固定行为：**默认既不带 evasionscan（主动反沙箱进程检测）也不带 bof（Beacon API 面）**。
func TestBuildTagList(t *testing.T) {
	cases := []struct {
		transport   string
		profile     string
		evasionScan bool
		bof         bool
		want        string
	}{
		{"tcp", "full", false, false, ""},
		{"tcp", "full", true, false, "evasionscan"},
		{"tcp", "full", false, true, "bof"},
		{"tcp", "full", true, true, "evasionscan bof"},
		{"http", "full", false, false, "transport_http"},
		{"http", "full", true, false, "transport_http evasionscan"},
		{"http", "light", false, false, "transport_http light"},
		{"websocket", "light", true, true, "transport_ws light evasionscan bof"},
		{"mqtt", "full", false, false, "transport_mqtt"},
	}
	for _, c := range cases {
		if got := buildTagList(c.transport, c.profile, c.evasionScan, c.bof, false); got != c.want {
			t.Errorf("buildTagList(%q,%q,%v,%v) = %q, want %q", c.transport, c.profile, c.evasionScan, c.bof, got, c.want)
		}
	}
	// 默认载荷（不勾选任何免杀选项）绝不能带 evasionscan / bof / execmodule。
	def := buildTagList("tcp", "full", false, false, false)
	if strings.Contains(def, "evasionscan") {
		t.Fatal("default build must not include evasionscan")
	}
	if strings.Contains(def, "bof") {
		t.Fatal("default build must not include bof (Beacon API 面默认不进载荷)")
	}
	// v1.4.0 S4：exec_module 同样是显式勾选项，默认载荷里不能有这条能力路径。
	if strings.Contains(def, "execmodule") {
		t.Fatal("default build must not include execmodule (内存模块能力默认不进载荷)")
	}
	if got := buildTagList("tcp", "light", false, false, true); got != "light execmodule" {
		t.Fatalf("buildTagList(tcp,light,...,execmodule=true) = %q, want %q（light 档也能按需加载模块，这是 S4 的核心价值）", got, "light execmodule")
	}
}

// BOF 支持必须由构建标签门控：默认实现（bof_stub_windows.go）不得包含任何 Beacon API 名字，
// 真实实现（bof_windows.go）必须只在 -tags bof 时编译。
func TestBOFIsOptIn(t *testing.T) {
	dir := "implant"
	realSrc, err := os.ReadFile(filepath.Join(dir, "bof_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(realSrc), "//go:build windows && !light && bof") {
		t.Error("bof_windows.go must be gated behind the bof tag")
	}
	stubSrc, err := os.ReadFile(filepath.Join(dir, "bof_stub_windows.go"))
	if err != nil {
		t.Fatalf("缺 bof_stub_windows.go：%v", err)
	}
	if !strings.Contains(string(stubSrc), "//go:build windows && !light && !bof") {
		t.Error("bof_stub_windows.go must be the default (no bof tag) implementation")
	}
	// 默认实现里不能出现任何 Beacon API 符号（否则静态特征又回来了）。
	// 注意要看"去掉注释后的代码"：stub 的文档注释里会解释为什么这些名字不能带，
	// 注释里出现名字是正常的（也不进二进制）。
	stubCode := stripLineComments(string(stubSrc))
	for _, bad := range []string{"BeaconDataParse", "BeaconOutput", "beaconAPI", "BeaconPrintf", "beaconState"} {
		if strings.Contains(stubCode, bad) {
			t.Errorf("默认 BOF stub 的代码里不应包含 %q（那是真实 BOF 兼容层的符号）", bad)
		}
	}
	if !strings.Contains(string(stubSrc), "func loadBOF(") {
		t.Error("bof_stub_windows.go 必须提供 loadBOF（main.go 的两处调用依赖它）")
	}
}

// 启动随机延迟必须真的被渲染进 main.go（模板占位符 {{STARTUP_DELAY_MIN/MAX}}）。
// 历史问题：Web 端 BuildRequest 里声明了 startup_delay_min/max，服务端结构体却没有
// 这两个字段 → 请求里的值被静默丢弃，只能吃服务端配置（表现为"随机延迟上线配置无效"）。
func TestProcessTemplatesRendersStartupDelay(t *testing.T) {
	tmpDir := t.TempDir()
	tmpl := config.ImplantConfig{TemplateDir: "implant"}
	if err := newBuilder(&tmpl).copyImplantSource(tmpDir, "windows"); err != nil {
		t.Fatalf("copyImplantSource: %v", err)
	}

	opts := BuildOptions{
		OS: "windows", Arch: "amd64", Format: "exe", Protocol: "tcp",
		StartDelayMin: 37, StartDelayMax: 91,
	}
	b := newBuilder(&tmpl)
	if err := b.processTemplates(tmpDir, opts); err != nil {
		t.Fatalf("processTemplates: %v", err)
	}

	src, err := os.ReadFile(filepath.Join(tmpDir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	content := string(src)
	if !strings.Contains(content, "startupDelayMin = 37") {
		t.Errorf("startupDelayMin not rendered with requested value 37")
	}
	if !strings.Contains(content, "startupDelayMax = 91") {
		t.Errorf("startupDelayMax not rendered with requested value 91")
	}
	if strings.Contains(content, "{{STARTUP_DELAY") {
		t.Errorf("unreplaced startup delay placeholder left in template")
	}
}

// 默认植入端模板必须**不含**主动反沙箱进程检测（进程枚举 + 杀软进程名），
// 该逻辑只能在 -tags evasionscan 时编译进来（gate_scan_windows.go）。
func TestDefaultTemplateHasNoProcessScan(t *testing.T) {
	dir := "implant"
	scanFile := filepath.Join(dir, "gate_scan_windows.go")
	offFile := filepath.Join(dir, "gate_scan_off_windows.go")
	for _, f := range []string{scanFile, offFile} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	scanSrc, err := os.ReadFile(scanFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(scanSrc), "//go:build windows && evasionscan") {
		t.Error("gate_scan_windows.go must be gated behind the evasionscan tag")
	}
	offSrc, err := os.ReadFile(offFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(offSrc), "//go:build windows && !evasionscan") {
		t.Error("gate_scan_off_windows.go must be the default (no evasionscan) implementation")
	}
	// 默认实现里不允许出现进程枚举/杀软进程名。
	for _, bad := range []string{"CreateToolhelp32Snapshot", "360tray", "huorong", "Process32First"} {
		if strings.Contains(string(offSrc), bad) {
			t.Errorf("default gate stub must not contain %q", bad)
		}
	}
	// 主 gate 文件也不应再包含枚举逻辑（已移入带标签的文件）。
	// 注释里会提到这些名字（说明为什么默认关闭），因此只看去掉注释后的代码。
	mainSrc, err := os.ReadFile(filepath.Join(dir, "gate_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"CreateToolhelp32Snapshot", "Process32First", "360tray", "huorong", "strings.Contains"} {
		if strings.Contains(stripLineComments(string(mainSrc)), bad) {
			t.Errorf("gate_windows.go must no longer call %q (moved to gate_scan_windows.go)", bad)
		}
	}
}

// stripLineComments 去掉整行注释与行尾 // 注释，便于对"代码"而不是"文档"做断言。
func stripLineComments(src string) string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

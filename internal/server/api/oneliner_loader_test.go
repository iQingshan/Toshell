package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loaderTestURL 与既有单测保持一致的下载地址形态。
const loaderTestURL = "https://c2.example.com:8443/api/v1/implant/payload/build-1"

// loaderTestBase 下载基址（去掉端点路径与 build id）。
const loaderTestBase = "https://c2.example.com:8443"

// loaderForbiddenNames 具体第三方软件名：加载器链的命令里不允许出现任何写死的第三方
// 软件/宿主名字（宿主由操作员自备，本项目不内置、不推荐）。
var loaderForbiddenNames = []string{
	"360", "腾讯", "电脑管家", "火绒", "金山", "百度", "搜狗", "迅雷",
	"微信", "WeChat", "QQ", "wps", "WPS", "钉钉", "DingTalk",
	"向日葵", "Sunlogin", "ToDesk", "AnyDesk", "TeamViewer",
	"Norton", "McAfee", "Kaspersky", "卡巴斯基", "小红伞", "Avast",
}

// loaderForbiddenPaths 指向项目内置/自带二进制的路径：命令里不允许引用仓库内的
// 加载器或产物路径（只能用系统自带程序 + 操作员自备的宿主路径占位符）。
var loaderForbiddenPaths = []string{
	"implants/", "implants\\", "payloads/", "payloads\\",
	"/tools/", "\\tools\\", "bin/", "dist/",
}

// loaderCommandText 返回用于特征断言的命令文本：powershell -enc 变体先解开内层脚本，
// 避免 Base64 里随机凑出 "360"/"WPS" 之类的字母组合造成误报。
func loaderCommandText(t *testing.T, cmd string) string {
	t.Helper()
	return decodeEncCommand(t, cmd)
}

// 加载器链：必须覆盖 task 要求的关键手法，且每条都有 Name/Desc/Command/Note。
func TestLoaderChainVariantsCoverage(t *testing.T) {
	chains := loaderChainVariants("windows", "exe", loaderTestURL)
	if len(chains) < 6 {
		t.Fatalf("loader chains = %d, want >= 6", len(chains))
	}

	var all strings.Builder
	for _, v := range chains {
		if v.Name == "" || v.Desc == "" || v.Command == "" || v.Note == "" {
			t.Fatalf("incomplete loader chain: %+v", v)
		}
		if v.OS != "windows" {
			t.Fatalf("loader chain %q os = %q, want windows", v.Name, v.OS)
		}
		if v.Shell == "" {
			t.Fatalf("loader chain %q missing shell", v.Name)
		}
		text := loaderCommandText(t, v.Command)
		all.WriteString(text)
		all.WriteString("\n")

		// 下载基址必须复用 oneLinerSet 的解析结果，不能凭空造地址。
		if !strings.Contains(text, loaderTestBase) {
			t.Fatalf("loader chain %q does not reuse the resolved download base: %s", v.Name, text)
		}
		if strings.Contains(text, "localhost") || strings.Contains(text, "127.0.0.1") {
			t.Fatalf("loader chain %q leaked a loopback address", v.Name)
		}
	}

	joined := all.String()
	for _, frag := range []string{
		"rundll32", "schtasks", "mshta", "regsvr32", "certutil", "scrobj.dll", "powershell",
	} {
		if !strings.Contains(joined, frag) {
			t.Errorf("loader chains missing key command fragment %q", frag)
		}
	}
	// 计划任务链必须给出创建/运行/删除三条命令。
	if !strings.Contains(joined, "schtasks /create") ||
		!strings.Contains(joined, "schtasks /run") ||
		!strings.Contains(joined, "schtasks /delete") {
		t.Error("计划任务链必须包含 schtasks 的 create/run/delete 三条命令")
	}
}

// 加载器链命令里不得出现写死的第三方软件名，也不得引用项目内置二进制路径。
func TestLoaderChainHasNoBundledThirdParty(t *testing.T) {
	chains := loaderChainVariants("windows", "shellcode", loaderTestURL)
	if len(chains) == 0 {
		t.Fatal("expected loader chains")
	}
	for _, v := range chains {
		text := loaderCommandText(t, v.Command)
		for _, bad := range loaderForbiddenNames {
			if strings.Contains(text, bad) {
				t.Errorf("loader chain %q 命令里出现第三方软件名 %q: %s", v.Name, bad, text)
			}
		}
		for _, bad := range loaderForbiddenPaths {
			if strings.Contains(text, bad) {
				t.Errorf("loader chain %q 命令里引用了内置二进制路径 %q: %s", v.Name, bad, text)
			}
		}
	}
}

// 占位符语义：载荷本身是 dll/shellcode 时直接用自己的下载地址，否则用同一接口下的占位 ID。
func TestLoaderPayloadURLForFormat(t *testing.T) {
	cases := []struct {
		format        string
		wantDLL       string
		wantShellcode string
	}{
		{"dll", loaderTestURL, loaderTestBase + payloadDownloadPath + loaderShellcodeIDPlaceholder},
		{"shellcode", loaderTestBase + payloadDownloadPath + loaderDLLIDPlaceholder, loaderTestURL},
		{"shellcode_bin", loaderTestBase + payloadDownloadPath + loaderDLLIDPlaceholder, loaderTestURL},
		{"exe", loaderTestBase + payloadDownloadPath + loaderDLLIDPlaceholder, loaderTestBase + payloadDownloadPath + loaderShellcodeIDPlaceholder},
	}
	for _, c := range cases {
		if got := loaderDLLURL(loaderTestURL, c.format); got != c.wantDLL {
			t.Errorf("loaderDLLURL(%q) = %q, want %q", c.format, got, c.wantDLL)
		}
		if got := loaderShellcodeURL(loaderTestURL, c.format); got != c.wantShellcode {
			t.Errorf("loaderShellcodeURL(%q) = %q, want %q", c.format, got, c.wantShellcode)
		}
	}

	if got := downloadBase(loaderTestURL); got != loaderTestBase {
		t.Errorf("downloadBase = %q, want %q", got, loaderTestBase)
	}
	if got := downloadBase("https://c2.example.com/other"); got != "" {
		t.Errorf("downloadBase(非载荷地址) = %q, want empty", got)
	}
	if got := payloadURLWithID(loaderTestURL, "build-9"); got != loaderTestBase+payloadDownloadPath+"build-9" {
		t.Errorf("payloadURLWithID = %q", got)
	}
}

// 只有 Windows 需要加载器链；Linux/macOS 走 LoaderAdvice 的文本建议。
func TestSupportsLoaderChain(t *testing.T) {
	cases := []struct {
		os, format string
		want       bool
	}{
		{"windows", "exe", true},
		{"windows", "raw", true},
		{"windows", "dll", true},
		{"windows", "shellcode", true},
		{"windows", "shellcode_bin", true},
		{"windows", "so", false},
		{"linux", "exe", false},
		{"linux", "shellcode", false},
		{"darwin", "dll", false},
	}
	for _, c := range cases {
		if got := supportsLoaderChain(c.os, c.format); got != c.want {
			t.Errorf("supportsLoaderChain(%q,%q) = %v, want %v", c.os, c.format, got, c.want)
		}
	}
	if got := loaderChainVariants("linux", "exe", loaderTestURL); len(got) != 0 {
		t.Errorf("linux 不应生成加载器链，got %d", len(got))
	}
}

// LoaderAdvice 各分支：返回非空标题与要点，且关键结论齐全。
func TestLoaderAdvice(t *testing.T) {
	cases := []struct {
		name            string
		os, format      string
		signed          bool
		titleContains   []string
		tipsMustContain []string
	}{
		{
			name: "windows 未签名 exe",
			os:   "windows", format: "exe", signed: false,
			titleContains:   []string{"未签名", "签名"},
			tipsMustContain: []string{"360", "电脑管家", "白加黑", "内存加载", "dll"},
		},
		{
			name: "windows 已签名 exe",
			os:   "windows", format: "exe", signed: true,
			titleContains:   []string{"已签名", "直接运行"},
			tipsMustContain: []string{"计划任务", "schtasks"},
		},
		{
			name: "windows 未签名 raw",
			os:   "windows", format: "raw", signed: false,
			titleContains:   []string{"未签名"},
			tipsMustContain: []string{"360"},
		},
		{
			name: "windows dll 未签名",
			os:   "windows", format: "dll", signed: false,
			titleContains:   []string{"DLL"},
			tipsMustContain: []string{"白加黑", "侧加载", "宿主", "NAME NOT FOUND"},
		},
		{
			name: "windows dll 已签名",
			os:   "windows", format: "dll", signed: true,
			titleContains:   []string{"DLL"},
			tipsMustContain: []string{"白加黑", "侧加载", "rundll32"},
		},
		{
			name: "windows shellcode 未签名",
			os:   "windows", format: "shellcode", signed: false,
			titleContains:   []string{"shellcode"},
			tipsMustContain: []string{"内存加载", "hex"},
		},
		{
			name: "windows shellcode_bin 已签名",
			os:   "windows", format: "shellcode_bin", signed: true,
			titleContains:   []string{"shellcode"},
			tipsMustContain: []string{"内存加载", "原始字节"},
		},
		{
			name: "linux",
			os:   "linux", format: "bin", signed: false,
			titleContains:   []string{"Linux"},
			tipsMustContain: []string{"noexec", "curl", "chmod"},
		},
		{
			name: "darwin",
			os:   "darwin", format: "exe", signed: false,
			titleContains:   []string{"macOS"},
			tipsMustContain: []string{"Gatekeeper", "quarantine"},
		},
		{
			name: "未知平台",
			os:   "solaris", format: "exe", signed: false,
			titleContains:   []string{"未知平台"},
			tipsMustContain: []string{"Windows"},
		},
		{
			name: "空参数按 Windows 未签名 exe 处理",
			os:   "", format: "", signed: false,
			titleContains:   []string{"未签名"},
			tipsMustContain: []string{"360"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			title, tips := LoaderAdvice(c.os, c.format, c.signed)
			if strings.TrimSpace(title) == "" {
				t.Fatal("title 不能为空")
			}
			for _, want := range c.titleContains {
				if !strings.Contains(title, want) {
					t.Errorf("title = %q, 缺少 %q", title, want)
				}
			}
			if len(tips) < 3 {
				t.Fatalf("tips = %d 条，至少要有 3 条", len(tips))
			}
			joined := strings.Join(tips, "\n")
			for _, want := range c.tipsMustContain {
				if !strings.Contains(joined, want) {
					t.Errorf("tips 缺少关键字 %q:\n%s", want, joined)
				}
			}
			for _, tip := range tips {
				if strings.TrimSpace(tip) == "" {
					t.Error("存在空 tip")
				}
			}
			// 纯函数：同样入参必须返回同样结果。
			title2, tips2 := LoaderAdvice(c.os, c.format, c.signed)
			if title2 != title || strings.Join(tips2, "\n") != joined {
				t.Error("LoaderAdvice 不是纯函数（两次调用结果不一致）")
			}
		})
	}
}

// 未签名/已签名的 Windows exe 建议必须给出可执行的动作，而不只是描述现象。
func TestLoaderAdviceWindowsExeActions(t *testing.T) {
	_, unsigned := LoaderAdvice("windows", "exe", false)
	joined := strings.Join(unsigned, "\n")
	for _, want := range []string{"签名", "白加黑", "计划任务", "内存加载"} {
		if !strings.Contains(joined, want) {
			t.Errorf("未签名 exe 建议缺少动作 %q:\n%s", want, joined)
		}
	}

	title, signed := LoaderAdvice("windows", "exe", true)
	if !strings.Contains(title, "直接运行") {
		t.Errorf("已签名 exe 应优先建议直接运行，got %q", title)
	}
	if !strings.Contains(strings.Join(signed, "\n"), "计划任务") {
		t.Error("已签名 exe 应把计划任务作为次选")
	}
}

// 集成：oneLinerSet 在既有「下载即执行」变体之后追加加载器链；
// dll 格式只给加载器链；不支持的格式仍然返回 nil。
func TestOneLinerSetIncludesLoaderChains(t *testing.T) {
	s := testServer("https://c2.example.com", "", 18081)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18081/api/v1/builders", nil)

	exe := s.oneLinerSet(r, "", "windows", "exe", "build-1", "", "")
	if exe == nil {
		t.Fatal("exe 载荷不应返回 nil")
	}
	if exe.Variants[0].Name != "PowerShell · Base64 编码" {
		t.Errorf("主推方案应保持不变，got %q", exe.Variants[0].Name)
	}
	directCount := len(windowsOneLiners(loaderTestURL))
	if len(exe.Variants) <= directCount {
		t.Fatalf("变体数 = %d，应大于原有 %d 条（未追加加载器链）", len(exe.Variants), directCount)
	}
	names := map[string]bool{}
	for _, v := range exe.Variants {
		names[v.Name] = true
	}
	for _, want := range []string{"白加黑 · 签名宿主 DLL 侧加载", "计划任务 · 已签名宿主加载", "LOLBin · regsvr32 Squiblydoo"} {
		if !names[want] {
			t.Errorf("缺少加载器链变体 %q", want)
		}
	}

	// dll 格式：不能直接执行，只给加载器链（全部带 Note）。
	dll := s.oneLinerSet(r, "", "windows", "dll", "build-2", "", "")
	if dll == nil {
		t.Fatal("windows dll 载荷应给出加载器链，不应返回 nil")
	}
	if len(dll.Variants) != len(loaderChainVariants("windows", "dll", loaderTestURL)) {
		t.Errorf("dll 变体数 = %d，应等于加载器链数量", len(dll.Variants))
	}
	for _, v := range dll.Variants {
		if v.Note == "" {
			t.Errorf("加载器链 %q 缺少 Note", v.Name)
		}
	}

	// 下载基址与 warning 透传。
	if dll.BaseURL != "https://c2.example.com" {
		t.Errorf("base_url = %q", dll.BaseURL)
	}

	// 不能给出任何链路的格式仍然返回 nil（保持既有语义）。
	if got := s.oneLinerSet(r, "", "linux", "so", "build-3", "", ""); got != nil {
		t.Error("linux so 不应返回变体")
	}
	if got := s.oneLinerSet(r, "", "darwin", "exe", "build-4", "", ""); got != nil {
		t.Error("darwin 不应返回变体")
	}
}

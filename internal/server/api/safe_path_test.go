package api

// safe_path_test.go —— 路径安全收敛点（safePayloadName / resolveInDir）的回归测试。
//
// 覆盖审计 Toshell_AUDIT_2026-10-24 的 H2/H3/M9 共用底座：拒绝穿越、拒绝非法
// 字符、拒绝软链逃逸，同时**不能**误伤服务端自己生成的合法名字
// （build-<unixnano> / implant-<unix>），也不影响目录内的正常下载。

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSafePayloadNameAcceptsLegitNames(t *testing.T) {
	legit := []string{
		"implant-1792",
		"implant-1792144113",
		"build-1792144113714300000",
		"build-1792144113714300000.raw",
		"build-1792144113714300000.txt",
		"a",
		"A_1.b-c",
		"payload_2026.10.24",
		strings.Repeat("a", maxPayloadNameLen), // 边界：恰好 64 字节
	}
	for _, name := range legit {
		got, err := safePayloadName(name)
		if err != nil {
			t.Errorf("合法名 %q 被拒: %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("合法名被改写: %q -> %q（必须逐字节保留）", name, got)
		}
	}
}

func TestSafePayloadNameRejectsUnsafeNames(t *testing.T) {
	cases := []struct {
		desc string
		name string
	}{
		{"父目录穿越", "../x"},
		{"纯点点", ".."},
		{"单点", "."},
		{"正斜杠", "a/b"},
		{"反斜杠", `a\b`},
		{"点开头隐藏名", ".hidden"},
		{"空串", ""},
		{"超长 65 字节", strings.Repeat("a", maxPayloadNameLen+1)},
		{"冒号（Windows 盘符）", "a:b"},
		{"盘符路径", `C:\Windows\win.ini`},
		{"NUL", "a\x00b"},
		{"空格", "my payload"},
		{"中文/非 ASCII", "载荷"},
		{"折叠型多段", "x/y/../../etc/passwd"},
		{"UNC 风格", `\\server\share`},
	}
	for _, tc := range cases {
		if got, err := safePayloadName(tc.name); err == nil {
			t.Errorf("%s: safePayloadName(%q) 应被拒绝，却返回 %q", tc.desc, tc.name, got)
		}
	}
}

func TestResolveInDirAllowsFileInside(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "build-1.raw")
	if err := os.WriteFile(target, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := resolveInDir(dir, "build-1.raw")
	if err != nil {
		t.Fatalf("目录内文件应通过: %v", err)
	}
	want, _ := filepath.Abs(target)
	if got != want {
		t.Fatalf("resolveInDir = %q, want %q", got, want)
	}

	// 子目录（resolveInDir 本身不限制层级，单段约束在 safePayloadName）
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "x.raw"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInDir(dir, filepath.Join("sub", "x.raw")); err != nil {
		t.Fatalf("目录内子路径应通过: %v", err)
	}
}

func TestResolveInDirRejectsEscapeAndAbsolute(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "implants")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// 目录外真实存在的目标文件：旧实现 Join 后正好命中它
	if err := os.WriteFile(filepath.Join(root, "outside.txt"), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	bad := []struct {
		desc string
		name string
	}{
		{"父目录穿越", "../outside.txt"},
		{"多级穿越", "../../outside.txt"},
		{"指向目录自身", "."},
		{"折叠回目录自身", "sub/.."},
		{"空路径", ""},
		{"绝对路径", filepath.Join(root, "outside.txt")},
	}
	if runtime.GOOS == "windows" {
		// 反斜杠在 Windows 是分隔符、在 Unix 是普通文件名字符，
		// 因此这条只在 Windows 上断言（Unix 上由 safePayloadName 负责拒绝）。
		bad = append(bad, struct {
			desc string
			name string
		}{"Windows 反斜杠穿越", `..\outside.txt`})
	}
	for _, tc := range bad {
		if got, err := resolveInDir(dir, tc.name); err == nil {
			t.Errorf("%s: resolveInDir(%q) 应被拒绝，却返回 %q", tc.desc, tc.name, got)
		}
	}
}

// TestResolveInDirRejectsSymlinkEscape 覆盖「词法在目录内、真实目标在目录外」。
// Windows 上创建符号链接需要管理员/开发者模式；建不了就跳过该子用例并注明。
func TestResolveInDirRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "implants")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("当前环境无法创建符号链接（Windows 需要管理员/开发者模式），跳过软链逃逸子用例: %v", err)
	}

	if got, err := resolveInDir(dir, "escape.txt"); err == nil {
		t.Fatalf("软链逃逸应被拒绝，却返回 %q", got)
	}

	// 反向对照：指向目录内部的软链应当仍可用（不误伤正常布局）。
	inside := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(inside, []byte("real"), 0644); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(dir, "alias.txt")
	if err := os.Symlink(inside, insideLink); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过软链内部对照: %v", err)
	}
	if _, err := resolveInDir(dir, "alias.txt"); err != nil {
		t.Fatalf("指向目录内部的软链不应被拒: %v", err)
	}
}

// TestPayloadDownloadExtsWhitelist 守护 H3：请求里的 format 只能当白名单标签，
// 绝不允许把任意字符串（尤其含分隔符/..）带进后缀候选。
func TestPayloadDownloadExtsWhitelist(t *testing.T) {
	for _, format := range []string{"yaml", "y/../../etc/passwd", `..\..\x`, "db", "", "raw"} {
		for _, ext := range payloadDownloadExts(format) {
			if strings.ContainsAny(ext, `/\:`) || ext == "." || ext == ".." {
				t.Fatalf("format=%q 产生了非法后缀候选 %q", format, ext)
			}
			switch ext {
			case "exe", "dll", "bin", "txt", "raw", "so":
			default:
				t.Fatalf("format=%q 产生了白名单外的后缀候选 %q", format, ext)
			}
		}
	}
	// format="raw" 应优先命中 raw（保留旧行为）
	if got := payloadDownloadExts("raw"); len(got) == 0 || got[0] != "raw" {
		t.Fatalf("payloadDownloadExts(\"raw\") = %v, want raw first", got)
	}
}

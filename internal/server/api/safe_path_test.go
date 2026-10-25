package api

// safe_path_test.go —— 路径安全收敛点（safePayloadName / resolveInDir）的回归测试。
//
// 覆盖审计 Toshell_AUDIT_2026-10-24 的 H2/H3/M9 共用底座：拒绝穿越、拒绝非法
// 字符、拒绝软链逃逸，同时**不能**误伤服务端自己生成的合法名字
// （build-<unixnano> / implant-<unix>），也不影响目录内的正常下载。

import (
	"os"
	"os/exec"
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
		// ── 复审计 N5：Windows 保留设备名与尾点/尾空格 ──────────────────────
		{"保留设备名 CON", "CON"},
		{"保留设备名小写 con", "con"},
		{"设备名带扩展名 NUL.raw", "NUL.raw"},
		{"设备名带扩展名 con.exe", "con.exe"},
		{"设备名 COM1", "COM1"},
		{"设备名 LPT9.dll", "LPT9.dll"},
		{"设备名 PRN", "PRN"},
		{"设备名 AUX.log", "AUX.log"},
		{"尾点 a.", "a."},
		{"尾点 build-1.exe.", "build-1.exe."},
		{"尾空格 a 空格", "a "},
		{"尾点+尾空格", "a. "},
	}
	for _, tc := range cases {
		if got, err := safePayloadName(tc.name); err == nil {
			t.Errorf("%s: safePayloadName(%q) 应被拒绝，却返回 %q", tc.desc, tc.name, got)
		}
	}
}

// TestSafePayloadNameN5LegitNamesStillPass 保证 N5 的加严不误伤服务端命名与
// 常见的合法文件名（点/下划线/连字符都在中间）。
func TestSafePayloadNameN5LegitNamesStillPass(t *testing.T) {
	for _, name := range []string{
		"build-1792",
		"build-1792144113714300000",
		"implant-x",
		"implant-1792",
		"a.b-c_d",
		"console",
		"nulled",
		"com10", // 只保留 COM1-9，COM10 不是设备名
		"lpt0",  // 同理 LPT0
		"a.raw",
		"payload_2026.10.24",
	} {
		if _, err := safePayloadName(name); err != nil {
			t.Errorf("合法名 %q 被 N5 加严误伤: %v", name, err)
		}
	}
}

// TestRequireSingleSegmentName 覆盖复审计 N1 要求的「file:/DB 候选强制单段名」。
func TestRequireSingleSegmentName(t *testing.T) {
	bad := []string{"", ".", "..", "a/b", `a\b`, "../x", `..\x`, "sub\\..\\x", "x/"}
	for _, name := range bad {
		if err := requireSingleSegmentName(name); err == nil {
			t.Errorf("requireSingleSegmentName(%q) 应被拒绝", name)
		}
	}
	// 目录内正常文件名（含空格/中文）必须仍然通过。
	for _, name := range []string{"build-1.exe", "a b.txt", "中文.exe", "build-1792.raw"} {
		if err := requireSingleSegmentName(name); err != nil {
			t.Errorf("合法单段名 %q 被拒: %v", name, err)
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

// ─── 复审计 N1：Windows 目录 junction（mount point）────────────────────────

// makeJunctionOrSkip 创建目录 junction。Windows 上 mklink /J 不需要管理员权限
// （只需要对 link 的父目录有写权限），因此测试里用 os/exec 直接调用；
// 若当前环境不允许（或非 Windows），跳过并注明原因。
func makeJunctionOrSkip(t *testing.T, link, target string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 有目录 junction（mount point）语义")
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("当前环境无法创建目录 junction（cmd mklink /J 失败: %v; 输出: %q）", err, strings.TrimSpace(string(out)))
	}
	// 只删 junction 本身（删除 reparse point 不会递归目标目录）。
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			t.Logf("清理 junction %q 失败: %v", link, err)
		}
	})
}

// TestResolveInDirRejectsJunctionEscape 是复审计 N1 的核心回归用例。
//
// 旧实现：EvalSymlinks("base/link/win.ini") 报错 → 当作"目标不存在"跳过物理断言
// → 只做词法断言 → 放行 → 随后 os.Open 由操作系统跟随 junction，读到 %WINDIR%
// 下的文件。本用例在旧实现下必须失败（变红），在当前 fail-closed 实现下通过。
func TestResolveInDirRejectsJunctionEscape(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction 仅 Windows")
	}
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	if _, err := os.Stat(filepath.Join(windir, "win.ini")); err != nil {
		t.Skipf("%%WINDIR%% 下没有 win.ini，跳过 junction 用例: %v", err)
	}

	base := t.TempDir()
	link := filepath.Join(base, "link")
	makeJunctionOrSkip(t, link, windir)

	// 前置事实：junction 在 Lstat 下**不是** symlink（Go 在 Windows 上把它标记为
	// ModeIrregular）；EvalSymlinks 对 "junction\子项" 直接报错。这正是 N1 的根因，
	// 也是"只检查 ModeSymlink"或"EvalSymlinks 失败就放行"都会漏掉它的原因。
	if fi, err := os.Lstat(link); err != nil {
		t.Fatalf("Lstat(junction) 失败: %v", err)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		t.Skipf("当前 Go/Windows 把 junction 标记成 ModeSymlink（%v），该环境语义不同", fi.Mode())
	}
	if _, err := filepath.EvalSymlinks(filepath.Join(link, "win.ini")); err == nil {
		t.Logf("提示：当前环境 EvalSymlinks 能解析 junction 子项；本用例仍要求严格拒绝")
	}

	// 1) 已存在的外部文件（正斜杠写法）：必须拒绝。
	if got, err := resolveInDir(base, filepath.Join("link", "win.ini")); err == nil {
		t.Fatalf("junction 逃逸应被拒绝，却放行 %q（复审计 N1 回归）", got)
	}
	// 2) 反斜杠写法（未认证 {id} 里正是这种形态）：必须拒绝。
	if got, err := resolveInDir(base, `link\win.ini`); err == nil {
		t.Fatalf("junction 逃逸（反斜杠）应被拒绝，却放行 %q", got)
	}
	// 3) junction 下的不存在目标：不能因为"目标不存在"就放行。
	if got, err := resolveInDir(base, `link\nope.txt`); err == nil {
		t.Fatalf("junction 下的不存在目标应被拒绝，却放行 %q", got)
	}
	// 4) junction 本身作为目标：EvalSymlinks 会"成功"返回它自己，只有逐段 Lstat
	//    的 ModeIrregular 检查能拦住。
	if got, err := resolveInDir(base, "link"); err == nil {
		t.Fatalf("junction 本身作为目标应被拒绝，却放行 %q", got)
	}

	// 对照：同目录下的普通文件仍必须通过（fail-closed ≠ 全拒绝）。
	ok := filepath.Join(base, "build-1.raw")
	if err := os.WriteFile(ok, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInDir(base, "build-1.raw"); err != nil {
		t.Fatalf("junction 存在时目录内普通文件仍应通过: %v", err)
	}
}

// TestResolveInDirRejectsMissingParent 复审计 N1：父目录必须能被解析，
// 不允许"目标不存在"成为跳过物理断言的理由。
func TestResolveInDirRejectsMissingParent(t *testing.T) {
	dir := t.TempDir()

	// 父目录不存在（多段名）：拒绝。
	if got, err := resolveInDir(dir, "nope/x.txt"); err == nil {
		t.Fatalf("父目录不存在时应拒绝，却放行 %q", got)
	}
	// 父目录不存在（反斜杠写法）：同样拒绝。
	if runtime.GOOS == "windows" {
		if got, err := resolveInDir(dir, `nope\x.txt`); err == nil {
			t.Fatalf("父目录不存在（反斜杠）时应拒绝，却放行 %q", got)
		}
	}
	// 对照：父目录存在、目标不存在的**单段**名字属于合法"创建/删除"意图，放行。
	got, err := resolveInDir(dir, "future.txt")
	if err != nil {
		t.Fatalf("父目录存在时，不存在的单段目标应通过: %v", err)
	}
	want, _ := filepath.Abs(filepath.Join(dir, "future.txt"))
	if got != want {
		t.Fatalf("resolveInDir = %q, want %q", got, want)
	}
}

package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestManager 构造一个绑定临时插件目录的 Manager。
// 不走 Init（sync.Once 全局单例），避免测试之间互相污染。
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建临时插件目录失败: %v", err)
	}
	return &Manager{pluginDir: dir, plugins: make(map[string]*Plugin)}
}

// TestValidatePluginName 覆盖 H4 修复的核心校验规则：
// 合法名（含空格/中文/括号）通过；穿越/相对路径/隐藏文件/空串/超长/盘符/控制字符/
// 未知扩展名全部拒绝。
func TestValidatePluginName(t *testing.T) {
	valid := []string{
		"cred_probe.exe",
		"a.dll",
		"x_1-2.bin",
		"A.RAW",
		"payload.o",
		"plugin.obj",
		"shell.sc",
		"我的插件.exe",                       // 中文
		"cred probe.exe",                 // 空格
		"a(1).dll",                       // 括号
		"café.exe",                       // 非 ASCII 文字
		strings.Repeat("a", 60) + ".exe", // 恰好 64 字节
		strings.Repeat("中", 20) + ".exe", // 60+4 = 64 字节
	}
	for _, name := range valid {
		if err := ValidatePluginName(name); err != nil {
			t.Fatalf("合法插件名 %q 被拒绝: %v", name, err)
		}
	}

	invalid := []string{
		"../x",
		"../x.exe",
		`..\x`,
		`..\x.exe`,
		"..",
		".",
		"a/b",
		"a/b.exe",
		`a\b`,
		`a\b.exe`,
		".hidden",
		".hidden.exe",
		"",
		strings.Repeat("a", 61) + ".exe", // 65 字节
		strings.Repeat("中", 21) + ".exe", // 67 字节
		"a:b",
		"a:b.exe",
		"NUL.exe",
		"nul .exe", // Windows 忽略设备名尾部空格
		"evil.txt", // 未知扩展名
		"a.exe.",   // 扩展名退化为 "."
		"\x00.exe", // NUL 字节
		"a\x00b.exe",
		"a\nb.exe",       // 换行（控制字符）
		"a\tb.exe",       // Tab（控制字符）
		"caf\xe9.exe",    // 非法 UTF-8
		"\u202Eevil.exe", // Unicode 格式控制符（RTL override）
		"../../../evil.exe",
	}
	for _, name := range invalid {
		err := ValidatePluginName(name)
		if err == nil {
			t.Fatalf("非法插件名 %q 未被拒绝", name)
		}
		if !errors.Is(err, ErrInvalidName) {
			t.Fatalf("非法插件名 %q 的错误未包裹 ErrInvalidName: %v", name, err)
		}
	}
}

// TestManagerAddRejectsTraversal 复现审计 H4 的 manager 层入口：
// 直接给 Add 传穿越名必须报错，且目标路径不能出现文件。
func TestManagerAddRejectsTraversal(t *testing.T) {
	m := newTestManager(t)

	// 审计 PoC 中使用的等价形式
	if _, err := m.Add("../../../evil.exe", []byte("pwn"), ""); err == nil {
		t.Fatal("Add(../../../evil.exe) 未被拒绝")
	} else if !errors.Is(err, ErrInvalidName) {
		t.Fatalf("错误未包裹 ErrInvalidName: %v", err)
	}

	// 用唯一文件名断言"目标路径确实没有文件被写出"
	unique := fmt.Sprintf("../../../toshell_h4_traversal_%d.exe", os.Getpid())
	escaped := filepath.Clean(filepath.Join(m.pluginDir, unique))
	if _, err := m.Add(unique, []byte("pwn"), ""); err == nil {
		t.Fatal("Add(穿越名) 未被拒绝")
	}
	if _, serr := os.Stat(escaped); !os.IsNotExist(serr) {
		t.Fatalf("穿越目标路径被写出: %s (stat err=%v)", escaped, serr)
	}

	// 未知扩展名同样拒绝，且不会在插件目录里落文件
	if _, err := m.Add("evil.txt", []byte("x"), ""); err == nil {
		t.Fatal("Add(evil.txt) 未知扩展名未被拒绝")
	}
	entries, rerr := os.ReadDir(m.pluginDir)
	if rerr != nil {
		t.Fatalf("读取插件目录失败: %v", rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("插件目录不应有文件，实际有 %d 个", len(entries))
	}
	if len(m.List()) != 0 {
		t.Fatalf("内存索引不应有插件，实际有 %d 个", len(m.List()))
	}
}

// TestManagerAddValid 合法名必须成功，文件落在 pluginDir 内且可被 Get/List 看到。
func TestManagerAddValid(t *testing.T) {
	m := newTestManager(t)
	data := []byte("MZ fake plugin bytes")

	p, err := m.Add("cred_probe.exe", data, "凭据探测")
	if err != nil {
		t.Fatalf("合法插件上传失败: %v", err)
	}
	wantPath := filepath.Join(m.pluginDir, "cred_probe.exe")
	if p.Path != wantPath {
		t.Fatalf("插件路径 = %q，期望 %q", p.Path, wantPath)
	}
	rel, rerr := filepath.Rel(m.pluginDir, p.Path)
	if rerr != nil || rel != "cred_probe.exe" {
		t.Fatalf("插件路径不在 pluginDir 内: rel=%q err=%v", rel, rerr)
	}
	got, rerr := os.ReadFile(wantPath)
	if rerr != nil {
		t.Fatalf("读取已写入的插件失败: %v", rerr)
	}
	if string(got) != string(data) {
		t.Fatalf("插件内容被改写: %q", got)
	}
	if p.ID != "cred_probe" || p.Type != PluginTypeEXE || p.Size != int64(len(data)) {
		t.Fatalf("插件元数据不符: id=%q type=%q size=%d", p.ID, p.Type, p.Size)
	}
	if cached, gerr := m.Get("cred_probe"); gerr != nil || cached.Name != "cred_probe.exe" {
		t.Fatalf("Get(cred_probe) 失败: plugin=%v err=%v", cached, gerr)
	}
	if len(m.List()) != 1 {
		t.Fatalf("List() 长度 = %d，期望 1", len(m.List()))
	}

	// 同名覆盖上传（O_TRUNC 路径）必须仍然工作
	if _, err := m.Add("cred_probe.exe", []byte("second"), ""); err != nil {
		t.Fatalf("同名覆盖上传失败: %v", err)
	}
	if got, _ := os.ReadFile(wantPath); string(got) != "second" {
		t.Fatalf("覆盖后内容 = %q，期望 second", got)
	}

	// 放宽字符集后，空格/中文/括号文件名必须仍然真正落盘且可读回。
	for _, name := range []string{"我的插件.exe", "cred probe.exe", "a(1).dll"} {
		pp, aerr := m.Add(name, []byte("unicode-payload"), "")
		if aerr != nil {
			t.Fatalf("合法 Unicode 插件名 %q 上传失败: %v", name, aerr)
		}
		rel, rerr := filepath.Rel(m.pluginDir, pp.Path)
		if rerr != nil || rel != name {
			t.Fatalf("插件 %q 未落在 pluginDir 内: rel=%q err=%v", name, rel, rerr)
		}
		b, rerr := os.ReadFile(pp.Path)
		if rerr != nil || string(b) != "unicode-payload" {
			t.Fatalf("插件 %q 读回失败: data=%q err=%v", name, b, rerr)
		}
	}
}

// TestManagerAddReplacesSymlinkWithoutFollowingIt 审计 H4 的符号链接攻击链：
// plugins/evil.exe 预先是符号链接时，Add 用 rename **替换掉链接目录项**而不是
// 跟随链接写穿；链接目标文件内容必须保持原样。
func TestManagerAddReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	base := t.TempDir()
	pluginDir := filepath.Join(base, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("创建临时插件目录失败: %v", err)
	}
	m := &Manager{pluginDir: pluginDir, plugins: make(map[string]*Plugin)}

	victim := filepath.Join(base, "victim.bin")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatalf("写入 victim 失败: %v", err)
	}
	link := filepath.Join(pluginDir, "evil.exe")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("当前环境无法创建符号链接（Windows 通常需要开发者模式/管理员权限），跳过: %v", err)
	}

	data := []byte("pwned-by-target-file")
	if _, err := m.Add("evil.exe", data, ""); err != nil {
		t.Fatalf("Add(符号链接目标) 应替换目录项并成功，实际失败: %v", err)
	}
	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("读取 victim 失败: %v", rerr)
	}
	if string(got) != "original" {
		t.Fatalf("符号链接目标被写入！内容 = %q", got)
	}
	fi, lerr := os.Lstat(link)
	if lerr != nil {
		t.Fatalf("Lstat 插件目标失败: %v", lerr)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("符号链接未被 rename 替换，仍然是符号链接")
	}
	if b, _ := os.ReadFile(link); string(b) != string(data) {
		t.Fatalf("插件文件内容 = %q，期望 %q", b, data)
	}
}

// TestManagerAddDoesNotWriteThroughHardlink 复现复审计 N3：
// 插件目录内 hard.exe 是指向目录外 victim.bin 的**硬链接**（同一 inode 的另一个
// 目录项，O_NOFOLLOW 挡不住）。Add 必须用 rename 替换目录项：victim.bin 内容不变，
// plugins/hard.exe 变成新内容且不再是 victim 的硬链接。
func TestManagerAddDoesNotWriteThroughHardlink(t *testing.T) {
	base := t.TempDir()
	pluginDir := filepath.Join(base, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("创建临时插件目录失败: %v", err)
	}
	m := &Manager{pluginDir: pluginDir, plugins: make(map[string]*Plugin)}

	original := []byte("original-victim-content")
	victim := filepath.Join(base, "victim.bin") // 插件目录之外
	if err := os.WriteFile(victim, original, 0o644); err != nil {
		t.Fatalf("写入 victim 失败: %v", err)
	}
	link := filepath.Join(pluginDir, "hard.exe")
	if err := os.Link(victim, link); err != nil {
		t.Skipf("当前环境无法创建硬链接（Windows 普通用户在同卷上通常可以；跨卷/权限不足会失败），跳过: %v", err)
	}
	if a, b := mustStat(t, victim), mustStat(t, link); !os.SameFile(a, b) {
		t.Fatal("前置条件不成立：os.Link 后两者不是同一文件")
	}

	newData := []byte("hardlink-replaced-by-rename")
	if _, err := m.Add("hard.exe", newData, ""); err != nil {
		t.Fatalf("Add(硬链接目标) 失败: %v", err)
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("读取目录外 victim 失败: %v", rerr)
	}
	if string(got) != string(original) {
		t.Fatalf("目录外 victim 被写穿！内容 = %q（期望 %q）", got, original)
	}
	if b, _ := os.ReadFile(link); string(b) != string(newData) {
		t.Fatalf("plugins/hard.exe 内容 = %q，期望 %q", b, newData)
	}
	if a, b := mustStat(t, victim), mustStat(t, link); os.SameFile(a, b) {
		t.Fatal("plugins/hard.exe 仍是 victim 的硬链接目录项，说明没有替换目录项")
	}
}

// mustStat 是 os.Stat 的测试辅助：失败即终止用例。
func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) 失败: %v", path, err)
	}
	return fi
}

// TestWritePluginFileAtomicCleansTempOnRenameFailure 原子写的失败路径：
// rename 覆盖失败（目标是目录）时必须删除临时文件，插件目录里不能残留
// .tsh-plugin-*。Windows 上难以制造"目录只读"，用"目标是目录"同样能让 rename
// 稳定失败，且不依赖权限/注入。
func TestWritePluginFileAtomicCleansTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "blocked.exe"), 0o755); err != nil {
		t.Fatalf("创建阻塞目录失败: %v", err)
	}
	if _, err := writePluginFileAtomic(dir, "blocked.exe", []byte("x")); err == nil {
		t.Fatal("rename 覆盖目录本应失败，实际成功")
	}
	if leftovers := tempPluginFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("失败路径残留临时文件: %v", leftovers)
	}
}

// TestWritePluginFileAtomicReplacesAndLeavesNoTemp 成功路径：覆盖已有文件，
// 内容正确、插件目录内没有 .tsh-plugin-* 残留。
func TestWritePluginFileAtomicReplacesAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("写入旧文件失败: %v", err)
	}
	got, err := writePluginFileAtomic(dir, "a.exe", []byte("new-content"))
	if err != nil {
		t.Fatalf("writePluginFileAtomic 失败: %v", err)
	}
	if got != target {
		t.Fatalf("返回路径 = %q，期望 %q", got, target)
	}
	if b, _ := os.ReadFile(target); string(b) != "new-content" {
		t.Fatalf("覆盖后内容 = %q，期望 new-content", b)
	}
	if leftovers := tempPluginFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("成功路径残留临时文件: %v", leftovers)
	}
}

// tempPluginFiles 列出插件目录内以 .tsh-plugin- 开头的临时文件。
func tempPluginFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tsh-plugin-") {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestManagerAddSymlinkedPluginDir 防回归：pluginDir 本身是符号链接（合法部署形态）
// 时，EvalSymlinks 断言不能把正常写入误判为逃逸。
func TestManagerAddSymlinkedPluginDir(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real_plugins")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("创建真实目录失败: %v", err)
	}
	linkDir := filepath.Join(base, "link_plugins")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("当前环境无法创建目录符号链接，跳过: %v", err)
	}
	m := &Manager{pluginDir: linkDir, plugins: make(map[string]*Plugin)}
	if _, err := m.Add("ok.bin", []byte("x"), ""); err != nil {
		t.Fatalf("pluginDir 为符号链接时合法上传失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realDir, "ok.bin")); err != nil {
		t.Fatalf("文件未落在真实目录内: %v", err)
	}
}

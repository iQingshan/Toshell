package api

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDownloadAllowed 校验 SSRF 防护：错误 scheme/内网/回环/保留地址必须被拒绝。
// 用 IP 字面量保证测试可复现（不依赖 DNS）；域名白名单用固定 IP 模拟。
func TestDownloadAllowed(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		allowlist []string
		wantErr   bool
	}{
		{name: "http-public-ip", url: "http://93.184.216.34/a.exe", wantErr: false},
		{name: "https-public-ip", url: "https://93.184.216.34/a.exe", wantErr: false},
		{name: "bad-scheme-ftp", url: "ftp://example.com/a.exe", wantErr: true},
		{name: "bad-scheme-file", url: "file:///etc/passwd", wantErr: true},
		{name: "loopback-127", url: "http://127.0.0.1/a.exe", wantErr: true},
		{name: "loopback-127-1", url: "http://127.0.1.1/a.exe", wantErr: true},
		{name: "private-10", url: "http://10.0.0.5/a.exe", wantErr: true},
		{name: "private-192", url: "http://192.168.1.1/a.exe", wantErr: true},
		{name: "private-172", url: "http://172.16.0.1/a.exe", wantErr: true},
		{name: "linklocal-169", url: "http://169.254.1.1/a.exe", wantErr: true},
		{name: "allowlist-matches-ip", url: "http://93.184.216.34/a.exe", allowlist: []string{"93.184.216.34"}, wantErr: false},
		{name: "allowlist-mismatch-ip", url: "http://93.184.216.34/a.exe", allowlist: []string{"1.2.3.4"}, wantErr: true},
		{name: "malformed", url: "://bad", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := downloadAllowed(c.url, c.allowlist)
			if c.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", c.url)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", c.url, err)
			}
		})
	}
}

// TestGuessTool 校验工具元数据推断（platform/arch/usage/kind）不因扩展名歧义而出错。
func TestGuessTool(t *testing.T) {
	if guessToolKind("mimikatz.exe") != "exe" {
		t.Fatal("mimikatz.exe should be exe")
	}
	if guessToolKind("inject.bin") != "shellcode" {
		t.Fatal("inject.bin should be shellcode")
	}
	if guessToolPlatform("x64_dump.dll") != "windows" {
		t.Fatal("should be windows")
	}
	if guessToolArch("tool-x64.exe") != "amd64" {
		t.Fatal("x64 -> amd64")
	}
	if guessToolUsage("mimikatz.exe") != "凭据收集" {
		t.Fatal("mimikatz -> 凭据收集")
	}
}

// ─── 复审计 N1：data/tools 下的 junction 必须让 resolveToolPath fail-closed ──

// TestResolveToolPathRejectsJunction 覆盖 N1 的第四条实测（data/tools 下 junction
// 让 plugin_upload 读到 %WINDIR%\win.ini）。旧实现把 EvalSymlinks 报错当作
// "不存在"放行，本用例在旧实现下会变红。
func TestResolveToolPathRejectsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction 仅 Windows")
	}
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	if _, err := os.Stat(filepath.Join(windir, "win.ini")); err != nil {
		t.Skipf("%%WINDIR%% 下没有 win.ini，跳过: %v", err)
	}

	root := t.TempDir()
	tools := filepath.Join(root, "data", "tools")
	if err := os.MkdirAll(tools, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root) // resolveToolPath 以进程 CWD 为基准拼 data/tools

	link := filepath.Join(tools, "link")
	makeJunctionOrSkip(t, link, windir)

	// 1) 已存在的外部文件（正/反斜杠两种写法）必须拒绝。
	for _, src := range []string{`link\win.ini`, "link/win.ini", "link"} {
		if got, err := resolveToolPath(src); err == nil {
			t.Errorf("resolveToolPath(%q) 应拒绝（junction 逃逸），却返回 %q", src, got)
		}
	}
	// 2) 对照：data/tools 内的正常工具文件仍可通过。
	ok := filepath.Join(tools, "tool.bin")
	if err := os.WriteFile(ok, []byte("MZ"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToolPath("tool.bin")
	if err != nil {
		t.Fatalf("正常工具文件被拒绝: %v", err)
	}
	if got != ok {
		t.Fatalf("resolveToolPath = %q, want %q", got, ok)
	}
	// 3) 对照：子目录内的正常工具仍可通过（resolveToolPath 允许子路径）。
	subDir := filepath.Join(tools, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	subTool := filepath.Join(subDir, "tool2.bin")
	if err := os.WriteFile(subTool, []byte("MZ"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveToolPath(filepath.Join("sub", "tool2.bin")); err != nil {
		t.Fatalf("子目录内正常工具被拒绝: %v", err)
	}
	// 4) 穿越写法仍然拒绝。
	for _, src := range []string{"../x", `..\x`, "sub/../../x"} {
		if _, err := resolveToolPath(src); err == nil {
			t.Errorf("resolveToolPath(%q) 应拒绝穿越", src)
		}
	}
}

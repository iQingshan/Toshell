package api

import (
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

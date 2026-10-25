package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBootstrapAdminPasswordWritesFileWithoutLoggingPlaintext 守护审计 L2：
// 首次启动自动生成的管理员口令只能落到 0600 的独立文件，绝不能出现在 stdout/日志里。
// 不断言 stdout 的其它内容（避免脆弱测试），只断言"日志含口令明文"这件事不会发生。
func TestBootstrapAdminPasswordWritesFileWithoutLoggingPlaintext(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	hash, err := bootstrapAdminPassword(dir)
	if err != nil {
		t.Fatalf("bootstrapAdminPassword: %v", err)
	}
	// 返回值必须是可直接用于 ValidateCredentials 的 bcrypt hash（$2a$ 前缀）。
	if !strings.HasPrefix(hash, "$2a$") {
		t.Fatalf("returned hash %q does not look like bcrypt ($2a$...)", hash)
	}

	path := filepath.Join(dir, initialAdminPasswordFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("initial password file not written: %v", err)
	}
	plain := strings.TrimSpace(string(raw))
	if len(plain) != 16 {
		t.Fatalf("generated password length = %d, want 16", len(plain))
	}
	if strings.TrimSpace(buf.String()) == "" {
		t.Error("expected a log line pointing at the password file")
	}
	if strings.Contains(buf.String(), plain) {
		t.Fatalf("log leaked the generated plaintext password (audit L2 regression)")
	}
	if !strings.Contains(buf.String(), initialAdminPasswordFile) {
		t.Errorf("log should tell the operator the file path, got %q", buf.String())
	}

	// POSIX 下必须只有属主可读写；Windows 无 POSIX mode（ACL 由 NTFS 管），跳过。
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat password file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("password file perm = %o, want 600", perm)
		}
	}
}

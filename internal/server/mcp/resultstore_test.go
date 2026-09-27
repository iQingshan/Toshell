package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *ResultStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewResultStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewResultStore: %v", err)
	}
	if s == nil {
		t.Fatal("store 为 nil")
	}
	return s
}

// TestResultStoreRoundTrip 落盘 → 回读 → tail 的往返正确性。
func TestResultStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	raw := []byte("0123456789abcdefghij")
	handle, n, err := s.Put("call-1", raw)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("Put total = %d, want %d", n, len(raw))
	}
	if !handleRe.MatchString(handle) {
		t.Fatalf("句柄格式非法: %q（应形如 20260927/<hex>）", handle)
	}

	got, total, err := s.Get(handle, 0, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if total != len(raw) || string(got) != string(raw) {
		t.Fatalf("Get 往返不一致: total=%d got=%q", total, string(got))
	}

	mid, _, err := s.Get(handle, 5, 4)
	if err != nil {
		t.Fatalf("Get(offset): %v", err)
	}
	if string(mid) != "5678" {
		t.Fatalf("分页回读 = %q, want 5678", string(mid))
	}

	tail, _, err := s.Tail(handle, 4)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	// raw = "0123456789abcdefghij"（20 字节），末尾 4 字节是 "ghij"
	if string(tail) != "ghij" {
		t.Fatalf("Tail = %q, want ghij", string(tail))
	}

	// n 超过总长时应返回全部内容而不是报错/越界
	allTail, _, err := s.Tail(handle, 999)
	if err != nil {
		t.Fatalf("Tail(over): %v", err)
	}
	if string(allTail) != string(raw) {
		t.Fatalf("Tail(over) = %q, want 全量", string(allTail))
	}
}

// TestResultStoreRejectsBadHandles 句柄是外部输入，必须严格白名单（防路径穿越）。
func TestResultStoreRejectsBadHandles(t *testing.T) {
	s := newTestStore(t)
	bad := []string{
		"",
		"../../etc/passwd",
		"20260927/../../configs/server.yaml",
		"20260927/..%2f..%2fetc",
		"/etc/passwd",
		`C:\Windows\win.ini`,
		"20260927/short",
		"2026092/deadbeefdeadbeef",            // 日期位数不对
		"20260927/DEADBEEFDEADBEEF",           // 大写 hex 不接受
		"20260927/deadbeefdeadbeef.bin.bin",   // 多余后缀
		"20260927/deadbeefdeadbeef/../../../", // 目录穿越
	}
	for _, h := range bad {
		if _, _, err := s.Get(h, 0, 0); err == nil {
			t.Errorf("非法句柄 %q 竟被接受", h)
		}
	}
}

// TestResultStoreNotFound 合法但不存在的句柄应报 ErrHandleNotFound。
func TestResultStoreNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Get("20260927/0011223344556677", 0, 0); err != ErrHandleNotFound {
		t.Fatalf("err = %v, want ErrHandleNotFound", err)
	}
}

// TestResultStoreGCRemovesExpired 过期结果会被 GC 清掉（含空目录结构下的文件）。
func TestResultStoreGCRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	s, err := NewResultStore(dir, time.Millisecond)
	if err != nil {
		t.Fatalf("NewResultStore: %v", err)
	}
	handle, _, err := s.Put("call", []byte("x"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	removed, err := s.GC()
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if removed != 1 {
		t.Fatalf("GC removed = %d, want 1", removed)
	}
	if _, _, err := s.Get(handle, 0, 0); err != ErrHandleNotFound {
		t.Fatalf("GC 后仍能读到文件: %v", err)
	}
}

// TestResultStoreMaxTotalEvictsOldest 超过容量上限时从最旧开始淘汰。
func TestResultStoreMaxTotalEvictsOldest(t *testing.T) {
	s := newTestStore(t)
	s.MaxTotal = 10 // 只允许 10 字节
	for i := 0; i < 4; i++ {
		if _, _, err := s.Put("c", []byte(strings.Repeat("a", 6))); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := s.GC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// 统计目录里剩余字节数，应 <= MaxTotal
	var total int64
	_ = filepath.WalkDir(s.Dir(), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		return nil
	})
	if total > s.MaxTotal {
		t.Fatalf("GC 后目录仍超出上限: %d > %d", total, s.MaxTotal)
	}
}

// TestNewResultStoreEmptyDirIsNil 空目录配置时返回 nil（调用方退化为内联截断），不应 panic。
func TestNewResultStoreEmptyDirIsNil(t *testing.T) {
	s, err := NewResultStore("", 0)
	if err != nil {
		t.Fatalf("空目录不应报错: %v", err)
	}
	if s != nil {
		t.Fatal("空目录应返回 nil store")
	}
	if _, _, err := s.Get("20260927/0011223344556677", 0, 0); err == nil {
		t.Fatal("nil store 的 Get 应报错而不是 panic")
	}
}

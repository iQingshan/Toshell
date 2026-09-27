package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// memStore 内存版 ResultWriter，用于不落盘的单元测试。
type memStore struct {
	data   map[string][]byte
	failOn bool
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Put(callID string, raw []byte) (string, int, error) {
	if m.failOn {
		return "", 0, ErrBadHandle
	}
	h := "20260101/deadbeefdeadbeef"
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.data[h] = cp
	return h, len(raw), nil
}

func (m *memStore) Get(handle string, offset, limit int) ([]byte, int, error) {
	d, ok := m.data[handle]
	if !ok {
		return nil, 0, ErrHandleNotFound
	}
	if offset > len(d) {
		offset = len(d)
	}
	end := offset + limit
	if limit <= 0 || end > len(d) {
		end = len(d)
	}
	return d[offset:end], len(d), nil
}

// TestEnvelopeInlineSmallResult 小结果直接内联，不应标注截断。
func TestEnvelopeInlineSmallResult(t *testing.T) {
	env := NewOK("session_list", "call-1", nil)
	out := env.FinalizeInline(newMemStore(), "hello", 1024)
	if !out.IsOK() {
		t.Fatal("状态应为 ok")
	}
	if out.Meta.Truncated {
		t.Fatal("小结果不应被标记为截断")
	}
	if out.Meta.ReturnedBytes != 5 || out.Meta.TotalBytes != 5 {
		t.Fatalf("字节统计不对: returned=%d total=%d", out.Meta.ReturnedBytes, out.Meta.TotalBytes)
	}
	if !out.Meta.Untrusted {
		t.Fatal("工具结果必须恒标记为不可信数据（防间接注入）")
	}
	if out.Data != "hello" {
		t.Fatalf("data = %v, want hello", out.Data)
	}
}

// TestEnvelopeLargeResultIsExternalized 大结果必须外置成句柄，并且**显式**标注截断。
func TestEnvelopeLargeResultIsExternalized(t *testing.T) {
	store := newMemStore()
	big := strings.Repeat("A", 4096)
	env := NewOK("exec", "call-2", nil)
	out := env.FinalizeInline(store, big, 1024)

	if !out.Meta.Truncated {
		t.Fatal("超限结果必须标记 Truncated=true")
	}
	if out.Meta.Handle == "" {
		t.Fatal("超限结果必须给出外置句柄")
	}
	if out.Meta.TruncationNote == "" {
		t.Fatal("截断必须带 TruncationNote（否则模型会把部分当全部）")
	}
	if out.Meta.ReturnedBytes != 0 {
		t.Fatalf("外置后不应再内联正文，returned=%d", out.Meta.ReturnedBytes)
	}
	data, ok := out.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("外置后 data 应为摘要结构，实际 %T", out.Data)
	}
	if data["handle"] != out.Meta.Handle {
		t.Fatalf("摘要里的 handle 与 meta.handle 不一致")
	}
	if data["read_tool"] != "result_read" {
		t.Fatalf("摘要里应指明回读工具为 result_read")
	}
}

// TestEnvelopeNoStoreStillMarksTruncation 没有外置存储时也不能静默截断。
func TestEnvelopeNoStoreStillMarksTruncation(t *testing.T) {
	big := strings.Repeat("B", 2048)
	out := NewOK("exec", "call-3", nil).FinalizeInline(nil, big, 512)
	if !out.Meta.Truncated || out.Meta.TruncationNote == "" {
		t.Fatal("无外置存储时也必须显式标注截断")
	}
	if out.Meta.ReturnedBytes != 512 {
		t.Fatalf("returned = %d, want 512", out.Meta.ReturnedBytes)
	}
}

// TestEnvelopeJSONAlwaysValid 信封序列化必须始终产出合法 JSON。
func TestEnvelopeJSONAlwaysValid(t *testing.T) {
	cases := []*Envelope{
		NewOK("session_list", "c", []string{"a"}),
		NewError("exec", "c", CodeNotAllowed, "工具未在允许列表内"),
		NewError("exec", "c", CodeInternal, "x").WithDetail("细节"),
		NewOK("exec", "c", nil).WithDuration(1500 * time.Millisecond),
	}
	for i, e := range cases {
		var v map[string]interface{}
		if err := json.Unmarshal(e.JSON(), &v); err != nil {
			t.Fatalf("case %d 产出非法 JSON: %v", i, err)
		}
		if v["status"] == nil {
			t.Fatalf("case %d 缺少 status", i)
		}
	}
}

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestInlineForModelSmallStaysRaw 未超限：原样交给模型，不标注截断、不给句柄。
func TestInlineForModelSmallStaysRaw(t *testing.T) {
	raw := `{"sessions":[],"count":0}`
	v := InlineForModel("session_list", "call-1", raw, newMemStore(), 1024)
	if v.Text != raw {
		t.Fatalf("小结果应原样内联，实际 %q", v.Text)
	}
	if v.Truncated || v.Handle != "" {
		t.Fatalf("小结果不该被标记截断/给句柄: truncated=%v handle=%q", v.Truncated, v.Handle)
	}
	if v.TotalBytes != len(raw) || v.ReturnedBytes != len(raw) {
		t.Fatalf("字节统计不对: total=%d returned=%d", v.TotalBytes, v.ReturnedBytes)
	}
	if v.SHA256 != "" {
		t.Fatal("未截断的结果不需要算 sha256（避免给每个小结果白算）")
	}
}

// TestInlineForModelBoundary 分档边界：恰好等于上限算"装得下"，多 1 字节就必须外置。
func TestInlineForModelBoundary(t *testing.T) {
	limit := 64
	exact := strings.Repeat("a", limit)
	if v := InlineForModel("exec", "c", exact, newMemStore(), limit); v.Truncated {
		t.Fatal("恰好等于上限应原样内联（不多花一次外置/回读）")
	}
	over := strings.Repeat("a", limit+1)
	v := InlineForModel("exec", "c", over, newMemStore(), limit)
	if !v.Truncated || v.Handle == "" {
		t.Fatalf("超过上限 1 字节就必须外置: truncated=%v handle=%q", v.Truncated, v.Handle)
	}
}

// TestInlineForModelZeroLimitFallsBackDefault 上限 <=0 时回落 DefaultInlineLimit（口径与配置一致）。
func TestInlineForModelZeroLimitFallsBackDefault(t *testing.T) {
	small := strings.Repeat("a", DefaultInlineLimit)
	if v := InlineForModel("exec", "c", small, nil, 0); v.Truncated {
		t.Fatal("上限为 0 时应按 DefaultInlineLimit 判定为未超限")
	}
	big := strings.Repeat("a", DefaultInlineLimit+1)
	if v := InlineForModel("exec", "c", big, nil, -1); !v.Truncated {
		t.Fatal("上限为负时应按 DefaultInlineLimit 判定为超限")
	}
}

// TestInlineForModelExternalizesAndExplains 超限且外置成功：模型可见文本是合法信封 JSON，
// 摘要里有句柄与"这不是全部、用 result_read 回读"的明确说明。
func TestInlineForModelExternalizesAndExplains(t *testing.T) {
	store := newMemStore()
	raw := `{"image":"` + strings.Repeat("iVBORw0KGgo", 400) + `","format":"png"}`
	v := InlineForModel("screenshot", "call-shot", raw, store, 512)

	if !v.Truncated {
		t.Fatal("超限结果必须 Truncated=true")
	}
	if v.Handle == "" {
		t.Fatal("超限且外置成功必须给出句柄")
	}
	if v.TruncationNote == "" {
		t.Fatal("截断必须带显式说明（否则模型会把部分当全部）")
	}
	if !strings.Contains(v.TruncationNote, "result_read") {
		t.Fatalf("截断说明必须告诉模型怎么回读，实际: %s", v.TruncationNote)
	}
	if v.TotalBytes != len(raw) {
		t.Fatalf("TotalBytes = %d, want %d", v.TotalBytes, len(raw))
	}
	if len(v.SHA256) != 64 {
		t.Fatalf("摘要应为 64 位 hex，实际 %q", v.SHA256)
	}

	// 模型拿到的一定是合法 JSON（这是本次修复的核心性质）。
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(v.Text), &m); err != nil {
		t.Fatalf("模型可见文本不是合法 JSON: %v\ntext=%s", err, v.Text)
	}
	if m["status"] != StatusOK {
		t.Fatalf("status = %v, want ok", m["status"])
	}
	meta, _ := m["meta"].(map[string]interface{})
	if meta == nil || meta["handle"] != v.Handle {
		t.Fatalf("信封 meta.handle 与 ModelView.Handle 不一致: %v", m["meta"])
	}
	if meta["truncated"] != true {
		t.Fatal("信封 meta.truncated 必须为 true")
	}
	data, _ := m["data"].(map[string]interface{})
	if data == nil || data["handle"] != v.Handle {
		t.Fatalf("摘要里必须带句柄: %v", m["data"])
	}
	if data["read_tool"] != "result_read" {
		t.Fatalf("摘要里必须指明回读工具: %v", data)
	}
	// 外置后不内联正文：模型文本里不能出现被切碎的原图 base64。
	if strings.Contains(v.Text, "iVBORw0KGgoiVBORw0KGgo") {
		t.Fatal("外置后不应把原文正文塞进模型文本")
	}
}

// TestInlineForModelPutFailureStillLegalJSON 外置失败（磁盘写不进去）时，
// 绝不允许退化成 raw[:limit] 这种坏 JSON 切片。
func TestInlineForModelPutFailureStillLegalJSON(t *testing.T) {
	store := newMemStore()
	store.failOn = true // Put 恒失败 → 走"外置失败"分支
	// 故意用一个"半截就非法"的 JSON：模拟截图 base64 被切在中间的场景。
	raw := `{"image":"` + strings.Repeat("QUJDRA", 300)

	v := InlineForModel("screenshot", "c", raw, store, 256)
	if !v.Truncated {
		t.Fatal("外置失败也必须标注截断")
	}
	if v.Handle != "" {
		t.Fatal("外置失败时不应给出（不存在的）句柄")
	}
	if v.TruncationNote == "" {
		t.Fatal("外置失败必须说明原因，不能静默")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(v.Text), &m); err != nil {
		t.Fatalf("外置失败时模型可见文本仍必须是合法 JSON: %v\ntext=%s", err, v.Text)
	}
	meta, _ := m["meta"].(map[string]interface{})
	if meta["truncated"] != true {
		t.Fatal("信封必须带 truncated=true")
	}
	// 预览必须是"能看懂是预览"的显式字段，而不是无声的半截正文。
	data, _ := m["data"].(map[string]interface{})
	if data["truncated_preview"] == nil {
		t.Fatalf("预览应放在 truncated_preview 字段里: %v", m["data"])
	}
	if !strings.Contains(strings.ToLower(v.Text), "truncated_preview") {
		t.Fatal("预览标记必须出现在文本里")
	}
}

// TestInlineForModelNoStoreExplainsWhy 未配置外置存储：同样要给合法 JSON + 明确告知无法回读。
func TestInlineForModelNoStoreExplainsWhy(t *testing.T) {
	raw := `{"output":"` + strings.Repeat("x", 4096) + `"}`
	v := InlineForModel("exec", "c", raw, nil, 512)

	if !v.Truncated || v.Handle != "" {
		t.Fatalf("无存储时应截断且无句柄: truncated=%v handle=%q", v.Truncated, v.Handle)
	}
	if !strings.Contains(v.TruncationNote, "未启用结果外置存储") {
		t.Fatalf("必须说明是「未配置存储」而非「已外置」：%s", v.TruncationNote)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(v.Text), &m); err != nil {
		t.Fatalf("无存储时模型可见文本仍必须是合法 JSON: %v", err)
	}
}

// TestInlineForModelPreviewKeepsUTF8Boundary 预览按字节切时不得把多字节字符切成两半
// （否则 json.Marshal 会替换成 U+FFFD，内容被无故改写）。
func TestInlineForModelPreviewKeepsUTF8Boundary(t *testing.T) {
	raw := strings.Repeat("中文", 400) // 每字 3 字节
	v := InlineForModel("exec", "c", raw, nil, 501)
	if !v.Truncated {
		t.Fatal("应判为超限")
	}
	if strings.Contains(v.Text, "\ufffd") {
		t.Fatal("预览出现了 U+FFFD 替换字符，说明切在了字符中间")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(v.Text), &m); err != nil {
		t.Fatalf("非法 JSON: %v", err)
	}
}

// TestInlineForModelReadBackRoundTrip 分页回读往返：外置 → 按 offset/limit 分页 → 拼回原文。
// 这条链路是"回读闭环"的最小可验证形态（真实调用走 api.invokeTool 的 result_read）。
func TestInlineForModelReadBackRoundTrip(t *testing.T) {
	store := newMemStore()
	raw := strings.Repeat("0123456789", 300) // 3000 字节
	v := InlineForModel("exec", "c", raw, store, 256)
	if v.Handle == "" {
		t.Fatal("应已外置")
	}

	var got []byte
	offset := 0
	for {
		chunk, total, err := store.Get(v.Handle, offset, 512)
		if err != nil {
			t.Fatalf("回读失败: %v", err)
		}
		if total != len(raw) {
			t.Fatalf("total = %d, want %d", total, len(raw))
		}
		if len(chunk) == 0 {
			break
		}
		got = append(got, chunk...)
		offset += len(chunk)
		if offset >= total {
			break
		}
	}
	if string(got) != raw {
		t.Fatalf("分页回读拼接结果与原文不一致（got %d 字节, want %d）", len(got), len(raw))
	}
}

// TestInlineForModelRejectsTraversalViaStore 句柄是外部输入：经本函数外置的结果，
// 用穿越型句柄必须读不到（白名单在 ResultStore.resolve 里，这里做一次端到端确认）。
func TestInlineForModelRejectsTraversalViaStore(t *testing.T) {
	s := newTestStore(t)
	raw := strings.Repeat("z", 2048)
	v := InlineForModel("exec", "c", raw, s, 128)
	if v.Handle == "" {
		t.Fatal("应已外置")
	}
	if chunk, _, err := s.Get(v.Handle, 0, 0); err != nil || string(chunk) != raw {
		t.Fatalf("合法句柄应能读回: err=%v", err)
	}
	for _, bad := range []string{
		"20260927/../../configs/server.yaml",
		"../../../etc/passwd",
		"20260927/" + strings.Repeat("a", 16) + "/../../x",
	} {
		if _, _, err := s.Get(bad, 0, 0); err == nil {
			t.Fatalf("穿越型句柄 %q 竟被接受", bad)
		}
	}
}

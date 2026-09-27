package builder

import (
	"bytes"
	"strings"
	"testing"
)

// 本测试**纯逻辑**：只在内存里构造假载荷字节，不读任何外部文件、不写盘、
// 不执行任何二进制（本机安全软件会删除/拦截新生成的 PE）。
//
// 覆盖点：
//  1. 含三类特征的假数据 → 擦除后特征串全部消失、长度不变、入参不被改动；
//  2. 干净数据 → 原样返回、removed 为空；
//  3. 幂等：连续调用两次结果一致，第二次不再记录；
//  4. 边界：空输入 / nil / 只有魔数没有版本串 / 版本串远离魔数（不该被擦）/
//     "go1.x" 非版本串 / `Go build ID:` 后不是规范 ID 形态。

// hardenFixture 拼一段贴近真实布局的假载荷：
//
//	填充 + buildinfo 魔数 + 16 字节头 + 长度前缀 + go1.20.14 + module 信息
//	+ 填充 + `Go build ID: "abcdef"` + 换行 + 填充
func hardenFixture() (data []byte, magicAt, versionAt, buildIDAt int) {
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0xAA}, 64))

	magicAt = b.Len()
	b.WriteString(goBuildInfoMagic) // "\xff Go buildinf:"（14 字节）
	b.Write([]byte{0x08, 0x02})     // 指针宽度 8 / 标志（新格式）
	b.Write(make([]byte, 16))       // 两个保留指针字，新格式下为 0

	versionAt = b.Len() + 1 // 长度前缀之后
	b.WriteByte(0x09)       // 变长长度前缀：9
	b.WriteString("go1.20.14")
	b.Write([]byte{0x04, 'p', 'a', 't', 'h', 0x09, 't', 'o', 's', 'h', 'e', 'l', 'l'})
	b.Write(bytes.Repeat([]byte{0xBB}, 200))

	buildIDAt = b.Len()
	b.WriteString(`Go build ID: "abcdef"` + "\n")
	b.Write(bytes.Repeat([]byte{0xCC}, 64))

	return b.Bytes(), magicAt, versionAt, buildIDAt
}

// TestScrubGoFingerprint_RemovesMarkers 三类特征都要被擦掉，且长度、入参都不变。
func TestScrubGoFingerprint_RemovesMarkers(t *testing.T) {
	in, magicAt, versionAt, buildIDAt := hardenFixture()
	before := append([]byte(nil), in...) // 快照，用于断言入参未被改动

	out, removed := ScrubGoFingerprint(in)

	if len(out) != len(in) {
		t.Fatalf("长度必须不变：in=%d out=%d", len(in), len(out))
	}
	if !bytes.Equal(in, before) {
		t.Fatalf("入参被修改了：ScrubGoFingerprint 必须是只读的")
	}
	if len(removed) == 0 {
		t.Fatalf("removed 不应为空")
	}

	for _, marker := range []string{goBuildInfoMagic, "go1.20.14", goBuildIDPrefix, "abcdef"} {
		if bytes.Contains(out, []byte(marker)) {
			t.Errorf("擦除后仍能找到特征串 %q", marker)
		}
	}

	// 长度不变 + 偏移不变：被擦的位置必须全部是 0x00。
	for _, span := range [][2]int{
		{magicAt, magicAt + goBuildInfoHeaderLen},
		{versionAt, versionAt + len("go1.20.14")},
		{buildIDAt, buildIDAt + len(`Go build ID: "abcdef"`) + 1}, // 含行尾换行
	} {
		for i := span[0]; i < span[1]; i++ {
			if out[i] != 0x00 {
				t.Fatalf("偏移 0x%x 应为 0x00，实际 0x%02x", i, out[i])
			}
		}
	}

	// 擦除只动命中区间：相邻字节保持原值（首字节 0xAA、module 信息区 0xBB）。
	if out[magicAt-1] != 0xAA {
		t.Errorf("魔数前的填充被误改：0x%02x", out[magicAt-1])
	}
	if out[buildIDAt+len(`Go build ID: "abcdef"`)+1] != 0xCC {
		t.Errorf("build ID 之后的填充被误改")
	}

	// 日志文本要能说明擦了什么（版本号是"证据"，必须留在 removed 里）。
	joined := strings.Join(removed, "；")
	for _, want := range []string{"Go buildinf 魔数", "go1.20.14", "Go build ID"} {
		if !strings.Contains(joined, want) {
			t.Errorf("removed 说明里缺少 %q，实际：%s", want, joined)
		}
	}
}

// TestScrubGoFingerprint_CleanInput 没有标记时必须原样返回、removed 为空。
func TestScrubGoFingerprint_CleanInput(t *testing.T) {
	in := []byte("MZ\x90\x00 this is just an ordinary blob, no go markers here at all")
	in = append(in, bytes.Repeat([]byte{0x00, 0xFF, 0x7F, 0x01}, 128)...)
	before := append([]byte(nil), in...)

	out, removed := ScrubGoFingerprint(in)

	if len(removed) != 0 {
		t.Errorf("干净输入不应有任何擦除记录，实际：%v", removed)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("干净输入必须原样返回")
	}
	if !bytes.Equal(in, before) {
		t.Errorf("干净输入也不应被改动")
	}
	if len(out) != len(in) {
		t.Errorf("长度必须不变：in=%d out=%d", len(in), len(out))
	}
}

// TestScrubGoFingerprint_Idempotent 连续两次调用结果一致、第二次不再记录。
func TestScrubGoFingerprint_Idempotent(t *testing.T) {
	in, _, _, _ := hardenFixture()

	out1, removed1 := ScrubGoFingerprint(in)
	out2, removed2 := ScrubGoFingerprint(out1)

	if len(removed1) == 0 {
		t.Fatalf("第一次调用应该有擦除记录")
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("幂等性被破坏：第二次输出与第一次不同")
	}
	if len(removed2) != 0 {
		t.Errorf("已擦除的输入再调用不应重复记录，实际：%v", removed2)
	}
	if len(out2) != len(in) {
		t.Errorf("长度必须不变：in=%d out2=%d", len(in), len(out2))
	}
}

// TestScrubGoFingerprint_EmptyInput 空输入 / nil 输入的边界。
func TestScrubGoFingerprint_EmptyInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	} {
		out, removed := ScrubGoFingerprint(tc.in)
		if len(out) != 0 {
			t.Errorf("%s：输出长度应为 0，实际 %d", tc.name, len(out))
		}
		if len(removed) != 0 {
			t.Errorf("%s：removed 应为空，实际 %v", tc.name, removed)
		}
	}
}

// TestScrubGoFingerprint_MagicWithoutVersion 只有魔数、窗口内没有版本串。
func TestScrubGoFingerprint_MagicWithoutVersion(t *testing.T) {
	in := append([]byte{}, bytes.Repeat([]byte{0x11}, 32)...)
	magicAt := len(in)
	in = append(in, []byte(goBuildInfoMagic)...)
	in = append(in, bytes.Repeat([]byte{0x22}, 128)...)

	out, removed := ScrubGoFingerprint(in)

	if len(out) != len(in) {
		t.Fatalf("长度必须不变：in=%d out=%d", len(in), len(out))
	}
	if bytes.Contains(out, []byte(goBuildInfoMagic)) {
		t.Errorf("魔数没被擦掉")
	}
	if len(removed) != 1 {
		t.Errorf("只应记录魔数一项，实际 %d 项：%v", len(removed), removed)
	}
	if out[magicAt+goBuildInfoHeaderLen] != 0x22 {
		t.Errorf("魔数之后的填充被误擦")
	}
}

// TestScrubGoFingerprint_MagicAtTail 魔数贴在文件末尾（不足 16 字节头）时不得越界 panic。
func TestScrubGoFingerprint_MagicAtTail(t *testing.T) {
	in := append(bytes.Repeat([]byte{0x33}, 16), []byte(goBuildInfoMagic)...) // 尾部仅 14 字节

	out, removed := ScrubGoFingerprint(in)

	if len(out) != len(in) {
		t.Fatalf("长度必须不变：in=%d out=%d", len(in), len(out))
	}
	if bytes.Contains(out, []byte(goBuildInfoMagic)) {
		t.Errorf("尾部魔数没被擦掉")
	}
	if len(removed) != 1 {
		t.Errorf("应记录一项，实际 %v", removed)
	}
}

// TestScrubGoFingerprint_VersionOutsideWindow 远离魔数的版本串**不应**被擦除（避免误伤）。
func TestScrubGoFingerprint_VersionOutsideWindow(t *testing.T) {
	const far = "go1.20.14"

	t.Run("版本串在魔数之后但超出 512 字节窗口", func(t *testing.T) {
		var b bytes.Buffer
		b.Write([]byte(goBuildInfoMagic))
		b.Write([]byte{0x08, 0x02})
		b.Write(make([]byte, 16))
		b.Write(bytes.Repeat([]byte{0x44}, goBuildInfoWindow)) // 把版本串推到窗口之外
		farAt := b.Len()
		b.WriteString(far)
		b.Write(bytes.Repeat([]byte{0x55}, 64))
		in := b.Bytes()

		out, _ := ScrubGoFingerprint(in)

		if len(out) != len(in) {
			t.Fatalf("长度必须不变：in=%d out=%d", len(in), len(out))
		}
		if !bytes.Equal(out[farAt:farAt+len(far)], []byte(far)) {
			t.Errorf("窗口之外的版本串被误擦：%q", out[farAt:farAt+len(far)])
		}
		if !bytes.Contains(out, []byte(far)) {
			t.Errorf("窗口之外的版本串整个消失了")
		}
	})

	t.Run("版本串在魔数之前", func(t *testing.T) {
		var b bytes.Buffer
		verAt := b.Len()
		b.WriteString(far)
		b.Write(bytes.Repeat([]byte{0x66}, 64))
		b.Write([]byte(goBuildInfoMagic))
		b.Write([]byte{0x04, 0x02})
		b.Write(make([]byte, 16))
		b.Write(bytes.Repeat([]byte{0x77}, 64))
		in := b.Bytes()

		out, _ := ScrubGoFingerprint(in)

		if !bytes.Equal(out[verAt:verAt+len(far)], []byte(far)) {
			t.Errorf("魔数之前的版本串被误擦：%q", out[verAt:verAt+len(far)])
		}
	})

	t.Run("窗口内 go1. 后面不是数字", func(t *testing.T) {
		var b bytes.Buffer
		b.Write([]byte(goBuildInfoMagic))
		b.Write([]byte{0x08, 0x02})
		b.Write(make([]byte, 16))
		b.WriteString("go1.x-not-a-version")
		b.Write(bytes.Repeat([]byte{0x88}, 32))
		in := b.Bytes()

		out, _ := ScrubGoFingerprint(in)

		if !bytes.Contains(out, []byte("go1.x-not-a-version")) {
			t.Errorf("非版本串的 go1.x 被误擦")
		}
	})

	t.Run("魔数窗口内版本串被擦、窗口外同串保留", func(t *testing.T) {
		var b bytes.Buffer
		b.Write([]byte(goBuildInfoMagic))
		b.Write([]byte{0x08, 0x02})
		b.Write(make([]byte, 16))
		b.WriteByte(0x09)
		b.WriteString(far) // 魔数 +33，窗口内
		b.Write(bytes.Repeat([]byte{0x99}, goBuildInfoWindow))
		b.WriteString(far) // 窗口外，必须保留
		in := b.Bytes()

		out, _ := ScrubGoFingerprint(in)

		if !bytes.Contains(out, []byte(far)) {
			t.Errorf("窗口外的版本串应保留")
		}
		if !bytes.Contains(out, []byte{0x99, 0x99, 0x99}) {
			t.Errorf("窗口外的填充被误擦")
		}
	})
}

// TestScrubGoBuildIDPrefix 前缀后面不是规范 ID 形态时只清前缀，不乱擦后续数据。
func TestScrubGoBuildIDPrefix(t *testing.T) {
	in := []byte("head|Go build ID: not-quoted-payload|tail")
	out, removed := ScrubGoFingerprint(in)

	if len(out) != len(in) {
		t.Fatalf("长度必须不变")
	}
	if bytes.Contains(out, []byte(goBuildIDPrefix)) {
		t.Errorf("前缀没被擦掉")
	}
	if !bytes.Contains(out, []byte("not-quoted-payload|tail")) {
		t.Errorf("非规范形态下，后续数据被误擦")
	}
	if len(removed) != 1 || !strings.Contains(removed[0], "仅前缀") {
		t.Errorf("应只记录前缀一项并说明原因，实际：%v", removed)
	}

	// 规范形态：ID 与行尾换行一起清掉。
	in2 := []byte("head|Go build ID: \"aB3_-/xY=\"" + "\n" + "tail")
	out2, removed2 := ScrubGoFingerprint(in2)
	if bytes.Contains(out2, []byte("aB3_-/xY=")) {
		t.Errorf("规范 ID 内容应一并擦除")
	}
	// 行尾换行按设计一并清掉，但 ID 之后的数据必须原样保留。
	if !bytes.Contains(out2, []byte("tail")) {
		t.Errorf("ID 之后的数据被误擦")
	}
	if len(removed2) != 1 || !strings.Contains(removed2[0], "含引号内的 ID") {
		t.Errorf("规范形态的记录应说明含 ID，实际：%v", removed2)
	}
}

// ─── 全文件版本串擦除（v1.4.0 S3：锚定窗口扫不到的那一份）────────────────────

// TestScrubGoVersionStrings_RemovesOutsideWindow 没有 buildinfo 魔数时，锚定窗口版擦除
// 完全失效（窗口由魔数反推），而 `runtime.buildVersion` 那份版本串还在 —— 这正是实测里
// exe 与 dll 都残留 1 次 go1.20.14 的原因。全文件版必须能收掉它。
func TestScrubGoVersionStrings_RemovesOutsideWindow(t *testing.T) {
	in := []byte("head\x00\x00go1.20.14\x00\x00middle\x00\x00tail")
	before := append([]byte(nil), in...)

	out, removed := ScrubGoVersionStrings(in)

	if len(out) != len(in) {
		t.Fatalf("长度必须不变：in=%d out=%d", len(in), len(out))
	}
	if !bytes.Equal(in, before) {
		t.Fatal("入参被修改：必须是只读的")
	}
	if bytes.Contains(out, []byte("go1.20.14")) {
		t.Error("版本串仍残留")
	}
	if !bytes.Contains(out, []byte("head")) || !bytes.Contains(out, []byte("tail")) {
		t.Error("相邻数据被误擦")
	}
	if len(removed) != 1 || !strings.Contains(removed[0], "全文件") {
		t.Fatalf("记录应说明是全文件扫描，实际：%v", removed)
	}
	// 幂等：再擦一次不应有命中。
	if _, again := ScrubGoVersionStrings(out); len(again) != 0 {
		t.Fatalf("幂等性被破坏，第二次仍擦到：%v", again)
	}
}

// TestScrubGoVersionStrings_KeepsLookalikes 只擦"go1." 紧跟数字的形态：
// 普通文本 go1.x / go1. / go1 一律不动，避免误伤业务字符串。
//
// 注意 `go1.2.3x` 这种"版本号后缀跟着字母"的形态：规则会清掉其中的 `go1.2.3`
// （数字/点连续段），末尾的 `x` 保留 —— 这与既有的窗口版 scrubGoVersions 行为**完全一致**
// （见 TestScrubGoFingerprint_VersionOutsideWindow），两条路径必须同规则，否则同一份产物
// 走 exe 与 dll 两条路径会得到不同的擦除结果。
func TestScrubGoVersionStrings_KeepsLookalikes(t *testing.T) {
	in := []byte("go1.x go1. go1 GO1.2 end")
	out, removed := ScrubGoVersionStrings(in)
	for _, keep := range []string{"go1.x", "go1. ", "go1 ", "GO1.2", "end"} {
		if !bytes.Contains(out, []byte(keep)) {
			t.Errorf("误擦了普通文本 %q：%q", keep, out)
		}
	}
	if len(removed) != 0 {
		t.Fatalf("这段文本里没有版本串，不该擦到任何东西：%v", removed)
	}

	// 版本号后缀字母：数字段被清、后缀保留（与窗口版同规则）。
	out2, removed2 := ScrubGoVersionStrings([]byte("go1.2.3x"))
	if len(removed2) != 1 {
		t.Fatalf("应清掉 1 处版本串，实际 %v", removed2)
	}
	if !bytes.Equal(out2, []byte("\x00\x00\x00\x00\x00\x00\x00x")) {
		t.Fatalf("应只清零 go1.2.3 这 7 字节，实际 %q", out2)
	}
}

// TestScrubGoVersionStrings_Empty 空输入不 panic、返回空。
func TestScrubGoVersionStrings_Empty(t *testing.T) {
	out, removed := ScrubGoVersionStrings(nil)
	if len(out) != 0 || len(removed) != 0 {
		t.Fatalf("空输入应原样返回：out=%v removed=%v", out, removed)
	}
}

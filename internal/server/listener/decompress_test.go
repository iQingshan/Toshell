package listener

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// ─── 审计 M7：gzip 解压上限（压缩炸弹）─────────────────────────────────────

// TestDecompressDataNormal 正常 gzip 帧必须照常解压（上限不能误伤正常路径）。
func TestDecompressDataNormal(t *testing.T) {
	want := bytes.Repeat([]byte("toshell-normal-frame;"), 4096) // ~80 KiB，> 1024 才会压缩

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := decompressData(buf.Bytes())
	if err != nil {
		t.Fatalf("正常 gzip 解压失败: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("解压结果不一致: got %d bytes, want %d", len(got), len(want))
	}
}

// TestDecompressDataPassthrough 非 gzip / 空输入保持原样（既有行为不变）。
func TestDecompressDataPassthrough(t *testing.T) {
	cases := [][]byte{nil, {}, []byte("not-gzip"), {0x1f}}
	for _, in := range cases {
		got, err := decompressData(in)
		if err != nil {
			t.Fatalf("非 gzip 输入不应报错: %v", err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("非 gzip 输入应原样返回: got %x want %x", got, in)
		}
	}
}

// TestDecompressDataRejectsCompressionBomb 构造一个"小输入、解压后 > 32 MiB"的
// gzip（全 0 字节 40 MiB）：必须在 32 MiB 处停下并返回明确错误，而不是把
// GB 级数据读进内存（否则测试机自己就 OOM 了）。
func TestDecompressDataRejectsCompressionBomb(t *testing.T) {
	const total = 40 << 20 // 40 MiB，超过 maxDecompressed(32 MiB)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	chunk := make([]byte, 1<<20) // 全 0，压缩率极高
	for i := 0; i < total/len(chunk); i++ {
		if _, err := gw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	// 压缩后应远小于 32 MiB（否则这个用例证明不了"小输入大膨胀"）。
	if buf.Len() > 1<<20 {
		t.Fatalf("压缩后体积 %d 字节，预期远小于 1 MiB", buf.Len())
	}

	got, err := decompressData(buf.Bytes())
	if err == nil {
		t.Fatalf("解压后 %d 字节（超过 %d 上限）必须报错", len(got), maxDecompressed)
	}
	if !errors.Is(err, errDecompressedTooLarge) {
		t.Fatalf("应返回 errDecompressedTooLarge 哨兵错误，got %v", err)
	}
	if got != nil {
		t.Fatalf("超限时不得返回部分解压数据（静默截断），got %d bytes", len(got))
	}
}

// TestMaxDecompressedValue 锁死上限值：32 MiB，且必须是帧上限（16 MiB）的 2 倍。
func TestMaxDecompressedValue(t *testing.T) {
	if maxDecompressed != 32<<20 {
		t.Fatalf("maxDecompressed = %d，want %d (32 MiB)", maxDecompressed, 32<<20)
	}
	const maxFrameSize = 16 * 1024 * 1024
	if maxDecompressed <= maxFrameSize {
		t.Fatalf("解压上限必须大于线上帧上限，否则正常大帧会被误杀")
	}
}

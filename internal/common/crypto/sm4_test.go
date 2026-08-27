package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// 测试用 cipher.Block 包装，供与标准库 crypto/cipher.NewGCM 交叉校验。
type sm4TestBlock struct{ rk [32]uint32 }

func (b *sm4TestBlock) BlockSize() int                       { return 16 }
func (b *sm4TestBlock) Encrypt(dst, src []byte)              { sm4BlockEncrypt(&b.rk, dst, src) }
func (b *sm4TestBlock) Decrypt(dst, src []byte)              { sm4BlockDecrypt(&b.rk, dst, src) }

// 官方 GB/T 32907 标准测试向量
func TestSM4BlockVector(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	pt, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	want, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")

	rk := sm4ExpandKey(key)
	out := make([]byte, 16)
	sm4BlockEncrypt(&rk, out, pt)
	if !bytes.Equal(out, want) {
		t.Fatalf("SM4 encrypt mismatch:\n got %x\nwant %x", out, want)
	}
}

// 解密向量：解密密文应还原明文
func TestSM4DecryptVector(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	pt, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ct, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")

	rk := sm4ExpandKey(key)
	out := make([]byte, 16)
	sm4BlockDecrypt(&rk, out, ct)
	if !bytes.Equal(out, pt) {
		t.Fatalf("SM4 decrypt mismatch:\n got %x\nwant %x", out, pt)
	}
}

// 加密 100 万次的标准向量（GB/T 32907 附录 A 示例 2）
func TestSM4MillionVector(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	pt, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	want, _ := hex.DecodeString("595298c7c6fd271f0402f804c33d3f66")

	rk := sm4ExpandKey(key)
	block := make([]byte, 16)
	copy(block, pt)
	for i := 0; i < 1000000; i++ {
		out := make([]byte, 16)
		sm4BlockEncrypt(&rk, out, block)
		copy(block, out)
	}
	if !bytes.Equal(block, want) {
		t.Fatalf("SM4 1e6 encrypt mismatch:\n got %x\nwant %x", block, want)
	}
}

// 自实现 GCM 与标准库 crypto/cipher.NewGCM 交叉校验。
func TestSM4GCMAgainstStdlib(t *testing.T) {
	key := DeriveSM4Key([]byte("12345678901234567890123456789012"))
	aead, err := cipher.NewGCM(&sm4TestBlock{rk: sm4ExpandKey(key)})
	if err != nil {
		t.Fatal(err)
	}

	for _, size := range []int{0, 1, 15, 16, 17, 1000, 65536} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}

		want := aead.Seal(nil, nonce, plain, nil) // ct||tag

		buf := make([]byte, len(plain), len(plain)+16)
		copy(buf, plain)
		got, err := sm4GCMSeal(buf, key, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size=%d: manual GCM seal != stdlib", size)
		}

		// 标准库解密自实现密文
		pt2, err := aead.Open(nil, nonce, got, nil)
		if err != nil || !bytes.Equal(pt2, plain) {
			t.Fatalf("size=%d: stdlib open of manual seal failed", size)
		}

		// 自实现解密标准库密文
		pt3, ok := sm4GCMOpen(want, key, nonce)
		if !ok || !bytes.Equal(pt3, plain) {
			t.Fatalf("size=%d: manual open of stdlib seal failed", size)
		}
	}
}

// 认证标签被篡改时必须解密失败。
func TestSM4GCMTamper(t *testing.T) {
	key := DeriveSM4Key([]byte("12345678901234567890123456789012"))
	nonce := make([]byte, 12)
	rand.Read(nonce)
	plain := []byte("hello sm4-gcm tamper detection")

	buf := make([]byte, len(plain), len(plain)+16)
	copy(buf, plain)
	sealed, err := sm4GCMSeal(buf, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	sealed[5] ^= 0xFF // 篡改密文

	if _, ok := sm4GCMOpen(sealed, key, nonce); ok {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

// 隧道封装往返。
func TestSM4TunnelRoundTrip(t *testing.T) {
	key := DeriveSM4Key([]byte("12345678901234567890123456789012"))
	plain := []byte("hello toshell tunnel sm4-gcm roundtrip 0123456789")
	enc, err := SM4EncryptTunnel(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 12+len(plain)+16 {
		t.Fatalf("bad ciphertext length %d", len(enc))
	}
	dec, err := SM4DecryptTunnel(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("roundtrip mismatch: %q vs %q", dec, plain)
	}
}

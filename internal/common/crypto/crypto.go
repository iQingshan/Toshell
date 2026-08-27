package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type Encryptor struct {
	aead       cipher.AEAD
	cipherType string
}

func NewAESEncryptor(key []byte) (*Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		aead:       gcm,
		cipherType: "aes-256-gcm",
	}, nil
}

func NewChaChaEncryptor(key []byte) (*Encryptor, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		aead:       aead,
		cipherType: "chacha20-poly1305",
	}, nil
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ciphertext, nil)
}

func (e *Encryptor) GetCipherType() string {
	return e.cipherType
}

type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [32]byte
	var publicKey [32]byte

	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (kp *KeyPair) DeriveSharedSecret(peerPublicKey [32]byte) []byte {
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &kp.PrivateKey, &peerPublicKey)

	hkdf := hkdf.New(sha256.New, sharedSecret[:], nil, []byte("toshell-session"))
	key := make([]byte, 32)
	hkdf.Read(key)

	return key
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

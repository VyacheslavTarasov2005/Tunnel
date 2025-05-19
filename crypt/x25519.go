package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
)

// GenerateKeyPair возвращает приватный и публичный ключи для Curve25519.
func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// DeriveSymmetricKey устаревшая схема DH → SHA256.
func DeriveSymmetricKey(privateKey, peerPublicKey []byte) []byte {
	shared, _ := curve25519.X25519(privateKey, peerPublicKey)
	h := sha256.Sum256(shared)
	return h[:]
}

// EncryptSymmetricKey выполняет гибридное шифрование symmKey c генерацией eph-ключа, выводит ephPub||nonce||ciphertext.
func EncryptSymmetricKey(symmKey, peerPub, priv []byte) ([]byte, error) {
	// 1) Сгенерировать эпхемеральный ключ
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	// 2) Вычислить общий секрет
	shared, err := curve25519.X25519(ephPriv, peerPub)
	if err != nil {
		return nil, err
	}
	// 3) Развернуть из shared AES-ключ через HKDF-SHA256
	hk := hkdf.New(sha256.New, shared, nil, []byte("hybrid key"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, aesKey); err != nil {
		return nil, err
	}
	// 4) Шифрование симметричного ключа AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, symmKey, nil)
	// 5) Упаковать ephPub||nonce||ct
	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptSymmetricKey расшифровывает пакет ephPub||nonce||ciphertext и возвращает оригинальный symmKey.
func DecryptSymmetricKey(data, peerPub, priv []byte) ([]byte, error) {
	if len(data) < 32+12 {
		return nil, errors.New("invalid encrypted symmetric key")
	}
	ephPub := data[:32]
	nonce := data[32 : 32+12]
	ct := data[32+12:]
	// 1) Вычислить shared = X25519(priv, ephPub)
	shared, err := curve25519.X25519(priv, ephPub)
	if err != nil {
		return nil, err
	}
	// 2) Получить тот же AES-ключ через HKDF
	hk := hkdf.New(sha256.New, shared, nil, []byte("hybrid key"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, aesKey); err != nil {
		return nil, err
	}
	// 3) AES-GCM‐дешифровка
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

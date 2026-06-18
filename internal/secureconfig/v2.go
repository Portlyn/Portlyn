package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
)

const (
	EncryptedPrefixV2 = "enc:v2:"
	argon2Time        = 2
	argon2Memory      = 64 * 1024
	argon2Threads     = 4
	argon2KeyLen      = 32
	argon2SaltLen     = 16
	argon2CacheMax    = 512
)

var (
	argon2KeyCache   sync.Map
	argon2CacheCount atomic.Int64
)

func argon2CacheKey(secret, salt []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(secret)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(salt)
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

func deriveArgon2Key(secret, salt []byte) []byte {
	cacheKey := argon2CacheKey(secret, salt)
	if value, ok := argon2KeyCache.Load(cacheKey); ok {
		return value.([]byte)
	}
	derived := argon2.IDKey(secret, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if argon2CacheCount.Load() >= argon2CacheMax {
		argon2KeyCache.Range(func(k, _ any) bool {
			argon2KeyCache.Delete(k)
			return true
		})
		argon2CacheCount.Store(0)
	}
	if _, loaded := argon2KeyCache.LoadOrStore(cacheKey, derived); !loaded {
		argon2CacheCount.Add(1)
	}
	return derived
}

func EncryptStringV2(secret []byte, value string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := deriveArgon2Key(secret, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append([]byte{}, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return EncryptedPrefixV2 + base64.StdEncoding.EncodeToString(payload), nil
}

func DecryptStringV2(secret []byte, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if !IsEncryptedValueV2(trimmed) {
		return "", fmt.Errorf("value is not encrypted with %s", EncryptedPrefixV2)
	}
	encoded := strings.TrimPrefix(trimmed, EncryptedPrefixV2)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < argon2SaltLen+12 {
		return "", fmt.Errorf("encrypted value too short")
	}
	salt := raw[:argon2SaltLen]
	key := deriveArgon2Key(secret, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < argon2SaltLen+nonceSize {
		return "", fmt.Errorf("encrypted value too short")
	}
	nonce := raw[argon2SaltLen : argon2SaltLen+nonceSize]
	ciphertext := raw[argon2SaltLen+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func IsEncryptedValueV2(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), EncryptedPrefixV2)
}

func IsEncryptedValue(value string) bool {
	return IsEncryptedValueV1(value) || IsEncryptedValueV2(value)
}

func EncryptStringLatest(secret []byte, value string) (string, error) {
	return EncryptStringV2(secret, value)
}

func EncryptBytesV2(secret, value []byte) ([]byte, error) {
	encoded, err := EncryptStringV2(secret, string(value))
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

func IsEncryptedBytesV2(value []byte) bool { return IsEncryptedValueV2(string(value)) }
func IsEncryptedBytes(value []byte) bool   { return IsEncryptedValue(string(value)) }

func DecryptBytesAuto(secrets [][]byte, value []byte) ([]byte, error) {
	plaintext, err := DecryptStringAuto(secrets, string(value))
	if err != nil {
		return nil, err
	}
	return []byte(plaintext), nil
}

func decryptStringV2WithSecrets(secrets [][]byte, value string) (string, error) {
	var lastErr error
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		out, err := DecryptStringV2(secret, value)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no secrets available for v2 decryption")
}

func DecryptStringAuto(secrets [][]byte, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if IsEncryptedValueV2(trimmed) {
		return decryptStringV2WithSecrets(secrets, trimmed)
	}
	if IsEncryptedValueV1(trimmed) {
		return DecryptStringV1WithSecrets(secrets, trimmed)
	}
	return "", fmt.Errorf("value is not an encrypted secureconfig value")
}

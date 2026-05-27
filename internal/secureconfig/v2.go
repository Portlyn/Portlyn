package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	EncryptedPrefixV2 = "enc:v2:"
	argon2Time        = 1
	argon2Memory      = 64 * 1024
	argon2Threads     = 4
	argon2KeyLen      = 32
	argon2SaltLen     = 16
)

var argon2KeyCache sync.Map

type argon2CacheKey struct {
	secret string
	salt   string
}

func deriveArgon2Key(secret, salt []byte) []byte {
	cacheKey := argon2CacheKey{secret: string(secret), salt: string(salt)}
	if value, ok := argon2KeyCache.Load(cacheKey); ok {
		return value.([]byte)
	}
	derived := argon2.IDKey(secret, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	argon2KeyCache.Store(cacheKey, derived)
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

// EncryptStringLatest produces the strongest current format (v2).
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

// DecryptStringAuto handles both v1 (sha256-derived) and v2 (argon2id-derived) formats,
// trying each provided secret. Use this for migration paths.
func DecryptStringAuto(secrets [][]byte, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if IsEncryptedValueV2(trimmed) {
		var lastErr error
		for _, secret := range secrets {
			if len(secret) == 0 {
				continue
			}
			out, err := DecryptStringV2(secret, trimmed)
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
	if IsEncryptedValueV1(trimmed) {
		return DecryptStringV1WithSecrets(secrets, trimmed)
	}
	return "", fmt.Errorf("value is not an encrypted secureconfig value")
}

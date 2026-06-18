package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const EncryptedPrefixV1 = "enc:v1:"

func EncryptJSON(secret []byte, value map[string]string) (string, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return EncryptString(secret, string(bytes))
}

func DecryptJSON(secret []byte, value string) (map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return map[string]string{}, nil
	}
	plaintext, err := DecryptString(secret, value)
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(plaintext), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func DecryptJSONWithSecrets(secrets [][]byte, value string) (map[string]string, error) {
	var lastErr error
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		out, err := DecryptJSON(secret, value)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no secrets available for decryption")
}

func EncryptString(secret []byte, value string) (string, error) {
	block, err := aes.NewCipher(deriveSecretKey(secret))
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
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func EncryptStringV1(secret []byte, value string) (string, error) {
	encrypted, err := EncryptString(secret, value)
	if err != nil {
		return "", err
	}
	return EncryptedPrefixV1 + encrypted, nil
}

func DecryptString(secret []byte, value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveSecretKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted value is too short")
	}
	nonce := raw[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func IsEncryptedValueV1(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), EncryptedPrefixV1)
}

func DecryptStringV1WithSecrets(secrets [][]byte, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if !IsEncryptedValueV1(trimmed) {
		return "", fmt.Errorf("value is not encrypted with %s", EncryptedPrefixV1)
	}
	encoded := strings.TrimPrefix(trimmed, EncryptedPrefixV1)
	return DecryptStringWithSecrets(secrets, encoded)
}

func DecryptStringWithSecrets(secrets [][]byte, value string) (string, error) {
	var lastErr error
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		out, err := DecryptString(secret, value)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no secrets available for decryption")
}

func EncryptBytesV1(secret []byte, value []byte) ([]byte, error) {
	encrypted, err := EncryptStringV1(secret, string(value))
	if err != nil {
		return nil, err
	}
	return []byte(encrypted), nil
}

func IsEncryptedBytesV1(value []byte) bool {
	return IsEncryptedValueV1(string(value))
}

func DecryptBytesV1WithSecrets(secrets [][]byte, value []byte) ([]byte, error) {
	plaintext, err := DecryptStringV1WithSecrets(secrets, string(value))
	if err != nil {
		return nil, err
	}
	return []byte(plaintext), nil
}

func MaskConfig(config map[string]string) map[string]any {
	out := make(map[string]any, len(config))
	for key, value := range config {
		if strings.TrimSpace(value) == "" {
			out[key] = ""
		} else {
			out[key] = "***"
		}
	}
	return out
}

func deriveSecretKey(source []byte) []byte {
	sum := sha256.Sum256(source)
	return sum[:]
}

package secureconfig

import (
	"strings"
	"testing"
)

func TestEncryptDecryptV2RoundTrip(t *testing.T) {
	secret := []byte("super-secret-with-enough-entropy-1234567890")
	plaintext := "hello world"
	encrypted, err := EncryptStringV2(secret, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(encrypted, EncryptedPrefixV2) {
		t.Fatalf("missing v2 prefix: %s", encrypted)
	}
	decrypted, err := DecryptStringV2(secret, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("got %q want %q", decrypted, plaintext)
	}
}

func TestDecryptStringAutoHandlesBothVersions(t *testing.T) {
	secret := []byte("the-encryption-secret-bytes-32+long")
	v1, err := EncryptStringV1(secret, "v1-value")
	if err != nil {
		t.Fatalf("v1 encrypt: %v", err)
	}
	v2, err := EncryptStringV2(secret, "v2-value")
	if err != nil {
		t.Fatalf("v2 encrypt: %v", err)
	}

	got, err := DecryptStringAuto([][]byte{secret}, v1)
	if err != nil || got != "v1-value" {
		t.Fatalf("v1 auto: got=%q err=%v", got, err)
	}
	got, err = DecryptStringAuto([][]byte{secret}, v2)
	if err != nil || got != "v2-value" {
		t.Fatalf("v2 auto: got=%q err=%v", got, err)
	}
}

func TestEncryptStringV2WrongSecretFails(t *testing.T) {
	encrypted, err := EncryptStringV2([]byte("right-secret-12345678901234567890"), "secret-data")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptStringV2([]byte("wrong-secret-09876543210987654321"), encrypted); err == nil {
		t.Fatal("expected decryption to fail with wrong secret")
	}
}

func TestKeyCachingReusesArgon2(t *testing.T) {
	secret := []byte("caching-secret-with-enough-bytes-here")
	salt := []byte("0123456789ABCDEF")
	first := deriveArgon2Key(secret, salt)
	second := deriveArgon2Key(secret, salt)
	if &first[0] != &second[0] {
		t.Fatal("expected cached argon2 key to be reused")
	}
}

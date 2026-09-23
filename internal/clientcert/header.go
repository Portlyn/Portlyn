package clientcert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	FingerprintHeader = "X-Portlyn-Client-Cert-SHA256"
	SignatureHeader   = "X-Portlyn-Client-Cert-Signature"
)

func Sign(secret, fingerprint string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("portlyn-client-cert-sha256:"))
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(fingerprint))))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(secret, fingerprint, signature string) bool {
	fingerprint = strings.TrimSpace(fingerprint)
	signature = strings.ToLower(strings.TrimSpace(signature))
	if strings.TrimSpace(secret) == "" || fingerprint == "" || signature == "" {
		return false
	}
	return hmac.Equal([]byte(Sign(secret, fingerprint)), []byte(signature))
}

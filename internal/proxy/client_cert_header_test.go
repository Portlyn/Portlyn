package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/clientcert"
)

func TestAdminHostSignsClientCertFingerprint(t *testing.T) {
	var got http.Header
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	manager := NewManager(newFakeRoutingStore(), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		AdminHost:              "admin.example.com",
		AdminAPITargetURL:      api.URL,
		ClientCertHeaderSecret: "secret",
	})

	raw := []byte("fake-cert")
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodGet, "https://admin.example.com/api/v1/nodes/1/heartbeat", nil)
	req.Host = "admin.example.com"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: raw}}}
	req.Header.Set(clientcert.FingerprintHeader, "spoofed")
	req.Header.Set(clientcert.SignatureHeader, "spoofed")
	rec := httptest.NewRecorder()
	manager.Handler().ServeHTTP(rec, req)

	if got == nil {
		t.Fatalf("admin api not reached, status %d: %s", rec.Code, rec.Body.String())
	}
	if got.Get(clientcert.FingerprintHeader) != fingerprint {
		t.Fatalf("fingerprint header = %q, want %q", got.Get(clientcert.FingerprintHeader), fingerprint)
	}
	if !clientcert.Verify("secret", fingerprint, got.Get(clientcert.SignatureHeader)) {
		t.Fatalf("signature header does not verify: %q", got.Get(clientcert.SignatureHeader))
	}

	got = nil
	spoofed := httptest.NewRequest(http.MethodGet, "https://admin.example.com/api/v1/nodes/1/heartbeat", nil)
	spoofed.Host = "admin.example.com"
	spoofed.Header.Set(clientcert.FingerprintHeader, fingerprint)
	spoofed.Header.Set(clientcert.SignatureHeader, clientcert.Sign("secret", fingerprint))
	manager.Handler().ServeHTTP(httptest.NewRecorder(), spoofed)
	if got == nil {
		t.Fatal("admin api not reached for request without client cert")
	}
	if got.Get(clientcert.FingerprintHeader) != "" || got.Get(clientcert.SignatureHeader) != "" {
		t.Fatalf("client-supplied cert headers were forwarded: %v", got)
	}
}

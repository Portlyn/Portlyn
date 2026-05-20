package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func TestManagerGetCertificateFallsBackToWildcardStoreEntry(t *testing.T) {
	manager, db := newManagerForGetCertificateTests(t)
	defer closeTestDB(t, db)

	certPEM, keyPEM := mustSelfSignedCertPEM(t, []string{"*.portlyn.schnittert.cloud"})
	if err := manager.tlsStore.StorePEM(context.Background(), "*.portlyn.schnittert.cloud", "test", certPEM, keyPEM, nil); err != nil {
		t.Fatalf("store wildcard cert: %v", err)
	}

	cert, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "whoami.portlyn.schnittert.cloud"})
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected wildcard certificate, got nil")
	}
}

func TestManagerGetCertificatePrefersExactMatchOverWildcard(t *testing.T) {
	manager, db := newManagerForGetCertificateTests(t)
	defer closeTestDB(t, db)

	wildcardPEM, wildcardKey := mustSelfSignedCertPEM(t, []string{"*.portlyn.schnittert.cloud"})
	if err := manager.tlsStore.StorePEM(context.Background(), "*.portlyn.schnittert.cloud", "test", wildcardPEM, wildcardKey, nil); err != nil {
		t.Fatalf("store wildcard cert: %v", err)
	}

	exactPEM, exactKey := mustSelfSignedCertPEM(t, []string{"whoami.portlyn.schnittert.cloud"})
	if err := manager.tlsStore.StorePEM(context.Background(), "whoami.portlyn.schnittert.cloud", "test", exactPEM, exactKey, nil); err != nil {
		t.Fatalf("store exact cert: %v", err)
	}

	cert, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: "whoami.portlyn.schnittert.cloud"})
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected exact certificate, got empty response")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse returned certificate: %v", err)
	}
	if leaf.Subject.CommonName != "whoami.portlyn.schnittert.cloud" {
		t.Fatalf("expected exact certificate CN, got %q", leaf.Subject.CommonName)
	}
}

func TestWildcardDomainForHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "whoami.portlyn.schnittert.cloud", want: "*.portlyn.schnittert.cloud"},
		{host: "whoami.EXAMPLE.com", want: "*.example.com"},
		{host: "*.example.com", want: ""},
		{host: "example.com", want: ""},
		{host: "localhost", want: ""},
	}
	for _, tc := range tests {
		if got := wildcardDomainForHost(tc.host); got != tc.want {
			t.Fatalf("wildcardDomainForHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func newManagerForGetCertificateTests(t *testing.T) (*Manager, *gorm.DB) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
		JWTSecret:      "12345678901234567890123456789012",
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	manager, err := NewManager(cfg, db, store.NewCertificateStore(db), store.NewDomainStore(db), store.NewDNSProviderStore(db), nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return manager, db
}

func closeTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close sql db: %v", err)
	}
}

func mustSelfSignedCertPEM(t *testing.T, dnsNames []string) ([]byte, []byte) {
	t.Helper()
	if len(dnsNames) == 0 {
		t.Fatal("dnsNames must not be empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

func TestManagerLoadsStaticCertificateAndSyncsMetadata(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	notAfter := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	if err := writeSelfSignedCert(certFile, keyFile, "static.example.com", notAfter); err != nil {
		t.Fatalf("write self-signed cert: %v", err)
	}

	cfg := config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
		JWTSecret:      "12345678901234567890123456789012",
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		ProxyHTTPSAddr: ":443",
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	domainStore := store.NewDomainStore(db)
	certStore := store.NewCertificateStore(db)
	if err := domainStore.Create(context.Background(), &domain.Domain{Name: "static.example.com", Type: "root"}); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	manager, err := NewManager(cfg, db, certStore, domainStore, store.NewDNSProviderStore(db), nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if !manager.HasHTTPS() {
		t.Fatal("expected static certificate to enable https")
	}

	item := &domain.Certificate{
		DomainID:          1,
		Domain:            domain.Domain{ID: 1, Name: "static.example.com"},
		PrimaryDomain:     "static.example.com",
		RenewalWindowDays: 30,
	}
	synced, err := manager.SyncCertificate(context.Background(), item)
	if err != nil {
		t.Fatalf("sync certificate: %v", err)
	}
	if synced.Status != domain.CertificateStatusIssued && synced.Status != domain.CertificateStatusExpiringSoon {
		t.Fatalf("unexpected certificate status %q", synced.Status)
	}
	if synced.ExpiresAt.IsZero() {
		t.Fatal("expected certificate expiry to be populated")
	}
	sqlDB, _ := db.DB()
	if sqlDB != nil {
		_ = sqlDB.Close()
	}
}

func writeSelfSignedCert(certFile, keyFile, commonName string, notAfter time.Time) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{commonName},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), 0o600)
}

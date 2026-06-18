package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/observability"
	"portlyn/internal/store"
)

type Manager struct {
	cfg          config.Config
	certificates *store.CertificateStore
	domains      *store.DomainStore
	dnsProviders *store.DNSProviderStore
	tlsStore     *DBCertificateStore
	storage      *CertMagicStorage
	worker       *AcmeWorker

	httpMagic      *certmagic.Config
	httpACMEIssuer *certmagic.ACMEIssuer

	mu         sync.RWMutex
	staticCert *tls.Certificate
	staticLeaf *x509.Certificate
	metrics    *observability.Metrics
	lastError  string
	lastSyncAt time.Time

	selfSignedMu    sync.RWMutex
	selfSignedCache map[string]*tls.Certificate
}

type Status struct {
	Level   string
	Summary string
	Reason  string
}

type SecretMigrationSummary struct {
	CertMagicPrivateKeys int
	StoredTLSPrivateKeys int
}

func NewManager(cfg config.Config, db *gorm.DB, certificateStore *store.CertificateStore, domainStore *store.DomainStore, dnsProviderStore *store.DNSProviderStore, metrics *observability.Metrics) (*Manager, error) {
	manager := &Manager{
		cfg:             cfg,
		certificates:    certificateStore,
		domains:         domainStore,
		dnsProviders:    dnsProviderStore,
		tlsStore:        NewDBCertificateStore(db, cfg.DataEncryptionSecrets()),
		storage:         NewCertMagicStorage(db, 30*time.Second, cfg.DataEncryptionSecrets()),
		metrics:         metrics,
		selfSignedCache: make(map[string]*tls.Certificate),
	}

	if err := manager.loadStaticCertificate(); err != nil {
		return nil, err
	}

	if cfg.ACMEEnabled {
		magic, issuer, err := manager.newHTTPChallengeConfig()
		if err != nil {
			return nil, err
		}
		manager.httpMagic = magic
		manager.httpACMEIssuer = issuer
		manager.worker = NewAcmeWorker(manager.tlsStore, certificateStore, manager, cfg.ACMEPollInterval, cfg.ACMERenewWithin, nil)
	}

	return manager, nil
}

func (m *Manager) HTTPChallengeHandler(next http.Handler) http.Handler {
	if m.httpACMEIssuer == nil {
		return next
	}
	return m.httpACMEIssuer.HTTPChallengeHandler(next)
}

func (m *Manager) StartWorker(ctx context.Context) {
	if m.worker == nil {
		return
	}
	m.worker.Start(ctx)
}

func (m *Manager) StopWorker() {
	if m.worker == nil {
		return
	}
	m.worker.Stop()
}

func (m *Manager) MigrateStoredSecrets(ctx context.Context) (SecretMigrationSummary, error) {
	summary := SecretMigrationSummary{}
	certMagicCount, err := m.storage.MigrateSensitiveValues(ctx)
	if err != nil {
		return summary, err
	}
	summary.CertMagicPrivateKeys = certMagicCount

	tlsCount, err := m.tlsStore.MigrateStoredPrivateKeys(ctx)
	if err != nil {
		return summary, err
	}
	summary.StoredTLSPrivateKeys = tlsCount
	return summary, nil
}

func (m *Manager) SyncCertificate(ctx context.Context, item *domain.Certificate) (*domain.Certificate, error) {
	started := time.Now()
	now := time.Now().UTC()
	item.LastCheckedAt = &now
	if item.Domain.Name == "" {
		loaded, err := m.domains.GetByID(ctx, item.DomainID)
		if err != nil {
			return nil, err
		}
		item.Domain = *loaded
	}

	if m.httpMagic == nil {
		if m.staticLeaf != nil {
			item.Status = domain.CertificateStatusIssued
			item.LastError = ""
			item.IssuedAt = &now
			item.ExpiresAt = m.staticLeaf.NotAfter.UTC()
			item.NextRenewalAt = renewalTime(item.ExpiresAt, item.RenewalWindowDays)
			if err := m.certificates.Update(ctx, item); err != nil {
				return nil, err
			}
			m.recordSync("static", "", started, item)
			return item, nil
		}
		item.Status = domain.CertificateStatusFailed
		item.LastError = "acme and static tls are not configured"
		if err := m.certificates.Update(ctx, item); err != nil {
			return nil, err
		}
		m.recordSync("sync", item.LastError, started, item)
		return item, nil
	}

	magic, issuer, names, err := m.configForCertificate(ctx, item)
	if err != nil {
		item.Status = domain.CertificateStatusFailed
		item.LastError = err.Error()
		if err := m.certificates.Update(ctx, item); err != nil {
			return nil, err
		}
		m.recordSync("sync", item.LastError, started, item)
		return item, nil
	}

	if err := magic.ManageSync(ctx, names); err != nil {
		item.Status = domain.CertificateStatusFailed
		item.LastError = err.Error()
		if err := m.certificates.Update(ctx, item); err != nil {
			return nil, err
		}
		m.recordSync("sync", item.LastError, started, item)
		return item, nil
	}

	if err := m.persistManagedCertificate(ctx, issuer.IssuerKey(), certificateNames(item)); err != nil {
		item.Status = domain.CertificateStatusFailed
		item.LastError = err.Error()
		if err := m.certificates.Update(ctx, item); err != nil {
			return nil, err
		}
		m.recordSync("sync", item.LastError, started, item)
		return item, nil
	}

	expiresAt, err := m.lookupStoredCertificateExpiry(ctx, firstCertificateName(item))
	if err != nil {
		item.Status = domain.CertificateStatusFailed
		item.LastError = err.Error()
		if err := m.certificates.Update(ctx, item); err != nil {
			return nil, err
		}
		m.recordSync("sync", item.LastError, started, item)
		return item, nil
	}

	item.Status = domain.CertificateStatusIssued
	item.LastError = ""
	if item.IssuedAt == nil {
		item.IssuedAt = &now
	}
	item.ExpiresAt = expiresAt
	item.NextRenewalAt = renewalTime(item.ExpiresAt, item.RenewalWindowDays)
	item.Status = derivedCertificateStatus(item, now)
	if err := m.certificates.Update(ctx, item); err != nil {
		return nil, err
	}
	m.recordSync("sync", "", started, item)
	return item, nil
}

func (m *Manager) ImportPEMCertificate(ctx context.Context, item *domain.Certificate, certPEM, keyPEM, issuerKey string) (*domain.Certificate, error) {
	if item == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	names := certificateNames(item)
	if len(names) == 0 {
		return nil, fmt.Errorf("certificate has no domain names")
	}
	issuer := strings.TrimSpace(issuerKey)
	if issuer == "" {
		issuer = "manual_import"
	}
	certBytes := []byte(strings.TrimSpace(certPEM))
	keyBytes := []byte(strings.TrimSpace(keyPEM))
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		return nil, fmt.Errorf("certificate_pem and private_key_pem are required")
	}
	for _, name := range names {
		if err := m.tlsStore.StorePEM(ctx, normalizeDomain(name), issuer, certBytes, keyBytes, nil); err != nil {
			return nil, err
		}
	}
	pair, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	item.IssuedAt = &now
	item.LastCheckedAt = &now
	item.ExpiresAt = leaf.NotAfter.UTC()
	if item.RenewalWindowDays == 0 {
		item.RenewalWindowDays = 30
	}
	item.NextRenewalAt = renewalTime(item.ExpiresAt, item.RenewalWindowDays)
	item.LastError = ""
	item.Status = derivedCertificateStatus(item, now)
	if err := m.certificates.Update(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (m *Manager) TLSConfig() *tls.Config {
	clientAuth := tls.NoClientCert
	if m.cfg.RequestClientCert {
		clientAuth = tls.RequestClientCert
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     clientAuth,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := normalizeDomain(hello.ServerName)
	if serverName != "" {
		cert, err := m.tlsStore.GetCertificate(context.Background(), serverName)
		if err == nil && cert != nil {
			return cert, nil
		}
		if wildcardName := wildcardDomainForHost(serverName); wildcardName != "" {
			cert, err = m.tlsStore.GetCertificate(context.Background(), wildcardName)
			if err == nil && cert != nil {
				return cert, nil
			}
		}
	}

	if m.httpMagic != nil && serverName != "" {
		cert, err := m.httpMagic.GetCertificate(hello)
		if err == nil && cert != nil {
			return cert, nil
		}
	}

	m.mu.RLock()
	if m.staticCert != nil {
		cert := m.staticCert
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	if serverName != "" {
		if cert, err := m.bootstrapCertFor(serverName); err == nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("no tls certificate available")
}

const (
	selfSignedRenewBefore     = time.Hour
	maxSelfSignedCacheEntries = 256
)

func selfSignedCertFresh(cert *tls.Certificate, now time.Time) bool {
	return cert != nil && cert.Leaf != nil && now.Before(cert.Leaf.NotAfter.Add(-selfSignedRenewBefore))
}

func (m *Manager) bootstrapCertFor(hostname string) (*tls.Certificate, error) {
	now := time.Now()
	m.selfSignedMu.RLock()
	if cert, ok := m.selfSignedCache[hostname]; ok && selfSignedCertFresh(cert, now) {
		m.selfSignedMu.RUnlock()
		return cert, nil
	}
	m.selfSignedMu.RUnlock()

	cert, err := generateSelfSignedCert(hostname)
	if err != nil {
		return nil, err
	}

	m.selfSignedMu.Lock()
	if existing, ok := m.selfSignedCache[hostname]; ok && selfSignedCertFresh(existing, now) {
		m.selfSignedMu.Unlock()
		return existing, nil
	}
	if len(m.selfSignedCache) >= maxSelfSignedCacheEntries {
		m.selfSignedCache = make(map[string]*tls.Certificate)
	}
	m.selfSignedCache[hostname] = cert
	m.selfSignedMu.Unlock()
	return cert, nil
}

func wildcardDomainForHost(host string) string {
	normalized := normalizeDomain(host)
	if normalized == "" || strings.HasPrefix(normalized, "*.") {
		return ""
	}
	labels := strings.Split(normalized, ".")
	if len(labels) < 3 {
		return ""
	}
	return "*." + strings.Join(labels[1:], ".")
}

func (m *Manager) HasHTTPS() bool {
	return m.cfg.ProxyHTTPSAddr != "" && (m.staticCert != nil || m.httpMagic != nil)
}

func (m *Manager) HasStaticCertificate() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.staticCert != nil
}

func (m *Manager) Status(context.Context) Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch {
	case m.httpMagic == nil && m.staticCert == nil:
		return Status{Level: "warn", Summary: "TLS is disabled or ACME is not configured", Reason: "tls_disabled"}
	case m.lastError != "":
		return Status{Level: "warn", Summary: m.lastError, Reason: "acme_last_error"}
	case m.httpMagic != nil:
		return Status{Level: "ok", Summary: "ACME manager ready", Reason: "acme_ready"}
	default:
		return Status{Level: "ok", Summary: "Static TLS certificate loaded", Reason: "static_tls"}
	}
}

func (m *Manager) loadStaticCertificate() error {
	if m.cfg.TLSCertFile == "" || m.cfg.TLSKeyFile == "" {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(m.cfg.TLSCertFile, m.cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(filepath.Clean(m.cfg.TLSCertFile))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	cert.Leaf = leaf

	m.mu.Lock()
	m.staticCert = &cert
	m.staticLeaf = leaf
	m.mu.Unlock()
	return nil
}

func (m *Manager) lookupStoredCertificateExpiry(ctx context.Context, serverName string) (time.Time, error) {
	cert, err := m.tlsStore.GetCertificate(ctx, serverName)
	if err != nil {
		return time.Time{}, err
	}
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter.UTC(), nil
	}
	if len(cert.Certificate) == 0 {
		return time.Time{}, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter.UTC(), nil
}

func (m *Manager) newHTTPChallengeConfig() (*certmagic.Config, *certmagic.ACMEIssuer, error) {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	cfg := certmagic.Config{
		Storage: m.storage,
	}
	magic = certmagic.New(cache, cfg)
	template := certmagic.ACMEIssuer{
		CA:                      certificateAuthorityURL(domain.CertificateIssuerLetsEncryptProd, m.cfg.ACMECAURL),
		Email:                   m.cfg.ACMEEmail,
		DisableTLSALPNChallenge: true,
	}
	issuer := certmagic.NewACMEIssuer(magic, template)
	magic.Issuers = []certmagic.Issuer{issuer}
	return magic, issuer, nil
}

func (m *Manager) configForCertificate(ctx context.Context, item *domain.Certificate) (*certmagic.Config, *certmagic.ACMEIssuer, []string, error) {
	names := certificateNames(item)
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	cfg := certmagic.Config{
		Storage: m.storage,
	}
	magic = certmagic.New(cache, cfg)
	issuerTemplate := certmagic.ACMEIssuer{
		CA:                      certificateAuthorityURL(item.Issuer, m.cfg.ACMECAURL),
		Email:                   m.cfg.ACMEEmail,
		DisableTLSALPNChallenge: true,
	}
	if item.ChallengeType == domain.CertificateChallengeDNS01 {
		if item.DNSProviderID == nil || *item.DNSProviderID == 0 {
			return nil, nil, nil, fmt.Errorf("dns-01 requires a dns provider")
		}
		provider, err := m.dnsProviders.GetByID(ctx, *item.DNSProviderID)
		if err != nil {
			return nil, nil, nil, err
		}
		appender, deleter, err := buildDNSProvider(m.cfg.DataEncryptionSecrets(), provider)
		if err != nil {
			return nil, nil, nil, err
		}
		issuerTemplate.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: dnsProviderAdapter{appender: appender, deleter: deleter},
				TTL:         2 * time.Minute,
			},
		}
	}
	issuer := certmagic.NewACMEIssuer(magic, issuerTemplate)
	magic.Issuers = []certmagic.Issuer{issuer}
	return magic, issuer, names, nil
}

func (m *Manager) persistManagedCertificate(ctx context.Context, issuerKey string, names []string) error {
	for _, name := range names {
		name = normalizeDomain(name)
		certPEM, err := m.storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name))
		if err != nil {
			return err
		}
		keyPEM, err := m.storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, name))
		if err != nil {
			return err
		}
		meta, _ := m.storage.Load(ctx, certmagic.StorageKeys.SiteMeta(issuerKey, name))
		if err := m.tlsStore.StorePEM(ctx, name, issuerKey, certPEM, keyPEM, meta); err != nil {
			return err
		}
	}
	return nil
}

func firstCertificateName(item *domain.Certificate) string {
	names := certificateNames(item)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func certificateNames(item *domain.Certificate) []string {
	names := make([]string, 0, len(item.SANs)+1)
	if strings.TrimSpace(item.PrimaryDomain) != "" {
		names = append(names, item.PrimaryDomain)
	} else if strings.TrimSpace(item.Domain.Name) != "" {
		names = append(names, item.Domain.Name)
	}
	for _, san := range item.SANs {
		if name := strings.TrimSpace(san.DomainName); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func certificateAuthorityURL(issuer, override string) string {
	switch issuer {
	case domain.CertificateIssuerLetsEncryptStaging:
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	case domain.CertificateIssuerLetsEncryptProd:
		if strings.TrimSpace(override) != "" {
			return strings.TrimSpace(override)
		}
		return "https://acme-v02.api.letsencrypt.org/directory"
	default:
		if strings.TrimSpace(override) != "" {
			return strings.TrimSpace(override)
		}
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
}

func renewalTime(expiresAt time.Time, renewalWindowDays int) *time.Time {
	if expiresAt.IsZero() || renewalWindowDays <= 0 {
		return nil
	}
	value := expiresAt.Add(-time.Duration(renewalWindowDays) * 24 * time.Hour).UTC()
	return &value
}

func (m *Manager) recordSync(operation, errMessage string, started time.Time, item *domain.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSyncAt = time.Now().UTC()
	m.lastError = strings.TrimSpace(errMessage)
	if m.metrics != nil {
		outcome := "success"
		if strings.TrimSpace(errMessage) != "" {
			outcome = "error"
		}
		m.metrics.ObserveACMEOperation(operation, outcome, time.Since(started))
		if item != nil {
			m.metrics.SetCertificateExpiry(firstCertificateName(item), item.ExpiresAt)
		}
	}
}

func derivedCertificateStatus(item *domain.Certificate, now time.Time) string {
	if strings.TrimSpace(item.LastError) != "" {
		return domain.CertificateStatusFailed
	}
	if !item.ExpiresAt.IsZero() {
		threshold := item.ExpiresAt.Add(-time.Duration(item.RenewalWindowDays) * 24 * time.Hour)
		if !now.Before(threshold) {
			return domain.CertificateStatusExpiringSoon
		}
	}
	return domain.CertificateStatusIssued
}

type dnsProviderAdapter struct {
	appender interface {
		AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error)
	}
	deleter interface {
		DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error)
	}
}

func (d dnsProviderAdapter) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return d.appender.AppendRecords(ctx, zone, recs)
}

func (d dnsProviderAdapter) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return d.deleter.DeleteRecords(ctx, zone, recs)
}

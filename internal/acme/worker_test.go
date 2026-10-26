package acme

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type fakeRenewer struct {
	calls          int
	previousStatus []string
}

func (f *fakeRenewer) SyncCertificate(_ context.Context, item *domain.Certificate) (*domain.Certificate, error) {
	f.calls++
	f.previousStatus = append(f.previousStatus, item.Status)
	return item, nil
}

func createTestCertificate(t *testing.T, db *store.CertificateStore, domains *store.DomainStore, cert domain.Certificate) *domain.Certificate {
	t.Helper()
	dom := &domain.Domain{Name: "broken.example.com", Type: "single"}
	if err := domains.Create(context.Background(), dom); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	cert.DomainID = dom.ID
	cert.PrimaryDomain = dom.Name
	if err := db.Create(context.Background(), &cert); err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &cert
}

func TestWorkerSkipsCertificatesUntilNextAttempt(t *testing.T) {
	_, db := newManagerForGetCertificateTests(t)
	defer closeTestDB(t, db)
	certs := store.NewCertificateStore(db)

	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	next := now.Add(10 * time.Minute)
	createTestCertificate(t, certs, store.NewDomainStore(db), domain.Certificate{
		Type:          domain.CertificateTypeSingle,
		Status:        domain.CertificateStatusFailed,
		IsAutoRenew:   true,
		FailureCount:  2,
		NextAttemptAt: &next,
	})

	renewer := &fakeRenewer{}
	worker := NewAcmeWorker(nil, certs, renewer, time.Minute, 30*24*time.Hour, nil)
	worker.now = func() time.Time { return now }

	worker.runOnce(context.Background())
	if renewer.calls != 0 {
		t.Fatalf("expected no sync before the next attempt, got %d", renewer.calls)
	}

	now = next
	worker.runOnce(context.Background())
	if renewer.calls != 1 {
		t.Fatalf("expected a sync once the attempt is due, got %d", renewer.calls)
	}
	if renewer.previousStatus[0] != domain.CertificateStatusFailed {
		t.Fatalf("expected sync to see the stored status, got %q", renewer.previousStatus[0])
	}
}

func TestSyncCertificateRecordsGrowingBackoff(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabaseDriver:  "sqlite",
		DatabasePath:    filepath.Join(dir, "portlyn.db"),
		JWTSecret:       "12345678901234567890123456789012",
		ACMEEnabled:     true,
		ACMERenewWithin: 30 * 24 * time.Hour,
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	defer closeTestDB(t, db)
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	certs := store.NewCertificateStore(db)
	domains := store.NewDomainStore(db)
	manager, err := NewManager(cfg, db, certs, domains, store.NewDNSProviderStore(db), nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	var changes int
	manager.SetStatusChangeHook(func(context.Context, *domain.Certificate, string) { changes++ })

	created := createTestCertificate(t, certs, domains, domain.Certificate{
		Type:          domain.CertificateTypeSingle,
		Status:        domain.CertificateStatusPending,
		ChallengeType: domain.CertificateChallengeDNS01,
		IsAutoRenew:   true,
	})

	for attempt := 1; attempt <= 2; attempt++ {
		item, err := certs.GetByID(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		before := time.Now()
		if _, err := manager.SyncCertificate(context.Background(), item); err != nil {
			t.Fatalf("sync: %v", err)
		}
		stored, err := certs.GetByID(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if stored.Status != domain.CertificateStatusFailed || stored.FailureCount != attempt {
			t.Fatalf("attempt %d: status %q failures %d", attempt, stored.Status, stored.FailureCount)
		}
		if stored.NextAttemptAt == nil || stored.NextAttemptAt.Before(before.Add(retryDelay(attempt)-time.Second)) {
			t.Fatalf("attempt %d: next attempt %v too early", attempt, stored.NextAttemptAt)
		}
	}
	if changes != 1 {
		t.Fatalf("expected one status change (pending to failed), got %d", changes)
	}
}

func TestNextRetryState(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour

	failures, next := nextRetryState(&domain.Certificate{Status: domain.CertificateStatusFailed, FailureCount: 2}, now, window)
	if failures != 3 || next == nil || !next.Equal(now.Add(4*retryBaseDelay)) {
		t.Fatalf("failed: %d %v", failures, next)
	}

	failures, next = nextRetryState(&domain.Certificate{Status: domain.CertificateStatusExpiringSoon, FailureCount: 4, ExpiresAt: now.Add(10 * 24 * time.Hour)}, now, window)
	if failures != 0 || next == nil || !next.Equal(now.Add(renewedRecheckWait)) {
		t.Fatalf("in window: %d %v", failures, next)
	}

	failures, next = nextRetryState(&domain.Certificate{Status: domain.CertificateStatusIssued, ExpiresAt: now.Add(80 * 24 * time.Hour)}, now, window)
	if failures != 0 || next != nil {
		t.Fatalf("healthy: %d %v", failures, next)
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	if got := retryDelay(1); got != retryBaseDelay {
		t.Fatalf("retryDelay(1) = %s", got)
	}
	if got := retryDelay(3); got != 4*retryBaseDelay {
		t.Fatalf("retryDelay(3) = %s", got)
	}
	if got := retryDelay(50); got != retryMaxDelay {
		t.Fatalf("retryDelay(50) = %s", got)
	}
}

package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestCertificateCacheServesHitsWithoutLoading(t *testing.T) {
	cache := newCertificateCache()
	loads := 0
	want := &tls.Certificate{}
	load := func(context.Context, string) (*tls.Certificate, error) {
		loads++
		return want, nil
	}

	for range 3 {
		got, err := cache.get(context.Background(), "app.example.com", load)
		if err != nil || got != want {
			t.Fatalf("get = %v, %v", got, err)
		}
	}
	if loads != 1 {
		t.Fatalf("expected one load, got %d", loads)
	}
}

func TestCertificateCacheReturnsStaleEntryWhileRefreshing(t *testing.T) {
	cache := newCertificateCache()
	now := time.Now()
	cache.now = func() time.Time { return now }
	old := &tls.Certificate{}
	fresh := &tls.Certificate{}
	release := make(chan struct{})
	current := old
	load := func(context.Context, string) (*tls.Certificate, error) {
		if current == fresh {
			<-release
		}
		return current, nil
	}

	if _, err := cache.get(context.Background(), "app.example.com", load); err != nil {
		t.Fatalf("prime: %v", err)
	}
	current = fresh
	now = now.Add(2 * certificateCacheFreshFor)

	got, err := cache.get(context.Background(), "app.example.com", load)
	if err != nil || got != old {
		t.Fatalf("expected stale entry without waiting, got %v, %v", got, err)
	}
	close(release)
}

func TestCertificateCacheRemembersMisses(t *testing.T) {
	cache := newCertificateCache()
	loads := 0
	load := func(context.Context, string) (*tls.Certificate, error) {
		loads++
		return nil, gorm.ErrRecordNotFound
	}

	for range 3 {
		if _, err := cache.get(context.Background(), "unknown.example.com", load); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("expected not found, got %v", err)
		}
	}
	if loads != 1 {
		t.Fatalf("expected one load, got %d", loads)
	}
}

func TestStorePEMReplacesCachedCertificate(t *testing.T) {
	manager, db := newManagerForGetCertificateTests(t)
	defer closeTestDB(t, db)
	ctx := context.Background()

	if _, err := manager.tlsStore.GetCertificate(ctx, "app.example.com"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected miss before store, got %v", err)
	}
	certPEM, keyPEM := mustSelfSignedCertPEM(t, []string{"app.example.com"})
	if err := manager.tlsStore.StorePEM(ctx, "app.example.com", "test", certPEM, keyPEM, nil); err != nil {
		t.Fatalf("store: %v", err)
	}
	if cert, err := manager.tlsStore.GetCertificate(ctx, "app.example.com"); err != nil || cert == nil {
		t.Fatalf("expected stored certificate after miss, got %v, %v", cert, err)
	}

	if err := manager.tlsStore.DeleteCertificate(ctx, "app.example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := manager.tlsStore.GetCertificate(ctx, "app.example.com"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected miss after delete, got %v", err)
	}
}

package acme

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func TestCertMagicStorageTryAcquireReturnsFalseOnExistingLock(t *testing.T) {
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
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	storageA := NewCertMagicStorage(db, 30*time.Second, []string{"12345678901234567890123456789012"})
	storageB := NewCertMagicStorage(db, 30*time.Second, []string{"12345678901234567890123456789012"})

	acquired, err := storageA.tryAcquire(context.Background(), "issue_cert_*.example.com")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if !acquired {
		t.Fatal("expected first lock acquisition to succeed")
	}
	t.Cleanup(func() {
		_ = storageA.Unlock(context.Background(), "issue_cert_*.example.com")
	})

	acquired, err = storageB.tryAcquire(context.Background(), "issue_cert_*.example.com")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if acquired {
		t.Fatal("expected second lock acquisition to report not acquired")
	}
}

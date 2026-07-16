package acme

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func TestDeleteCertificatesForDomain(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
	})
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	storage := NewCertMagicStorage(db, 30*time.Second, []string{"12345678901234567890123456789012"})
	ctx := context.Background()

	keys := []string{
		"certificates/le/example.com/example.com.crt",
		"certificates/le/example.com/example.com.key",
		"certificates/le/wildcard_.example.com/wildcard_.example.com.crt",
	}
	for _, key := range keys {
		if err := storage.Store(ctx, key, []byte("x")); err != nil {
			t.Fatalf("store %s: %v", key, err)
		}
	}

	if err := storage.DeleteCertificatesForDomain(ctx, "example.com"); err != nil {
		t.Fatalf("delete example.com: %v", err)
	}
	if storage.Exists(ctx, "certificates/le/example.com/example.com.crt") {
		t.Error("expected example.com cert key to be gone")
	}
	if !storage.Exists(ctx, "certificates/le/wildcard_.example.com/wildcard_.example.com.crt") {
		t.Error("expected the wildcard folder to survive deletion of the single domain")
	}

	if err := storage.DeleteCertificatesForDomain(ctx, "*.example.com"); err != nil {
		t.Fatalf("delete wildcard: %v", err)
	}
	if storage.Exists(ctx, "certificates/le/wildcard_.example.com/wildcard_.example.com.crt") {
		t.Error("expected wildcard cert key to be gone")
	}
}

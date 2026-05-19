package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

func TestAppSettingsStoreEncryptsAndDecryptsSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
		JWTSecret:      "12345678901234567890123456789012",
	}
	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	store := NewAppSettingsStore(db)
	store.SetDataEncryptionSecrets([]string{"active-12345678901234567890123456789012"})

	item := &domain.AppSettings{
		ID:               1,
		FrontendBaseURL:  "http://localhost",
		OIDCClientSecret: "oidc-secret-value",
		SMTPPassword:     "smtp-secret-value",
	}
	if err := store.Upsert(context.Background(), item); err != nil {
		t.Fatalf("upsert app settings: %v", err)
	}

	var raw domain.AppSettings
	if err := db.WithContext(context.Background()).First(&raw, 1).Error; err != nil {
		t.Fatalf("load raw app settings: %v", err)
	}
	if !secureconfig.IsEncryptedValueV1(raw.OIDCClientSecret) || !secureconfig.IsEncryptedValueV1(raw.SMTPPassword) {
		t.Fatal("expected secrets to be encrypted at rest")
	}

	loaded, err := store.Get(context.Background())
	if err != nil {
		t.Fatalf("load app settings: %v", err)
	}
	if loaded.OIDCClientSecret != "oidc-secret-value" || loaded.SMTPPassword != "smtp-secret-value" {
		t.Fatal("expected decrypted secrets to match original values")
	}
}

func TestAppSettingsStoreMigratesLegacyPlaintextSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
		JWTSecret:      "12345678901234567890123456789012",
	}
	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	if err := db.WithContext(context.Background()).Create(&domain.AppSettings{
		ID:               1,
		FrontendBaseURL:  "http://localhost",
		OIDCClientSecret: "legacy-oidc-secret",
		SMTPPassword:     "legacy-smtp-secret",
	}).Error; err != nil {
		t.Fatalf("seed legacy app settings: %v", err)
	}

	store := NewAppSettingsStore(db)
	store.SetDataEncryptionSecrets([]string{"active-12345678901234567890123456789012"})
	updated, err := store.MigrateStoredSecrets(context.Background())
	if err != nil {
		t.Fatalf("migrate legacy settings: %v", err)
	}
	if updated != 2 {
		t.Fatalf("expected two migrated fields, got %d", updated)
	}

	var raw domain.AppSettings
	if err := db.WithContext(context.Background()).First(&raw, 1).Error; err != nil {
		t.Fatalf("load migrated settings: %v", err)
	}
	if !strings.HasPrefix(raw.OIDCClientSecret, secureconfig.EncryptedPrefixV1) || !strings.HasPrefix(raw.SMTPPassword, secureconfig.EncryptedPrefixV1) {
		t.Fatal("expected migrated secrets to be stored with encryption prefix")
	}
}

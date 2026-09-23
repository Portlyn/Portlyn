package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

func newStoreBackedService(t *testing.T) (*Service, *store.UserStore) {
	t.Helper()
	db, err := store.NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(t.TempDir(), "portlyn.db"),
	})
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	users := store.NewUserStore(db)
	service, err := NewService(users, store.NewGroupStore(db), store.NewLoginTokenStore(db), store.NewSessionStore(db), store.NewAppSettingsStore(db),
		"12345678901234567890123456789012", "12345678901234567890123456789013", "12345678901234567890123456789014", "12345678901234567890123456789015",
		"portlyn", "", time.Minute, time.Hour, config.OIDCConfig{}, config.OTPConfig{}, time.Minute,
		config.RateLimitConfig{LoginAttempts: 100, Window: time.Minute}, time.Minute, true, nil)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service, users
}

func TestMFAFlowWritesOnlyMFAColumns(t *testing.T) {
	service, users := newStoreBackedService(t)
	ctx := context.Background()

	user := &domain.User{Email: "mfa@example.com", PasswordHash: "hash", Role: domain.RoleAdmin, Active: true, AuthProvider: domain.AuthProviderLocal}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	setup, err := service.BeginTOTPSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	if err := users.UpdateColumns(ctx, user.ID, map[string]any{"role": domain.RoleViewer}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	status, err := service.EnableTOTP(ctx, user.ID, generateTOTP(setup.Secret, time.Now().UTC()))
	if err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if !status.Enabled {
		t.Fatal("expected mfa to be enabled")
	}
	reloaded, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Role != domain.RoleViewer || reloaded.PasswordHash != "hash" {
		t.Fatalf("mfa enable rewrote unrelated columns: role=%s", reloaded.Role)
	}
	if !reloaded.MFAEnabled || reloaded.MFAPendingSecret != "" || len(reloaded.MFARecoveryCodes) != len(setup.RecoveryCodes) || reloaded.MFALastTOTPCounter == 0 {
		t.Fatalf("unexpected mfa state after enable: %+v", reloaded)
	}

	if _, err := service.RegenerateRecoveryCodes(ctx, user.ID, setup.RecoveryCodes[0]); err != nil {
		t.Fatalf("regenerate with recovery code: %v", err)
	}
}

func TestEnableTOTPFailsAfterConcurrentMFAReset(t *testing.T) {
	service, users := newStoreBackedService(t)
	ctx := context.Background()

	user := &domain.User{Email: "reset@example.com", PasswordHash: "hash", Role: domain.RoleViewer, Active: true, AuthProvider: domain.AuthProviderLocal}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	setup, err := service.BeginTOTPSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	stale, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := service.ResetUserMFA(ctx, user.ID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	stale.MFAEnabled = true
	stale.MFASecret = stale.MFAPendingSecret
	err = users.UpdateFieldsIf(ctx, stale, map[string]any{"mfa_pending_secret": stale.MFAPendingSecret}, mfaColumns...)
	if !errors.Is(err, store.ErrStale) {
		t.Fatalf("expected stale enable to be rejected, got %v", err)
	}
	if _, err := service.EnableTOTP(ctx, user.ID, generateTOTP(setup.Secret, time.Now().UTC())); err == nil {
		t.Fatal("expected enable after reset to fail")
	}
}

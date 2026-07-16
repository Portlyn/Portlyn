package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func newAPITokenTestStore(t *testing.T) *APITokenStore {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
	})
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewAPITokenStore(db)
}

func TestAPITokenStoreLifecycle(t *testing.T) {
	store := newAPITokenTestStore(t)
	ctx := context.Background()

	tok := &domain.APIToken{Name: "ci", Prefix: "plyn_deadbeef", TokenHash: "hash", Role: domain.RoleAdmin}
	if err := store.Create(ctx, tok); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.FindActiveByPrefix(ctx, "plyn_deadbeef")
	if err != nil {
		t.Fatalf("find active: %v", err)
	}
	if got.ID != tok.ID || got.Role != domain.RoleAdmin {
		t.Fatalf("unexpected token: %+v", got)
	}

	if err := store.TouchLastUsed(ctx, tok.ID, time.Now().UTC()); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if refreshed, err := store.FindActiveByPrefix(ctx, "plyn_deadbeef"); err != nil || refreshed.LastUsedAt == nil {
		t.Fatalf("expected last_used_at to be set: err=%v item=%+v", err, refreshed)
	}

	if err := store.Revoke(ctx, tok.ID, time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.FindActiveByPrefix(ctx, "plyn_deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected revoked token to be inactive, got %v", err)
	}
	if err := store.Revoke(ctx, tok.ID, time.Now().UTC()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected second revoke to be a no-op ErrNotFound, got %v", err)
	}
}

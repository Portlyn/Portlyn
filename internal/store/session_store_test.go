package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func newSessionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(t.TempDir(), "portlyn.db"),
	})
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func TestSessionRotateDoesNotUndoRevocation(t *testing.T) {
	db := newSessionTestDB(t)
	ctx := context.Background()
	users := NewUserStore(db)
	sessions := NewSessionStore(db)

	user := &domain.User{Email: "session@example.com", Role: domain.RoleViewer, Active: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Now().UTC()
	item := &domain.Session{UserID: user.ID, TokenID: "tok-1", RefreshTokenHash: "hash-1", ExpiresAt: now.Add(time.Hour)}
	if err := sessions.Create(ctx, item); err != nil {
		t.Fatalf("create session: %v", err)
	}

	stale, err := sessions.GetByID(ctx, item.ID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if err := sessions.RevokeByUser(ctx, user.ID, now); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	stale.TokenID = "tok-2"
	stale.RefreshTokenHash = "hash-2"
	if err := sessions.Rotate(ctx, stale, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected rotate on revoked session to fail, got %v", err)
	}
	if err := sessions.Touch(ctx, item.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected touch on revoked session to fail, got %v", err)
	}
	reloaded, err := sessions.GetByID(ctx, item.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.RevokedAt == nil || reloaded.TokenID != "tok-1" {
		t.Fatalf("revocation was undone: %+v", reloaded)
	}
}

func TestSessionRotateRequiresCurrentRefreshHash(t *testing.T) {
	db := newSessionTestDB(t)
	ctx := context.Background()
	users := NewUserStore(db)
	sessions := NewSessionStore(db)

	user := &domain.User{Email: "rotate@example.com", Role: domain.RoleViewer, Active: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	item := &domain.Session{UserID: user.ID, TokenID: "tok-1", RefreshTokenHash: "hash-1", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := sessions.Create(ctx, item); err != nil {
		t.Fatalf("create session: %v", err)
	}

	first := *item
	first.TokenID = "tok-2"
	first.RefreshTokenHash = "hash-2"
	if err := sessions.Rotate(ctx, &first, "hash-1"); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	second := *item
	second.TokenID = "tok-3"
	second.RefreshTokenHash = "hash-3"
	if err := sessions.Rotate(ctx, &second, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected second rotate with stale hash to fail, got %v", err)
	}
	reloaded, err := sessions.GetByID(ctx, item.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.TokenID != "tok-2" || reloaded.RefreshTokenHash != "hash-2" {
		t.Fatalf("unexpected session after rotation: %+v", reloaded)
	}
}

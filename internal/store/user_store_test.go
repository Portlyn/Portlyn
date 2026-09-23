package store

import (
	"context"
	"errors"
	"testing"

	"portlyn/internal/domain"
)

func TestUserUpdateFieldsKeepsConcurrentAdminChanges(t *testing.T) {
	db := newSessionTestDB(t)
	ctx := context.Background()
	users := NewUserStore(db)

	user := &domain.User{Email: "stale@example.com", PasswordHash: "old-hash", Role: domain.RoleAdmin, Active: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	snapshot, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if err := users.UpdateColumns(ctx, user.ID, map[string]any{"role": domain.RoleViewer, "active": false}); err != nil {
		t.Fatalf("demote: %v", err)
	}

	snapshot.MFAPendingSecret = "pending"
	snapshot.MFAPendingRecoveryCodes = domain.JSONStringSlice{"code"}
	if err := users.UpdateFields(ctx, snapshot, "mfa_pending_secret", "mfa_pending_recovery_codes"); err != nil {
		t.Fatalf("update fields: %v", err)
	}
	reloaded, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Role != domain.RoleViewer || reloaded.Active {
		t.Fatalf("self-service write undid the demotion: role=%s active=%v", reloaded.Role, reloaded.Active)
	}
	if reloaded.MFAPendingSecret != "pending" || len(reloaded.MFAPendingRecoveryCodes) != 1 {
		t.Fatalf("expected pending mfa fields to be written: %+v", reloaded)
	}
}

func TestUserUpdateFieldsIfRejectsStaleGuard(t *testing.T) {
	db := newSessionTestDB(t)
	ctx := context.Background()
	users := NewUserStore(db)

	user := &domain.User{Email: "guard@example.com", PasswordHash: "old-hash", Role: domain.RoleViewer, Active: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	snapshot, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if err := users.UpdateColumns(ctx, user.ID, map[string]any{"password_hash": "admin-reset-hash"}); err != nil {
		t.Fatalf("admin reset: %v", err)
	}

	snapshot.PasswordHash = "self-service-hash"
	err = users.UpdateFieldsIf(ctx, snapshot, map[string]any{"password_hash": "old-hash"}, "password_hash")
	if !errors.Is(err, ErrStale) {
		t.Fatalf("expected stale guard to fail, got %v", err)
	}
	reloaded, err := users.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.PasswordHash != "admin-reset-hash" {
		t.Fatalf("admin password reset was overwritten: %q", reloaded.PasswordHash)
	}
}

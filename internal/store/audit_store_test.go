package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func newAuditTestStore(t *testing.T) *AuditStore {
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
	return NewAuditStore(db, []byte("test-key"))
}

func TestAuditCompactDropsAccessNoiseAndRechains(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := []domain.AuditLog{
		{Timestamp: base, Action: "login_succeeded", ResourceType: "auth"},
		{Timestamp: base.Add(time.Second), Action: "proxy_access", ResourceType: "service", Details: `{"outcome":"proxied"}`},
		{Timestamp: base.Add(2 * time.Second), Action: "api_access", ResourceType: "http_request", Details: `{"channel":"api"}`},
		{Timestamp: base.Add(3 * time.Second), Action: "proxy_access", ResourceType: "service", Details: `{"outcome":"denied","reason":"authz"}`},
		{Timestamp: base.Add(4 * time.Second), Action: "update", ResourceType: "service"},
	}
	for i := range rows {
		if err := s.Create(ctx, &rows[i]); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	if _, err := s.VerifyChain(ctx); err != nil {
		t.Fatalf("pre-compaction chain invalid: %v", err)
	}

	result, err := s.Compact(ctx)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if result.Scanned != 5 || result.Removed != 2 || result.Kept != 3 {
		t.Fatalf("unexpected compaction result: %+v", result)
	}

	verify, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("post-compaction chain invalid: %v", err)
	}
	if verify.Verified != 3 {
		t.Fatalf("expected 3 surviving rows, got %d", verify.Verified)
	}

	remaining, total, err := s.List(ctx, AuditListParams{Limit: 200})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected 3 rows in table, got %d", total)
	}
	for _, row := range remaining {
		if row.ResourceType == "http_request" {
			t.Fatalf("api access row survived: %+v", row)
		}
		if row.Action == "proxy_access" && auditDetailOutcome(row.Details) != "denied" {
			t.Fatalf("non-denial proxy access row survived: %+v", row)
		}
	}
}

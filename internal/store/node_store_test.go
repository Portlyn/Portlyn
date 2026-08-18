package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func newNodeTestStores(t *testing.T) (*NodeStore, *NodeEnrollmentTokenStore, *gorm.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
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
	return NewNodeStore(db), NewNodeEnrollmentTokenStore(db), db
}

func newSingleUseToken(t *testing.T, tokens *NodeEnrollmentTokenStore, hash string) *domain.NodeEnrollmentToken {
	t.Helper()
	token := &domain.NodeEnrollmentToken{Name: "enroll", TokenHash: hash, SingleUse: true, Active: true}
	if err := tokens.Create(context.Background(), token); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return token
}

func TestEnrollWithTokenClaimsTokenAndCreatesNode(t *testing.T) {
	nodes, tokens, _ := newNodeTestStores(t)
	ctx := context.Background()
	token := newSingleUseToken(t, tokens, "hash-ok")

	node := &domain.Node{Name: "node-a", Status: domain.NodeStatusOnline, HeartbeatAuthMode: "token"}
	enrolled, err := nodes.EnrollWithToken(ctx, node, token.ID, true, time.Now().UTC(), func(created *domain.Node) {
		created.HeartbeatEndpoint = "/api/v1/nodes/x/heartbeat"
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !enrolled {
		t.Fatal("expected enrollment to succeed")
	}
	if node.ID == 0 {
		t.Fatal("expected node to get an ID")
	}

	stored, err := nodes.GetByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if stored.HeartbeatEndpoint != "/api/v1/nodes/x/heartbeat" {
		t.Fatalf("finalize not persisted, got %q", stored.HeartbeatEndpoint)
	}

	claimed, err := tokens.GetByID(ctx, token.ID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if claimed.Active {
		t.Fatal("expected single-use token to be deactivated")
	}
	if claimed.UsedAt == nil {
		t.Fatal("expected used_at to be set")
	}
}

func TestEnrollWithTokenRejectsSecondUse(t *testing.T) {
	nodes, tokens, _ := newNodeTestStores(t)
	ctx := context.Background()
	token := newSingleUseToken(t, tokens, "hash-twice")

	first := &domain.Node{Name: "node-a", Status: domain.NodeStatusOnline}
	if enrolled, err := nodes.EnrollWithToken(ctx, first, token.ID, true, time.Now().UTC(), nil); err != nil || !enrolled {
		t.Fatalf("first enroll: enrolled=%v err=%v", enrolled, err)
	}

	second := &domain.Node{Name: "node-b", Status: domain.NodeStatusOnline}
	enrolled, err := nodes.EnrollWithToken(ctx, second, token.ID, true, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("second enroll returned error: %v", err)
	}
	if enrolled {
		t.Fatal("expected second use of a single-use token to be rejected")
	}

	count, err := nodes.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one node, got %d", count)
	}
}

func TestEnrollWithTokenRollsBackClaimOnNodeFailure(t *testing.T) {
	nodes, tokens, _ := newNodeTestStores(t)
	ctx := context.Background()
	token := newSingleUseToken(t, tokens, "hash-rollback")

	existing := &domain.Node{Name: "taken", Status: domain.NodeStatusOnline}
	if err := nodes.Create(ctx, existing); err != nil {
		t.Fatalf("create existing node: %v", err)
	}

	// Reusing the primary key makes the insert fail inside the transaction.
	conflicting := &domain.Node{ID: existing.ID, Name: "conflict", Status: domain.NodeStatusOnline}
	enrolled, err := nodes.EnrollWithToken(ctx, conflicting, token.ID, true, time.Now().UTC(), nil)
	if err == nil {
		t.Fatal("expected node creation to fail")
	}
	if enrolled {
		t.Fatal("expected enrolled to be false on failure")
	}

	unchanged, err := tokens.GetByID(ctx, token.ID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if !unchanged.Active || unchanged.UsedAt != nil {
		t.Fatal("expected the token to stay usable after a failed enrollment")
	}

	count, err := nodes.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected no extra node, got %d", count)
	}
}

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

func TestNodeUpdateHeartbeatTouchesOnlyHeartbeatColumns(t *testing.T) {
	nodes, _, _ := newNodeTestStores(t)
	ctx := context.Background()

	node := &domain.Node{Name: "node-a", Status: domain.NodeStatusOnline, HeartbeatAuthMode: "token", HeartbeatTokenHash: "old-hash", WGPublicKey: "old-key"}
	if err := nodes.Create(ctx, node); err != nil {
		t.Fatalf("create: %v", err)
	}
	stale, err := nodes.GetByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("get stale: %v", err)
	}
	fresh, err := nodes.GetByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("get fresh: %v", err)
	}
	fresh.HeartbeatTokenHash = "new-hash"
	fresh.WGPublicKey = ""
	if err := nodes.Update(ctx, fresh); err != nil {
		t.Fatalf("update: %v", err)
	}

	now := time.Now().UTC()
	stale.LastHeartbeatAt = &now
	stale.Status = domain.NodeStatusOffline
	stale.Load = 0.5
	if err := nodes.UpdateHeartbeat(ctx, stale); err != nil {
		t.Fatalf("update heartbeat: %v", err)
	}

	stored, err := nodes.GetByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("get stored: %v", err)
	}
	if stored.HeartbeatTokenHash != "new-hash" || stored.WGPublicKey != "" {
		t.Fatalf("heartbeat overwrote credential columns: hash=%q key=%q", stored.HeartbeatTokenHash, stored.WGPublicKey)
	}
	if stored.Status != domain.NodeStatusOffline || stored.Load != 0.5 || stored.LastHeartbeatAt == nil {
		t.Fatalf("heartbeat columns not persisted: status=%q load=%v", stored.Status, stored.Load)
	}
	if stored.Name != "node-a" || stored.CreatedAt.IsZero() {
		t.Fatalf("unexpected row after update: name=%q created_at=%v", stored.Name, stored.CreatedAt)
	}
}

func TestNodeUpdatesDoNotRecreateDeletedNode(t *testing.T) {
	nodes, _, _ := newNodeTestStores(t)
	ctx := context.Background()

	node := &domain.Node{Name: "node-a", Status: domain.NodeStatusOnline, HeartbeatAuthMode: "token"}
	if err := nodes.Create(ctx, node); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := nodes.Delete(ctx, node.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := nodes.UpdateHeartbeat(ctx, node); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound from heartbeat update, got %v", err)
	}
	if err := nodes.Update(ctx, node); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound from update, got %v", err)
	}
	count, err := nodes.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected deleted node to stay deleted, found %d rows", count)
	}
}

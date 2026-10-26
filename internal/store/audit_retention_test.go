package store

import (
	"context"
	"testing"
	"time"

	"portlyn/internal/domain"
)

func seedAuditRows(t *testing.T, s *AuditStore, start time.Time, count int) {
	t.Helper()
	items := make([]domain.AuditLog, count)
	for i := range items {
		items[i] = domain.AuditLog{
			Timestamp:    start.Add(time.Duration(i) * time.Hour),
			Action:       "update",
			ResourceType: "service",
		}
	}
	if err := s.CreateBatch(context.Background(), items); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestAuditPruneKeepsChainVerifiable(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedAuditRows(t, s, start, 10)

	result, err := s.PruneBefore(ctx, start.Add(4*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if result.Removed != 4 {
		t.Fatalf("expected 4 removed, got %d", result.Removed)
	}

	seedAuditRows(t, s, start.Add(20*time.Hour), 2)
	verify, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify after prune: %v", err)
	}
	if verify.Verified != 8 || verify.AnchorID != result.LastID || verify.Pruned != 4 {
		t.Fatalf("unexpected verify result %+v", verify)
	}

	if _, err := s.PruneBefore(ctx, start.Add(6*time.Hour)); err != nil {
		t.Fatalf("second prune: %v", err)
	}
	verify, err = s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify after second prune: %v", err)
	}
	if verify.Verified != 6 || verify.Pruned != 6 {
		t.Fatalf("unexpected verify result after second prune %+v", verify)
	}
}

func TestAuditPruneNeverRemovesNewestEntry(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedAuditRows(t, s, start, 3)

	result, err := s.PruneBefore(ctx, start.Add(100*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if result.Removed != 2 {
		t.Fatalf("expected 2 removed, got %d", result.Removed)
	}

	item := domain.AuditLog{Timestamp: start.Add(200 * time.Hour), Action: "update", ResourceType: "service"}
	if err := s.Create(ctx, &item); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.VerifyChain(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAuditPruneAcrossBatches(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedAuditRows(t, s, start, auditPruneBatchSize+250)

	result, err := s.PruneBefore(ctx, start.Add(time.Duration(auditPruneBatchSize+100)*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if result.Removed != int64(auditPruneBatchSize+100) {
		t.Fatalf("expected %d removed, got %d", auditPruneBatchSize+100, result.Removed)
	}
	if _, err := s.VerifyChain(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAuditCheckpointTamperingIsDetected(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedAuditRows(t, s, start, 5)
	if _, err := s.PruneBefore(ctx, start.Add(2*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if err := s.db.Where("id <= ?", 3).Delete(&domain.AuditLog{}).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.VerifyChain(ctx); err == nil {
		t.Fatal("expected verification to fail after deleting rows past the checkpoint")
	}

	other := NewAuditStore(s.db, []byte("other-key"))
	if _, err := other.VerifyChain(ctx); err == nil {
		t.Fatal("expected checkpoint signed with another key to be rejected")
	}
}

func TestAuditCompactDropsCheckpoint(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedAuditRows(t, s, start, 5)
	if _, err := s.PruneBefore(ctx, start.Add(2*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := s.Compact(ctx); err != nil {
		t.Fatalf("compact: %v", err)
	}
	checkpoint, err := s.Checkpoint(ctx)
	if err != nil || checkpoint != nil {
		t.Fatalf("expected no checkpoint after compaction, got %+v, %v", checkpoint, err)
	}
	verify, err := s.VerifyChain(ctx)
	if err != nil || verify.Verified != 3 {
		t.Fatalf("verify after compaction: %+v, %v", verify, err)
	}
}

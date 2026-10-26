package store

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

const (
	auditCheckpointBucket = "audit"
	auditCheckpointKey    = "checkpoint"
	auditPruneBatchSize   = 1000
)

type AuditCheckpoint struct {
	LastID    uint      `json:"last_id"`
	LastHash  string    `json:"last_hash"`
	Pruned    int64     `json:"pruned"`
	PrunedAt  time.Time `json:"pruned_at"`
	Signature string    `json:"signature"`
}

type AuditPruneResult struct {
	Removed int64 `json:"removed"`
	LastID  uint  `json:"last_id"`
}

func (s *AuditStore) PruneBefore(ctx context.Context, before time.Time) (AuditPruneResult, error) {
	result := AuditPruneResult{}
	for {
		removed, lastID, done, err := s.pruneBatch(ctx, before)
		if err != nil {
			return result, err
		}
		result.Removed += removed
		if lastID > 0 {
			result.LastID = lastID
		}
		if done {
			return result, nil
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
	}
}

func (s *AuditStore) pruneBatch(ctx context.Context, before time.Time) (int64, uint, bool, error) {
	var (
		removed int64
		lastID  uint
		done    = true
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var newestID uint
		if err := tx.Model(&domain.AuditLog{}).Select("COALESCE(MAX(id), 0)").Scan(&newestID).Error; err != nil {
			return err
		}
		var batch []domain.AuditLog
		if err := tx.Select("id", "timestamp", "hash").
			Where("id < ?", newestID).
			Order("id asc").
			Limit(auditPruneBatchSize).
			Find(&batch).Error; err != nil {
			return err
		}
		cut := -1
		for i := range batch {
			if !batch[i].Timestamp.Before(before) {
				break
			}
			cut = i
		}
		if cut < 0 {
			return nil
		}
		last := batch[cut]
		res := tx.Where("id <= ?", last.ID).Delete(&domain.AuditLog{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		previous, err := s.loadCheckpoint(tx)
		if err != nil {
			return err
		}
		next := AuditCheckpoint{
			LastID:   last.ID,
			LastHash: last.Hash,
			Pruned:   res.RowsAffected,
			PrunedAt: time.Now().UTC(),
		}
		if previous != nil {
			next.Pruned += previous.Pruned
		}
		if err := s.saveCheckpoint(tx, next); err != nil {
			return err
		}
		removed = res.RowsAffected
		lastID = last.ID
		done = cut < len(batch)-1 || len(batch) < auditPruneBatchSize
		return nil
	})
	return removed, lastID, done, err
}

func (s *AuditStore) Checkpoint(ctx context.Context) (*AuditCheckpoint, error) {
	return s.loadCheckpoint(s.db.WithContext(ctx))
}

func (s *AuditStore) loadCheckpoint(db *gorm.DB) (*AuditCheckpoint, error) {
	var row domain.DistributedKV
	if err := db.Where("bucket = ? AND key = ?", auditCheckpointBucket, auditCheckpointKey).Limit(1).Find(&row).Error; err != nil {
		return nil, err
	}
	if row.ID == 0 {
		return nil, nil
	}
	var checkpoint AuditCheckpoint
	if err := json.Unmarshal(row.Value, &checkpoint); err != nil {
		return nil, fmt.Errorf("decode audit checkpoint: %w", err)
	}
	if !hmac.Equal([]byte(checkpoint.Signature), []byte(s.checkpointSignature(checkpoint))) {
		return nil, fmt.Errorf("audit checkpoint signature mismatch")
	}
	return &checkpoint, nil
}

func (s *AuditStore) saveCheckpoint(tx *gorm.DB, checkpoint AuditCheckpoint) error {
	checkpoint.Signature = s.checkpointSignature(checkpoint)
	value, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if err := deleteAuditCheckpoint(tx); err != nil {
		return err
	}
	return tx.Create(&domain.DistributedKV{
		Bucket:     auditCheckpointBucket,
		Key:        auditCheckpointKey,
		Value:      value,
		ModifiedAt: time.Now().UTC(),
	}).Error
}

func deleteAuditCheckpoint(tx *gorm.DB) error {
	return tx.Where("bucket = ? AND key = ?", auditCheckpointBucket, auditCheckpointKey).Delete(&domain.DistributedKV{}).Error
}

func (s *AuditStore) checkpointSignature(checkpoint AuditCheckpoint) string {
	payload, _ := json.Marshal(map[string]any{
		"kind":      "audit_checkpoint",
		"last_id":   checkpoint.LastID,
		"last_hash": checkpoint.LastHash,
		"pruned":    checkpoint.Pruned,
		"pruned_at": checkpoint.PrunedAt.UTC().Format(time.RFC3339Nano),
	})
	return signAuditPayload(s.hmacKey, payload)
}

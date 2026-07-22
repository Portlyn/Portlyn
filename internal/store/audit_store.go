package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type AuditListParams struct {
	Limit        int
	Offset       int
	UserID       *uint
	ResourceType string
	ResourceID   *uint
	ActionLike   string
	RequestID    string
	Method       string
	StatusCode   *int
	Host         string
	From         *time.Time
	To           *time.Time
}

type AuditStore struct {
	db      *gorm.DB
	hmacKey []byte
}

func NewAuditStore(db *gorm.DB, hmacKey []byte) *AuditStore {
	return &AuditStore{db: db, hmacKey: append([]byte(nil), hmacKey...)}
}

func (s *AuditStore) Create(ctx context.Context, item *domain.AuditLog) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		prevHash, err := latestAuditHash(tx.WithContext(ctx))
		if err != nil {
			return err
		}
		item.PrevHash = prevHash
		item.Hash = computeAuditHash(s.hmacKey, prevHash, item)
		return tx.WithContext(ctx).Create(item).Error
	})
}

func (s *AuditStore) CreateBatch(ctx context.Context, items []domain.AuditLog) error {
	if len(items) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		prevHash, err := latestAuditHash(tx.WithContext(ctx))
		if err != nil {
			return err
		}
		for i := range items {
			items[i].PrevHash = prevHash
			items[i].Hash = computeAuditHash(s.hmacKey, prevHash, &items[i])
			prevHash = items[i].Hash
		}
		return tx.WithContext(ctx).Create(&items).Error
	})
}

func (s *AuditStore) List(ctx context.Context, params AuditListParams) ([]domain.AuditLog, int64, error) {
	query := s.db.WithContext(ctx).Model(&domain.AuditLog{})
	if params.UserID != nil {
		query = query.Where("user_id = ?", *params.UserID)
	}
	if params.ResourceType != "" {
		query = query.Where("resource_type = ?", params.ResourceType)
	}
	if params.ResourceID != nil {
		query = query.Where("resource_id = ?", *params.ResourceID)
	}
	if params.ActionLike != "" {
		query = query.Where("action LIKE ?", params.ActionLike)
	}
	if params.RequestID != "" {
		query = query.Where("request_id = ?", params.RequestID)
	}
	if params.Method != "" {
		query = query.Where("method = ?", params.Method)
	}
	if params.StatusCode != nil {
		query = query.Where("status_code = ?", *params.StatusCode)
	}
	if params.Host != "" {
		query = query.Where("host = ?", params.Host)
	}
	if params.From != nil {
		query = query.Where("timestamp >= ?", *params.From)
	}
	if params.To != nil {
		query = query.Where("timestamp <= ?", *params.To)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if params.Limit <= 0 || params.Limit > 200 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	var items []domain.AuditLog
	err := query.Order("timestamp desc").Limit(params.Limit).Offset(params.Offset).Find(&items).Error
	return items, total, err
}

func (s *AuditStore) CountByActionLikeSince(ctx context.Context, actionLike string, since time.Time) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&domain.AuditLog{}).
		Where("action LIKE ? AND timestamp >= ?", actionLike, since).
		Count(&count).Error
	return count, err
}

func latestAuditHash(db *gorm.DB) (string, error) {
	var latest domain.AuditLog
	if err := db.Order("id desc").Limit(1).Find(&latest).Error; err != nil {
		return "", err
	}
	return latest.Hash, nil
}

func computeAuditHash(key []byte, prevHash string, item *domain.AuditLog) string {
	payload := map[string]any{
		"prev_hash":     prevHash,
		"timestamp":     item.Timestamp.UTC().Format(time.RFC3339Nano),
		"request_id":    item.RequestID,
		"user_id":       item.UserID,
		"action":        item.Action,
		"resource_type": item.ResourceType,
		"resource_id":   item.ResourceID,
		"method":        item.Method,
		"host":          item.Host,
		"path":          item.Path,
		"status_code":   item.StatusCode,
		"latency_ms":    item.LatencyMs,
		"remote_addr":   item.RemoteAddr,
		"user_agent":    item.UserAgent,
		"details":       item.Details,
	}
	encoded, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyAuditHashChain(key []byte, items []domain.AuditLog) error {
	prevHash := ""
	for i := range items {
		next, err := verifyAuditChainSegment(key, prevHash, items[i:i+1])
		if err != nil {
			return err
		}
		prevHash = next
	}
	return nil
}

func verifyAuditChainSegment(key []byte, prevHash string, items []domain.AuditLog) (string, error) {
	for i := range items {
		item := &items[i]
		if item.PrevHash != prevHash {
			return "", fmt.Errorf("audit chain mismatch at id %d", item.ID)
		}
		expected := computeAuditHash(key, prevHash, item)
		if item.Hash != expected {
			return "", fmt.Errorf("audit hash mismatch at id %d", item.ID)
		}
		prevHash = item.Hash
	}
	return prevHash, nil
}

type AuditChainResult struct {
	Verified   int64  `json:"verified"`
	LatestID   uint   `json:"latest_id"`
	LatestHash string `json:"latest_hash"`
}

type AuditCompactionResult struct {
	Scanned    int64  `json:"scanned"`
	Removed    int64  `json:"removed"`
	Kept       int64  `json:"kept"`
	LatestHash string `json:"latest_hash"`
}

func auditRowIsAccessNoise(item *domain.AuditLog) bool {
	if item.ResourceType == "http_request" {
		return true
	}
	if item.Action == "proxy_access" {
		return auditDetailOutcome(item.Details) != "denied"
	}
	return false
}

func auditDetailOutcome(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var parsed struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return ""
	}
	return parsed.Outcome
}

func (s *AuditStore) Compact(ctx context.Context) (AuditCompactionResult, error) {
	const batchSize = 500
	result := AuditCompactionResult{}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		prevHash := ""
		var lastID uint
		for {
			var batch []domain.AuditLog
			if err := tx.Where("id > ?", lastID).Order("id asc").Limit(batchSize).Find(&batch).Error; err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			for i := range batch {
				row := &batch[i]
				lastID = row.ID
				result.Scanned++
				if auditRowIsAccessNoise(row) {
					if err := tx.Delete(&domain.AuditLog{}, row.ID).Error; err != nil {
						return err
					}
					result.Removed++
					continue
				}
				newHash := computeAuditHash(s.hmacKey, prevHash, row)
				if row.PrevHash != prevHash || row.Hash != newHash {
					if err := tx.Model(&domain.AuditLog{}).Where("id = ?", row.ID).
						Updates(map[string]any{"prev_hash": prevHash, "hash": newHash}).Error; err != nil {
						return err
					}
				}
				prevHash = newHash
				result.Kept++
			}
			if len(batch) < batchSize {
				break
			}
		}
		result.LatestHash = prevHash
		return nil
	})
	if err != nil {
		return AuditCompactionResult{}, err
	}
	return result, nil
}

func (s *AuditStore) Vacuum(ctx context.Context) error {
	return s.db.WithContext(ctx).Exec("VACUUM").Error
}

func (s *AuditStore) VerifyChain(ctx context.Context) (AuditChainResult, error) {
	const batchSize = 500
	result := AuditChainResult{}
	prevHash := ""
	var lastID uint
	for {
		var batch []domain.AuditLog
		if err := s.db.WithContext(ctx).
			Where("id > ?", lastID).
			Order("id asc").
			Limit(batchSize).
			Find(&batch).Error; err != nil {
			return result, err
		}
		if len(batch) == 0 {
			break
		}
		next, err := verifyAuditChainSegment(s.hmacKey, prevHash, batch)
		if err != nil {
			return result, err
		}
		prevHash = next
		lastID = batch[len(batch)-1].ID
		result.Verified += int64(len(batch))
		if len(batch) < batchSize {
			break
		}
	}
	result.LatestID = lastID
	result.LatestHash = prevHash
	return result, nil
}

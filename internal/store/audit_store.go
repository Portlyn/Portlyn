package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

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
		sanitizeAuditLog(item)
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
			sanitizeAuditLog(&items[i])
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

const (
	legacyInvalidUTF8Marker = string(rune(0xFDD0))
	legacyInvalidUTF8Escape = `\` + "ufffd"
)

func computeAuditHash(key []byte, prevHash string, item *domain.AuditLog) string {
	encoded, _ := json.Marshal(auditHashPayload(prevHash, item, string(utf8.RuneError)))
	return signAuditPayload(key, encoded)
}

func computeLegacyAuditHash(key []byte, prevHash string, item *domain.AuditLog) string {
	encoded, _ := json.Marshal(auditHashPayload(prevHash, item, legacyInvalidUTF8Marker))
	encoded = bytes.ReplaceAll(encoded, []byte(legacyInvalidUTF8Marker), []byte(legacyInvalidUTF8Escape))
	return signAuditPayload(key, encoded)
}

func auditHashPayload(prevHash string, item *domain.AuditLog, invalid string) map[string]any {
	clean := func(value string) string { return replaceInvalidUTF8(value, invalid) }
	return map[string]any{
		"prev_hash":     prevHash,
		"timestamp":     item.Timestamp.UTC().Format(time.RFC3339Nano),
		"request_id":    clean(item.RequestID),
		"user_id":       item.UserID,
		"action":        clean(item.Action),
		"resource_type": clean(item.ResourceType),
		"resource_id":   item.ResourceID,
		"method":        clean(item.Method),
		"host":          clean(item.Host),
		"path":          clean(item.Path),
		"status_code":   item.StatusCode,
		"latency_ms":    item.LatencyMs,
		"remote_addr":   clean(item.RemoteAddr),
		"user_agent":    clean(item.UserAgent),
		"details":       clean(item.Details),
	}
}

func signAuditPayload(key, encoded []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil))
}

func replaceInvalidUTF8(value, replacement string) string {
	if utf8.ValidString(value) {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(replacement)
		} else {
			b.WriteString(value[i : i+size])
		}
		i += size
	}
	return b.String()
}

func auditLogHasInvalidUTF8(item *domain.AuditLog) bool {
	for _, value := range []string{item.RequestID, item.Action, item.ResourceType, item.Method, item.Host, item.Path, item.RemoteAddr, item.UserAgent, item.Details} {
		if !utf8.ValidString(value) {
			return true
		}
	}
	return false
}

func sanitizeAuditLog(item *domain.AuditLog) {
	valid := func(value string) string { return replaceInvalidUTF8(value, string(utf8.RuneError)) }
	item.RequestID = valid(item.RequestID)
	item.Action = valid(item.Action)
	item.ResourceType = valid(item.ResourceType)
	item.Method = valid(item.Method)
	item.Host = valid(item.Host)
	item.Path = valid(item.Path)
	item.RemoteAddr = valid(item.RemoteAddr)
	item.UserAgent = valid(item.UserAgent)
	item.Details = valid(item.Details)
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
		if item.Hash != computeAuditHash(key, prevHash, item) &&
			(!auditLogHasInvalidUTF8(item) || item.Hash != computeLegacyAuditHash(key, prevHash, item)) {
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
	AnchorID   uint   `json:"anchor_id,omitempty"`
	Pruned     int64  `json:"pruned,omitempty"`
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
		outcome, reason := auditDetailOutcome(item.Details)
		if outcome != "denied" {
			return true
		}
		return reason == "login_required" || (reason == "authz" && item.StatusCode == http.StatusFound)
	}
	return false
}

func auditDetailOutcome(raw string) (string, string) {
	if strings.TrimSpace(raw) == "" {
		return "", ""
	}
	var parsed struct {
		Outcome string `json:"outcome"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "", ""
	}
	return parsed.Outcome, parsed.Reason
}

func (s *AuditStore) Compact(ctx context.Context) (AuditCompactionResult, error) {
	const batchSize = 500
	result := AuditCompactionResult{}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := deleteAuditCheckpoint(tx); err != nil {
			return err
		}
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
	checkpoint, err := s.Checkpoint(ctx)
	if err != nil {
		return result, err
	}
	if checkpoint != nil {
		prevHash = checkpoint.LastHash
		lastID = checkpoint.LastID
		result.AnchorID = checkpoint.LastID
		result.Pruned = checkpoint.Pruned
	}
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

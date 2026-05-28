package store

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

type AuditWebhookStore struct {
	db                  *gorm.DB
	dataEncryptionBytes [][]byte
}

func NewAuditWebhookStore(db *gorm.DB) *AuditWebhookStore {
	return &AuditWebhookStore{db: db}
}

func (s *AuditWebhookStore) SetDataEncryptionSecrets(values []string) {
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, []byte(trimmed))
		}
	}
	s.dataEncryptionBytes = out
}

func (s *AuditWebhookStore) encryptSecret(item *domain.AuditWebhook) error {
	if len(s.dataEncryptionBytes) == 0 || strings.TrimSpace(item.SecretEncrypted) == "" {
		return nil
	}
	if secureconfig.IsEncryptedValue(item.SecretEncrypted) {
		return nil
	}
	encrypted, err := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.SecretEncrypted)
	if err != nil {
		return err
	}
	item.SecretEncrypted = encrypted
	return nil
}

func (s *AuditWebhookStore) decryptSecret(item *domain.AuditWebhook) {
	if strings.TrimSpace(item.SecretEncrypted) == "" || !secureconfig.IsEncryptedValue(item.SecretEncrypted) {
		return
	}
	if plain, err := secureconfig.DecryptStringAuto(s.dataEncryptionBytes, item.SecretEncrypted); err == nil {
		item.SecretEncrypted = plain
	}
}

func (s *AuditWebhookStore) List(ctx context.Context) ([]domain.AuditWebhook, error) {
	var items []domain.AuditWebhook
	err := s.db.WithContext(ctx).Order("id asc").Find(&items).Error
	if err != nil {
		return nil, err
	}
	for i := range items {
		s.decryptSecret(&items[i])
	}
	return items, nil
}

var DefaultWebhookEvents = map[string]struct{}{
	"login_succeeded":                {},
	"login_failed":                   {},
	"mfa_verify_succeeded":           {},
	"mfa_verify_failed":              {},
	"create":                         {},
	"update":                         {},
	"delete":                         {},
	"enroll":                         {},
	"magic_link_issued":              {},
	"tunnel_bootstrap":               {},
	"tunnel_revoke":                  {},
	"passkey_registered":             {},
	"passkey_deleted":                {},
	"node_heartbeat_rejected":        {},
	"route_pin_failed":               {},
	"route_email_code_verify_failed": {},
	"security_alert":                 {},
	"break_glass_login":              {},
}

func (s *AuditWebhookStore) ActiveByEvent(ctx context.Context, action string) ([]domain.AuditWebhook, error) {
	var items []domain.AuditWebhook
	err := s.db.WithContext(ctx).Where("active = ?", true).Find(&items).Error
	if err != nil {
		return nil, err
	}
	out := items[:0]
	for _, item := range items {
		matched := false
		if len(item.EventTypes) == 0 {
			if _, ok := DefaultWebhookEvents[action]; ok {
				matched = true
			}
		} else {
			for _, allowed := range item.EventTypes {
				if allowed == action || allowed == "*" {
					matched = true
					break
				}
			}
		}
		if matched {
			s.decryptSecret(&item)
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *AuditWebhookStore) GetByID(ctx context.Context, id uint) (*domain.AuditWebhook, error) {
	var item domain.AuditWebhook
	err := s.db.WithContext(ctx).First(&item, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.decryptSecret(&item)
	return &item, nil
}

func (s *AuditWebhookStore) Create(ctx context.Context, item *domain.AuditWebhook) error {
	encrypted := *item
	if err := s.encryptSecret(&encrypted); err != nil {
		return err
	}
	if err := s.db.WithContext(ctx).Create(&encrypted).Error; err != nil {
		return err
	}
	item.ID = encrypted.ID
	return nil
}

func (s *AuditWebhookStore) Update(ctx context.Context, item *domain.AuditWebhook) error {
	encrypted := *item
	if err := s.encryptSecret(&encrypted); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(&encrypted).Error
}

func (s *AuditWebhookStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.AuditWebhook{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

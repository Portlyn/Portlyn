package store

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type AuditWebhookStore struct {
	db *gorm.DB
}

func NewAuditWebhookStore(db *gorm.DB) *AuditWebhookStore {
	return &AuditWebhookStore{db: db}
}

func (s *AuditWebhookStore) List(ctx context.Context) ([]domain.AuditWebhook, error) {
	var items []domain.AuditWebhook
	err := s.db.WithContext(ctx).Order("id asc").Find(&items).Error
	return items, err
}

func (s *AuditWebhookStore) ActiveByEvent(ctx context.Context, action string) ([]domain.AuditWebhook, error) {
	var items []domain.AuditWebhook
	err := s.db.WithContext(ctx).Where("active = ?", true).Find(&items).Error
	if err != nil {
		return nil, err
	}
	out := items[:0]
	for _, item := range items {
		if len(item.EventTypes) == 0 {
			out = append(out, item)
			continue
		}
		for _, allowed := range item.EventTypes {
			if allowed == action || allowed == "*" {
				out = append(out, item)
				break
			}
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
	return &item, nil
}

func (s *AuditWebhookStore) Create(ctx context.Context, item *domain.AuditWebhook) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *AuditWebhookStore) Update(ctx context.Context, item *domain.AuditWebhook) error {
	return s.db.WithContext(ctx).Save(item).Error
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

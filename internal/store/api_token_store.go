package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type APITokenStore struct {
	db *gorm.DB
}

func NewAPITokenStore(db *gorm.DB) *APITokenStore {
	return &APITokenStore{db: db}
}

func (s *APITokenStore) Create(ctx context.Context, item *domain.APIToken) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *APITokenStore) List(ctx context.Context) ([]domain.APIToken, error) {
	var items []domain.APIToken
	err := s.db.WithContext(ctx).Order("created_at desc").Find(&items).Error
	return items, err
}

func (s *APITokenStore) FindActiveByPrefix(ctx context.Context, prefix string) (*domain.APIToken, error) {
	var item domain.APIToken
	err := s.db.WithContext(ctx).Where("prefix = ? AND revoked_at IS NULL", prefix).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *APITokenStore) Revoke(ctx context.Context, id uint, at time.Time) error {
	result := s.db.WithContext(ctx).Model(&domain.APIToken{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", at.UTC())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *APITokenStore) TouchLastUsed(ctx context.Context, id uint, at time.Time) error {
	return s.db.WithContext(ctx).Model(&domain.APIToken{}).
		Where("id = ?", id).
		Update("last_used_at", at.UTC()).Error
}

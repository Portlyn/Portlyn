package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type NodeEnrollmentTokenStore struct {
	db *gorm.DB
}

func NewNodeEnrollmentTokenStore(db *gorm.DB) *NodeEnrollmentTokenStore {
	return &NodeEnrollmentTokenStore{db: db}
}

func (s *NodeEnrollmentTokenStore) List(ctx context.Context) ([]domain.NodeEnrollmentToken, error) {
	var items []domain.NodeEnrollmentToken
	err := s.db.WithContext(ctx).Order("created_at desc").Find(&items).Error
	return items, err
}

func (s *NodeEnrollmentTokenStore) Create(ctx context.Context, item *domain.NodeEnrollmentToken) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *NodeEnrollmentTokenStore) GetByID(ctx context.Context, id uint) (*domain.NodeEnrollmentToken, error) {
	var item domain.NodeEnrollmentToken
	err := s.db.WithContext(ctx).First(&item, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *NodeEnrollmentTokenStore) GetActiveByHash(ctx context.Context, tokenHash string, now time.Time) (*domain.NodeEnrollmentToken, error) {
	var item domain.NodeEnrollmentToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND active = ? AND (expires_at IS NULL OR expires_at > ?)", tokenHash, true, now).
		First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if item.SingleUse && item.UsedAt != nil {
		return nil, ErrNotFound
	}
	return &item, nil
}

func (s *NodeEnrollmentTokenStore) Update(ctx context.Context, item *domain.NodeEnrollmentToken) error {
	return s.db.WithContext(ctx).Save(item).Error
}

func (s *NodeEnrollmentTokenStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.NodeEnrollmentToken{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

package store

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type UserCredentialStore struct {
	db *gorm.DB
}

func NewUserCredentialStore(db *gorm.DB) *UserCredentialStore {
	return &UserCredentialStore{db: db}
}

func (s *UserCredentialStore) ListByUser(ctx context.Context, userID uint) ([]domain.UserCredential, error) {
	var items []domain.UserCredential
	err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at asc").Find(&items).Error
	return items, err
}

func (s *UserCredentialStore) GetByCredentialID(ctx context.Context, credentialID string) (*domain.UserCredential, error) {
	var item domain.UserCredential
	err := s.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *UserCredentialStore) Create(ctx context.Context, item *domain.UserCredential) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *UserCredentialStore) Update(ctx context.Context, item *domain.UserCredential) error {
	return s.db.WithContext(ctx).Save(item).Error
}

func (s *UserCredentialStore) Delete(ctx context.Context, userID, id uint) error {
	result := s.db.WithContext(ctx).Where("user_id = ? AND id = ?", userID, id).Delete(&domain.UserCredential{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

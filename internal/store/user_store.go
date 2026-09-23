package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type UserStore struct {
	db *gorm.DB
}

func NewUserStore(db *gorm.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) Count(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&domain.User{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (s *UserStore) Create(ctx context.Context, user *domain.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

func (s *UserStore) List(ctx context.Context) ([]domain.User, error) {
	var users []domain.User
	err := s.db.WithContext(ctx).Order("id asc").Find(&users).Error
	return users, err
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := s.db.WithContext(ctx).Where("lower(email) = ?", strings.ToLower(email)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserStore) GetByProviderRef(ctx context.Context, provider, ref string) (*domain.User, error) {
	var user domain.User
	err := s.db.WithContext(ctx).
		Where("auth_provider = ? AND auth_provider_ref = ?", provider, strings.TrimSpace(ref)).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserStore) GetByID(ctx context.Context, id uint) (*domain.User, error) {
	var user domain.User
	err := s.db.WithContext(ctx).First(&user, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserStore) UpdateFields(ctx context.Context, user *domain.User, fields ...string) error {
	return s.UpdateFieldsIf(ctx, user, nil, fields...)
}

func (s *UserStore) UpdateFieldsIf(ctx context.Context, user *domain.User, guard map[string]any, fields ...string) error {
	if len(fields) == 0 {
		return nil
	}
	query := s.db.WithContext(ctx).Model(user).Select(fields)
	if len(guard) > 0 {
		query = query.Where(guard)
	}
	result := query.Updates(user)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		if len(guard) > 0 {
			return ErrStale
		}
		return ErrNotFound
	}
	return nil
}

func (s *UserStore) UpdateColumns(ctx context.Context, id uint, values map[string]any) error {
	return s.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Updates(values).Error
}

func (s *UserStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.User{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *UserStore) CountActiveAdmins(ctx context.Context, excludeUserID *uint) (int64, error) {
	query := s.db.WithContext(ctx).Model(&domain.User{}).Where("role = ? AND active = ?", domain.RoleAdmin, true)
	if excludeUserID != nil {
		query = query.Where("id <> ?", *excludeUserID)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (s *UserStore) UpdateLastLogin(ctx context.Context, id uint, at time.Time) error {
	return s.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Update("last_login_at", at).Error
}

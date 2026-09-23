package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type SessionStore struct {
	db *gorm.DB
}

func NewSessionStore(db *gorm.DB) *SessionStore {
	return &SessionStore{db: db}
}

func (s *SessionStore) Create(ctx context.Context, item *domain.Session) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *SessionStore) GetByRefreshHash(ctx context.Context, refreshHash string) (*domain.Session, error) {
	var item domain.Session
	err := s.db.WithContext(ctx).Where("refresh_token_hash = ?", refreshHash).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *SessionStore) GetByID(ctx context.Context, id uint) (*domain.Session, error) {
	var item domain.Session
	err := s.db.WithContext(ctx).First(&item, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *SessionStore) GetByTokenID(ctx context.Context, tokenID string) (*domain.Session, error) {
	var item domain.Session
	err := s.db.WithContext(ctx).Where("token_id = ?", tokenID).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *SessionStore) ListByUser(ctx context.Context, userID uint) ([]domain.Session, error) {
	var items []domain.Session
	err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at desc").Find(&items).Error
	return items, err
}

func (s *SessionStore) Rotate(ctx context.Context, item *domain.Session, previousRefreshHash string) error {
	result := s.db.WithContext(ctx).Model(&domain.Session{}).
		Where("id = ? AND revoked_at IS NULL AND refresh_token_hash = ?", item.ID, previousRefreshHash).
		Updates(map[string]any{
			"token_id":           item.TokenID,
			"refresh_token_hash": item.RefreshTokenHash,
			"user_agent":         item.UserAgent,
			"remote_addr":        item.RemoteAddr,
			"last_seen_at":       item.LastSeenAt,
			"expires_at":         item.ExpiresAt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SessionStore) Touch(ctx context.Context, id uint, at time.Time) error {
	result := s.db.WithContext(ctx).Model(&domain.Session{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("last_seen_at", at)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SessionStore) MarkBootstrapDismissed(ctx context.Context, id uint, now time.Time) error {
	result := s.db.WithContext(ctx).Model(&domain.Session{}).Where("id = ?", id).Updates(map[string]any{
		"bootstrap_dismissed": true,
		"updated_at":          now,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SessionStore) Revoke(ctx context.Context, id uint, revokedAt time.Time) error {
	result := s.db.WithContext(ctx).Model(&domain.Session{}).Where("id = ? AND revoked_at IS NULL", id).Updates(map[string]any{
		"revoked_at": revokedAt,
		"updated_at": revokedAt,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SessionStore) RevokeByUser(ctx context.Context, userID uint, revokedAt time.Time) error {
	return s.db.WithContext(ctx).Model(&domain.Session{}).Where("user_id = ? AND revoked_at IS NULL", userID).Updates(map[string]any{
		"revoked_at": revokedAt,
		"updated_at": revokedAt,
	}).Error
}

func (s *SessionStore) RevokeByUserExcept(ctx context.Context, userID uint, exceptSessionID uint, revokedAt time.Time) error {
	q := s.db.WithContext(ctx).Model(&domain.Session{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if exceptSessionID != 0 {
		q = q.Where("id <> ?", exceptSessionID)
	}
	return q.Updates(map[string]any{
		"revoked_at": revokedAt,
		"updated_at": revokedAt,
	}).Error
}

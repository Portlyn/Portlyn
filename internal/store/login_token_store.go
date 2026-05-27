package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type LoginTokenStore struct {
	db *gorm.DB
}

var sha256HexPattern = regexp.MustCompile("^[a-f0-9]{64}$")

func NewLoginTokenStore(db *gorm.DB) *LoginTokenStore {
	return &LoginTokenStore{db: db}
}

func (s *LoginTokenStore) Create(ctx context.Context, item *domain.LoginToken) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *LoginTokenStore) CountRecentByEmail(ctx context.Context, email string, since time.Time) (int64, error) {
	return s.CountRecentByEmailAndScope(ctx, email, domain.LoginTokenScopeAccountLogin, nil, since)
}

func (s *LoginTokenStore) CountRecentByEmailAndScope(ctx context.Context, email, scope string, serviceID *uint, since time.Time) (int64, error) {
	var count int64
	query := s.db.WithContext(ctx).
		Model(&domain.LoginToken{}).
		Where("lower(email) = ? AND scope = ? AND created_at >= ?", strings.ToLower(strings.TrimSpace(email)), strings.TrimSpace(scope), since)
	if serviceID == nil {
		query = query.Where("service_id IS NULL")
	} else {
		query = query.Where("service_id = ?", *serviceID)
	}
	err := query.Count(&count).Error
	return count, err
}

func (s *LoginTokenStore) GetValidToken(ctx context.Context, email, token string) (*domain.LoginToken, error) {
	return s.GetValidTokenByScope(ctx, email, token, domain.LoginTokenScopeAccountLogin, nil)
}

func (s *LoginTokenStore) GetValidTokenByScope(ctx context.Context, email, token, scope string, serviceID *uint) (*domain.LoginToken, error) {
	var item domain.LoginToken
	hashedToken := hashLoginToken(strings.TrimSpace(token))
	query := s.db.WithContext(ctx).
		Where("scope = ? AND (token = ? OR token = ?)", strings.TrimSpace(scope), hashedToken, strings.TrimSpace(token))
	if strings.TrimSpace(email) != "" {
		query = query.Where("lower(email) = ?", strings.ToLower(strings.TrimSpace(email)))
	}
	if serviceID == nil {
		query = query.Where("service_id IS NULL")
	} else {
		query = query.Where("service_id = ?", *serviceID)
	}
	err := query.Order("id desc").First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *LoginTokenStore) MarkUsed(ctx context.Context, id uint, usedAt time.Time) error {
	return s.db.WithContext(ctx).Model(&domain.LoginToken{}).Where("id = ?", id).Update("used_at", usedAt).Error
}

func (s *LoginTokenStore) GetMagicLink(ctx context.Context, serviceID uint, token string) (*domain.LoginToken, error) {
	var item domain.LoginToken
	hashed := hashLoginToken(strings.TrimSpace(token))
	err := s.db.WithContext(ctx).
		Where("scope = ? AND service_id = ? AND token = ?", domain.LoginTokenScopeMagicLink, serviceID, hashed).
		Order("id desc").
		First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func hashLoginToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *LoginTokenStore) MigratePlainTokens(ctx context.Context) (int, error) {
	var rows []domain.LoginToken
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return 0, err
	}
	updated := 0
	for _, row := range rows {
		token := strings.TrimSpace(row.Token)
		if token == "" || sha256HexPattern.MatchString(token) {
			continue
		}
		if err := s.db.WithContext(ctx).Model(&domain.LoginToken{}).Where("id = ?", row.ID).Update("token", hashLoginToken(token)).Error; err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

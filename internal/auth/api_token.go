package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"portlyn/internal/domain"
)

const apiTokenScheme = "plyn"

type APITokenStore interface {
	FindActiveByPrefix(ctx context.Context, prefix string) (*domain.APIToken, error)
	TouchLastUsed(ctx context.Context, id uint, at time.Time) error
}

func (s *Service) SetAPITokenStore(store APITokenStore) {
	s.apiTokens = store
}

func GenerateAPIToken() (prefix, token, hash string, err error) {
	idBytes := make([]byte, 4)
	secretBytes := make([]byte, 24)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", err
	}
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", "", err
	}
	prefix = apiTokenScheme + "_" + hex.EncodeToString(idBytes)
	token = prefix + "_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	hash = HashAPIToken(token)
	return prefix, token, hash, nil
}

func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func LooksLikeAPIToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), apiTokenScheme+"_")
}

func apiTokenPrefix(token string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(token), "_", 3)
	if len(parts) != 3 || parts[0] != apiTokenScheme || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[0] + "_" + parts[1], true
}

func (s *Service) authenticateAPIToken(ctx context.Context, token string) (*domain.User, []uint, *domain.Session, error) {
	prefix, ok := apiTokenPrefix(token)
	if !ok {
		return nil, nil, nil, ErrInvalidToken
	}
	rec, err := s.apiTokens.FindActiveByPrefix(ctx, prefix)
	if err != nil {
		return nil, nil, nil, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(HashAPIToken(token)), []byte(rec.TokenHash)) != 1 {
		return nil, nil, nil, ErrInvalidToken
	}
	now := time.Now().UTC()
	if rec.RevokedAt != nil || (rec.ExpiresAt != nil && !rec.ExpiresAt.After(now)) {
		return nil, nil, nil, ErrInvalidToken
	}
	_ = s.apiTokens.TouchLastUsed(ctx, rec.ID, now)

	role := rec.Role
	if role != domain.RoleAdmin && role != domain.RoleViewer {
		role = domain.RoleViewer
	}
	var uid uint
	if rec.CreatedByID != nil {
		uid = *rec.CreatedByID
	}
	user := &domain.User{
		ID:     uid,
		Email:  "api-token:" + rec.Name,
		Role:   role,
		Active: true,
	}
	return user, nil, nil, nil
}

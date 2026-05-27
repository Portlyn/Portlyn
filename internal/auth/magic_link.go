package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type MagicLinkIssueResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) IssueMagicLink(ctx context.Context, serviceID uint, ttl time.Duration, meta RequestMetadata, label string) (*MagicLinkIssueResult, error) {
	if serviceID == 0 {
		return nil, ErrInvalidToken
	}
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	token, err := randomCode(16)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	item := &domain.LoginToken{
		ServiceID:  &serviceID,
		Email:      strings.ToLower(strings.TrimSpace(label)),
		Token:      hashToken(token),
		Scope:      domain.LoginTokenScopeMagicLink,
		ExpiresAt:  expires,
		RemoteAddr: meta.RemoteAddr,
		UserAgent:  meta.UserAgent,
	}
	if err := s.loginTokens.Create(ctx, item); err != nil {
		return nil, err
	}
	return &MagicLinkIssueResult{Token: token, ExpiresAt: expires}, nil
}

func (s *Service) ConsumeMagicLink(ctx context.Context, serviceID uint, token string) error {
	if serviceID == 0 || strings.TrimSpace(token) == "" {
		return ErrInvalidToken
	}
	item, err := s.loginTokens.GetMagicLink(ctx, serviceID, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		return err
	}
	now := time.Now().UTC()
	if item.UsedAt != nil {
		return fmt.Errorf("magic link already used")
	}
	if item.ExpiresAt.Before(now) {
		return fmt.Errorf("magic link expired")
	}
	if err := s.loginTokens.MarkUsed(ctx, item.ID, now); err != nil {
		return err
	}
	return nil
}

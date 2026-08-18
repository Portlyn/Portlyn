package auth

import (
	"context"
	"fmt"
	"portlyn/internal/domain"
	"portlyn/internal/store"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (s *Service) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return s.jwtSigningSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (s *Service) AuthenticateAccessToken(ctx context.Context, tokenString string) (*domain.User, []uint, *domain.Session, error) {
	claims, parseErr := s.ParseToken(tokenString)
	if parseErr != nil {
		return nil, nil, nil, parseErr
	}
	if user, groupIDs, ok := s.getCachedAuthResult(ctx, tokenString); ok {
		if user == nil || !user.Active {
			return nil, nil, nil, ErrInactiveUser
		}
		var session *domain.Session
		if claims.SessionID != 0 && s.sessions != nil {
			s2, err := s.sessions.GetByTokenID(ctx, claims.TokenID)
			if err != nil {
				return nil, nil, nil, ErrInvalidToken
			}
			if s2.RevokedAt != nil {
				return nil, nil, nil, ErrSessionRevoked
			}
			now := time.Now().UTC()
			if s2.ExpiresAt.Before(now) {
				return nil, nil, nil, ErrRefreshExpired
			}
			session = s2
		}
		return user, groupIDs, session, nil
	}
	user, err := s.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, nil, nil, err
	}
	if !user.Active {
		return nil, nil, nil, ErrInactiveUser
	}
	var session *domain.Session
	if claims.SessionID != 0 && s.sessions != nil {
		s2, err := s.sessions.GetByTokenID(ctx, claims.TokenID)
		if err != nil {
			return nil, nil, nil, ErrInvalidToken
		}
		if s2.RevokedAt != nil {
			return nil, nil, nil, ErrSessionRevoked
		}
		now := time.Now().UTC()
		if s2.ExpiresAt.Before(now) {
			return nil, nil, nil, ErrRefreshExpired
		}
		s2.LastSeenAt = &now
		_ = s.sessions.Update(ctx, s2)
		session = s2
	}
	groupIDs, err := s.GetUserGroupIDs(ctx, user.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	s.storeCachedAuthResult(tokenString, user, groupIDs, claims.ExpiresAt)
	return user, groupIDs, session, nil
}

func (s *Service) issueToken(user *domain.User, session *domain.Session) (string, error) {
	now := time.Now()
	tokenID := ""
	sessionID := uint(0)
	if session != nil {
		tokenID = session.TokenID
		sessionID = session.ID
	}
	claims := Claims{
		UserID:    user.ID,
		SessionID: sessionID,
		TokenID:   tokenID,
		Role:      user.Role,
		Email:     user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("%d", user.ID),
			ID:        tokenID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSigningSecret)
}

func (s *Service) createSession(ctx context.Context, user *domain.User, meta RequestMetadata) (*domain.Session, string, error) {
	if s.sessions == nil {
		return nil, "", nil
	}
	now := time.Now().UTC()
	tokenID, err := randomCode(16)
	if err != nil {
		return nil, "", err
	}
	refreshToken, err := randomCode(24)
	if err != nil {
		return nil, "", err
	}
	session := &domain.Session{
		UserID:           user.ID,
		TokenID:          tokenID,
		RefreshTokenHash: hashToken(refreshToken),
		UserAgent:        strings.TrimSpace(meta.UserAgent),
		RemoteAddr:       rateLimitRemoteAddr(meta.RemoteAddr),
		LastSeenAt:       &now,
		ExpiresAt:        now.Add(s.refreshTokenTTL),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, "", err
	}
	return session, refreshToken, nil
}

func (s *Service) RefreshSession(ctx context.Context, refreshToken string, meta RequestMetadata) (*LoginResult, error) {
	if s.sessions == nil {
		return nil, ErrInvalidToken
	}
	session, err := s.sessions.GetByRefreshHash(ctx, hashToken(refreshToken))
	if err != nil {
		return nil, ErrInvalidToken
	}
	now := time.Now().UTC()
	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}
	if session.ExpiresAt.Before(now) {
		return nil, ErrRefreshExpired
	}
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if !user.Active {
		return nil, ErrInactiveUser
	}

	newTokenID, err := randomCode(16)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := randomCode(24)
	if err != nil {
		return nil, err
	}
	session.TokenID = newTokenID
	session.RefreshTokenHash = hashToken(newRefreshToken)
	session.UserAgent = firstNonEmpty(strings.TrimSpace(meta.UserAgent), session.UserAgent)
	session.RemoteAddr = firstNonEmpty(rateLimitRemoteAddr(meta.RemoteAddr), session.RemoteAddr)
	session.LastSeenAt = &now
	session.ExpiresAt = now.Add(s.refreshTokenTTL)
	if err := s.sessions.Update(ctx, session); err != nil {
		return nil, err
	}
	s.InvalidateUser(user.ID)
	token, err := s.issueToken(user, session)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: token, RefreshToken: newRefreshToken, User: user, Session: session}, nil
}

func (s *Service) ListUserSessions(ctx context.Context, userID uint) ([]domain.Session, error) {
	if s.sessions == nil {
		return []domain.Session{}, nil
	}
	return s.sessions.ListByUser(ctx, userID)
}

func (s *Service) RevokeSession(ctx context.Context, userID, sessionID uint) error {
	if s.sessions == nil {
		return store.ErrNotFound
	}
	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != userID {
		return store.ErrNotFound
	}
	if err := s.sessions.Revoke(ctx, sessionID, time.Now().UTC()); err != nil {
		return err
	}
	s.InvalidateUser(userID)
	return nil
}

func (s *Service) RevokeAllUserSessions(ctx context.Context, userID uint) error {
	if s.sessions == nil {
		return nil
	}
	if err := s.sessions.RevokeByUser(ctx, userID, time.Now().UTC()); err != nil {
		return err
	}
	s.InvalidateUser(userID)
	return nil
}

func (s *Service) RevokeOtherUserSessions(ctx context.Context, userID uint, keepSessionID uint) error {
	if s.sessions == nil {
		return nil
	}
	if err := s.sessions.RevokeByUserExcept(ctx, userID, keepSessionID, time.Now().UTC()); err != nil {
		return err
	}
	s.InvalidateUser(userID)
	return nil
}

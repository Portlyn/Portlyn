package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/observability"
	"portlyn/internal/rate"
	"portlyn/internal/store"
)

type Service struct {
	users                   *store.UserStore
	groups                  *store.GroupStore
	loginTokens             *store.LoginTokenStore
	sessions                *store.SessionStore
	settings                *store.AppSettingsStore
	jwtSigningSecret        []byte
	sessionBridgeSecret     []byte
	oidcStateSecret         []byte
	mfaEncryptionSecret     []byte
	issuer                  string
	tokenTTL                time.Duration
	refreshTokenTTL         time.Duration
	routeAuthTTL            time.Duration
	rateLimit               config.RateLimitConfig
	fallbackFrontendBaseURL string
	fallbackOIDC            config.OIDCConfig
	fallbackOTP             config.OTPConfig
	allowInsecureDevMode    bool
	oidcMu                  sync.RWMutex
	oidcCacheKey            string
	oidcCache               *OIDCAuthenticator
	cacheTTL                time.Duration
	cacheMu                 sync.RWMutex
	authCache               map[string]cachedAuthResult
	userTokens              map[uint]map[string]struct{}
	distributedRateLimiter  rate.RateLimiter
	fallbackRateLimiter     *rate.LocalLimiter
	distributedAuthCache    AuthCache
	metrics                 *observability.Metrics
	passkeyChecker          func(ctx context.Context, userID uint) bool
	apiTokens               APITokenStore
}

func (s *Service) SetPasskeyChecker(fn func(ctx context.Context, userID uint) bool) {
	s.passkeyChecker = fn
}

func (s *Service) userHasPasskey(ctx context.Context, userID uint) bool {
	if s.passkeyChecker == nil {
		return false
	}
	return s.passkeyChecker(ctx, userID)
}

func (s *Service) UserHasPasskey(ctx context.Context, userID uint) bool {
	return s.userHasPasskey(ctx, userID)
}

func (s *Service) UserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
}

func (s *Service) CompletePasskeyLogin(ctx context.Context, userID uint, meta RequestMetadata) (*LoginResult, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.Active {
		return nil, ErrInactiveUser
	}
	result, err := s.completeSuccessfulLogin(ctx, user, meta)
	if err == nil {
		s.observeAuth("passkey", "success")
	}
	return result, err
}

type cachedAuthResult struct {
	user      *domain.User
	groupIDs  []uint
	expiresAt time.Time
}

type Claims struct {
	UserID    uint   `json:"user_id"`
	SessionID uint   `json:"session_id"`
	TokenID   string `json:"token_id"`
	Role      string `json:"role"`
	Email     string `json:"email"`
	jwt.RegisteredClaims
}

type RequestMetadata struct {
	RemoteAddr string
	UserAgent  string
}

type LoginResult struct {
	Token             string
	RefreshToken      string
	User              *domain.User
	Session           *domain.Session
	MFARequired       bool
	MFAToken          string
	MFAExpiresAt      time.Time
	BootstrapRequired bool
}

type OTPRequestResult struct {
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"`
}

func NewService(
	users *store.UserStore,
	groups *store.GroupStore,
	loginTokens *store.LoginTokenStore,
	sessions *store.SessionStore,
	settings *store.AppSettingsStore,
	jwtSigningSecret, sessionBridgeSecret, oidcStateSecret, mfaEncryptionSecret, issuer, frontendBaseURL string,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	oidcCfg config.OIDCConfig,
	otpCfg config.OTPConfig,
	routeAuthTTL time.Duration,
	rateLimit config.RateLimitConfig,
	cacheTTL time.Duration,
	allowInsecureDevMode bool,
	metrics *observability.Metrics,
) (*Service, error) {
	return &Service{
		users:                   users,
		groups:                  groups,
		loginTokens:             loginTokens,
		sessions:                sessions,
		settings:                settings,
		jwtSigningSecret:        []byte(jwtSigningSecret),
		sessionBridgeSecret:     []byte(sessionBridgeSecret),
		oidcStateSecret:         []byte(oidcStateSecret),
		mfaEncryptionSecret:     []byte(mfaEncryptionSecret),
		issuer:                  issuer,
		tokenTTL:                tokenTTL,
		refreshTokenTTL:         refreshTokenTTL,
		routeAuthTTL:            routeAuthTTL,
		rateLimit:               rateLimit,
		fallbackFrontendBaseURL: strings.TrimRight(frontendBaseURL, "/"),
		fallbackOIDC:            oidcCfg,
		fallbackOTP:             otpCfg,
		allowInsecureDevMode:    allowInsecureDevMode,
		distributedRateLimiter:  rate.NewLocalLimiter(),
		fallbackRateLimiter:     rate.NewLocalLimiter(),
		cacheTTL:                cacheTTL,
		authCache:               make(map[string]cachedAuthResult),
		userTokens:              make(map[uint]map[string]struct{}),
		metrics:                 metrics,
	}, nil
}

func (s *Service) SetRateLimiter(limiter rate.RateLimiter) {
	s.distributedRateLimiter = limiter
}

func (s *Service) SetAuthCache(cache AuthCache) {
	s.distributedAuthCache = cache
}

func (s *Service) SeedInitialAdmin(ctx context.Context, email, password string) error {
	count, err := s.users.Count(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return nil
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.users.Create(ctx, &domain.User{
		Email:              strings.ToLower(strings.TrimSpace(email)),
		PasswordHash:       hash,
		Role:               domain.RoleAdmin,
		Active:             true,
		MustChangePassword: true,
		AuthProvider:       domain.AuthProviderLocal,
	})
}

func (s *Service) SeedUserIfMissing(ctx context.Context, email, password, role string) error {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return nil
	}

	_, err := s.users.GetByEmail(ctx, email)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.users.Create(ctx, &domain.User{
		Email:        strings.ToLower(strings.TrimSpace(email)),
		PasswordHash: hash,
		Role:         role,
		Active:       true,
		AuthProvider: domain.AuthProviderLocal,
	})
}

func (s *Service) Login(ctx context.Context, email, password string, meta RequestMetadata) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	if s.isRateLimited(ctx, "pwd:"+email, now) || s.isRateLimited(ctx, "pwd-ip:"+rateLimitRemoteAddr(meta.RemoteAddr), now) {
		s.observeAuth("password", "rate_limited")
		return nil, ErrRateLimited
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.observeAuth("password", "invalid_credentials")
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.AuthProvider != "" && user.AuthProvider != domain.AuthProviderLocal && user.PasswordHash == "" {
		s.observeAuth("password", "invalid_credentials")
		return nil, ErrInvalidCredentials
	}

	if err := CheckPassword(user.PasswordHash, password); err != nil {
		s.observeAuth("password", "invalid_credentials")
		return nil, ErrInvalidCredentials
	}
	if !user.Active {
		s.observeAuth("password", "inactive")
		return nil, ErrInactiveUser
	}

	result, err := s.completePrimaryLogin(ctx, user, meta)
	if err == nil {
		s.observeAuth("password", "success")
	}
	return result, err
}

func (s *Service) LoginBreakGlass(ctx context.Context, email, password string, meta RequestMetadata) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	if s.isRateLimited(ctx, "breakglass:"+email, now) || s.isRateLimited(ctx, "breakglass-ip:"+rateLimitRemoteAddr(meta.RemoteAddr), now) {
		s.observeAuth("break_glass", "rate_limited")
		return nil, ErrRateLimited
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.observeAuth("break_glass", "invalid_credentials")
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if user.Role != domain.RoleAdmin || user.AuthProvider != domain.AuthProviderLocal {
		s.observeAuth("break_glass", "rejected")
		return nil, ErrBreakGlassRejected
	}
	if err := CheckPassword(user.PasswordHash, password); err != nil {
		s.observeAuth("break_glass", "invalid_credentials")
		return nil, ErrInvalidCredentials
	}
	if !user.Active {
		s.observeAuth("break_glass", "inactive")
		return nil, ErrInactiveUser
	}
	result, err := s.completeSuccessfulLogin(ctx, user, meta)
	if err == nil {
		s.observeAuth("break_glass", "success")
	}
	return result, err
}

func (s *Service) StartOIDC(ctx context.Context, next string) (string, error) {
	authenticator, err := s.getOIDCAuthenticator(ctx)
	if err != nil {
		return "", err
	}
	return authenticator.StartURL(next)
}

func (s *Service) CompleteOIDC(ctx context.Context, code, state string) (*LoginResult, map[string]any, string, error) {
	authenticator, err := s.getOIDCAuthenticator(ctx)
	if err != nil {
		return nil, nil, "", err
	}

	claims, next, err := authenticator.Exchange(ctx, code, state)
	if err != nil {
		return nil, nil, "", err
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if authenticator.cfg.RequireVerifiedEmail && !claims.EmailVerified {
		return nil, map[string]any{"email": email, "next": next}, next, ErrOIDCEmailUnverified
	}
	if err := authenticator.ValidateAllowedEmailDomain(email); err != nil {
		return nil, map[string]any{"email": email, "next": next}, next, err
	}

	user, err := s.findOrCreateOIDCUser(ctx, claims, authenticator)
	if err != nil {
		return nil, nil, next, err
	}
	if !user.Active {
		return nil, nil, next, ErrInactiveUser
	}

	result, err := s.completePrimaryLogin(ctx, user, RequestMetadata{})
	if err != nil {
		return nil, nil, next, err
	}
	return result, map[string]any{
		"email":    user.Email,
		"issuer":   authenticator.Issuer(),
		"provider": authenticator.ProviderLabel(),
		"next":     next,
	}, next, nil
}

func (s *Service) RequestOTP(ctx context.Context, email string, meta RequestMetadata) (*OTPRequestResult, error) {
	otpCfg := s.currentOTPConfig(ctx)
	if !otpCfg.Enabled {
		return nil, ErrOTPDisabled
	}

	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	if s.isRateLimited(ctx, "otp:"+email, now) {
		s.observeAuth("otp_request", "rate_limited")
		return nil, ErrRateLimited
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if !user.Active {
		return nil, ErrInactiveUser
	}

	requests, err := s.loginTokens.CountRecentByEmail(ctx, email, now.Add(-otpCfg.RequestWindow))
	if err != nil {
		return nil, err
	}
	if requests >= int64(otpCfg.RequestLimit) {
		return nil, ErrRateLimited
	}

	token, err := randomCode(8)
	if err != nil {
		return nil, err
	}
	item := &domain.LoginToken{
		UserID:     &user.ID,
		Email:      email,
		Token:      hashToken(token),
		Scope:      domain.LoginTokenScopeAccountLogin,
		ExpiresAt:  now.Add(otpCfg.TokenTTL),
		RemoteAddr: meta.RemoteAddr,
		UserAgent:  meta.UserAgent,
	}
	if err := s.loginTokens.Create(ctx, item); err != nil {
		return nil, err
	}

	response := &OTPRequestResult{ExpiresAt: item.ExpiresAt}
	if err := s.sendOTPEmail(ctx, email, token, item.ExpiresAt, false); err != nil {
		s.observeAuth("otp_request", "delivery_failed")
		return nil, err
	}
	s.observeAuth("otp_request", "success")
	if otpCfg.ResponseIncludesCode {
		response.Token = token
	}
	return response, nil
}

func (s *Service) VerifyOTP(ctx context.Context, email, token string, meta RequestMetadata) (*LoginResult, error) {
	if !s.currentOTPConfig(ctx).Enabled {
		return nil, ErrOTPDisabled
	}
	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	if s.isRateLimited(ctx, "otp-verify:"+email, now) || s.isRateLimited(ctx, "otp-verify-ip:"+rateLimitRemoteAddr(meta.RemoteAddr), now) {
		s.observeAuth("otp_verify", "rate_limited")
		return nil, ErrRateLimited
	}

	item, err := s.loginTokens.GetValidToken(ctx, email, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if item.UsedAt != nil {
		return nil, ErrOTPUsed
	}
	if item.ExpiresAt.Before(now) {
		return nil, ErrOTPExpired
	}
	if item.UserID == nil {
		return nil, ErrInvalidCredentials
	}
	user, err := s.users.GetByID(ctx, *item.UserID)
	if err != nil {
		return nil, err
	}
	if !user.Active {
		return nil, ErrInactiveUser
	}
	if err := s.loginTokens.MarkUsed(ctx, item.ID, now); err != nil {
		return nil, err
	}

	result, err := s.completePrimaryLogin(ctx, user, meta)
	if err == nil {
		s.observeAuth("otp_verify", "success")
	}
	return result, err
}

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

func (s *Service) GetUser(ctx context.Context, id uint) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *Service) GetUserGroupIDs(ctx context.Context, id uint) ([]uint, error) {
	if s.groups == nil {
		return []uint{}, nil
	}
	return s.groups.ListGroupIDsForUser(ctx, id)
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

func (s *Service) completeSuccessfulLogin(ctx context.Context, user *domain.User, meta RequestMetadata) (*LoginResult, error) {
	now := time.Now().UTC()
	if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now

	session, refreshToken, err := s.createSession(ctx, user, meta)
	if err != nil {
		return nil, err
	}
	token, err := s.issueToken(user, session)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Token:             token,
		RefreshToken:      refreshToken,
		User:              user,
		Session:           session,
		BootstrapRequired: s.BootstrapRequired(ctx, user),
	}, nil
}

func (s *Service) completePrimaryLogin(ctx context.Context, user *domain.User, meta RequestMetadata) (*LoginResult, error) {
	if user.MFAEnabled {
		return s.beginMFAChallenge(ctx, user, meta)
	}
	return s.completeSuccessfulLogin(ctx, user, meta)
}

func (s *Service) CompleteAccountSetup(ctx context.Context, userID uint, email, password string) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, ErrInvalidCredentials
	}
	if existing, err := s.users.GetByEmail(ctx, email); err == nil && existing.ID != user.ID {
		return nil, store.ErrConflict
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	user.Email = email
	user.PasswordHash = hash
	user.MustChangePassword = false
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.InvalidateUser(user.ID)
	if current, ok := SessionFromContext(ctx); ok && current != nil {
		_ = s.RevokeOtherUserSessions(ctx, user.ID, current.ID)
	} else {
		_ = s.RevokeAllUserSessions(ctx, user.ID)
	}
	return user, nil
}

func (s *Service) ChangeOwnPassword(ctx context.Context, userID uint, currentPassword, newPassword string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.AuthProvider != "" && user.AuthProvider != domain.AuthProviderLocal && user.PasswordHash == "" {
		return ErrInvalidCredentials
	}
	if err := CheckPassword(user.PasswordHash, currentPassword); err != nil {
		return ErrInvalidCredentials
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	user.MustChangePassword = false
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	s.InvalidateUser(user.ID)
	if current, ok := SessionFromContext(ctx); ok && current != nil {
		_ = s.RevokeOtherUserSessions(ctx, user.ID, current.ID)
	} else {
		_ = s.RevokeAllUserSessions(ctx, user.ID)
	}
	return nil
}

func (s *Service) findOrCreateOIDCUser(ctx context.Context, claims *OIDCIdentity, authenticator *OIDCAuthenticator) (*domain.User, error) {
	ref := strings.TrimSpace(claims.Subject)
	if ref == "" {
		return nil, ErrOIDCLinkDenied
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	role := domain.RoleViewer
	if authenticator.IsAdmin(claims.Claims) {
		role = domain.RoleAdmin
	}

	if ref != "" {
		user, err := s.users.GetByProviderRef(ctx, domain.AuthProviderOIDC, ref)
		if err == nil {
			user.Email = email
			user.Username = claims.PreferredUsername
			user.DisplayName = claims.Name
			user.AuthIssuer = authenticator.Issuer()
			columns := map[string]any{
				"email":             email,
				"username":          claims.PreferredUsername,
				"display_name":      claims.Name,
				"auth_provider":     domain.AuthProviderOIDC,
				"auth_provider_ref": ref,
				"auth_issuer":       authenticator.Issuer(),
			}
			if authenticator.cfg.ManageRoles {
				s.logOIDCRoleChange(user, role)
				user.Role = role
				columns["role"] = role
			}
			if err := s.users.UpdateColumns(ctx, user.ID, columns); err != nil {
				return nil, err
			}
			user.AuthProvider = domain.AuthProviderOIDC
			user.AuthProviderRef = ref
			return user, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	if email != "" {
		user, err := s.users.GetByEmail(ctx, email)
		if err == nil {
			if !claims.EmailVerified {
				return nil, ErrOIDCLinkDenied
			}
			if user.AuthProvider == domain.AuthProviderLocal && !authenticator.cfg.AllowEmailLinking {
				return nil, ErrOIDCLinkDenied
			}
			if user.AuthProvider == domain.AuthProviderOIDC && user.AuthProviderRef != "" && ref != "" && user.AuthProviderRef != ref {
				return nil, ErrOIDCLinkDenied
			}
			user.DisplayName = claims.Name
			user.Username = claims.PreferredUsername
			if user.AuthProvider == "" || user.AuthProvider == domain.AuthProviderLocal {
				user.AuthProvider = domain.AuthProviderOIDC
				user.AuthProviderRef = ref
			}
			user.AuthIssuer = authenticator.Issuer()
			if authenticator.cfg.ManageRoles {
				s.logOIDCRoleChange(user, role)
				user.Role = role
			}
			if err := s.users.Update(ctx, user); err != nil {
				return nil, err
			}
			return user, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	user := &domain.User{
		Email:           email,
		Role:            role,
		Active:          true,
		AuthProvider:    domain.AuthProviderOIDC,
		AuthProviderRef: ref,
		AuthIssuer:      authenticator.Issuer(),
		DisplayName:     claims.Name,
		Username:        claims.PreferredUsername,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) logOIDCRoleChange(user *domain.User, newRole string) {
	if user == nil || user.Role == newRole {
		return
	}
	slog.Warn("oidc role change applied on login",
		"user_id", user.ID,
		"email", user.Email,
		"old_role", user.Role,
		"new_role", newRole,
		"admin_demotion", user.Role == domain.RoleAdmin && newRole != domain.RoleAdmin,
		"admin_promotion", user.Role != domain.RoleAdmin && newRole == domain.RoleAdmin,
	)
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

const PasswordHashCost = 12

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordHashCost)
	return string(hash), err
}

func CheckPassword(hash, password string) error {
	if hash == "" {
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

func randomCode(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Service) InvalidateUser(userID uint) {
	if s.distributedAuthCache != nil {
		_ = s.distributedAuthCache.InvalidateUser(context.Background(), userID)
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	for tokenKey := range s.userTokens[userID] {
		delete(s.authCache, tokenKey)
	}
	delete(s.userTokens, userID)
}

func (s *Service) InvalidateAll() {
	if s.distributedAuthCache != nil {
		_ = s.distributedAuthCache.Flush(context.Background())
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.authCache = make(map[string]cachedAuthResult)
	s.userTokens = make(map[uint]map[string]struct{})
}

func (s *Service) getCachedAuthResult(ctx context.Context, tokenString string) (*domain.User, []uint, bool) {
	if s.cacheTTL <= 0 {
		if s.distributedAuthCache == nil {
			return nil, nil, false
		}
	}
	tokenKey := hashToken(tokenString)
	now := time.Now().UTC()

	if s.distributedAuthCache != nil {
		entry, ok, err := s.distributedAuthCache.Get(ctx, tokenKey)
		if err == nil && ok {
			userCopy := entry.User
			groupCopy := append([]uint(nil), entry.GroupIDs...)
			return &userCopy, groupCopy, true
		}
	}

	if s.cacheTTL <= 0 {
		return nil, nil, false
	}

	s.cacheMu.RLock()
	cached, ok := s.authCache[tokenKey]
	s.cacheMu.RUnlock()
	if !ok || now.After(cached.expiresAt) {
		if ok {
			s.cacheMu.Lock()
			delete(s.authCache, tokenKey)
			s.cacheMu.Unlock()
		}
		return nil, nil, false
	}

	groupIDs := append([]uint(nil), cached.groupIDs...)
	userCopy := *cached.user
	return &userCopy, groupIDs, true
}

func (s *Service) StartCacheJanitor(ctx context.Context) {
	if s.cacheTTL <= 0 {
		return
	}
	interval := s.cacheTTL
	if interval > 5*time.Minute {
		interval = 5 * time.Minute
	}
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepAuthCache()
			}
		}
	}()
}

const authCacheMaxEntries = 10000

func (s *Service) sweepAuthCache() {
	now := time.Now().UTC()
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for key, entry := range s.authCache {
		if now.After(entry.expiresAt) {
			delete(s.authCache, key)
			if entry.user != nil {
				if tokens, ok := s.userTokens[entry.user.ID]; ok {
					delete(tokens, key)
					if len(tokens) == 0 {
						delete(s.userTokens, entry.user.ID)
					}
				}
			}
		}
	}
	if len(s.authCache) <= authCacheMaxEntries {
		return
	}
	type ageEntry struct {
		key       string
		userID    uint
		expiresAt time.Time
	}
	entries := make([]ageEntry, 0, len(s.authCache))
	for key, entry := range s.authCache {
		var uid uint
		if entry.user != nil {
			uid = entry.user.ID
		}
		entries = append(entries, ageEntry{key: key, userID: uid, expiresAt: entry.expiresAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].expiresAt.Before(entries[j].expiresAt) })
	excess := len(entries) - authCacheMaxEntries
	for i := 0; i < excess; i++ {
		delete(s.authCache, entries[i].key)
		if tokens, ok := s.userTokens[entries[i].userID]; ok {
			delete(tokens, entries[i].key)
			if len(tokens) == 0 {
				delete(s.userTokens, entries[i].userID)
			}
		}
	}
}

func (s *Service) storeCachedAuthResult(tokenString string, user *domain.User, groupIDs []uint, expiresAt *jwt.NumericDate) {
	if s.cacheTTL <= 0 || user == nil {
		return
	}
	cacheExpiry := time.Now().UTC().Add(s.cacheTTL)
	if expiresAt != nil && expiresAt.Time.Before(cacheExpiry) {
		cacheExpiry = expiresAt.Time
	}
	if !cacheExpiry.After(time.Now().UTC()) {
		return
	}

	tokenKey := hashToken(tokenString)
	userCopy := *user
	groupCopy := append([]uint(nil), groupIDs...)

	if s.distributedAuthCache != nil {
		_ = s.distributedAuthCache.Set(context.Background(), tokenKey, CachedAuthEntry{
			User:      userCopy,
			GroupIDs:  groupCopy,
			ExpiresAt: cacheExpiry,
		}, time.Until(cacheExpiry))
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.authCache[tokenKey] = cachedAuthResult{
		user:      &userCopy,
		groupIDs:  groupCopy,
		expiresAt: cacheExpiry,
	}
	if _, ok := s.userTokens[user.ID]; !ok {
		s.userTokens[user.ID] = make(map[string]struct{})
	}
	s.userTokens[user.ID][tokenKey] = struct{}{}
}

func rateLimitRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func (s *Service) isRateLimited(ctx context.Context, key string, now time.Time) bool {
	if s.distributedRateLimiter != nil {
		allowed, _, _, err := s.distributedRateLimiter.Allow(ctx, key, s.rateLimit.LoginAttempts, s.rateLimit.Window)
		if err != nil {
			if s.fallbackRateLimiter == nil {
				return true
			}
			allowed, _, _, _ = s.fallbackRateLimiter.Allow(ctx, key, s.rateLimit.LoginAttempts, s.rateLimit.Window)
		}
		if !allowed && s.metrics != nil {
			namespace := strings.SplitN(key, ":", 2)[0]
			s.metrics.ObserveRateLimit(namespace)
		}
		return !allowed
	}
	_ = now
	return false
}

func (s *Service) observeAuth(method, outcome string) {
	if s.metrics != nil {
		s.metrics.ObserveAuthAttempt(method, outcome)
	}
}

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

const (
	SessionCookieName = "portlyn_session"
	RefreshCookieName = "portlyn_refresh"
	CSRFCookieName    = "portlyn_csrf"
)

type RouteAccessClaims struct {
	ServiceID uint   `json:"service_id"`
	Method    string `json:"method"`
	Email     string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

type SessionBridgeClaims struct {
	AccessToken string `json:"access_token"`
	Host        string `json:"host"`
	jwt.RegisteredClaims
}

type RouteAccessBridgeClaims struct {
	ServiceID uint   `json:"service_id"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	Email     string `json:"email,omitempty"`
	ReturnTo  string `json:"return_to,omitempty"`
	jwt.RegisteredClaims
}

type RouteEmailCodeResult struct {
	ExpiresAt time.Time `json:"expires_at"`
	Code      string    `json:"code,omitempty"`
}

func SessionCookieNameForService(serviceID uint) string {
	return fmt.Sprintf("portlyn_route_access_%d", serviceID)
}

func (s *Service) AuthenticateRequest(ctx context.Context, r *http.Request) (*domain.User, []uint, error) {
	token := strings.TrimSpace(bearerTokenFromHeader(r.Header.Get("Authorization")))
	if token == "" {
		cookie, err := r.Cookie(SessionCookieName)
		if err == nil {
			token = strings.TrimSpace(cookie.Value)
		}
	}
	if token == "" {
		return nil, nil, ErrInvalidToken
	}
	return s.AuthenticateAccessToken(ctx, token)
}

func bearerTokenFromHeader(header string) string {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func (s *Service) SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   int(s.tokenTTL.Seconds()),
	})
}

func (s *Service) SetRefreshCookie(w http.ResponseWriter, token string, secure bool) {
	if strings.TrimSpace(token) == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    token,
		Path:     "/api/v1/auth",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   int(s.refreshTokenTTL.Seconds()),
	})
}

func (s *Service) SetSessionCookieForHost(w http.ResponseWriter, token, host string, secure bool) {
	host = strings.TrimSpace(host)
	if host != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookieName,
			Value:    "",
			Path:     "/",
			Domain:   host,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
			MaxAge:   -1,
		})
	}
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   int(s.tokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func (s *Service) ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

func (s *Service) ClearRefreshCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     "/api/v1/auth",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

func (s *Service) RefreshTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(RefreshCookieName)
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	return strings.TrimSpace(bearerTokenFromHeader(r.Header.Get("X-Refresh-Token")))
}

func (s *Service) BuildRouteLoginURL(ctx context.Context, serviceID uint, returnTo string) string {
	return s.buildRouteFrontendURL(ctx, "/route-login", serviceID, returnTo)
}

func (s *Service) BuildRouteForbiddenURL(ctx context.Context, serviceID uint, returnTo string) string {
	return s.buildRouteFrontendURL(ctx, "/route-forbidden", serviceID, returnTo)
}

func (s *Service) buildRouteFrontendURL(ctx context.Context, path string, serviceID uint, returnTo string) string {
	base := s.currentFrontendBaseURL(ctx)
	if base == "" {
		base = s.oidcFrontendBase(ctx)
	}
	target, err := url.Parse(base + path)
	if err != nil {
		target = &url.URL{Path: path}
	}
	query := target.Query()
	query.Set("serviceId", strconv.FormatUint(uint64(serviceID), 10))
	if sanitized := sanitizeReturnTo(returnTo); sanitized != "" {
		query.Set("returnTo", sanitized)
	}
	target.RawQuery = query.Encode()
	return target.String()
}

func sanitizeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return ""
	}
	return parsed.String()
}

func (s *Service) RouteAccessCookieClaims(r *http.Request, serviceID uint) (*RouteAccessClaims, error) {
	cookie, err := r.Cookie(SessionCookieNameForService(serviceID))
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &RouteAccessClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return s.jwtSigningSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*RouteAccessClaims)
	if !ok || !token.Valid || claims.ServiceID != serviceID {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (s *Service) SetRouteAccessCookie(w http.ResponseWriter, serviceID uint, method, email string) error {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, RouteAccessClaims{
		ServiceID: serviceID,
		Method:    strings.TrimSpace(method),
		Email:     strings.ToLower(strings.TrimSpace(email)),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("route:%d", serviceID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.routeAuthTTL)),
		},
	})
	signed, err := token.SignedString(s.jwtSigningSecret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieNameForService(serviceID),
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !s.allowInsecureDevMode,
		MaxAge:   int(s.routeAuthTTL.Seconds()),
	})
	return nil
}

func (s *Service) SessionTokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	return strings.TrimSpace(bearerTokenFromHeader(r.Header.Get("Authorization")))
}

func (s *Service) RequestRouteEmailCode(ctx context.Context, serviceID uint, email string, meta RequestMetadata, includeCode bool) (*RouteEmailCodeResult, error) {
	otpCfg := s.currentOTPConfig(ctx)
	if !otpCfg.Enabled {
		return nil, ErrOTPDisabled
	}
	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	if s.isRateLimited(ctx, "route-email:"+strconv.FormatUint(uint64(serviceID), 10)+":"+email, now) {
		return nil, ErrRateLimited
	}
	requests, err := s.loginTokens.CountRecentByEmailAndScope(ctx, email, domain.LoginTokenScopeRouteAccess, &serviceID, now.Add(-otpCfg.RequestWindow))
	if err != nil {
		return nil, err
	}
	if requests >= int64(otpCfg.RequestLimit) {
		return nil, ErrRateLimited
	}
	code, err := randomCode(4)
	if err != nil {
		return nil, err
	}
	item := &domain.LoginToken{
		ServiceID:  &serviceID,
		Email:      email,
		Token:      hashToken(code),
		Scope:      domain.LoginTokenScopeRouteAccess,
		ExpiresAt:  now.Add(otpCfg.TokenTTL),
		RemoteAddr: meta.RemoteAddr,
		UserAgent:  meta.UserAgent,
	}
	if err := s.loginTokens.Create(ctx, item); err != nil {
		return nil, err
	}
	if err := s.sendOTPEmail(ctx, email, code, item.ExpiresAt, true); err != nil {
		return nil, err
	}
	result := &RouteEmailCodeResult{ExpiresAt: item.ExpiresAt}
	if includeCode {
		result.Code = code
	}
	return result, nil
}

func (s *Service) VerifyRouteEmailCode(ctx context.Context, serviceID uint, email, code string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().UTC()
	item, err := s.loginTokens.GetValidTokenByScope(ctx, email, code, domain.LoginTokenScopeRouteAccess, &serviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidCredentials
		}
		return err
	}
	if item.UsedAt != nil {
		return ErrOTPUsed
	}
	if item.ExpiresAt.Before(now) {
		return ErrOTPExpired
	}
	return s.loginTokens.MarkUsed(ctx, item.ID, now)
}

func (s *Service) oidcFrontendBase(ctx context.Context) string {
	cfg := s.currentOIDCConfig(ctx)
	if !cfg.Enabled {
		return ""
	}
	return strings.TrimRight(frontendBaseFromRedirect(cfg.RedirectURL), "/")
}

func frontendBaseFromRedirect(redirectURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(redirectURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}

func (s *Service) IssueSessionBridgeToken(accessToken, host string) (string, error) {
	host = strings.TrimSpace(host)
	if accessToken == "" || host == "" {
		return "", ErrInvalidToken
	}
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionBridgeClaims{
		AccessToken: accessToken,
		Host:        host,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   "session_bridge",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
	})
	return token.SignedString(s.sessionBridgeSecret)
}

func (s *Service) IssueRouteAccessBridgeToken(serviceID uint, host, method, email, returnTo string) (string, error) {
	host = normalizeBridgeHost(host)
	if serviceID == 0 || host == "" {
		return "", ErrInvalidToken
	}
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, RouteAccessBridgeClaims{
		ServiceID: serviceID,
		Host:      host,
		Method:    strings.TrimSpace(method),
		Email:     strings.ToLower(strings.TrimSpace(email)),
		ReturnTo:  sanitizeReturnTo(returnTo),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("route_bridge:%d", serviceID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
	})
	return token.SignedString(s.sessionBridgeSecret)
}

func (s *Service) ParseRouteAccessBridgeToken(tokenString string) (*RouteAccessBridgeClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RouteAccessBridgeClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return s.sessionBridgeSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*RouteAccessBridgeClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func normalizeBridgeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if idx := strings.Index(host, ":"); idx >= 0 {
		return host[:idx]
	}
	return host
}

func (s *Service) ParseSessionBridgeToken(tokenString string) (*SessionBridgeClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionBridgeClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return s.sessionBridgeSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*SessionBridgeClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

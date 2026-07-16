package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"portlyn/internal/config"
	"portlyn/internal/netguard"
)

type OIDCAuthenticator struct {
	cfg         config.OIDCConfig
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
	stateSecret []byte
	httpClient  *http.Client
}

func oidcHTTPClient(allowPrivate bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout: 10 * time.Second,
		Control: netguard.DialControl(allowPrivate),
	}).DialContext
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

type oidcStateClaims struct {
	Nonce string `json:"nonce"`
	Next  string `json:"next"`
	jwt.RegisteredClaims
}

type OIDCIdentity struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Claims            map[string]any
}

func NewOIDCAuthenticator(cfg config.OIDCConfig, stateSecret []byte) (*OIDCAuthenticator, error) {
	client := oidcHTTPClient(cfg.AllowPrivateIssuer)
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}

	return &OIDCAuthenticator{
		cfg: cfg,
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		stateSecret: stateSecret,
		httpClient:  client,
	}, nil
}

func (a *OIDCAuthenticator) StartURL(next string) (string, error) {
	nonce, err := randomCode(8)
	if err != nil {
		return "", err
	}
	state, err := a.signState(next, nonce)
	if err != nil {
		return "", err
	}
	verifier := a.pkceVerifier(nonce)
	return a.oauthConfig.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func (a *OIDCAuthenticator) pkceVerifier(nonce string) string {
	mac := hmac.New(sha256.New, a.stateSecret)
	_, _ = mac.Write([]byte("pkce:" + nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *OIDCAuthenticator) Exchange(ctx context.Context, code, state string) (*OIDCIdentity, string, error) {
	if a.httpClient != nil {
		ctx = oidc.ClientContext(ctx, a.httpClient)
	}
	stateClaims, err := a.parseState(state)
	if err != nil {
		return nil, "", err
	}

	token, err := a.oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", a.pkceVerifier(stateClaims.Nonce)))
	if err != nil {
		return nil, "", fmt.Errorf("exchange oidc code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return nil, "", errors.New("oidc provider did not return id_token")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("verify oidc id token: %w", err)
	}
	if idToken.Nonce != stateClaims.Nonce {
		return nil, "", ErrInvalidToken
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, "", fmt.Errorf("decode oidc claims: %w", err)
	}

	return &OIDCIdentity{
		Subject:           stringValue(claims["sub"]),
		Email:             stringValue(claims["email"]),
		EmailVerified:     boolValue(claims["email_verified"]),
		Name:              firstNonEmpty(stringValue(claims["name"]), stringValue(claims["given_name"])),
		PreferredUsername: firstNonEmpty(stringValue(claims["preferred_username"]), stringValue(claims["nickname"])),
		Claims:            claims,
	}, stateClaims.Next, nil
}

func (a *OIDCAuthenticator) ValidateAllowedEmailDomain(email string) error {
	if len(a.cfg.AllowedEmailDomains) == 0 || email == "" {
		return nil
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ErrOIDCEmailBlocked
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, allowed := range a.cfg.AllowedEmailDomains {
		if strings.EqualFold(domain, strings.TrimSpace(allowed)) {
			return nil
		}
	}
	return ErrOIDCEmailBlocked
}

func (a *OIDCAuthenticator) IsAdmin(claims map[string]any) bool {
	if strings.TrimSpace(a.cfg.AdminRoleValue) == "" {
		return false
	}
	values := extractClaimPathValues(claims, a.cfg.AdminRoleClaimPath)
	for _, value := range values {
		if value == a.cfg.AdminRoleValue {
			return true
		}
	}
	return false
}

func (a *OIDCAuthenticator) ProviderLabel() string {
	return a.cfg.DefaultProviderLabel
}

func (a *OIDCAuthenticator) Issuer() string {
	return a.cfg.IssuerURL
}

func (a *OIDCAuthenticator) signState(next, nonce string) (string, error) {
	if next == "" {
		next = "/services"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, oidcStateClaims{
		Nonce: nonce,
		Next:  sanitizeNext(next),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(10 * time.Minute)),
		},
	})
	return token.SignedString(a.stateSecret)
}

func (a *OIDCAuthenticator) parseState(state string) (*oidcStateClaims, error) {
	parsed, err := jwt.ParseWithClaims(state, &oidcStateClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return a.stateSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*oidcStateClaims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func extractClaimPathValues(claims map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	current := any(claims)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	switch typed := current.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := stringValue(item); value != "" {
				values = append(values, value)
			}
		}
		return values
	case []string:
		return typed
	default:
		if value := stringValue(typed); value != "" {
			return []string{value}
		}
		return nil
	}
}

func sanitizeNext(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/services"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || strings.HasPrefix(value, "//") {
		return "/services"
	}
	if !strings.HasPrefix(value, "/") {
		return "/services"
	}
	return value
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"portlyn/internal/config"
)

func TestOIDCValidateAllowedEmailDomain(t *testing.T) {
	authenticator := &OIDCAuthenticator{
		cfg: config.OIDCConfig{
			AllowedEmailDomains: []string{"example.com", "corp.local"},
		},
	}

	if err := authenticator.ValidateAllowedEmailDomain("user@example.com"); err != nil {
		t.Fatalf("expected example.com to be allowed: %v", err)
	}
	if err := authenticator.ValidateAllowedEmailDomain("user@corp.local"); err != nil {
		t.Fatalf("expected corp.local to be allowed: %v", err)
	}
	if err := authenticator.ValidateAllowedEmailDomain("user@blocked.test"); err != ErrOIDCEmailBlocked {
		t.Fatalf("expected blocked domain to return ErrOIDCEmailBlocked, got %v", err)
	}
	if err := authenticator.ValidateAllowedEmailDomain("not-an-email"); err != ErrOIDCEmailBlocked {
		t.Fatalf("expected malformed email to return ErrOIDCEmailBlocked, got %v", err)
	}
}

func TestOIDCIsAdminFromNestedClaimPath(t *testing.T) {
	authenticator := &OIDCAuthenticator{
		cfg: config.OIDCConfig{
			AdminRoleClaimPath: "realm_access.roles",
			AdminRoleValue:     "portlyn-admin",
		},
	}

	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"viewer", "portlyn-admin"},
		},
	}
	if !authenticator.IsAdmin(claims) {
		t.Fatal("expected nested admin claim to be recognized")
	}

	claims["realm_access"] = map[string]any{"roles": []any{"viewer"}}
	if authenticator.IsAdmin(claims) {
		t.Fatal("expected claims without admin role to be rejected")
	}
}

func TestSanitizeNextRejectsExternalTargets(t *testing.T) {
	tests := map[string]string{
		"":                          "/services",
		"/audit-logs":               "/audit-logs",
		"https://evil.example/test": "/services",
		"//evil.example/test":       "/services",
		"relative/path":             "/services",
		"/\\evil.example":           "/services",
		"/x\\y":                     "/services",
		"/\t/evil.example":          "/services",
		"/\n/evil.example":          "/services",
		"/ /evil.example":           "/services",
		"/services?tab=1#top":       "/services?tab=1#top",
	}

	for input, want := range tests {
		if got := sanitizeNext(input); got != want {
			t.Fatalf("sanitizeNext(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOIDCAccessTokenClaimsRequireVerifiedTokenForSameUser(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer := "https://auth.example.com/realms/lab"
	authenticator := &OIDCAuthenticator{
		cfg:         config.OIDCConfig{ClientID: "portlyn", AdminRoleClaimPath: "realm_access.roles", AdminRoleValue: "portlyn-admin"},
		jwtVerifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{SkipClientIDCheck: true}),
	}
	sign := func(signer *rsa.PrivateKey, claims jwt.MapClaims) string {
		base := jwt.MapClaims{"iss": issuer, "sub": "user-1", "azp": "portlyn", "aud": []string{"account"}, "exp": time.Now().Add(time.Minute).Unix(), "realm_access": map[string]any{"roles": []string{"portlyn-admin"}}}
		for k, v := range claims {
			base[k] = v
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, base).SignedString(signer)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return raw
	}

	claims := authenticator.accessTokenClaims(context.Background(), sign(key, nil), "user-1")
	if !authenticator.IsAdmin(map[string]any{}, claims) {
		t.Fatal("expected admin role from the access token to be recognized")
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rejected := map[string]string{
		"foreign signature": sign(other, nil),
		"other subject":     sign(key, jwt.MapClaims{"sub": "user-2"}),
		"other client":      sign(key, jwt.MapClaims{"azp": "someone-else"}),
		"opaque token":      "opaque-access-token",
	}
	for name, raw := range rejected {
		if claims := authenticator.accessTokenClaims(context.Background(), raw, "user-1"); claims != nil {
			t.Fatalf("%s: expected access token claims to be ignored", name)
		}
	}
}

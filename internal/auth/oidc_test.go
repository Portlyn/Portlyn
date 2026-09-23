package auth

import (
	"testing"

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

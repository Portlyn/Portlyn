package config

import (
	"strings"
	"testing"
)

func setStrongSecrets(t *testing.T) {
	t.Helper()
	secrets := map[string]string{
		"JWT_SECRET":             strings.Repeat("a", 40),
		"JWT_SIGNING_SECRET":     strings.Repeat("b", 40),
		"SESSION_BRIDGE_SECRET":  strings.Repeat("c", 40),
		"OIDC_STATE_SECRET":      strings.Repeat("d", 40),
		"MFA_ENCRYPTION_SECRET":  strings.Repeat("e", 40),
		"CSRF_SECRET":            strings.Repeat("f", 40),
		"DATA_ENCRYPTION_SECRET": strings.Repeat("g", 40),
		"AUDIT_HMAC_SECRET":      strings.Repeat("h", 40),
	}
	for key, value := range secrets {
		t.Setenv(key, value)
	}
}

func hasErrorCode(issues []ValidationIssue, code string) bool {
	for _, issue := range issues {
		if issue.Level == "error" && issue.Code == code {
			return true
		}
	}
	return false
}

func TestSSLModeDisableToPrivateHostIsNotAnError(t *testing.T) {
	setStrongSecrets(t)
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "false")
	t.Setenv("DATABASE_DRIVER", "postgres")
	t.Setenv("DATABASE_URL", "postgres://u:p@postgres:5432/portlyn?sslmode=disable")

	cfg, _ := Load()
	issues := cfg.ValidationIssues()
	if hasErrorCode(issues, "insecure_database_transport") {
		t.Fatal("expected no hard error for sslmode=disable to a private/container-local host")
	}
}

func TestSSLModeDisableToPublicHostIsAnError(t *testing.T) {
	setStrongSecrets(t)
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "false")
	t.Setenv("DATABASE_DRIVER", "postgres")
	t.Setenv("DATABASE_URL", "postgres://u:p@db.example.com:5432/portlyn?sslmode=disable")

	cfg, _ := Load()
	if !hasErrorCode(cfg.ValidationIssues(), "insecure_database_transport") {
		t.Fatal("expected sslmode=disable to a public host to be an error")
	}
}

func TestDNSProviderWithoutTokenIsAnError(t *testing.T) {
	setStrongSecrets(t)
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "false")
	t.Setenv("DATABASE_DRIVER", "sqlite")
	t.Setenv("ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("ACME_DNS_CLOUDFLARE_API_TOKEN", "")

	cfg, _ := Load()
	if !hasErrorCode(cfg.ValidationIssues(), "missing_dns_provider_credential") {
		t.Fatal("expected missing token for ACME_DNS_PROVIDER=cloudflare to be an error")
	}
}

func TestValidationIssuesCarryHints(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "false")
	t.Setenv("JWT_SECRET", "")

	cfg, _ := Load()
	for _, issue := range cfg.ValidationIssues() {
		if issue.Code == "missing_secret" && strings.TrimSpace(issue.Hint) == "" {
			t.Fatal("expected missing_secret issues to carry a fix hint")
		}
	}
}

func TestLoadRejectsMissingSecretsOutsideDevMode(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "false")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("JWT_SIGNING_SECRET", "")
	t.Setenv("SESSION_BRIDGE_SECRET", "")
	t.Setenv("OIDC_STATE_SECRET", "")
	t.Setenv("MFA_ENCRYPTION_SECRET", "")
	t.Setenv("CSRF_SECRET", "")
	t.Setenv("DATA_ENCRYPTION_SECRET", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected Load to fail when required secrets are missing outside dev mode")
	}
}

func TestLoadGeneratesSecretsInDevMode(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DEV_MODE", "true")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("JWT_SIGNING_SECRET", "")
	t.Setenv("SESSION_BRIDGE_SECRET", "")
	t.Setenv("OIDC_STATE_SECRET", "")
	t.Setenv("MFA_ENCRYPTION_SECRET", "")
	t.Setenv("CSRF_SECRET", "")
	t.Setenv("DATA_ENCRYPTION_SECRET", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected Load to succeed in insecure dev mode, got error: %v", err)
	}
	if cfg.JWTSecret == "" || cfg.JWTSigningSecret == "" || cfg.DataEncryptionSecret == "" {
		t.Fatal("expected generated non-empty secrets in insecure dev mode")
	}
}

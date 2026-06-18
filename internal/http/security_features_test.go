package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"portlyn/internal/auth"
	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

func TestBreakGlassLoginBypassesAdminMFARequirement(t *testing.T) {
	server, cleanup := newIntegrationServer(t, func(cfg *config.Config) {
		cfg.BreakGlassEnabled = true
		cfg.BreakGlassToken = "break-glass-token-1234567890"
		cfg.BreakGlassTTL = time.Hour
		cfg.BreakGlassAllowCIDRs = []string{"127.0.0.1/32"}
	})
	defer cleanup()

	hash, err := auth.HashPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	admin := &domain.User{
		Email:        "admin-breakglass@example.com",
		PasswordHash: hash,
		Role:         domain.RoleAdmin,
		Active:       true,
		AuthProvider: domain.AuthProviderLocal,
	}
	if err := server.users.Create(context.Background(), admin); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	settings, err := server.appSettings.Get(context.Background())
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	settings.RequireMFAForAdmins = true
	if err := server.appSettings.Upsert(context.Background(), settings); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	csrf := mustIssueCSRFToken(t, server)
	normalLoginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"email":"admin-breakglass@example.com","password":"StrongPass123!"}`))
	normalLoginReq.Header.Set("Content-Type", "application/json")
	normalLoginReq.Header.Set("X-CSRF-Token", csrf)
	normalLoginReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	normalLoginRec := httptest.NewRecorder()
	server.Router().ServeHTTP(normalLoginRec, normalLoginReq)
	if normalLoginRec.Code != http.StatusOK {
		t.Fatalf("expected normal admin login to succeed in bootstrap mode, got %d: %s", normalLoginRec.Code, normalLoginRec.Body.String())
	}
	if !bytes.Contains(normalLoginRec.Body.Bytes(), []byte(`"bootstrap_required":true`)) {
		t.Fatalf("expected bootstrap_required=true in login response, got %s", normalLoginRec.Body.String())
	}

	breakGlassReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/break-glass/login", bytes.NewBufferString(`{"email":"admin-breakglass@example.com","password":"StrongPass123!","token":"break-glass-token-1234567890"}`))
	breakGlassReq.RemoteAddr = "127.0.0.1:23456"
	breakGlassReq.Header.Set("Content-Type", "application/json")
	breakGlassReq.Header.Set("X-CSRF-Token", csrf)
	breakGlassReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	breakGlassRec := httptest.NewRecorder()
	server.Router().ServeHTTP(breakGlassRec, breakGlassReq)
	if breakGlassRec.Code != http.StatusOK {
		t.Fatalf("expected break-glass login success, got %d: %s", breakGlassRec.Code, breakGlassRec.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/break-glass/login", bytes.NewBufferString(`{"email":"admin-breakglass@example.com","password":"StrongPass123!","token":"break-glass-token-1234567890"}`))
	secondReq.RemoteAddr = "127.0.0.1:23456"
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set("X-CSRF-Token", csrf)
	secondReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	secondRec := httptest.NewRecorder()
	server.Router().ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected one-time break-glass token to be consumed, got %d: %s", secondRec.Code, secondRec.Body.String())
	}
}

func TestDataKeyReencryptFromLegacySecret(t *testing.T) {
	server, cleanup := newIntegrationServer(t, func(cfg *config.Config) {
		cfg.DataEncryptionSecret = "active-12345678901234567890123456789012"
		cfg.DataEncryptionLegacySecrets = []string{"legacy-12345678901234567890123456789012"}
	})
	defer cleanup()

	token := loginAsAdmin(t, server, "rotate-admin@example.com", "StrongPass123!")

	legacyConfig := map[string]string{"api_token": "secret-token-value"}
	legacyEncrypted, err := secureconfig.EncryptJSON([]byte("legacy-12345678901234567890123456789012"), legacyConfig)
	if err != nil {
		t.Fatalf("encrypt legacy config: %v", err)
	}
	provider := &domain.DNSProvider{
		Name:                "legacy-provider",
		Type:                domain.DNSProviderTypeCloudflare,
		ConfigEncrypted:     legacyEncrypted,
		ConfigHint:          "test",
		IsActive:            true,
		HasStoredSecret:     true,
		SupportedChallenges: domain.JSONStringSlice{domain.CertificateChallengeDNS01},
	}
	if err := server.dnsProviders.Create(context.Background(), provider); err != nil {
		t.Fatalf("create dns provider: %v", err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/security/rotation/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+token)
	statusRec := httptest.NewRecorder()
	server.Router().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("rotation status failed: %d %s", statusRec.Code, statusRec.Body.String())
	}

	reencryptReq := httptest.NewRequest(http.MethodPost, "/api/v1/security/rotation/data-key/reencrypt", bytes.NewBufferString(`{"dry_run":false}`))
	reencryptReq.Header.Set("Content-Type", "application/json")
	reencryptReq.Header.Set("Authorization", "Bearer "+token)
	csrf := mustIssueCSRFToken(t, server)
	reencryptReq.Header.Set("X-CSRF-Token", csrf)
	reencryptReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	reencryptRec := httptest.NewRecorder()
	server.Router().ServeHTTP(reencryptRec, reencryptReq)
	if reencryptRec.Code != http.StatusOK {
		t.Fatalf("reencrypt failed: %d %s", reencryptRec.Code, reencryptRec.Body.String())
	}

	updated, err := server.dnsProviders.GetByID(context.Background(), provider.ID)
	if err != nil {
		t.Fatalf("reload provider: %v", err)
	}
	if !secureconfig.IsEncryptedJSONLatest(updated.ConfigEncrypted) {
		t.Fatalf("expected reencrypted config to use the latest encryption format")
	}
	if _, err := secureconfig.DecryptJSONAuto([][]byte{[]byte(server.cfg.DataEncryptionSecret)}, updated.ConfigEncrypted); err != nil {
		t.Fatalf("expected config to be decryptable with active key: %v", err)
	}
}

func TestSecurityAlertsEndpoint(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	token := loginAsAdmin(t, server, "alert-admin@example.com", "StrongPass123!")
	now := time.Now().UTC()
	for i := 0; i < 25; i++ {
		if err := server.auditStore.Create(context.Background(), &domain.AuditLog{
			Timestamp:    now,
			Action:       "login_failed",
			ResourceType: "auth",
		}); err != nil {
			t.Fatalf("seed audit login_failed: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/security-alerts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts endpoint failed: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Alerts []map[string]any `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode alerts response: %v", err)
	}
	if len(payload.Alerts) == 0 {
		t.Fatalf("expected at least one alert, got none")
	}
}

func TestIsNodeAuthPathMatchesOnlyExpectedRoutes(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	if !server.isNodeAuthPath("/api/v1/nodes/enroll") {
		t.Fatal("expected enroll endpoint to bypass csrf")
	}
	if !server.isNodeAuthPath("/api/v1/nodes/42/heartbeat") {
		t.Fatal("expected node heartbeat endpoint to bypass csrf")
	}
	if server.isNodeAuthPath("/api/v1/nodes/heartbeat-debug") {
		t.Fatal("unexpected csrf bypass for non-node heartbeat path")
	}
	if server.isNodeAuthPath("/api/v1/auth/heartbeat/reset") {
		t.Fatal("unexpected csrf bypass for auth heartbeat path")
	}
}

func TestValidateServiceTargetURL(t *testing.T) {
	if err := validateServiceTargetURL("https://service.internal:8443/app"); err != nil {
		t.Fatalf("expected https service target to be valid: %v", err)
	}
	if err := validateServiceTargetURL("ftp://example.com"); err == nil {
		t.Fatal("expected non-http target scheme to be rejected")
	}
	if err := validateServiceTargetURL("http://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("expected metadata endpoint target to be blocked")
	}
}

func loginAsAdmin(t *testing.T, server *Server, email, password string) string {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	admin := &domain.User{
		Email:        email,
		PasswordHash: hash,
		Role:         domain.RoleAdmin,
		Active:       true,
		AuthProvider: domain.AuthProviderLocal,
	}
	if err := server.users.Create(context.Background(), admin); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	csrf := mustIssueCSRFToken(t, server)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", rec.Code, rec.Body.String())
	}
	var loginResult struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResult); err != nil {
		t.Fatalf("decode admin login response: %v", err)
	}
	if strings.TrimSpace(loginResult.Token) == "" {
		t.Fatal("expected admin login token")
	}
	return loginResult.Token
}

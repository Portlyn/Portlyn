package http

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"portlyn/internal/audit"
	"portlyn/internal/auth"
	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/observability"
	"portlyn/internal/store"
)

func TestIntegrationOTPLoginFlow(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	user := &domain.User{
		Email:        "otp@example.com",
		Role:         domain.RoleViewer,
		Active:       true,
		AuthProvider: domain.AuthProviderLocal,
	}
	if err := server.users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	requestBody := bytes.NewBufferString(`{"email":"otp@example.com"}`)
	requestReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/request-otp", requestBody)
	requestReq.Header.Set("Content-Type", "application/json")
	csrfToken := mustIssueCSRFToken(t, server)
	requestReq.Header.Set("X-CSRF-Token", csrfToken)
	requestReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
	requestRec := httptest.NewRecorder()
	server.Router().ServeHTTP(requestRec, requestReq)
	if requestRec.Code != http.StatusOK {
		t.Fatalf("expected otp request 200, got %d: %s", requestRec.Code, requestRec.Body.String())
	}

	var otpResult struct {
		ExpiresAt string `json:"expires_at"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(requestRec.Body.Bytes(), &otpResult); err != nil {
		t.Fatalf("decode otp result: %v", err)
	}
	if otpResult.Token == "" {
		t.Fatal("expected otp token in response for insecure test mode")
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-otp", bytes.NewBufferString(`{"email":"otp@example.com","token":"`+otpResult.Token+`"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("X-CSRF-Token", csrfToken)
	verifyReq.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
	verifyRec := httptest.NewRecorder()
	server.Router().ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected otp verify 200, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	var loginResult struct {
		Token string      `json:"token"`
		User  domain.User `json:"user"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &loginResult); err != nil {
		t.Fatalf("decode login result: %v", err)
	}
	if loginResult.Token == "" {
		t.Fatal("expected access token in login response")
	}
	if loginResult.User.Email != "otp@example.com" {
		t.Fatalf("unexpected user email %q", loginResult.User.Email)
	}
}

func TestIntegrationStartupSmoke(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	for _, path := range []string{"/livez", "/readyz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected %s to return 200, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestMetricsRequiresAdminAuthByDefault(t *testing.T) {
	server, cleanup := newIntegrationServer(t, func(cfg *config.Config) {
		cfg.MetricsPublic = false
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected metrics to require auth, got %d: %s", rec.Code, rec.Body.String())
	}

	token := loginAsAdmin(t, server, "metrics-admin@example.com", "StrongPass123!")
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected authenticated admin metrics access, got %d: %s", rec.Code, rec.Body.String())
	}
}

func newIntegrationServer(t *testing.T, mutate ...func(*config.Config)) (*Server, func()) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		AppVersion:            "test",
		HTTPAddr:              ":8080",
		ProxyHTTPAddr:         ":80",
		DatabaseDriver:        "sqlite",
		DatabasePath:          filepath.Join(dir, "portlyn.db"),
		JWTSecret:             "12345678901234567890123456789012",
		JWTSigningSecret:      "12345678901234567890123456789012",
		SessionBridgeSecret:   "12345678901234567890123456789013",
		OIDCStateSecret:       "12345678901234567890123456789014",
		MFAEncryptionSecret:   "12345678901234567890123456789015",
		CSRFSecret:            "12345678901234567890123456789016",
		DataEncryptionSecret:  "12345678901234567890123456789017",
		JWTIssuer:             "portlyn-test",
		FrontendBaseURL:       "http://localhost:3000",
		TokenTTL:              time.Hour,
		RefreshTokenTTL:       24 * time.Hour,
		RouteAuthTTL:          time.Hour,
		AuthRateLimit:         config.RateLimitConfig{LoginAttempts: 10, Window: time.Minute},
		AuthCacheTTL:          time.Minute,
		AllowInsecureDevMode:  true,
		MetricsPublic:         true,
		CSRFTokenTTL:          time.Hour,
		RequestBodyLimitBytes: 1 << 20,
		OTP: config.OTPConfig{
			Enabled:              true,
			TokenTTL:             10 * time.Minute,
			RequestLimit:         5,
			RequestWindow:        15 * time.Minute,
			ResponseIncludesCode: true,
		},
	}
	for _, fn := range mutate {
		if fn != nil {
			fn(&cfg)
		}
	}

	db, err := store.NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	userStore := store.NewUserStore(db)
	groupStore := store.NewGroupStore(db)
	loginTokenStore := store.NewLoginTokenStore(db)
	sessionStore := store.NewSessionStore(db)
	appSettingsStore := store.NewAppSettingsStore(db)
	appSettingsStore.SetDataEncryptionSecrets(cfg.DataEncryptionSecrets())
	if err := appSettingsStore.SeedDefaults(context.Background(), cfg); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	authService, err := auth.NewService(userStore, groupStore, loginTokenStore, sessionStore, appSettingsStore, cfg.JWTSigningSecret, cfg.SessionBridgeSecret, cfg.OIDCStateSecret, cfg.MFAEncryptionSecret, cfg.JWTIssuer, cfg.FrontendBaseURL, cfg.TokenTTL, cfg.RefreshTokenTTL, cfg.OIDC, cfg.OTP, cfg.RouteAuthTTL, cfg.AuthRateLimit, cfg.AuthCacheTTL, cfg.AllowInsecureDevMode, nil)
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}

	auditStore := store.NewAuditStore(db)
	auditLogger := audit.NewLogger(noopAuditSink{})
	server := NewServer(
		cfg,
		slog.Default(),
		db,
		authService,
		auditLogger,
		nil,
		nil,
		userStore,
		groupStore,
		store.NewNodeStore(db),
		store.NewDomainStore(db),
		store.NewCertificateStore(db),
		store.NewDNSProviderStore(db),
		store.NewServiceGroupStore(db),
		store.NewServiceStore(db),
		appSettingsStore,
		loginTokenStore,
		auditStore,
		sessionStore,
		store.NewNodeEnrollmentTokenStore(db),
		observability.NewMetrics(),
		nil,
		NewDBHealthCheck(func(ctx context.Context) error {
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			return sqlDB.PingContext(ctx)
		}),
	)
	return server, func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	}
}

type noopAuditSink struct{}

func (noopAuditSink) WriteEvent(context.Context, audit.AuditEvent) error { return nil }

func mustIssueCSRFToken(t *testing.T, server *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.CSRFCookieName {
			return cookie.Value
		}
	}
	t.Fatal("csrf cookie not issued")
	return ""
}

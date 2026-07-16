package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppVersion                      string
	HTTPAddr                        string
	FrontendBaseURL                 string
	BootstrapAdminEnabled           bool
	ProxyHTTPAddr                   string
	ProxyHTTPSAddr                  string
	RedisURL                        string
	DatabaseDriver                  string
	DatabaseURL                     string
	DatabasePath                    string
	JWTSecret                       string
	JWTSigningSecret                string
	SessionBridgeSecret             string
	OIDCStateSecret                 string
	MFAEncryptionSecret             string
	CSRFSecret                      string
	DataEncryptionSecret            string
	DataEncryptionLegacySecrets     []string
	JWTIssuer                       string
	TokenTTL                        time.Duration
	RefreshTokenTTL                 time.Duration
	LogLevel                        slog.Level
	AllowedOrigins                  []string
	TrustedProxyCIDRs               []string
	ExposeAuthTokens                bool
	AdminEmail                      string
	AdminPassword                   string
	ViewerEmail                     string
	ViewerPassword                  string
	TLSCertFile                     string
	TLSKeyFile                      string
	RedirectHTTPToHTTPS             bool
	CertificateStorageDir           string
	ACMEEmail                       string
	ACMECAURL                       string
	ACMEEnabled                     bool
	ACMELeader                      bool
	ACMEDNSProvider                 string
	ACMEDNSConfig                   map[string]string
	ACMEPollInterval                time.Duration
	ACMERenewWithin                 time.Duration
	NodeOfflineAfter                time.Duration
	NodeRequireHTTPS                bool
	NodeTrustForwardedProto         bool
	NodeAllowMTLSHeaderFallback     bool
	RequestClientCert               bool
	NodeEnrollRateLimit             int
	NodeEnrollRateWindow            time.Duration
	NodeHeartbeatAuthFailRateLimit  int
	NodeHeartbeatAuthFailRateWindow time.Duration
	BreakGlassEnabled               bool
	BreakGlassToken                 string
	BreakGlassTTL                   time.Duration
	BreakGlassAllowCIDRs            []string
	AlertLoginFailSpikeThreshold    int
	AlertNodeHeartbeatFailThreshold int
	AlertAuditAnomalyThreshold      int
	AlertWindow                     time.Duration
	MetricsPublic                   bool
	OIDC                            OIDCConfig
	OTP                             OTPConfig
	RouteAuthTTL                    time.Duration
	AuthRateLimit                   RateLimitConfig
	AuthCacheTTL                    time.Duration
	AuditBufferSize                 int
	AuditBatchSize                  int
	AuditFlushInterval              time.Duration
	AuditDropPolicy                 string
	RouteCacheTTL                   time.Duration
	RouteLocalCacheTTL              time.Duration
	RouteLocalCacheSize             int
	AllowInsecureDevMode            bool
	RequireMFAForAdmins             bool
	CSRFTokenTTL                    time.Duration
	RequestBodyLimitBytes           int64
	GeoIPFailOpen                   bool
	CrowdSecFailOpen                bool
	HealthExposeVersion             bool
	AuditHMACSecret                 string
	AllowPrivateUpstreams           bool
}

type OIDCConfig struct {
	Enabled              bool
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	AllowedEmailDomains  []string
	AdminRoleClaimPath   string
	AdminRoleValue       string
	DefaultProviderLabel string
	AllowEmailLinking    bool
	RequireVerifiedEmail bool
	ManageRoles          bool
}

type OTPConfig struct {
	Enabled              bool
	TokenTTL             time.Duration
	RequestLimit         int
	RequestWindow        time.Duration
	ResponseIncludesCode bool
}

type RateLimitConfig struct {
	LoginAttempts int
	Window        time.Duration
}

type ValidationIssue struct {
	Level   string `json:"level"`
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func Load() (Config, error) {
	_ = godotenv.Load()
	secrets := make(map[string]string, 7)
	allowInsecureDevMode := getEnvBool("ALLOW_INSECURE_DEV_MODE", false)

	cfg := Config{
		AppVersion:                      getEnv("APP_VERSION", "dev"),
		HTTPAddr:                        getEnv("HTTP_ADDR", ":8080"),
		FrontendBaseURL:                 strings.TrimRight(getEnv("FRONTEND_BASE_URL", "http://localhost"), "/"),
		BootstrapAdminEnabled:           getEnvBool("BOOTSTRAP_ADMIN_ENABLED", false),
		ProxyHTTPAddr:                   getEnv("PROXY_HTTP_ADDR", ":80"),
		ProxyHTTPSAddr:                  getEnv("PROXY_HTTPS_ADDR", ":443"),
		RedisURL:                        strings.TrimSpace(os.Getenv("REDIS_URL")),
		DatabaseDriver:                  strings.ToLower(getEnv("DATABASE_DRIVER", "")),
		DatabaseURL:                     strings.TrimSpace(os.Getenv("DATABASE_URL")),
		DatabasePath:                    getEnv("DATABASE_PATH", "portlyn.db"),
		JWTSecret:                       getSecretEnv("JWT_SECRET", secrets, allowInsecureDevMode),
		JWTSigningSecret:                getSecretEnv("JWT_SIGNING_SECRET", secrets, allowInsecureDevMode),
		SessionBridgeSecret:             getSecretEnv("SESSION_BRIDGE_SECRET", secrets, allowInsecureDevMode),
		OIDCStateSecret:                 getSecretEnv("OIDC_STATE_SECRET", secrets, allowInsecureDevMode),
		MFAEncryptionSecret:             getSecretEnv("MFA_ENCRYPTION_SECRET", secrets, allowInsecureDevMode),
		CSRFSecret:                      getSecretEnv("CSRF_SECRET", secrets, allowInsecureDevMode),
		DataEncryptionSecret:            getSecretEnv("DATA_ENCRYPTION_SECRET", secrets, allowInsecureDevMode),
		DataEncryptionLegacySecrets:     getEnvList("DATA_ENCRYPTION_LEGACY_SECRETS", []string{}),
		JWTIssuer:                       getEnv("JWT_ISSUER", "portlyn"),
		TokenTTL:                        getEnvDuration("TOKEN_TTL", 30*time.Minute),
		RefreshTokenTTL:                 getEnvDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		LogLevel:                        getEnvLogLevel("LOG_LEVEL", slog.LevelInfo),
		AllowedOrigins:                  getEnvList("CORS_ALLOWED_ORIGINS", []string{"http://localhost", "http://127.0.0.1"}),
		TrustedProxyCIDRs:               getEnvList("TRUSTED_PROXY_CIDRS", []string{"127.0.0.1/32", "::1/128"}),
		ExposeAuthTokens:                getEnvBool("EXPOSE_AUTH_TOKENS", false),
		AdminEmail:                      strings.TrimSpace(os.Getenv("ADMIN_EMAIL")),
		AdminPassword:                   os.Getenv("ADMIN_PASSWORD"),
		ViewerEmail:                     strings.TrimSpace(os.Getenv("VIEWER_EMAIL")),
		ViewerPassword:                  os.Getenv("VIEWER_PASSWORD"),
		TLSCertFile:                     strings.TrimSpace(os.Getenv("TLS_CERT_FILE")),
		TLSKeyFile:                      strings.TrimSpace(os.Getenv("TLS_KEY_FILE")),
		RedirectHTTPToHTTPS:             getEnvBool("REDIRECT_HTTP_TO_HTTPS", false),
		CertificateStorageDir:           getEnv("CERTIFICATE_STORAGE_DIR", "certificates"),
		ACMEEmail:                       strings.TrimSpace(os.Getenv("ACME_EMAIL")),
		ACMECAURL:                       strings.TrimSpace(os.Getenv("ACME_CA_URL")),
		ACMEEnabled:                     getEnvBool("ACME_ENABLED", false),
		ACMELeader:                      getEnvBool("ACME_LEADER", false),
		ACMEDNSProvider:                 strings.ToLower(strings.TrimSpace(os.Getenv("ACME_DNS_PROVIDER"))),
		ACMEDNSConfig:                   dnsProviderConfigFromEnv(strings.ToLower(strings.TrimSpace(os.Getenv("ACME_DNS_PROVIDER")))),
		ACMEPollInterval:                getEnvDuration("ACME_POLL_INTERVAL", 1*time.Minute),
		ACMERenewWithin:                 getEnvDuration("ACME_RENEW_WITHIN", 30*24*time.Hour),
		NodeOfflineAfter:                getEnvDuration("NODE_OFFLINE_AFTER", 2*time.Minute),
		NodeRequireHTTPS:                getEnvBool("NODE_REQUIRE_HTTPS", true),
		NodeTrustForwardedProto:         getEnvBool("NODE_TRUST_FORWARDED_PROTO", true),
		NodeAllowMTLSHeaderFallback:     getEnvBool("NODE_ALLOW_MTLS_HEADER_FALLBACK", false),
		RequestClientCert:               getEnvBool("REQUEST_CLIENT_CERT", false),
		NodeEnrollRateLimit:             getEnvInt("NODE_ENROLL_RATE_LIMIT", 20),
		NodeEnrollRateWindow:            getEnvDuration("NODE_ENROLL_RATE_WINDOW", 10*time.Minute),
		NodeHeartbeatAuthFailRateLimit:  getEnvInt("NODE_HEARTBEAT_AUTH_FAIL_RATE_LIMIT", 20),
		NodeHeartbeatAuthFailRateWindow: getEnvDuration("NODE_HEARTBEAT_AUTH_FAIL_RATE_WINDOW", 1*time.Minute),
		BreakGlassEnabled:               getEnvBool("BREAK_GLASS_ENABLED", false),
		BreakGlassToken:                 strings.TrimSpace(os.Getenv("BREAK_GLASS_TOKEN")),
		BreakGlassTTL:                   getEnvDuration("BREAK_GLASS_TTL", 15*time.Minute),
		BreakGlassAllowCIDRs:            getEnvList("BREAK_GLASS_ALLOW_CIDRS", []string{"127.0.0.1/32", "::1/128"}),
		AlertLoginFailSpikeThreshold:    getEnvInt("ALERT_LOGIN_FAIL_SPIKE_THRESHOLD", 20),
		AlertNodeHeartbeatFailThreshold: getEnvInt("ALERT_NODE_HEARTBEAT_FAIL_THRESHOLD", 20),
		AlertAuditAnomalyThreshold:      getEnvInt("ALERT_AUDIT_ANOMALY_THRESHOLD", 10),
		AlertWindow:                     getEnvDuration("ALERT_WINDOW", 15*time.Minute),
		MetricsPublic:                   getEnvBool("METRICS_PUBLIC", false),
		OIDC: OIDCConfig{
			Enabled:              getEnvBool("OIDC_ENABLED", false),
			IssuerURL:            strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
			ClientID:             strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
			ClientSecret:         os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:          strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
			AllowedEmailDomains:  getEnvList("OIDC_ALLOWED_EMAIL_DOMAINS", []string{}),
			AdminRoleClaimPath:   getEnv("OIDC_ADMIN_ROLE_CLAIM_PATH", "realm_access.roles"),
			AdminRoleValue:       strings.TrimSpace(os.Getenv("OIDC_ADMIN_ROLE_VALUE")),
			DefaultProviderLabel: getEnv("OIDC_PROVIDER_LABEL", "SSO"),
			AllowEmailLinking:    getEnvBool("OIDC_ALLOW_EMAIL_LINKING", false),
			RequireVerifiedEmail: getEnvBool("OIDC_REQUIRE_VERIFIED_EMAIL", true),
			ManageRoles:          getEnvBool("OIDC_MANAGE_ROLES", true),
		},
		OTP: OTPConfig{
			Enabled:              getEnvBool("OTP_ENABLED", true),
			TokenTTL:             getEnvDuration("OTP_TOKEN_TTL", 10*time.Minute),
			RequestLimit:         getEnvInt("OTP_REQUEST_LIMIT", 5),
			RequestWindow:        getEnvDuration("OTP_REQUEST_WINDOW", 15*time.Minute),
			ResponseIncludesCode: getEnvBool("OTP_RESPONSE_INCLUDES_CODE", false),
		},
		RouteAuthTTL: getEnvDuration("ROUTE_AUTH_TTL", 12*time.Hour),
		AuthRateLimit: RateLimitConfig{
			LoginAttempts: getEnvInt("AUTH_RATE_LIMIT_ATTEMPTS", 10),
			Window:        getEnvDuration("AUTH_RATE_LIMIT_WINDOW", 10*time.Minute),
		},
		AuthCacheTTL:          getEnvDuration("AUTH_CACHE_TTL", 1*time.Minute),
		AuditBufferSize:       getEnvInt("AUDIT_BUFFER_SIZE", 1024),
		AuditBatchSize:        getEnvInt("AUDIT_BATCH_SIZE", 128),
		AuditFlushInterval:    getEnvDuration("AUDIT_FLUSH_INTERVAL", 250*time.Millisecond),
		AuditDropPolicy:       strings.ToLower(getEnv("AUDIT_DROP_POLICY", "sync_fallback")),
		RouteCacheTTL:         getEnvDuration("ROUTE_CACHE_TTL", 30*time.Second),
		RouteLocalCacheTTL:    getEnvDuration("ROUTE_LOCAL_CACHE_TTL", 5*time.Second),
		RouteLocalCacheSize:   getEnvInt("ROUTE_LOCAL_CACHE_SIZE", 2048),
		AllowInsecureDevMode:  allowInsecureDevMode,
		RequireMFAForAdmins:   getEnvBool("REQUIRE_MFA_FOR_ADMINS", true),
		CSRFTokenTTL:          getEnvDuration("CSRF_TOKEN_TTL", 12*time.Hour),
		RequestBodyLimitBytes: getEnvInt64("REQUEST_BODY_LIMIT_BYTES", 1<<20),
		GeoIPFailOpen:         getEnvBool("GEOIP_FAIL_OPEN", false),
		CrowdSecFailOpen:      getEnvBool("CROWDSEC_FAIL_OPEN", true),
		HealthExposeVersion:   getEnvBool("HEALTH_EXPOSE_VERSION", false),
		AuditHMACSecret:       getSecretEnv("AUDIT_HMAC_SECRET", secrets, allowInsecureDevMode),
		AllowPrivateUpstreams: getEnvBool("PROXY_ALLOW_PRIVATE_UPSTREAMS", true),
	}

	return cfg, cfg.Validate()
}

func (cfg *Config) Validate() error {
	issues := cfg.ValidationIssues()
	for _, issue := range issues {
		if issue.Level == "error" {
			return fmt.Errorf("%s", issue.Message)
		}
	}
	return nil
}

func (cfg *Config) ValidationIssues() []ValidationIssue {
	issues := make([]ValidationIssue, 0)
	add := func(level, field, code, message string) {
		issues = append(issues, ValidationIssue{Level: level, Field: field, Code: code, Message: message})
	}
	secretFields := []struct {
		Field string
		Value string
	}{
		{Field: "JWT_SECRET", Value: cfg.JWTSecret},
		{Field: "JWT_SIGNING_SECRET", Value: cfg.JWTSigningSecret},
		{Field: "SESSION_BRIDGE_SECRET", Value: cfg.SessionBridgeSecret},
		{Field: "OIDC_STATE_SECRET", Value: cfg.OIDCStateSecret},
		{Field: "MFA_ENCRYPTION_SECRET", Value: cfg.MFAEncryptionSecret},
		{Field: "CSRF_SECRET", Value: cfg.CSRFSecret},
		{Field: "DATA_ENCRYPTION_SECRET", Value: cfg.DataEncryptionSecret},
		{Field: "AUDIT_HMAC_SECRET", Value: cfg.AuditHMACSecret},
	}
	for _, secret := range secretFields {
		if strings.TrimSpace(secret.Value) == "" {
			add("error", secret.Field, "missing_secret", secret.Field+" must not be empty")
		}
	}
	if cfg.DatabaseDriver == "" {
		if cfg.DatabaseURL != "" {
			cfg.DatabaseDriver = "postgres"
		} else {
			cfg.DatabaseDriver = "sqlite"
		}
	}
	switch cfg.DatabaseDriver {
	case "sqlite":
		if cfg.DatabasePath == "" {
			add("error", "DATABASE_PATH", "missing_database_path", "DATABASE_PATH must not be empty when DATABASE_DRIVER=sqlite")
		}
	case "postgres", "postgresql":
		cfg.DatabaseDriver = "postgres"
		if cfg.DatabaseURL == "" {
			add("error", "DATABASE_URL", "missing_database_url", "DATABASE_URL must not be empty when DATABASE_DRIVER=postgres")
		} else if !cfg.AllowInsecureDevMode {
			sslMode := postgresSSLMode(cfg.DatabaseURL)
			privateDB := isPrivateOrLocalHost(hostFromURL(cfg.DatabaseURL))
			if sslMode == "disable" {
				if privateDB {
					add("warn", "DATABASE_URL", "insecure_database_transport_private", "DATABASE_URL disables TLS (sslmode=disable) to a private/container-local host; acceptable on a trusted network but prefer TLS if the link ever crosses one")
				} else {
					add("error", "DATABASE_URL", "insecure_database_transport", "DATABASE_URL must not disable TLS in production (avoid sslmode=disable)")
				}
			}
			if sslMode == "allow" || sslMode == "prefer" || sslMode == "" {
				add("warn", "DATABASE_URL", "weak_database_transport", "DATABASE_URL is not enforcing TLS verification; prefer sslmode=require, verify-ca, or verify-full")
			}
		}
	default:
		add("error", "DATABASE_DRIVER", "unsupported_database_driver", fmt.Sprintf("unsupported DATABASE_DRIVER %q", cfg.DatabaseDriver))
	}
	if !cfg.AllowInsecureDevMode {
		for _, secret := range secretFields {
			if len(secret.Value) < 32 {
				add("error", secret.Field, "weak_secret", secret.Field+" must be unique and at least 32 characters unless ALLOW_INSECURE_DEV_MODE=true")
			}
		}
		seenSecrets := map[string]string{
			strings.TrimSpace(secretFields[0].Value): secretFields[0].Field,
		}
		for _, secret := range secretFields[1:] {
			key := strings.TrimSpace(secret.Value)
			if existingField, exists := seenSecrets[key]; exists {
				add("error", secret.Field, "secret_reuse", secret.Field+" must be different from "+existingField+" outside insecure dev mode")
				continue
			}
			seenSecrets[key] = secret.Field
		}
		if !secureOrLocalURL(cfg.FrontendBaseURL) {
			add("error", "FRONTEND_BASE_URL", "insecure_frontend_base_url", "FRONTEND_BASE_URL must use https outside local development")
		}
		for _, origin := range cfg.AllowedOrigins {
			if !secureOrLocalURL(origin) {
				add("error", "CORS_ALLOWED_ORIGINS", "insecure_cors_origin", "CORS_ALLOWED_ORIGINS must use https outside local development")
				break
			}
		}
		if cfg.OTP.ResponseIncludesCode {
			add("error", "OTP_RESPONSE_INCLUDES_CODE", "unsafe_otp_setting", "OTP_RESPONSE_INCLUDES_CODE must be false unless ALLOW_INSECURE_DEV_MODE=true")
		}
		if cfg.TokenTTL > 7*24*time.Hour {
			add("warn", "TOKEN_TTL", "long_token_ttl", "TOKEN_TTL is unusually long for an access token")
		}
	}
	if cfg.OIDC.Enabled {
		if cfg.OIDC.IssuerURL == "" || cfg.OIDC.ClientID == "" || cfg.OIDC.ClientSecret == "" || cfg.OIDC.RedirectURL == "" {
			add("error", "OIDC", "oidc_incomplete", "OIDC is enabled but OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URL are incomplete")
		}
		if !strings.HasPrefix(strings.ToLower(cfg.OIDC.RedirectURL), "https://") && !cfg.AllowInsecureDevMode {
			add("error", "OIDC_REDIRECT_URL", "insecure_oidc_redirect", "OIDC_REDIRECT_URL must use https outside insecure dev mode")
		}
	}
	if cfg.OTP.Enabled && cfg.OTP.TokenTTL < 2*time.Minute {
		add("warn", "OTP_TOKEN_TTL", "short_otp_ttl", "OTP token TTL below 2 minutes may be too aggressive")
	}
	if cfg.AuthRateLimit.LoginAttempts < 3 {
		add("warn", "AUTH_RATE_LIMIT_ATTEMPTS", "tight_rate_limit", "AUTH_RATE_LIMIT_ATTEMPTS is very low and may create operator lockouts")
	}
	if cfg.RequestBodyLimitBytes <= 0 {
		add("error", "REQUEST_BODY_LIMIT_BYTES", "invalid_request_body_limit", "REQUEST_BODY_LIMIT_BYTES must be greater than zero")
	}
	if cfg.NodeEnrollRateLimit <= 0 {
		add("error", "NODE_ENROLL_RATE_LIMIT", "invalid_node_enroll_rate_limit", "NODE_ENROLL_RATE_LIMIT must be greater than zero")
	}
	if cfg.NodeEnrollRateWindow <= 0 {
		add("error", "NODE_ENROLL_RATE_WINDOW", "invalid_node_enroll_rate_window", "NODE_ENROLL_RATE_WINDOW must be greater than zero")
	}
	if cfg.NodeHeartbeatAuthFailRateLimit <= 0 {
		add("error", "NODE_HEARTBEAT_AUTH_FAIL_RATE_LIMIT", "invalid_node_heartbeat_auth_fail_rate_limit", "NODE_HEARTBEAT_AUTH_FAIL_RATE_LIMIT must be greater than zero")
	}
	if cfg.NodeHeartbeatAuthFailRateWindow <= 0 {
		add("error", "NODE_HEARTBEAT_AUTH_FAIL_RATE_WINDOW", "invalid_node_heartbeat_auth_fail_rate_window", "NODE_HEARTBEAT_AUTH_FAIL_RATE_WINDOW must be greater than zero")
	}
	if cfg.BreakGlassEnabled {
		if strings.TrimSpace(cfg.BreakGlassToken) == "" {
			add("error", "BREAK_GLASS_TOKEN", "missing_break_glass_token", "BREAK_GLASS_TOKEN must be set when BREAK_GLASS_ENABLED=true")
		}
		if cfg.BreakGlassTTL <= 0 {
			add("error", "BREAK_GLASS_TTL", "invalid_break_glass_ttl", "BREAK_GLASS_TTL must be greater than zero")
		}
		for _, raw := range cfg.BreakGlassAllowCIDRs {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
				add("error", "BREAK_GLASS_ALLOW_CIDRS", "invalid_break_glass_allow_cidr", "BREAK_GLASS_ALLOW_CIDRS entries must be CIDR prefixes")
				break
			}
		}
	}
	if cfg.NodeAllowMTLSHeaderFallback && !cfg.NodeTrustForwardedProto {
		add("error", "NODE_ALLOW_MTLS_HEADER_FALLBACK", "unsafe_mtls_header_fallback", "NODE_ALLOW_MTLS_HEADER_FALLBACK requires NODE_TRUST_FORWARDED_PROTO=true behind a trusted proxy")
	}
	if cfg.NodeTrustForwardedProto && len(cfg.TrustedProxyCIDRs) == 0 {
		add("error", "NODE_TRUST_FORWARDED_PROTO", "missing_trusted_proxy_cidrs", "NODE_TRUST_FORWARDED_PROTO requires TRUSTED_PROXY_CIDRS")
	}
	if !cfg.AllowInsecureDevMode {
		if cfg.ExposeAuthTokens {
			add("error", "EXPOSE_AUTH_TOKENS", "unsafe_token_exposure", "EXPOSE_AUTH_TOKENS must be false unless ALLOW_INSECURE_DEV_MODE=true")
		}
		if !cfg.NodeRequireHTTPS {
			add("error", "NODE_REQUIRE_HTTPS", "node_https_required", "NODE_REQUIRE_HTTPS must be true unless ALLOW_INSECURE_DEV_MODE=true")
		}
		if cfg.NodeAllowMTLSHeaderFallback {
			add("warn", "NODE_ALLOW_MTLS_HEADER_FALLBACK", "mtls_header_fallback_enabled", "mTLS header fallback is enabled; prefer direct TLS client cert validation")
		}
	} else if frontendHost := hostFromURL(cfg.FrontendBaseURL); frontendHost != "" && !isLoopbackHost(frontendHost) {
		add("error", "ALLOW_INSECURE_DEV_MODE", "insecure_dev_mode_in_production", "ALLOW_INSECURE_DEV_MODE=true is only valid when FRONTEND_BASE_URL points at localhost; refusing to start in production with weakened defenses")
	}
	if cfg.RedirectHTTPToHTTPS && cfg.ProxyHTTPSAddr == "" {
		add("error", "PROXY_HTTPS_ADDR", "missing_https_listener", "PROXY_HTTPS_ADDR must be configured when REDIRECT_HTTP_TO_HTTPS=true")
	}
	if cfg.AlertLoginFailSpikeThreshold <= 0 {
		add("error", "ALERT_LOGIN_FAIL_SPIKE_THRESHOLD", "invalid_alert_login_fail_spike_threshold", "ALERT_LOGIN_FAIL_SPIKE_THRESHOLD must be greater than zero")
	}
	if cfg.AlertNodeHeartbeatFailThreshold <= 0 {
		add("error", "ALERT_NODE_HEARTBEAT_FAIL_THRESHOLD", "invalid_alert_node_heartbeat_fail_threshold", "ALERT_NODE_HEARTBEAT_FAIL_THRESHOLD must be greater than zero")
	}
	if cfg.AlertAuditAnomalyThreshold <= 0 {
		add("error", "ALERT_AUDIT_ANOMALY_THRESHOLD", "invalid_alert_audit_anomaly_threshold", "ALERT_AUDIT_ANOMALY_THRESHOLD must be greater than zero")
	}
	if cfg.AlertWindow <= 0 {
		add("error", "ALERT_WINDOW", "invalid_alert_window", "ALERT_WINDOW must be greater than zero")
	}
	for _, raw := range cfg.TrustedProxyCIDRs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			add("error", "TRUSTED_PROXY_CIDRS", "invalid_trusted_proxy_cidr", "TRUSTED_PROXY_CIDRS entries must be CIDR prefixes")
			break
		}
	}
	if cfg.ACMEDNSProvider != "" {
		required, supported := dnsProviderRequiredKeys(cfg.ACMEDNSProvider)
		if !supported {
			add("error", "ACME_DNS_PROVIDER", "unsupported_dns_provider", fmt.Sprintf("unsupported ACME_DNS_PROVIDER %q (expected cloudflare, hetzner, digitalocean, or route53)", cfg.ACMEDNSProvider))
		} else {
			for _, key := range required {
				if strings.TrimSpace(cfg.ACMEDNSConfig[key]) == "" {
					add("error", "ACME_DNS_PROVIDER", "missing_dns_provider_credential", fmt.Sprintf("ACME_DNS_PROVIDER=%s requires %s", cfg.ACMEDNSProvider, dnsProviderEnvKey(cfg.ACMEDNSProvider, key)))
				}
			}
		}
	}
	for i := range issues {
		if hint := validationHint(issues[i].Code); hint != "" {
			issues[i].Hint = hint
		}
	}
	return issues
}

func (cfg Config) DataEncryptionSecrets() []string {
	secrets := make([]string, 0, 1+len(cfg.DataEncryptionLegacySecrets))
	if strings.TrimSpace(cfg.DataEncryptionSecret) != "" {
		secrets = append(secrets, strings.TrimSpace(cfg.DataEncryptionSecret))
	}
	for _, item := range cfg.DataEncryptionLegacySecrets {
		value := strings.TrimSpace(item)
		if value != "" {
			secrets = append(secrets, value)
		}
	}
	return secrets
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getSecretEnv(key string, generated map[string]string, allowInsecureDevMode bool) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value != "" {
		return value
	}
	if !allowInsecureDevMode {
		return ""
	}
	if existing, ok := generated[key]; ok {
		return existing
	}
	generated[key] = randomSecret(48)
	return generated[key]
}

func randomSecret(size int) string {
	if size < 32 {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("unable to generate random secret: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvLogLevel(key string, fallback slog.Level) slog.Level {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info", "":
		return slog.LevelInfo
	default:
		if numeric, err := strconv.Atoi(value); err == nil {
			return slog.Level(numeric)
		}
		return fallback
	}
}

func getEnvList(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func secureOrLocalURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return true
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func postgresSSLMode(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Query().Get("sslmode")))
}

func isPrivateOrLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if isLoopbackHost(host) {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
	}
	return !strings.Contains(host, ".")
}

func dnsProviderRequiredKeys(providerType string) ([]string, bool) {
	switch providerType {
	case "cloudflare":
		return []string{"api_token"}, true
	case "hetzner":
		return []string{"dns_api_token"}, true
	case "digitalocean":
		return []string{"api_token"}, true
	case "route53":
		return nil, true
	default:
		return nil, false
	}
}

func dnsProviderEnvKey(providerType, configKey string) string {
	switch providerType {
	case "cloudflare":
		return "ACME_DNS_CLOUDFLARE_API_TOKEN"
	case "hetzner":
		return "ACME_DNS_HETZNER_API_TOKEN"
	case "digitalocean":
		return "ACME_DNS_DIGITALOCEAN_API_TOKEN"
	default:
		return "ACME_DNS_" + strings.ToUpper(providerType) + "_" + strings.ToUpper(configKey)
	}
}

func dnsProviderConfigFromEnv(providerType string) map[string]string {
	out := make(map[string]string)
	set := func(key, envName string) {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			out[key] = value
		}
	}
	switch providerType {
	case "cloudflare":
		set("api_token", "ACME_DNS_CLOUDFLARE_API_TOKEN")
	case "hetzner":
		set("dns_api_token", "ACME_DNS_HETZNER_API_TOKEN")
	case "digitalocean":
		set("api_token", "ACME_DNS_DIGITALOCEAN_API_TOKEN")
	case "route53":
		set("access_key_id", "ACME_DNS_ROUTE53_ACCESS_KEY_ID")
		set("secret_access_key", "ACME_DNS_ROUTE53_SECRET_ACCESS_KEY")
		set("session_token", "ACME_DNS_ROUTE53_SESSION_TOKEN")
		set("region", "ACME_DNS_ROUTE53_REGION")
		set("hosted_zone_id", "ACME_DNS_ROUTE53_HOSTED_ZONE_ID")
		set("profile", "ACME_DNS_ROUTE53_PROFILE")
	}
	return out
}

func validationHint(code string) string {
	switch code {
	case "missing_secret", "weak_secret", "secret_reuse":
		return "Run 'portlyn init' to generate strong unique secrets, or set a distinct 32+ char random value (openssl rand -base64 48)."
	case "insecure_database_transport":
		return "Add ?sslmode=require (or verify-full) to DATABASE_URL, or point it at a private/container-local host."
	case "unsupported_database_driver":
		return "Set DATABASE_DRIVER to 'sqlite' or 'postgres'."
	case "missing_database_url":
		return "Set DATABASE_URL, e.g. postgres://user:pass@host:5432/portlyn?sslmode=require."
	case "insecure_frontend_base_url":
		return "Use an https:// URL for FRONTEND_BASE_URL, or keep http://localhost for local development."
	case "insecure_cors_origin":
		return "List https:// origins in CORS_ALLOWED_ORIGINS (http:// is only allowed for localhost)."
	case "insecure_oidc_redirect":
		return "OIDC_REDIRECT_URL must be https:// in production."
	case "oidc_incomplete":
		return "Set OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URL, or disable OIDC with OIDC_ENABLED=false."
	case "insecure_dev_mode_in_production":
		return "Set ALLOW_INSECURE_DEV_MODE=false for any non-localhost FRONTEND_BASE_URL."
	case "node_https_required":
		return "Keep NODE_REQUIRE_HTTPS=true; only relax it in insecure dev mode."
	case "unsafe_token_exposure":
		return "Set EXPOSE_AUTH_TOKENS=false outside local development."
	case "unsafe_otp_setting":
		return "Set OTP_RESPONSE_INCLUDES_CODE=false; the code must never be returned in API responses in production."
	case "missing_trusted_proxy_cidrs":
		return "Set TRUSTED_PROXY_CIDRS to the CIDR(s) of your fronting proxy, or set NODE_TRUST_FORWARDED_PROTO=false."
	case "missing_https_listener":
		return "Set PROXY_HTTPS_ADDR (e.g. :443) when REDIRECT_HTTP_TO_HTTPS=true."
	case "unsupported_dns_provider":
		return "Set ACME_DNS_PROVIDER to cloudflare, hetzner, digitalocean, or route53."
	case "missing_dns_provider_credential":
		return "Provide the API token env var for the selected ACME_DNS_PROVIDER."
	case "missing_break_glass_token":
		return "Set BREAK_GLASS_TOKEN (32+ random chars) when BREAK_GLASS_ENABLED=true."
	default:
		return ""
	}
}

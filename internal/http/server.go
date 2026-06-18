package http

import (
	"context"
	"errors"
	"log/slog"
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"

	"portlyn/internal/acme"
	"portlyn/internal/audit"
	"portlyn/internal/auth"
	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/geoip"
	"portlyn/internal/observability"
	"portlyn/internal/proxy"
	"portlyn/internal/rate"
	"portlyn/internal/scanner"
	"portlyn/internal/security"
	"portlyn/internal/store"
	"portlyn/internal/tunnel"
)

type Server struct {
	cfg              config.Config
	logger           *slog.Logger
	db               *gorm.DB
	healthChecks     []HealthCheck
	metrics          *observability.Metrics
	validate         *validator.Validate
	auth             *auth.Service
	audit            *audit.Logger
	acme             *acme.Manager
	proxy            *proxy.Manager
	users            *store.UserStore
	groups           *store.GroupStore
	nodes            *store.NodeStore
	clients          *store.ClientStore
	domains          *store.DomainStore
	certificates     *store.CertificateStore
	dnsProviders     *store.DNSProviderStore
	serviceGroups    *store.ServiceGroupStore
	services         *store.ServiceStore
	appSettings      *store.AppSettingsStore
	loginTokens      *store.LoginTokenStore
	auditStore       *store.AuditStore
	sessions         *store.SessionStore
	enrollmentTokens *store.NodeEnrollmentTokenStore
	auditWebhooks    *store.AuditWebhookStore
	exposureReports  *store.ExposureReportStore
	exposureScanner  *scanner.Scanner
	tunnel           *tunnel.Manager
	webauthn         *auth.WebAuthnService
	geoip            *geoip.Lookup
	crowdsec         *security.CrowdSec
	crowdsecCtx      context.Context
	webhookDispatch  *audit.WebhookDispatcher
	nodeRateLimiter  rate.RateLimiter
	bootWarnings     []StatusCondition
	breakGlass       breakGlassState
}

func (s *Server) SetNetworkSecurity(ctx context.Context, lookup *geoip.Lookup, crowdsec *security.CrowdSec) {
	s.crowdsecCtx = ctx
	s.geoip = lookup
	s.crowdsec = crowdsec
}

func (s *Server) SetWebhookDispatcher(dispatcher *audit.WebhookDispatcher) {
	s.webhookDispatch = dispatcher
}

func (s *Server) SetNodeRateLimiter(limiter rate.RateLimiter) {
	if limiter != nil {
		s.nodeRateLimiter = limiter
	}
}

func NewServer(
	cfg config.Config,
	logger *slog.Logger,
	db *gorm.DB,
	authService *auth.Service,
	auditLogger *audit.Logger,
	acmeManager *acme.Manager,
	proxyManager *proxy.Manager,
	userStore *store.UserStore,
	groupStore *store.GroupStore,
	nodeStore *store.NodeStore,
	clientStore *store.ClientStore,
	domainStore *store.DomainStore,
	certificateStore *store.CertificateStore,
	dnsProviderStore *store.DNSProviderStore,
	serviceGroupStore *store.ServiceGroupStore,
	serviceStore *store.ServiceStore,
	appSettingsStore *store.AppSettingsStore,
	loginTokenStore *store.LoginTokenStore,
	auditStore *store.AuditStore,
	sessionStore *store.SessionStore,
	enrollmentTokenStore *store.NodeEnrollmentTokenStore,
	auditWebhookStore *store.AuditWebhookStore,
	exposureReportStore *store.ExposureReportStore,
	exposureScanner *scanner.Scanner,
	tunnelManager *tunnel.Manager,
	webAuthnService *auth.WebAuthnService,
	metrics *observability.Metrics,
	bootWarnings []StatusCondition,
	healthChecks ...HealthCheck,
) *Server {
	if len(healthChecks) == 0 {
		healthChecks = []HealthCheck{NewDBHealthCheck(func(ctx context.Context) error {
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			return sqlDB.PingContext(ctx)
		})}
	}
	return &Server{
		cfg:              cfg,
		logger:           logger,
		db:               db,
		healthChecks:     healthChecks,
		metrics:          metrics,
		validate:         validator.New(validator.WithRequiredStructEnabled()),
		auth:             authService,
		audit:            auditLogger,
		acme:             acmeManager,
		proxy:            proxyManager,
		users:            userStore,
		groups:           groupStore,
		nodes:            nodeStore,
		clients:          clientStore,
		domains:          domainStore,
		certificates:     certificateStore,
		dnsProviders:     dnsProviderStore,
		serviceGroups:    serviceGroupStore,
		services:         serviceStore,
		appSettings:      appSettingsStore,
		loginTokens:      loginTokenStore,
		auditStore:       auditStore,
		sessions:         sessionStore,
		enrollmentTokens: enrollmentTokenStore,
		auditWebhooks:    auditWebhookStore,
		exposureReports:  exposureReportStore,
		exposureScanner:  exposureScanner,
		tunnel:           tunnelManager,
		webauthn:         webAuthnService,
		nodeRateLimiter:  rate.NewLocalLimiter(),
		bootWarnings:     append([]StatusCondition(nil), bootWarnings...),
		breakGlass: breakGlassState{
			enabled:   cfg.BreakGlassEnabled,
			token:     strings.TrimSpace(cfg.BreakGlassToken),
			expiresAt: time.Now().UTC().Add(cfg.BreakGlassTTL),
		},
	}
}

func (s *Server) ProxyHandler() stdhttp.Handler {
	handler := s.proxy.Handler()
	handler = middleware.Recoverer(handler)
	handler = middleware.RequestID(handler)
	return handler
}

func (s *Server) SyncProxyState(ctx context.Context) error {
	return s.proxy.SyncAllServicesFromDB(ctx)
}

func (s *Server) Router() stdhttp.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(s.traceContextMiddleware)
	r.Use(s.securityHeadersMiddleware)
	r.Use(s.requestBodyLimitMiddleware)
	r.Use(s.csrfMiddleware)
	r.Use(s.accessLogMiddleware("api"))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Refresh-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/livez", s.handleLivez)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/healthz", s.handleHealthz)
	r.Get("/install.sh", s.handleInstallScript)
	r.Get("/metrics", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if s.metrics == nil {
			writeErrorRequest(w, r, stdhttp.StatusNotFound, "metrics_disabled", "metrics are not configured")
			return
		}
		if !s.cfg.MetricsPublic {
			user, _, _, err := s.auth.AuthenticateRequest(r.Context(), r)
			if err != nil || user == nil || !user.Active || user.Role != domain.RoleAdmin {
				writeErrorRequest(w, r, stdhttp.StatusUnauthorized, "unauthorized", "admin authentication required")
				return
			}
		}
		s.metrics.Handler().ServeHTTP(w, r)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/break-glass/login", s.handleBreakGlassLogin)
		r.Post("/auth/request-otp", s.handleRequestOTP)
		r.Post("/auth/verify-otp", s.handleVerifyOTP)
		r.Post("/auth/verify-mfa", s.handleVerifyMFA)
		r.Post("/auth/passkey/begin-login", s.handleBeginPasskeyLogin)
		r.Post("/auth/passkey/finish-login", s.handleFinishPasskeyLogin)
		r.Post("/auth/refresh", s.handleRefreshSession)
		r.Post("/auth/logout", s.handleLogoutSession)
		r.Get("/auth/oidc/start", s.handleOIDCStart)
		r.Get("/auth/oidc/callback", s.handleOIDCCallback)
		r.Get("/auth/config", s.handleAuthConfig)
		r.Post("/nodes/enroll", s.handleEnrollNode)
		r.Post("/nodes/{id}/heartbeat", s.handleHeartbeatNode)
		r.Post("/nodes/{id}/wg-bootstrap", s.handleNodeSelfBootstrap)
		r.Get("/nodes/{id}/tunnel-targets", s.handleNodeTunnelTargets)
		r.Get("/route-auth/service/{id}", s.handleGetRouteAuthService)
		r.Post("/route-auth/pin", s.handleRoutePIN)
		r.Post("/route-auth/request-email-code", s.handleRouteRequestEmailCode)
		r.Post("/route-auth/verify-email-code", s.handleRouteVerifyEmailCode)

		r.Group(func(r chi.Router) {
			r.Use(s.auth.RequireAuth)
			r.Use(s.auth.RequireBootstrapComplete)
			r.Get("/me", s.handleMe)
			r.Post("/me/account-setup", s.handleCompleteAccountSetup)
			r.Post("/me/password", s.handleChangeOwnPassword)
			r.Get("/me/mfa", s.handleGetMyMFAStatus)
			r.Post("/me/mfa/setup", s.handleBeginMyMFASetup)
			r.Post("/me/mfa/enable", s.handleEnableMyMFA)
			r.Post("/me/mfa/disable", s.handleDisableMyMFA)
			r.Post("/me/mfa/recovery-codes", s.handleRegenerateMyRecoveryCodes)
			r.Post("/me/bootstrap/dismiss", s.handleDismissBootstrap)
			r.Get("/sessions", s.handleListMySessions)
			r.Delete("/sessions/{id}", s.handleRevokeMySession)
			r.Post("/sessions/revoke-all", s.handleRevokeAllMySessions)
			r.Post("/route-auth/session-bridge-token", s.handleCreateSessionBridgeToken)

			r.Get("/me/passkeys", s.handleListPasskeys)
			r.Post("/me/passkeys/begin-registration", s.handleBeginPasskeyRegistration)
			r.Post("/me/passkeys/finish-registration", s.handleFinishPasskeyRegistration)
			r.Delete("/me/passkeys/{id}", s.handleDeletePasskey)

			r.Get("/services", s.handleListServices)

			r.Group(func(r chi.Router) {
				r.Use(auth.RequireRole(domain.RoleAdmin))
				r.Get("/nodes", s.handleListNodes)
				r.Get("/nodes/{id}", s.handleGetNode)
				r.Get("/domains", s.handleListDomains)
				r.Get("/domains/{id}", s.handleGetDomain)
				r.Get("/certificates", s.handleListCertificates)
				r.Get("/certificates/{id}", s.handleGetCertificate)
				r.Get("/dns-providers", s.handleListDNSProviders)
				r.Get("/dns-providers/{id}", s.handleGetDNSProvider)
				r.Get("/services/{id}", s.handleGetService)
				r.Get("/services/{id}/last-denials", s.handleListServiceDenials)
				r.Post("/services/{id}/explain", s.handleExplainServiceAccess)
				r.Get("/audit-logs", s.handleListAuditLogs)
				r.Get("/audit-logs/verify", s.handleVerifyAuditChain)
				r.Get("/settings/auth", s.handleGetAuthSettings)
				r.Patch("/settings/auth", s.handleUpdateAuthSettings)
				r.Post("/settings/auth/test-email", s.handleSendTestEmail)
				r.Get("/settings/network", s.handleGetNetworkSettings)
				r.Patch("/settings/network", s.handleUpdateNetworkSettings)
				r.Get("/system/overview", s.handleSystemOverview)
				r.Get("/system/security-alerts", s.handleSecurityAlerts)
				r.Get("/security/rotation/status", s.handleRotationStatus)
				r.Post("/security/rotation/data-key/reencrypt", s.handleReencryptDataKey)
				r.Get("/users", s.handleListUsers)
				r.Get("/users/{id}", s.handleGetUser)
				r.Post("/users", s.handleCreateUser)
				r.Patch("/users/{id}", s.handleUpdateUser)
				r.Delete("/users/{id}", s.handleDeleteUser)
				r.Post("/users/{id}/mfa/reset", s.handleResetUserMFA)
				r.Get("/users/{id}/sessions", s.handleListUserSessions)
				r.Delete("/users/{id}/sessions/{sessionId}", s.handleRevokeUserSession)
				r.Post("/users/{id}/sessions/revoke-all", s.handleRevokeAllUserSessions)
				r.Get("/groups", s.handleListGroups)
				r.Get("/groups/{id}", s.handleGetGroup)
				r.Post("/groups", s.handleCreateGroup)
				r.Patch("/groups/{id}", s.handleUpdateGroup)
				r.Delete("/groups/{id}", s.handleDeleteGroup)
				r.Post("/groups/{id}/members", s.handleAddGroupMember)
				r.Delete("/groups/{id}/members/{userId}", s.handleDeleteGroupMember)
				r.Get("/service-groups", s.handleListServiceGroups)
				r.Get("/service-groups/{id}", s.handleGetServiceGroup)
				r.Post("/service-groups", s.handleCreateServiceGroup)
				r.Patch("/service-groups/{id}", s.handleUpdateServiceGroup)
				r.Delete("/service-groups/{id}", s.handleDeleteServiceGroup)
				r.Post("/service-groups/{id}/services", s.handleAddServiceGroupService)
				r.Delete("/service-groups/{id}/services/{serviceId}", s.handleDeleteServiceGroupService)
				r.Post("/nodes", s.handleCreateNode)
				r.Patch("/nodes/{id}", s.handleUpdateNode)
				r.Delete("/nodes/{id}", s.handleDeleteNode)

				r.Post("/domains", s.handleCreateDomain)
				r.Patch("/domains/{id}", s.handleUpdateDomain)
				r.Delete("/domains/{id}", s.handleDeleteDomain)

				r.Post("/certificates", s.handleCreateCertificate)
				r.Patch("/certificates/{id}", s.handleUpdateCertificate)
				r.Delete("/certificates/{id}", s.handleDeleteCertificate)
				r.Post("/certificates/{id}/retry", s.handleRetryCertificate)
				r.Post("/certificates/{id}/renew", s.handleRenewCertificate)
				r.Post("/certificates/{id}/sync-status", s.handleSyncCertificateStatus)
				r.Post("/certificates/{id}/import-pem", s.handleImportCertificatePEM)
				r.Post("/dns-providers", s.handleCreateDNSProvider)
				r.Patch("/dns-providers/{id}", s.handleUpdateDNSProvider)
				r.Delete("/dns-providers/{id}", s.handleDeleteDNSProvider)
				r.Post("/dns-providers/{id}/test", s.handleTestDNSProvider)

				r.Post("/services", s.handleCreateService)
				r.Patch("/services/{id}", s.handleUpdateService)
				r.Delete("/services/{id}", s.handleDeleteService)
				r.Get("/node-enrollment-tokens", s.handleListNodeEnrollmentTokens)
				r.Post("/node-enrollment-tokens", s.handleCreateNodeEnrollmentToken)
				r.Delete("/node-enrollment-tokens/{id}", s.handleDeleteNodeEnrollmentToken)

				r.Get("/tunnel/settings", s.handleGetTunnelSettings)
				r.Patch("/tunnel/settings", s.handleUpdateTunnelSettings)
				r.Delete("/nodes/{id}/wg-tunnel", s.handleRevokeNodeTunnel)

				r.Get("/clients", s.handleListClients)
				r.Post("/clients", s.handleCreateClient)
				r.Post("/clients/{id}/rotate", s.handleRotateClient)
				r.Delete("/clients/{id}", s.handleDeleteClient)

				r.Post("/services/{id}/magic-link", s.handleIssueMagicLink)

				r.Get("/audit-webhooks", s.handleListAuditWebhooks)
				r.Post("/audit-webhooks", s.handleCreateAuditWebhook)
				r.Patch("/audit-webhooks/{id}", s.handleUpdateAuditWebhook)
				r.Delete("/audit-webhooks/{id}", s.handleDeleteAuditWebhook)
				r.Post("/audit-webhooks/{id}/test", s.handleTestAuditWebhook)
				r.Post("/audit-webhooks/{id}/rotate-secret", s.handleRotateAuditWebhookSecret)

				r.Get("/exposure-reports", s.handleListExposureReports)
				r.Get("/exposure-reports/{id}", s.handleGetExposureReport)
				r.Post("/services/{id}/exposure-scan", s.handleRunExposureScan)
				r.Post("/services/{id}/redeploy", s.handleRedeployService)
			})
		})
	})

	return r
}

func (s *Server) handleLogin(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req loginRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	result, err := s.auth.Login(r.Context(), req.Email, req.Password, s.requestMeta(r))
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "login_failed", "auth", nil, map[string]any{"email": req.Email, "method": "password"})
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeErrorRequest(w, r, stdhttp.StatusUnauthorized, "invalid_credentials", "invalid email or password")
			return
		}
		if errors.Is(err, auth.ErrRateLimited) {
			writeErrorRequest(w, r, stdhttp.StatusTooManyRequests, "rate_limited", "too many login attempts")
			return
		}
		if errors.Is(err, auth.ErrInactiveUser) {
			writeErrorRequest(w, r, stdhttp.StatusForbidden, "inactive_user", "user account is inactive")
			return
		}
		if errors.Is(err, auth.ErrMFASetupRequired) {
			writeErrorRequest(w, r, stdhttp.StatusForbidden, "mfa_setup_required", "admin mfa is required before this account can sign in")
			return
		}
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, &result.User.ID, "login_succeeded", "auth", nil, map[string]any{"email": result.User.Email, "method": "password"})
	s.writeLoginResult(w, r, result)
}

func (s *Server) handleMe(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeErrorRequest(w, r, stdhttp.StatusUnauthorized, "unauthorized", "missing auth context")
		return
	}
	dismissed := false
	if session, ok := auth.SessionFromContext(r.Context()); ok && session != nil {
		dismissed = session.BootstrapDismissed
	}
	response := struct {
		*domain.User
		BootstrapRequired  bool `json:"bootstrap_required"`
		BootstrapDismissed bool `json:"bootstrap_dismissed"`
		MFARequiredForRole bool `json:"mfa_required_for_role"`
	}{
		User:               user,
		BootstrapRequired:  s.auth.BootstrapRequired(r.Context(), user),
		BootstrapDismissed: dismissed,
		MFARequiredForRole: s.auth.MFARequiredForUser(r.Context(), user),
	}
	writeJSON(w, stdhttp.StatusOK, response)
}

func (s *Server) handleDismissBootstrap(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	session, ok := auth.SessionFromContext(r.Context())
	if !ok || session == nil {
		writeErrorRequest(w, r, stdhttp.StatusUnauthorized, "unauthorized", "session required")
		return
	}
	user, _ := auth.UserFromContext(r.Context())
	if user == nil {
		writeErrorRequest(w, r, stdhttp.StatusUnauthorized, "unauthorized", "missing auth context")
		return
	}
	if !user.MustChangePassword && s.auth.MFARequiredForUser(r.Context(), user) && !user.MFAEnabled && !s.auth.UserHasPasskey(r.Context(), user.ID) {
		writeErrorRequest(w, r, stdhttp.StatusForbidden, "mfa_required", "mfa enrollment is required and cannot be dismissed")
		return
	}
	if err := s.sessions.MarkBootstrapDismissed(r.Context(), session.ID, time.Now().UTC()); err != nil {
		s.internalError(w, err)
		return
	}
	session.BootstrapDismissed = true
	_ = s.audit.Log(r.Context(), &user.ID, "bootstrap_dismissed", "user", &user.ID, nil)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"bootstrap_dismissed": true})
}

func (s *Server) decodeAndValidate(w stdhttp.ResponseWriter, r *stdhttp.Request, target any) bool {
	if err := decodeStrictJSON(r, target); err != nil {
		writeErrorRequest(w, r, stdhttp.StatusBadRequest, "invalid_json", "request body is not valid JSON")
		return false
	}
	if err := s.validate.Struct(target); err != nil {
		writeErrorRequest(w, r, stdhttp.StatusBadRequest, "validation_error", formatValidationError(err))
		return false
	}
	return true
}

func formatValidationError(err error) string {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) || len(verrs) == 0 {
		return "request validation failed"
	}
	fields := make([]string, 0, len(verrs))
	for _, fe := range verrs {
		fields = append(fields, fe.Field())
	}
	return "invalid or missing fields: " + strings.Join(fields, ", ")
}

func (s *Server) parseIDParam(w stdhttp.ResponseWriter, r *stdhttp.Request, key string) (uint, bool) {
	rawID := chi.URLParam(r, key)
	id, err := strconv.ParseUint(strings.TrimSpace(rawID), 10, strconv.IntSize)
	if err != nil {
		writeErrorRequest(w, r, stdhttp.StatusBadRequest, "invalid_id", "resource id must be a positive integer")
		return 0, false
	}
	return uint(id), true
}

func (s *Server) handleStoreError(w stdhttp.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, stdhttp.StatusNotFound, "not_found", "resource not found")
		return
	}
	s.internalError(w, err)
}

func (s *Server) internalError(w stdhttp.ResponseWriter, err error) {
	s.logger.Error("request failed", "error", err)
	writeError(w, stdhttp.StatusInternalServerError, "internal_error", "an internal error occurred")
}

func (s *Server) pingDB(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *Server) loadNode(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.Node, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.nodes.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func (s *Server) handleAuthConfig(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	writeJSON(w, stdhttp.StatusOK, s.auth.CurrentAuthConfig(r.Context()))
}

func (s *Server) requestMeta(r *stdhttp.Request) auth.RequestMetadata {
	return auth.RequestMetadata{
		RemoteAddr: s.clientIPForRequest(r),
		UserAgent:  r.UserAgent(),
	}
}

func (s *Server) loadUser(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.User, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.users.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func (s *Server) loadDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.Domain, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.domains.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func (s *Server) loadCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.Certificate, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.certificates.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func (s *Server) loadDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.DNSProvider, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.dnsProviders.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func (s *Server) loadService(w stdhttp.ResponseWriter, r *stdhttp.Request) (*domain.Service, bool) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	item, err := s.services.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return nil, false
	}
	return item, true
}

func normalizeHostname(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *Server) currentUserID(r *stdhttp.Request) *uint {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		return nil
	}
	return &user.ID
}

func (s *Server) evaluateNodeStatus(node *domain.Node) {
	if node.LastHeartbeatAt == nil || s.cfg.NodeOfflineAfter <= 0 {
		return
	}
	if time.Since(*node.LastHeartbeatAt) > s.cfg.NodeOfflineAfter {
		node.Status = domain.NodeStatusOffline
		return
	}
	node.Status = domain.NodeStatusOnline
}

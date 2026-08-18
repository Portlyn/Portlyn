package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"portlyn/internal/audit"
	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/observability"
)

type Manager struct {
	routes                    RoutingStore
	services                  ServiceDeploymentStore
	cache                     ConfigCache
	bus                       ConfigBus
	auth                      *auth.Service
	audit                     *audit.Logger
	logger                    *slog.Logger
	transport                 *http.Transport
	revision                  uint64
	localCache                *ttlLRU[string, []Route]
	startOnce                 sync.Once
	metrics                   *observability.Metrics
	breakersMu                sync.Mutex
	breakers                  map[string]*targetCircuitState
	adminHost                 string
	trustedProxyCIDRs         []string
	bootstrapAdminEnabled     bool
	bootstrapAdminAllowRemote bool
	adminUI                   http.Handler
	adminAPI                  http.Handler
	tunnelTransport           *http.Transport
	tunnelDialer              TunnelDialer
	countryLookup             CountryLookup
	reputation                ReputationBlocklist
	geoIPFailOpen             bool
	crowdSecFailOpen          bool
}

type RuntimeRoute struct {
	ServiceID          uint                 `json:"service_id"`
	ServiceName        string               `json:"service_name"`
	Host               string               `json:"host"`
	Path               string               `json:"path"`
	TargetURL          string               `json:"target_url"`
	DomainName         string               `json:"domain_name"`
	AccessMode         string               `json:"access_mode"`
	AccessMethod       string               `json:"access_method"`
	InheritedFromGroup *domain.ServiceGroup `json:"inherited_from_group,omitempty"`
	DeploymentRevision uint64               `json:"deployment_revision"`
	LastDeployedAt     *time.Time           `json:"last_deployed_at,omitempty"`
	UseGroupPolicy     bool                 `json:"use_group_policy"`
}

type Route struct {
	ServiceID             uint
	ServiceName           string
	Host                  string
	Path                  string
	TargetURL             string
	TLSMode               string
	Service               domain.Service
	EffectivePolicy       domain.AccessPolicy
	EffectiveMethod       string
	EffectiveMethodConfig domain.JSONObject
	InheritedFromGroup    *domain.ServiceGroup
	AllowPrefixes         []netip.Prefix
	BlockPrefixes         []netip.Prefix
	AllowedCountries      []string
	BlockedCountries      []string
	CompiledWindows       []compiledAccessWindow
	DeploymentRevision    uint64
	ReverseProxyHandler   http.Handler
}

type CountryLookup interface {
	CountryISO(ip net.IP) string
	Available() bool
}

type ReputationBlocklist interface {
	IsBlocked(ip net.IP) (bool, string)
	Healthy() bool
	Enabled() bool
}

type compiledAccessWindow struct {
	Name         string
	Weekdays     map[time.Weekday]struct{}
	StartMinutes int
	EndMinutes   int
	Location     *time.Location
}

type ManagerOptions struct {
	LocalCacheTTL               time.Duration
	LocalCacheCapacity          int
	AdminHost                   string
	TrustedProxyCIDRs           []string
	BootstrapAdminEnabled       bool
	BootstrapAdminAllowRemote   bool
	AdminUITargetURL            string
	AdminAPITargetURL           string
	EmbeddedAdminUI             http.Handler
	EmbeddedAdminUIScriptHashes []string
	TunnelDialer                TunnelDialer
	CountryLookup               CountryLookup
	Reputation                  ReputationBlocklist
	ServiceDeploymentStore      ServiceDeploymentStore
	GeoIPFailOpen               bool
	CrowdSecFailOpen            bool
	BlockPrivateUpstreams       bool
}

type TunnelDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Started() bool
}

type targetCircuitState struct {
	consecutiveFailures int
	degradedUntil       time.Time
	lastError           string
}

type ServiceDeploymentStore interface {
	GetByID(ctx context.Context, id uint) (*domain.Service, error)
	Update(ctx context.Context, item *domain.Service) error
}

func NewManager(routingStore RoutingStore, cache ConfigCache, bus ConfigBus, authService *auth.Service, auditLogger *audit.Logger, logger *slog.Logger, metrics *observability.Metrics, options ManagerOptions) *Manager {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   makeDialControl(options.BlockPrivateUpstreams),
		}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if options.LocalCacheTTL <= 0 {
		options.LocalCacheTTL = 5 * time.Second
	}
	if options.LocalCacheCapacity <= 0 {
		options.LocalCacheCapacity = 1024
	}

	var adminUIHandler http.Handler
	if options.EmbeddedAdminUI != nil {
		adminUIHandler = withStaticSecurityHeaders(options.EmbeddedAdminUI, options.EmbeddedAdminUIScriptHashes)
	} else if strings.TrimSpace(options.AdminUITargetURL) != "" {
		if target, err := url.Parse(strings.TrimSpace(options.AdminUITargetURL)); err == nil {
			adminUIHandler = reverseProxyForTarget(target, transport, "/", directProto, nil, false)
		}
	}

	var adminAPIHandler http.Handler
	if strings.TrimSpace(options.AdminAPITargetURL) != "" {
		if target, err := url.Parse(strings.TrimSpace(options.AdminAPITargetURL)); err == nil {
			adminAPIHandler = reverseProxyForTarget(target, transport, "/", directProto, nil, false)
		}
	}

	var tunnelTransport *http.Transport
	if options.TunnelDialer != nil {
		dialer := options.TunnelDialer
		tunnelTransport = &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}

	return &Manager{
		routes:                    routingStore,
		services:                  options.ServiceDeploymentStore,
		cache:                     cache,
		bus:                       bus,
		auth:                      authService,
		audit:                     auditLogger,
		logger:                    logger,
		transport:                 transport,
		localCache:                newTTLLRU[string, []Route](options.LocalCacheCapacity, options.LocalCacheTTL),
		metrics:                   metrics,
		breakers:                  make(map[string]*targetCircuitState),
		adminHost:                 normalizeHost(options.AdminHost),
		trustedProxyCIDRs:         append([]string(nil), options.TrustedProxyCIDRs...),
		bootstrapAdminEnabled:     options.BootstrapAdminEnabled,
		bootstrapAdminAllowRemote: options.BootstrapAdminAllowRemote,
		adminUI:                   adminUIHandler,
		adminAPI:                  adminAPIHandler,
		tunnelTransport:           tunnelTransport,
		tunnelDialer:              options.TunnelDialer,
		countryLookup:             options.CountryLookup,
		reputation:                options.Reputation,
		geoIPFailOpen:             options.GeoIPFailOpen,
		crowdSecFailOpen:          options.CrowdSecFailOpen,
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		if m.bus == nil {
			return
		}
		events := m.bus.SubscribeRouteChanged(ctx)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-events:
					if !ok {
						return
					}
					m.localCache.Remove(normalizeHost(event.Host))
				}
			}
		}()
	})
}

func (m *Manager) SyncAllServicesFromDB(context.Context) error {
	m.localCache.Purge()
	return nil
}

func (m *Manager) InvalidateHost(ctx context.Context, host string) error {
	started := time.Now()
	host = normalizeHost(host)
	m.localCache.Remove(host)
	if m.cache != nil {
		if err := m.cache.InvalidateHost(ctx, host); err != nil {
			return err
		}
	}
	if m.bus != nil {
		if err := m.bus.PublishRouteChanged(ctx, host); err != nil {
			return err
		}
	}
	if m.metrics != nil {
		m.metrics.ObserveConfigPropagation("invalidate_host", time.Since(started), false)
	}
	return nil
}

func (m *Manager) ApplyServiceChange(ctx context.Context, serviceID uint) (*domain.Service, error) {
	config, err := m.routes.GetRouteByID(ctx, fmt.Sprintf("%d", serviceID))
	if err != nil {
		return nil, err
	}
	if m.services != nil {
		service, err := m.services.GetByID(ctx, serviceID)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		service.LastDeployedAt = &now
		service.DeploymentRevision++
		if err := m.services.Update(ctx, service); err != nil {
			return nil, err
		}
	}
	if err := m.InvalidateHost(ctx, config.Host); err != nil {
		return nil, err
	}
	serviceCopy := config.Service
	if m.services != nil {
		if service, err := m.services.GetByID(ctx, serviceID); err == nil {
			serviceCopy = *service
		}
	}
	return &serviceCopy, nil
}

func (m *Manager) RemoveService(ctx context.Context, serviceID uint) error {
	config, err := m.routes.GetRouteByID(ctx, fmt.Sprintf("%d", serviceID))
	if err != nil {
		return nil
	}
	return m.InvalidateHost(ctx, config.Host)
}

func (m *Manager) RuntimeRoutes() []RuntimeRoute {
	configs, err := m.routes.ListRoutes(context.Background(), RouteFilter{})
	if err != nil {
		return nil
	}

	out := make([]RuntimeRoute, 0, len(configs))
	for _, route := range configs {
		item := RuntimeRoute{
			ServiceID:          route.ServiceID,
			ServiceName:        route.ServiceName,
			Host:               normalizeHost(route.Host),
			Path:               normalizePath(route.Path),
			TargetURL:          route.TargetURL,
			DomainName:         route.Service.Domain.Name,
			AccessMode:         route.EffectivePolicy.AccessMode,
			AccessMethod:       route.EffectiveMethod,
			DeploymentRevision: route.DeploymentRevision,
			LastDeployedAt:     route.LastDeployedAt,
			UseGroupPolicy:     route.Service.UseGroupPolicy,
		}
		if route.InheritedFromGroup != nil {
			copyGroup := *route.InheritedFromGroup
			item.InheritedFromGroup = &copyGroup
		}
		out = append(out, item)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Path < out[j].Path
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func (m *Manager) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		writer := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		var matchedRoute *Route
		var user *domain.User
		outcome := "proxied"
		reason := "upstream"

		defer func() {
			m.logAccess(r, writer, startedAt, matchedRoute, user, outcome, reason)
		}()

		if m.handleSessionBridge(writer, r) {
			outcome = "session_bridge"
			reason = "session_bridge"
			return
		}
		if m.handleRouteAccessBridge(writer, r) {
			outcome = "route_access_bridge"
			reason = "route_access_bridge"
			return
		}
		if m.handleMagicLink(writer, r) {
			outcome = "magic_link"
			reason = "magic_link"
			return
		}

		host := normalizeHost(r.Host)
		path := normalizePath(r.URL.Path)

		if m.allowAdminHost(host, r) {
			if m.handleAdminHost(writer, r, path) {
				outcome = "admin"
				reason = "admin_host"
				return
			}
		}

		route, ok := m.matchRoute(r.Context(), host, path)
		if !ok {
			outcome = "not_found"
			reason = "route_miss"
			http.NotFound(writer, r)
			return
		}
		matchedRoute = &route
		sanitizePortlynIdentityHeaders(r.Header)

		if ok := m.enforceNetworkRules(writer, r, route); !ok {
			outcome = "denied"
			reason = "network_policy"
			return
		}

		var groupIDs []uint
		user, groupIDs, ok = m.authorizeRequest(writer, r, route)
		if !ok {
			outcome = "denied"
			reason = "authz"
			return
		}

		if ok := m.enforceAccessWindows(writer, route); !ok {
			outcome = "denied"
			reason = "access_window"
			return
		}

		if route.EffectivePolicy.AccessMode == domain.AccessModeRestricted {
			if !isAllowedByRestrictedPolicy(user, groupIDs, route.EffectivePolicy) {
				outcome = "denied"
				reason = "restricted_policy"
				if expectsTokenAuth(r) {
					writeProxyError(writer, http.StatusForbidden, "forbidden", "restricted service policy denied access")
				} else {
					m.redirectToRouteForbidden(writer, r, route)
				}
				return
			}
		}

		if user != nil {
			r.Header.Set("X-Portlyn-User-Email", user.Email)
			r.Header.Set("X-Portlyn-User-Role", user.Role)
			r.Header.Set("X-Portlyn-User-ID", fmt.Sprintf("%d", user.ID))
		}
		if fingerprint := clientCertSHA256(r); fingerprint != "" {
			r.Header.Set("X-Portlyn-Client-Cert-SHA256", fingerprint)
		} else {
			r.Header.Del("X-Portlyn-Client-Cert-SHA256")
		}
		if degraded, degradedReason := m.isTargetDegraded(route.TargetURL); degraded {
			outcome = "degraded"
			reason = degradedReason
			writeProxyError(writer, http.StatusServiceUnavailable, "target_degraded", "target temporarily degraded after repeated upstream failures")
			return
		}
		route.ReverseProxyHandler.ServeHTTP(writer, r)
	})
}

func (m *Manager) isAdminHost(host string) bool {
	normalized := normalizeHost(host)
	if m.adminHost != "" && normalized == m.adminHost {
		return true
	}
	return m.bootstrapAdminEnabled && isBootstrapAdminHost(normalized)
}

func (m *Manager) allowAdminHost(host string, r *http.Request) bool {
	normalized := normalizeHost(host)
	if m.adminHost != "" && normalized == m.adminHost {
		return true
	}
	if !m.bootstrapAdminEnabled || !isBootstrapAdminHost(normalized) {
		return false
	}
	if m.bootstrapAdminAllowRemote {
		return true
	}
	return isLocalRequestSource(r)
}

func (m *Manager) handleAdminHost(w http.ResponseWriter, r *http.Request, path string) bool {
	if strings.HasPrefix(path, "/api/") || path == "/livez" || path == "/readyz" || path == "/healthz" || path == "/metrics" || path == "/install.sh" {
		if m.adminAPI != nil {
			m.adminAPI.ServeHTTP(w, r)
			return true
		}
		return false
	}

	if m.adminUI != nil {
		m.adminUI.ServeHTTP(w, r)
		return true
	}
	return false
}

func (m *Manager) handleSessionBridge(w http.ResponseWriter, r *http.Request) bool {
	if normalizePath(r.URL.Path) != "/_portlyn/session-bridge" {
		return false
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeProxyError(w, http.StatusBadRequest, "invalid_token", "missing session bridge token")
		return true
	}
	claims, err := m.auth.ParseSessionBridgeToken(token)
	if err != nil {
		writeProxyError(w, http.StatusUnauthorized, "invalid_token", "invalid session bridge token")
		return true
	}
	if normalizeHost(claims.Host) != normalizeHost(r.Host) {
		writeProxyError(w, http.StatusForbidden, "forbidden", "session bridge host mismatch")
		return true
	}
	if !m.auth.ConsumeBridgeToken(r.Context(), claims.ID) {
		writeProxyError(w, http.StatusUnauthorized, "invalid_token", "session bridge token already used")
		return true
	}
	m.auth.SetSessionCookieForHost(w, claims.AccessToken, normalizeHost(r.Host), m.forwardedProto(r) == "https")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusFound)
	return true
}

func (m *Manager) logAccess(r *http.Request, writer middleware.WrapResponseWriter, startedAt time.Time, route *Route, user *domain.User, outcome, reason string) {
	if writer == nil {
		return
	}

	statusCode := writer.Status()
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	latency := time.Since(startedAt)

	requestID := middleware.GetReqID(r.Context())
	remoteAddr := m.authoritativeClientIP(r)
	if remoteAddr == "" {
		remoteAddr = r.RemoteAddr
	}
	args := []any{
		"component", "proxy",
		"kind", "proxy_access",
		"request_id", requestID,
		"trace_id", requestID,
		"method", r.Method,
		"host", normalizeHost(r.Host),
		"path", r.URL.Path,
		"status", statusCode,
		"latency_ms", latency.Milliseconds(),
		"bytes", writer.BytesWritten(),
		"outcome", outcome,
		"reason", reason,
		"remote_addr", remoteAddr,
		"user_agent", r.UserAgent(),
	}

	var userID *uint
	var resourceID *uint
	resourceType := "proxy_request"
	action := "proxy_access"
	details := map[string]any{
		"outcome": outcome,
		"reason":  reason,
		"bytes":   writer.BytesWritten(),
	}

	if route != nil {
		args = append(args,
			"service_id", route.ServiceID,
			"service_name", route.ServiceName,
			"target_host", targetHostForLogs(route.TargetURL),
			"route_host", route.Host,
			"route_path", route.Path,
			"access_mode", route.EffectivePolicy.AccessMode,
			"access_method", route.EffectiveMethod,
			"deployment_revision", route.DeploymentRevision,
		)
		resourceID = &route.ServiceID
		resourceType = "service"
		details["service_name"] = route.ServiceName
		details["target_host"] = targetHostForLogs(route.TargetURL)
		details["route_path"] = route.Path
	}
	if user != nil {
		userID = &user.ID
		args = append(args, "user_id", user.ID, "user_role", user.Role)
		details["user_id"] = user.ID
	}
	if m.logger != nil {
		m.logger.Info("proxy request completed", args...)
	}
	if m.metrics != nil {
		serviceName := "unknown"
		if route != nil && strings.TrimSpace(route.ServiceName) != "" {
			serviceName = route.ServiceName
		}
		m.metrics.ObserveProxyRequest(serviceName, outcome, statusCode, latency)
	}
	if m.audit != nil && outcome == "denied" {
		_ = m.audit.LogHTTPAccess(r.Context(), audit.HTTPAccessEvent{
			Request:      r,
			UserID:       userID,
			Action:       action,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			StatusCode:   statusCode,
			Latency:      latency,
			Details:      details,
		})
	}
}

// Without hashes the policy falls back to 'unsafe-inline' rather than serving a
// UI that cannot boot.
func withStaticSecurityHeaders(next http.Handler, scriptHashes []string) http.Handler {
	scriptSrc := "script-src 'self' 'unsafe-inline'"
	if len(scriptHashes) > 0 {
		scriptSrc = "script-src 'self' " + strings.Join(scriptHashes, " ")
	}
	csp := "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; " + scriptSrc + "; connect-src 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

type retryTransport struct {
	base    http.RoundTripper
	retries int
	backoff time.Duration
}

func isBootstrapAdminHost(host string) bool {
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return false
}

func isLocalRequestSource(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	return false
}

func normalizePath(value string) string {
	path := strings.TrimSpace(value)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func (m *Manager) forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if m.requestFromTrustedProxy(r) {
		if proto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			return strings.ToLower(proto)
		}
	}
	return "http"
}

func (m *Manager) requestURL(r *http.Request) string {
	return m.forwardedProto(r) + "://" + r.Host + r.URL.RequestURI()
}

func (m *Manager) requestFromTrustedProxy(r *http.Request) bool {
	if r == nil || len(m.trustedProxyCIDRs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addrInTrustedCIDRs(addr, m.trustedProxyCIDRs)
}

func firstForwardedValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}

func addrInTrustedCIDRs(addr netip.Addr, cidrs []string) bool {
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func clientIPFromForwardedChain(header string, trustedCIDRs []string) (netip.Addr, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if !addrInTrustedCIDRs(addr, trustedCIDRs) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func expectsTokenAuth(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("Authorization")) != ""
}

func compileCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func compileAccessWindows(values []domain.AccessWindow) ([]compiledAccessWindow, error) {
	compiled := make([]compiledAccessWindow, 0, len(values))
	for _, value := range values {
		start, err := time.Parse("15:04", value.StartTime)
		if err != nil {
			return nil, err
		}
		end, err := time.Parse("15:04", value.EndTime)
		if err != nil {
			return nil, err
		}
		location := time.UTC
		if strings.TrimSpace(value.Timezone) != "" {
			loaded, err := time.LoadLocation(value.Timezone)
			if err != nil {
				return nil, err
			}
			location = loaded
		}
		weekdays := make(map[time.Weekday]struct{}, len(value.DaysOfWeek))
		for _, day := range value.DaysOfWeek {
			if weekday, ok := parseWeekday(day); ok {
				weekdays[weekday] = struct{}{}
			}
		}
		compiled = append(compiled, compiledAccessWindow{
			Name:         value.Name,
			Weekdays:     weekdays,
			StartMinutes: start.Hour()*60 + start.Minute(),
			EndMinutes:   end.Hour()*60 + end.Minute(),
			Location:     location,
		})
	}
	return compiled, nil
}

func parseWeekday(value string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sunday":
		return time.Sunday, true
	case "monday":
		return time.Monday, true
	case "tuesday":
		return time.Tuesday, true
	case "wednesday":
		return time.Wednesday, true
	case "thursday":
		return time.Thursday, true
	case "friday":
		return time.Friday, true
	case "saturday":
		return time.Saturday, true
	default:
		return time.Sunday, false
	}
}

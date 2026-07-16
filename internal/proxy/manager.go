package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"portlyn/internal/audit"
	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/netguard"
	"portlyn/internal/observability"
)

func makeDialControl(blockPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("unresolved dial address %q", host)
		}
		blocked := netguard.IsBlockedAddr(addr)
		if blockPrivate {
			blocked = netguard.IsBlockedAddrStrict(addr)
		}
		if blocked {
			return fmt.Errorf("connection to blocked address %s denied", host)
		}
		return nil
	}
}

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
	LocalCacheTTL             time.Duration
	LocalCacheCapacity        int
	AdminHost                 string
	TrustedProxyCIDRs         []string
	BootstrapAdminEnabled     bool
	BootstrapAdminAllowRemote bool
	AdminUITargetURL          string
	AdminAPITargetURL         string
	EmbeddedAdminUI           http.Handler
	TunnelDialer              TunnelDialer
	CountryLookup             CountryLookup
	Reputation                ReputationBlocklist
	ServiceDeploymentStore    ServiceDeploymentStore
	GeoIPFailOpen             bool
	CrowdSecFailOpen          bool
	BlockPrivateUpstreams     bool
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
		adminUIHandler = withStaticSecurityHeaders(options.EmbeddedAdminUI)
	} else if strings.TrimSpace(options.AdminUITargetURL) != "" {
		if target, err := url.Parse(strings.TrimSpace(options.AdminUITargetURL)); err == nil {
			adminUIHandler = reverseProxyForTarget(target, transport, "/", directProto, nil)
		}
	}

	var adminAPIHandler http.Handler
	if strings.TrimSpace(options.AdminAPITargetURL) != "" {
		if target, err := url.Parse(strings.TrimSpace(options.AdminAPITargetURL)); err == nil {
			adminAPIHandler = reverseProxyForTarget(target, transport, "/", directProto, nil)
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

func clientCertSHA256(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

func sanitizePortlynIdentityHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Del("X-Portlyn-User-Email")
	headers.Del("X-Portlyn-User-Role")
	headers.Del("X-Portlyn-User-ID")
	headers.Del("X-Portlyn-Client-Cert-SHA256")
}

func (m *Manager) matchRoute(ctx context.Context, host, path string) (Route, bool) {
	routes, err := m.resolveRoutesForHost(ctx, host)
	if err != nil {
		return Route{}, false
	}
	for _, route := range routes {
		if matchesPath(route.Path, path) {
			return route, true
		}
	}
	return Route{}, false
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

func (m *Manager) resolveRoutesForHost(ctx context.Context, host string) ([]Route, error) {
	host = normalizeHost(host)

	if cached, ok := m.localCache.Get(host); ok {
		if m.metrics != nil {
			m.metrics.ObserveConfigPropagation("local_cache", 0, true)
		}
		return cached, nil
	}

	var (
		configs []RouteConfig
		ok      bool
		err     error
	)
	if m.cache != nil {
		configs, ok, err = m.cache.GetRoutesForHost(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	if !ok {
		started := time.Now()
		configs, err = m.routes.GetRoutesForHost(ctx, host)
		if err != nil {
			return nil, err
		}
		if m.cache != nil {
			_ = m.cache.SetRoutesForHost(ctx, host, configs, 30*time.Second)
		}
		if m.metrics != nil {
			m.metrics.ObserveConfigPropagation("routing_store", time.Since(started), false)
		}
	} else if m.metrics != nil {
		m.metrics.ObserveConfigPropagation("shared_cache", 0, true)
	}

	compiled := make([]Route, 0, len(configs))
	for _, config := range configs {
		route, err := m.routeFromConfig(config)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, route)
	}

	sort.Slice(compiled, func(i, j int) bool {
		return len(compiled[i].Path) > len(compiled[j].Path)
	})
	m.localCache.Add(host, compiled)
	return compiled, nil
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

func (m *Manager) routeFromConfig(config RouteConfig) (Route, error) {
	targetURL, viaNode := rewriteTargetForTunnel(config.TargetURL, config.Service)
	target, err := url.Parse(targetURL)
	if err != nil {
		return Route{}, fmt.Errorf("parse target url for service %d: %w", config.ServiceID, err)
	}
	_ = viaNode

	allowPrefixes, err := compileCIDRs(config.AllowCIDRs)
	if err != nil {
		return Route{}, fmt.Errorf("compile allowlist for service %d: %w", config.ServiceID, err)
	}
	blockPrefixes, err := compileCIDRs(config.BlockCIDRs)
	if err != nil {
		return Route{}, fmt.Errorf("compile blocklist for service %d: %w", config.ServiceID, err)
	}
	compiledWindows, err := compileAccessWindows(config.AccessWindows)
	if err != nil {
		return Route{}, fmt.Errorf("compile access windows for service %d: %w", config.ServiceID, err)
	}
	revision := config.DeploymentRevision
	if revision == 0 {
		revision = atomic.AddUint64(&m.revision, 1)
	}

	routePath := normalizePath(config.Path)
	effectiveTargetURL := targetURL
	chosenTransport := m.transport
	if viaNode && m.tunnelTransport != nil && m.tunnelDialer != nil && m.tunnelDialer.Started() {
		chosenTransport = m.tunnelTransport
	}
	proxy := reverseProxyForTarget(target, chosenTransport, routePath, m.forwardedProto, m.authoritativeClientIP)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		m.recordTargetFailure(config.TargetURL, err)
		writeProxyError(w, http.StatusBadGateway, "upstream_unavailable", "upstream target request failed")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= http.StatusBadGateway {
			m.recordTargetFailure(config.TargetURL, fmt.Errorf("returned status %d", resp.StatusCode))
			return nil
		}
		m.recordTargetSuccess(config.TargetURL)
		return nil
	}

	return Route{
		ServiceID:             config.ServiceID,
		ServiceName:           config.ServiceName,
		Host:                  normalizeHost(config.Host),
		Path:                  routePath,
		TargetURL:             effectiveTargetURL,
		TLSMode:               config.TLSMode,
		Service:               config.Service,
		EffectivePolicy:       normalizedPolicy(config.EffectivePolicy, config.Service.AuthPolicy),
		EffectiveMethod:       normalizedAccessMethod(config.EffectiveMethod),
		EffectiveMethodConfig: cloneJSONObject(config.EffectiveMethodConfig),
		InheritedFromGroup:    config.InheritedFromGroup,
		AllowPrefixes:         allowPrefixes,
		BlockPrefixes:         blockPrefixes,
		AllowedCountries:      append([]string{}, config.AllowedCountries...),
		BlockedCountries:      append([]string{}, config.BlockedCountries...),
		CompiledWindows:       compiledWindows,
		DeploymentRevision:    revision,
		ReverseProxyHandler:   proxy,
	}, nil
}

func reverseProxyForTarget(target *url.URL, transport *http.Transport, routePath string, protoForRequest func(*http.Request) string, clientIPForRequest func(*http.Request) string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &retryTransport{base: transport, retries: 1, backoff: 100 * time.Millisecond}
	originalDirector := proxy.Director
	normalizedRoutePath := normalizePath(routePath)

	proxy.Director = func(req *http.Request) {
		incomingHost := req.Host
		incomingProto := directProto(req)
		if protoForRequest != nil {
			incomingProto = protoForRequest(req)
		}
		var authoritativeClientIP string
		if clientIPForRequest != nil {
			authoritativeClientIP = clientIPForRequest(req)
		}
		originalURI := req.URL.RequestURI()
		req.URL.Path = stripRoutePrefix(normalizedRoutePath, req.URL.Path)
		if req.URL.RawPath != "" {
			req.URL.RawPath = stripRoutePrefix(normalizedRoutePath, req.URL.RawPath)
		}
		if authoritativeClientIP != "" {
			req.Header.Set("X-Forwarded-For", authoritativeClientIP)
		} else {
			req.Header.Del("X-Forwarded-For")
		}
		originalDirector(req)
		req.Host = target.Host
		if authoritativeClientIP != "" {
			req.Header.Set("X-Real-Ip", authoritativeClientIP)
		} else {
			req.Header.Del("X-Real-Ip")
		}
		req.Header.Set("X-Forwarded-Host", normalizeHost(incomingHost))
		req.Header.Set("X-Forwarded-Proto", incomingProto)
		req.Header.Set("X-Forwarded-Uri", originalURI)
		if normalizedRoutePath != "/" {
			req.Header.Set("X-Forwarded-Prefix", normalizedRoutePath)
		} else {
			req.Header.Del("X-Forwarded-Prefix")
		}
	}

	return proxy
}

func directProto(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	return "http"
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
		"remote_addr", r.RemoteAddr,
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
	if m.audit != nil {
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

func targetHostForLogs(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
}

func (m *Manager) authorizeRequest(w http.ResponseWriter, r *http.Request, route Route) (*domain.User, []uint, bool) {
	user, groupIDs, ok := m.enforceAccessMethod(w, r, route)
	if !ok {
		return nil, nil, false
	}
	method := normalizedAccessMethod(route.EffectiveMethod)
	methodIsSelfSufficient := method == domain.AccessMethodPIN || method == domain.AccessMethodEmailCode
	switch route.EffectivePolicy.AccessMode {
	case "", domain.AccessModePublic:
		return user, groupIDs, true
	case domain.AccessModeAuthenticated, domain.AccessModeRestricted:
		if user == nil && !methodIsSelfSufficient {
			var status int
			var authOK bool
			user, groupIDs, status, authOK = m.authenticateProxyRequest(r)
			if !authOK {
				if method == domain.AccessMethodSession && expectsTokenAuth(r) {
					writeProxyError(w, status, statusCode(status), statusMessage(status))
				} else {
					m.redirectToRouteLogin(w, r, route)
				}
				return nil, nil, false
			}
		}
		return user, groupIDs, true
	default:
		writeProxyError(w, http.StatusForbidden, "forbidden", "unsupported access policy")
		return nil, nil, false
	}
}

func (m *Manager) enforceAccessMethod(w http.ResponseWriter, r *http.Request, route Route) (*domain.User, []uint, bool) {
	switch normalizedAccessMethod(route.EffectiveMethod) {
	case domain.AccessMethodSession:
		return nil, nil, true
	case domain.AccessMethodOIDCOnly:
		user, groupIDs, status, ok := m.authenticateProxyRequest(r)
		if !ok || user == nil || user.AuthProvider != domain.AuthProviderOIDC || !user.Active {
			if ok && user != nil && user.AuthProvider != domain.AuthProviderOIDC {
				status = http.StatusUnauthorized
			}
			_ = status
			m.redirectToRouteLogin(w, r, route)
			return nil, nil, false
		}
		return user, groupIDs, true
	case domain.AccessMethodPIN, domain.AccessMethodEmailCode:
		claims, err := m.auth.RouteAccessCookieClaims(r, route.ServiceID)
		if err != nil || claims == nil || claims.Method != normalizedAccessMethod(route.EffectiveMethod) {
			m.redirectToRouteLogin(w, r, route)
			return nil, nil, false
		}
		if normalizedAccessMethod(route.EffectiveMethod) == domain.AccessMethodEmailCode && !routeEmailAllowed(claims.Email, route.EffectiveMethodConfig) {
			m.redirectToRouteLogin(w, r, route)
			return nil, nil, false
		}
		return nil, nil, true
	default:
		writeProxyError(w, http.StatusForbidden, "forbidden", "unsupported access method")
		return nil, nil, false
	}
}

func withStaticSecurityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'"
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

func routeEmailAllowed(email string, config domain.JSONObject) bool {
	normalized := strings.ToLower(strings.TrimSpace(email))
	allowedEmails := make([]string, 0)
	switch raw := config["allowed_emails"].(type) {
	case []any:
		for _, entry := range raw {
			if s, ok := entry.(string); ok {
				allowedEmails = append(allowedEmails, strings.ToLower(strings.TrimSpace(s)))
			}
		}
	case []string:
		for _, entry := range raw {
			allowedEmails = append(allowedEmails, strings.ToLower(strings.TrimSpace(entry)))
		}
	}
	if len(allowedEmails) > 0 {
		for _, allowed := range allowedEmails {
			if allowed != "" && allowed == normalized {
				return true
			}
		}
		return false
	}
	if raw, ok := config["allowed_email_domain"].(string); ok {
		allowed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "@")
		if allowed == "" {
			return true
		}
		parts := strings.Split(normalized, "@")
		return len(parts) == 2 && parts[1] == allowed
	}
	return true
}

func (m *Manager) authenticateProxyRequest(r *http.Request) (*domain.User, []uint, int, bool) {
	user, groupIDs, session, err := m.auth.AuthenticateRequest(r.Context(), r)
	if err != nil {
		return nil, nil, http.StatusUnauthorized, false
	}
	if !m.auth.BootstrapAccessAllowed(r.Context(), user, session) {
		return nil, nil, http.StatusForbidden, false
	}
	return user, groupIDs, http.StatusOK, true
}

func (m *Manager) redirectToRouteLogin(w http.ResponseWriter, r *http.Request, route Route) {
	location := m.auth.BuildRouteLoginURL(r.Context(), route.ServiceID, m.requestURL(r))
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func (m *Manager) redirectToRouteForbidden(w http.ResponseWriter, r *http.Request, route Route) {
	location := m.auth.BuildRouteForbiddenURL(r.Context(), route.ServiceID, m.requestURL(r))
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func (m *Manager) enforceNetworkRules(w http.ResponseWriter, r *http.Request, route Route) bool {
	clientIP, err := m.realClientIP(r)
	if err != nil {
		writeProxyError(w, http.StatusForbidden, "forbidden", "unable to determine client ip")
		return false
	}

	if matchesAnyPrefix(clientIP, route.BlockPrefixes) {
		writeProxyError(w, http.StatusForbidden, "forbidden", "client ip is blocked")
		return false
	}

	if len(route.AllowPrefixes) > 0 && !matchesAnyPrefix(clientIP, route.AllowPrefixes) {
		writeProxyError(w, http.StatusForbidden, "forbidden", "client ip is not allowed")
		return false
	}

	if m.reputation != nil && m.reputation.Enabled() {
		if !m.reputation.Healthy() {
			if m.crowdSecFailOpen {
				if m.logger != nil {
					m.logger.Warn("reputation decisions unavailable or stale; failing open per config",
						"service_id", route.ServiceID, "host", route.Host)
				}
			} else {
				if m.logger != nil {
					m.logger.Warn("reputation decisions unavailable or stale; denying request (fail-closed)",
						"service_id", route.ServiceID, "host", route.Host)
				}
				writeProxyError(w, http.StatusServiceUnavailable, "reputation_unavailable", "reputation cannot be evaluated")
				return false
			}
		}
		if blocked, reason := m.reputation.IsBlocked(net.IP(clientIP.AsSlice())); blocked {
			writeProxyError(w, http.StatusForbidden, "forbidden", "reputation block: "+reason)
			return false
		}
	}

	if len(route.AllowedCountries) > 0 || len(route.BlockedCountries) > 0 {
		switch {
		case m.countryLookup == nil || !m.countryLookup.Available():
			if m.geoIPFailOpen {
				if m.logger != nil {
					m.logger.Warn("geoip rules configured but database not loaded; failing open per config",
						"service_id", route.ServiceID, "host", route.Host)
				}
			} else {
				if m.logger != nil {
					m.logger.Warn("geoip rules configured but database not loaded; denying request (fail-closed)",
						"service_id", route.ServiceID, "host", route.Host)
				}
				writeProxyError(w, http.StatusServiceUnavailable, "geoip_unavailable", "geo restriction cannot be evaluated")
				return false
			}
		default:
			country := m.countryLookup.CountryISO(net.IP(clientIP.AsSlice()))
			if country == "" && m.logger != nil {
				m.logger.Warn("geoip could not resolve client country; check trusted proxy config",
					"service_id", route.ServiceID, "client_ip", clientIP.String())
			}
			ok, reason := countryAllowedByRoute(country, route.AllowedCountries, route.BlockedCountries)
			if !ok {
				writeProxyError(w, http.StatusForbidden, "forbidden", "geoip: "+reason)
				return false
			}
		}
	}

	return true
}

func countryAllowedByRoute(country string, allowed, blocked []string) (bool, string) {
	if country == "" {
		return true, ""
	}
	for _, c := range blocked {
		if strings.EqualFold(c, country) {
			return false, "blocked_country"
		}
	}
	if len(allowed) == 0 {
		return true, ""
	}
	for _, c := range allowed {
		if strings.EqualFold(c, country) {
			return true, ""
		}
	}
	return false, "country_not_allowed"
}

func (m *Manager) enforceAccessWindows(w http.ResponseWriter, route Route) bool {
	if len(route.CompiledWindows) == 0 {
		return true
	}
	now := time.Now().UTC()
	for _, window := range route.CompiledWindows {
		if accessWindowMatches(window, now) {
			return true
		}
	}
	writeProxyError(w, http.StatusForbidden, "outside_access_window", "service is outside its configured access window")
	return false
}

func EffectiveAccessForService(service domain.Service) (domain.AccessPolicy, string, domain.JSONObject, *domain.ServiceGroup) {
	sort.Slice(service.ServiceGroups, func(i, j int) bool {
		return service.ServiceGroups[i].ID < service.ServiceGroups[j].ID
	})
	serviceMethod := strings.TrimSpace(service.AccessMethod)
	if !service.UseGroupPolicy {
		return normalizedPolicy(domain.AccessPolicy{
				AccessMode:           service.AccessMode,
				AllowedRoles:         service.AllowedRoles,
				AllowedGroups:        service.AllowedGroups,
				AllowedServiceGroups: service.AllowedServiceGroups,
			}, service.AuthPolicy),
			normalizedAccessMethod(serviceMethod),
			cloneJSONObject(service.AccessMethodConfig),
			nil
	}
	for _, group := range service.ServiceGroups {
		if strings.TrimSpace(group.DefaultAccessPolicy.AccessMode) != "" || strings.TrimSpace(group.AccessMethod) != "" {
			copyGroup := group
			method := strings.TrimSpace(group.AccessMethod)
			config := cloneJSONObject(group.AccessMethodConfig)
			if serviceMethod != "" {
				method = serviceMethod
				config = cloneJSONObject(service.AccessMethodConfig)
			}
			return normalizedPolicy(group.DefaultAccessPolicy, service.AuthPolicy), normalizedAccessMethod(method), config, &copyGroup
		}
	}
	return normalizedPolicy(domain.AccessPolicy{}, service.AuthPolicy), normalizedAccessMethod(serviceMethod), cloneJSONObject(service.AccessMethodConfig), nil
}

func effectiveAccessForService(service domain.Service) (domain.AccessPolicy, string, domain.JSONObject, *domain.ServiceGroup) {
	return EffectiveAccessForService(service)
}

func normalizedPolicy(policy domain.AccessPolicy, legacy string) domain.AccessPolicy {
	if strings.TrimSpace(policy.AccessMode) == "" {
		switch legacy {
		case domain.AuthPolicyPublic:
			policy.AccessMode = domain.AccessModePublic
		case domain.AuthPolicyAdminOnly:
			policy.AccessMode = domain.AccessModeRestricted
			policy.AllowedRoles = domain.JSONStringSlice{domain.RoleAdmin}
		default:
			policy.AccessMode = domain.AccessModeAuthenticated
		}
	}
	return policy
}

func normalizedAccessMethod(value string) string {
	switch strings.TrimSpace(value) {
	case "", domain.AccessMethodSession:
		return domain.AccessMethodSession
	case domain.AccessMethodOIDCOnly:
		return domain.AccessMethodOIDCOnly
	case domain.AccessMethodPIN:
		return domain.AccessMethodPIN
	case domain.AccessMethodEmailCode:
		return domain.AccessMethodEmailCode
	default:
		return domain.AccessMethodSession
	}
}

func cloneJSONObject(value domain.JSONObject) domain.JSONObject {
	if len(value) == 0 {
		return domain.JSONObject{}
	}
	out := make(domain.JSONObject, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func isAllowedByRestrictedPolicy(user *domain.User, groupIDs []uint, policy domain.AccessPolicy) bool {
	if user == nil {
		return false
	}
	for _, role := range policy.AllowedRoles {
		if role == user.Role {
			return true
		}
	}
	groupSet := make(map[uint]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		groupSet[id] = struct{}{}
	}
	for _, groupID := range policy.AllowedGroups {
		if _, ok := groupSet[groupID]; ok {
			return true
		}
	}
	return false
}

func accessWindowMatches(window compiledAccessWindow, now time.Time) bool {
	local := now.In(window.Location)
	if len(window.Weekdays) > 0 {
		if _, ok := window.Weekdays[local.Weekday()]; !ok {
			return false
		}
	}

	currentMinutes := local.Hour()*60 + local.Minute()
	if window.EndMinutes >= window.StartMinutes {
		return currentMinutes >= window.StartMinutes && currentMinutes <= window.EndMinutes
	}
	return currentMinutes >= window.StartMinutes || currentMinutes <= window.EndMinutes
}

func matchesAnyPrefix(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func parseClientIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return netip.ParseAddr(host)
	}
	return netip.ParseAddr(remoteAddr)
}

func (m *Manager) authoritativeClientIP(r *http.Request) string {
	addr, err := m.realClientIP(r)
	if err != nil || !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func (m *Manager) realClientIP(r *http.Request) (netip.Addr, error) {
	if m.requestFromTrustedProxy(r) {
		if addr, ok := clientIPFromForwardedChain(r.Header.Get("X-Forwarded-For"), m.trustedProxyCIDRs); ok {
			return addr, nil
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" {
			if addr, err := netip.ParseAddr(realIP); err == nil {
				return addr, nil
			}
		}
	}
	return parseClientIP(r.RemoteAddr)
}

func writeProxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"status":  status,
		},
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (m *Manager) isTargetDegraded(target string) (bool, string) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	state := m.breakers[target]
	if state == nil {
		return false, ""
	}
	if time.Now().UTC().Before(state.degradedUntil) {
		return true, firstNonEmpty(state.lastError, "circuit_open")
	}
	return false, ""
}

func (m *Manager) recordTargetFailure(target string, err error) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	state := m.breakers[target]
	if state == nil {
		state = &targetCircuitState{}
		m.breakers[target] = state
	}
	state.consecutiveFailures++
	if err != nil {
		state.lastError = err.Error()
	}
	if state.consecutiveFailures >= 3 {
		state.degradedUntil = time.Now().UTC().Add(30 * time.Second)
	}
}

func (m *Manager) recordTargetSuccess(target string) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	delete(m.breakers, target)
}

type retryTransport struct {
	base    http.RoundTripper
	retries int
	backoff time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	attempts := 1 + t.retries
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		resp, err := base.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isIdempotentMethod(req.Method) || attempt+1 >= attempts {
			break
		}
		time.Sleep(t.backoff)
	}
	return nil, lastErr
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
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

func statusCode(status int) string {
	if status == http.StatusUnauthorized {
		return "unauthorized"
	}
	return "forbidden"
}

func statusMessage(status int) string {
	if status == http.StatusUnauthorized {
		return "missing or invalid bearer token"
	}
	return "insufficient permissions"
}

func matchesPath(routePath, requestPath string) bool {
	if routePath == "/" {
		return true
	}
	if requestPath == routePath {
		return true
	}
	return strings.HasPrefix(requestPath, strings.TrimRight(routePath, "/")+"/")
}

func stripRoutePrefix(routePath, requestPath string) string {
	if requestPath == "" || routePath == "/" {
		if requestPath == "" {
			return "/"
		}
		return requestPath
	}
	if requestPath == routePath {
		return "/"
	}
	trimmedRoutePath := strings.TrimRight(routePath, "/")
	if strings.HasPrefix(requestPath, trimmedRoutePath+"/") {
		trimmed := strings.TrimPrefix(requestPath, trimmedRoutePath)
		if trimmed == "" {
			return "/"
		}
		return trimmed
	}
	return requestPath
}

func normalizeHost(value string) string {
	host := strings.TrimSpace(strings.ToLower(value))
	if idx := strings.Index(host, ":"); idx >= 0 {
		return host[:idx]
	}
	return host
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

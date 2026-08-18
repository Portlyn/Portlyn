package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

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
	upstreamServerName := upstreamTLSServerName(config.Service, config.TargetURL)
	switch {
	case strings.TrimSpace(config.Service.UpstreamCAPEM) != "":
		if pinned := pinnedUpstreamTransport(chosenTransport, strings.TrimSpace(config.Service.UpstreamCAPEM), upstreamServerName); pinned != nil {
			chosenTransport = pinned
		}
	case config.Service.UpstreamSkipVerify:
		chosenTransport = insecureUpstreamTransport(chosenTransport)
	case viaNode && upstreamServerName != "" && target.Scheme == "https":
		chosenTransport = serverNameUpstreamTransport(chosenTransport, upstreamServerName)
	}
	proxy := reverseProxyForTarget(target, chosenTransport, routePath, m.forwardedProto, m.authoritativeClientIP, config.Service.PassHostHeader)
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

func directProto(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	return "http"
}

func targetHostForLogs(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
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

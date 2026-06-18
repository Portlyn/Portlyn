package proxy

import (
	"net/http"
	"strings"

	"portlyn/internal/domain"
)

func (m *Manager) handleMagicLink(w http.ResponseWriter, r *http.Request) bool {
	path := normalizePath(r.URL.Path)
	const prefix = "/_portlyn/magic/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	token := strings.TrimPrefix(path, prefix)
	if idx := strings.Index(token, "/"); idx >= 0 {
		token = token[:idx]
	}
	token = strings.TrimSpace(token)
	if token == "" {
		writeProxyError(w, http.StatusBadRequest, "invalid_token", "missing magic link token")
		return true
	}
	host := normalizeHost(r.Host)
	route, ok := m.matchRoute(r.Context(), host, "/")
	if !ok {
		writeProxyError(w, http.StatusNotFound, "route_not_found", "no service matches this host")
		return true
	}
	remoteAddr := r.RemoteAddr
	if ip, err := m.realClientIP(r); err == nil {
		remoteAddr = ip.String()
	}
	if err := m.auth.ConsumeMagicLink(r.Context(), route.ServiceID, token, remoteAddr); err != nil {
		writeProxyError(w, http.StatusForbidden, "invalid_magic_link", "magic link is invalid or expired")
		return true
	}
	if err := m.auth.SetRouteAccessCookie(w, route.ServiceID, magicLinkMethod(route), ""); err != nil {
		writeProxyError(w, http.StatusInternalServerError, "cookie_error", "could not establish route access")
		return true
	}
	target := route.Path
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
	return true
}

func magicLinkMethod(route Route) string {
	if route.EffectiveMethod == domain.AccessMethodPIN || route.EffectiveMethod == domain.AccessMethodEmailCode {
		return route.EffectiveMethod
	}
	return domain.AccessMethodEmailCode
}

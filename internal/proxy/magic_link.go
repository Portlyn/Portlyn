package proxy

import (
	"context"
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
	if err := m.auth.ConsumeMagicLink(context.Background(), route.ServiceID, token); err != nil {
		writeProxyError(w, http.StatusForbidden, "invalid_magic_link", err.Error())
		return true
	}
	if err := m.auth.SetRouteAccessCookie(w, route.ServiceID, magicLinkMethod(route), ""); err != nil {
		writeProxyError(w, http.StatusInternalServerError, "cookie_error", err.Error())
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

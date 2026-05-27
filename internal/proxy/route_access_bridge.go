package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

func (m *Manager) handleRouteAccessBridge(w http.ResponseWriter, r *http.Request) bool {
	if normalizePath(r.URL.Path) != "/_portlyn/route-access" {
		return false
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeProxyError(w, http.StatusBadRequest, "invalid_token", "missing route access bridge token")
		return true
	}
	claims, err := m.auth.ParseRouteAccessBridgeToken(token)
	if err != nil {
		writeProxyError(w, http.StatusUnauthorized, "invalid_token", "invalid route access bridge token")
		return true
	}
	if normalizeHost(claims.Host) != normalizeHost(r.Host) {
		writeProxyError(w, http.StatusForbidden, "forbidden", "route access bridge host mismatch")
		return true
	}
	if err := m.auth.SetRouteAccessCookie(w, claims.ServiceID, claims.Method, claims.Email); err != nil {
		writeProxyError(w, http.StatusInternalServerError, "cookie_error", err.Error())
		return true
	}
	target := sanitizeReturnPath(claims.ReturnTo, r.Host, m.forwardedProto(r))
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
	return true
}

func sanitizeReturnPath(returnTo, host, scheme string) string {
	value := strings.TrimSpace(returnTo)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if parsed.Scheme == "" && parsed.Host == "" {
		return parsed.RequestURI()
	}
	if normalizeHost(parsed.Host) != normalizeHost(host) {
		return ""
	}
	parsed.Scheme = scheme
	return parsed.String()
}

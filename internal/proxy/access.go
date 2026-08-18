package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"portlyn/internal/domain"
	"sort"
	"strings"
	"time"
)

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
			if m.metrics != nil {
				m.metrics.ObserveReputationBlock()
			}
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

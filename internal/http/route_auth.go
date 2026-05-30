package http

import (
	"errors"
	"fmt"
	stdhttp "net/http"
	"net/url"
	"strings"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/proxy"
)

type routeAuthServiceResponse struct {
	ID                    uint                 `json:"id"`
	Name                  string               `json:"name"`
	DomainName            string               `json:"domain_name"`
	Path                  string               `json:"path"`
	AccessMode            string               `json:"access_mode"`
	AccessMethod          string               `json:"access_method"`
	AccessMethodConfig    domain.JSONObject    `json:"access_method_config"`
	AccessMessage         string               `json:"access_message"`
	InheritedFromGroup    *routeAuthGroupBrief `json:"inherited_from_group,omitempty"`
	ServiceOverridesGroup bool                 `json:"service_overrides_group"`
}

type routeAuthGroupBrief struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

func (s *Server) handleGetRouteAuthService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	service, ok := s.loadService(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, buildRouteAuthServiceResponse(*service))
}

func (s *Server) handleCreateSessionBridgeToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req sessionBridgeTokenRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	token := s.auth.SessionTokenFromRequest(r)
	if token == "" {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}
	host := normalizeBridgeHost(req.Host)
	if host == "" {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", "invalid bridge host")
		return
	}
	bridgeToken, err := s.auth.IssueSessionBridgeToken(token, host)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{"token": bridgeToken})
}

func (s *Server) handleRoutePIN(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req routePINRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	service, err := s.services.GetByID(r.Context(), req.ServiceID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	_, method, config, _ := proxy.EffectiveAccessForService(*service)
	if method != domain.AccessMethodPIN {
		writeError(w, stdhttp.StatusBadRequest, "invalid_access_method", "service is not protected by a route pin")
		return
	}

	pinHash := strings.TrimSpace(stringValueFromAny(config["pin_hash"]))
	if pinHash == "" {
		writeError(w, stdhttp.StatusConflict, "pin_not_configured", "route pin is not configured")
		return
	}
	if !s.enforceNodeRateLimit(w, r, fmt.Sprintf("route_pin:%d", service.ID), s.cfg.AuthRateLimit.LoginAttempts, s.cfg.AuthRateLimit.Window) {
		return
	}
	if err := auth.CheckPassword(pinHash, req.PIN); err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "route_pin_failed", "service", &service.ID, map[string]any{"service_id": service.ID})
		writeError(w, stdhttp.StatusUnauthorized, "invalid_pin", "invalid route pin")
		return
	}
	bridgeURL, err := s.buildRouteAccessBridgeURL(r, service, domain.AccessMethodPIN, "")
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.auth.SetRouteAccessCookie(w, service.ID, domain.AccessMethodPIN, "")
	_ = s.audit.LogRequest(r.Context(), r, nil, "route_pin_succeeded", "service", &service.ID, map[string]any{"service_id": service.ID})
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true, "bridge_url": bridgeURL})
}

func (s *Server) handleRouteRequestEmailCode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req routeEmailCodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	service, err := s.services.GetByID(r.Context(), req.ServiceID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	_, method, config, _ := proxy.EffectiveAccessForService(*service)
	if method != domain.AccessMethodEmailCode {
		writeError(w, stdhttp.StatusBadRequest, "invalid_access_method", "service is not protected by an email code")
		return
	}
	if err := validateRouteEmailDomain(req.Email, config); err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_request_failed", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email, "reason": err.Error()})
		writeError(w, stdhttp.StatusForbidden, "email_domain_not_allowed", "email domain is not allowed for this route")
		return
	}
	result, err := s.auth.RequestRouteEmailCode(r.Context(), service.ID, req.Email, s.requestMeta(r), s.cfg.AllowInsecureDevMode || s.cfg.OTP.ResponseIncludesCode)
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_request_failed", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email})
		if errors.Is(err, auth.ErrRateLimited) {
			writeError(w, stdhttp.StatusTooManyRequests, "rate_limited", "too many code requests")
			return
		}
		if errors.Is(err, auth.ErrOTPDisabled) {
			writeError(w, stdhttp.StatusNotFound, "otp_disabled", "email code login is disabled")
			return
		}
		if errors.Is(err, auth.ErrSMTPNotConfigured) {
			writeError(w, stdhttp.StatusConflict, "smtp_not_configured", "smtp is not configured for email delivery")
			return
		}
		if errors.Is(err, auth.ErrSMTPDeliveryFailed) {
			writeError(w, stdhttp.StatusBadGateway, "smtp_delivery_failed", "route access email could not be delivered")
			return
		}
		s.internalError(w, err)
		return
	}

	_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_requested", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email, "expires_at": result.ExpiresAt})
	writeJSON(w, stdhttp.StatusOK, result)
}

func (s *Server) handleRouteVerifyEmailCode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req routeVerifyEmailCodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	service, err := s.services.GetByID(r.Context(), req.ServiceID)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	_, method, config, _ := proxy.EffectiveAccessForService(*service)
	if method != domain.AccessMethodEmailCode {
		writeError(w, stdhttp.StatusBadRequest, "invalid_access_method", "service is not protected by an email code")
		return
	}
	if err := validateRouteEmailDomain(req.Email, config); err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_verify_failed", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email, "reason": err.Error()})
		writeError(w, stdhttp.StatusForbidden, "email_domain_not_allowed", "email domain is not allowed for this route")
		return
	}
	if !s.enforceNodeRateLimit(w, r, fmt.Sprintf("route_email_verify:%d", service.ID), s.cfg.AuthRateLimit.LoginAttempts, s.cfg.AuthRateLimit.Window) {
		return
	}
	if err := s.auth.VerifyRouteEmailCode(r.Context(), service.ID, req.Email, req.Code); err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_verify_failed", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email})
		switch {
		case errors.Is(err, auth.ErrOTPExpired):
			writeError(w, stdhttp.StatusUnauthorized, "code_expired", "email code expired")
		case errors.Is(err, auth.ErrOTPUsed):
			writeError(w, stdhttp.StatusUnauthorized, "code_used", "email code was already used")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_code", "invalid email or code")
		default:
			s.internalError(w, err)
		}
		return
	}
	bridgeURL, err := s.buildRouteAccessBridgeURL(r, service, domain.AccessMethodEmailCode, req.Email)
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.auth.SetRouteAccessCookie(w, service.ID, domain.AccessMethodEmailCode, req.Email)
	_ = s.audit.LogRequest(r.Context(), r, nil, "route_email_code_verified", "service", &service.ID, map[string]any{"service_id": service.ID, "email": req.Email})
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true, "bridge_url": bridgeURL})
}

func (s *Server) buildRouteAccessBridgeURL(r *stdhttp.Request, service *domain.Service, method, email string) (string, error) {
	host := domain.ServiceHost(*service)
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("service has no host")
	}
	returnTo := strings.TrimSpace(r.URL.Query().Get("returnTo"))
	if returnTo == "" {
		returnTo = strings.TrimSpace(r.Header.Get("X-Portlyn-Return-To"))
	}
	token, err := s.auth.IssueRouteAccessBridgeToken(service.ID, host, method, email, returnTo)
	if err != nil {
		return "", err
	}
	scheme := "https"
	if s.cfg.AllowInsecureDevMode {
		scheme = "http"
	}
	values := url.Values{}
	values.Set("token", token)
	if returnTo != "" {
		values.Set("returnTo", returnTo)
	}
	return scheme + "://" + host + "/_portlyn/route-access?" + values.Encode(), nil
}

func buildRouteAuthServiceResponse(service domain.Service) routeAuthServiceResponse {
	policy, method, config, inheritedFrom := proxy.EffectiveAccessForService(service)
	response := routeAuthServiceResponse{
		ID:                    service.ID,
		Name:                  service.Name,
		DomainName:            domain.ServiceHost(service),
		Path:                  service.Path,
		AccessMode:            policy.AccessMode,
		AccessMethod:          method,
		AccessMethodConfig:    publicAccessMethodConfig(method, config),
		AccessMessage:         strings.TrimSpace(service.AccessMessage),
		ServiceOverridesGroup: strings.TrimSpace(service.AccessMethod) != "",
	}
	if inheritedFrom != nil {
		response.InheritedFromGroup = &routeAuthGroupBrief{ID: inheritedFrom.ID, Name: inheritedFrom.Name}
	}
	return response
}

func validateRouteEmailDomain(email string, config domain.JSONObject) error {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	allowedEmails := normalizeAllowedEmails(stringSliceFromAny(config["allowed_emails"]))
	if len(allowedEmails) > 0 {
		for _, allowedEmail := range allowedEmails {
			if normalizedEmail == allowedEmail {
				return nil
			}
		}
		return fmt.Errorf("email address not allowed")
	}
	allowed := strings.ToLower(strings.TrimSpace(stringValueFromAny(config["allowed_email_domain"])))
	if allowed == "" {
		return nil
	}
	parts := strings.Split(normalizedEmail, "@")
	if len(parts) != 2 || parts[1] != strings.TrimPrefix(allowed, "@") {
		return fmt.Errorf("email domain not allowed")
	}
	return nil
}

func normalizeBridgeHost(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	if strings.Contains(trimmed, ":") {
		if parsed, err := url.Parse("http://" + trimmed); err == nil {
			return parsed.Hostname()
		}
	}
	return trimmed
}

func parseBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

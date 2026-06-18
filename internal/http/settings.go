package http

import (
	"errors"
	stdhttp "net/http"
	"strings"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
)

func (s *Server) handleGetAuthSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, s.authSettingsResponse(item))
}

func (s *Server) handleUpdateAuthSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.handleStoreError(w, err)
		return
	}

	var req updateAuthSettingsRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	if req.FrontendBaseURL != nil {
		item.FrontendBaseURL = strings.TrimSpace(*req.FrontendBaseURL)
	}
	if req.AuthBrandName != nil {
		item.AuthBrandName = strings.TrimSpace(*req.AuthBrandName)
	}
	if req.AuthLogoURL != nil {
		item.AuthLogoURL = strings.TrimSpace(*req.AuthLogoURL)
	}
	if req.AuthBackgroundColor != nil {
		item.AuthBackgroundColor = strings.TrimSpace(*req.AuthBackgroundColor)
	}
	if req.AuthBackgroundAccent != nil {
		item.AuthBackgroundAccent = strings.TrimSpace(*req.AuthBackgroundAccent)
	}
	if req.AuthPanelColor != nil {
		item.AuthPanelColor = strings.TrimSpace(*req.AuthPanelColor)
	}
	if req.AuthButtonColor != nil {
		item.AuthButtonColor = strings.TrimSpace(*req.AuthButtonColor)
	}
	if req.AuthTextColor != nil {
		item.AuthTextColor = strings.TrimSpace(*req.AuthTextColor)
	}
	if req.AuthMutedTextColor != nil {
		item.AuthMutedTextColor = strings.TrimSpace(*req.AuthMutedTextColor)
	}
	if req.AuthLoginTitle != nil {
		item.AuthLoginTitle = strings.TrimSpace(*req.AuthLoginTitle)
	}
	if req.AuthLoginSubtitle != nil {
		item.AuthLoginSubtitle = strings.TrimSpace(*req.AuthLoginSubtitle)
	}
	if req.AuthRouteLoginTitle != nil {
		item.AuthRouteLoginTitle = strings.TrimSpace(*req.AuthRouteLoginTitle)
	}
	if req.AuthRouteLoginSubtitle != nil {
		item.AuthRouteLoginSubtitle = strings.TrimSpace(*req.AuthRouteLoginSubtitle)
	}
	if req.AuthForbiddenTitle != nil {
		item.AuthForbiddenTitle = strings.TrimSpace(*req.AuthForbiddenTitle)
	}
	if req.AuthForbiddenSubtitle != nil {
		item.AuthForbiddenSubtitle = strings.TrimSpace(*req.AuthForbiddenSubtitle)
	}
	if req.AuthLoginPasswordLabel != nil {
		item.AuthLoginPasswordLabel = strings.TrimSpace(*req.AuthLoginPasswordLabel)
	}
	if req.AuthLoginOIDCLabel != nil {
		item.AuthLoginOIDCLabel = strings.TrimSpace(*req.AuthLoginOIDCLabel)
	}
	if req.AuthLoginOTPRequestLabel != nil {
		item.AuthLoginOTPRequestLabel = strings.TrimSpace(*req.AuthLoginOTPRequestLabel)
	}
	if req.AuthLoginOTPVerifyLabel != nil {
		item.AuthLoginOTPVerifyLabel = strings.TrimSpace(*req.AuthLoginOTPVerifyLabel)
	}
	if req.AuthRouteContinueLabel != nil {
		item.AuthRouteContinueLabel = strings.TrimSpace(*req.AuthRouteContinueLabel)
	}
	if req.AuthRouteOIDCLabel != nil {
		item.AuthRouteOIDCLabel = strings.TrimSpace(*req.AuthRouteOIDCLabel)
	}
	if req.AuthRoutePINLabel != nil {
		item.AuthRoutePINLabel = strings.TrimSpace(*req.AuthRoutePINLabel)
	}
	if req.AuthRouteEmailSendLabel != nil {
		item.AuthRouteEmailSendLabel = strings.TrimSpace(*req.AuthRouteEmailSendLabel)
	}
	if req.AuthRouteEmailVerifyLabel != nil {
		item.AuthRouteEmailVerifyLabel = strings.TrimSpace(*req.AuthRouteEmailVerifyLabel)
	}
	if req.AuthForbiddenRetryLabel != nil {
		item.AuthForbiddenRetryLabel = strings.TrimSpace(*req.AuthForbiddenRetryLabel)
	}
	if req.OIDCEnabled != nil {
		item.OIDCEnabled = *req.OIDCEnabled
	}
	if req.OIDCIssuerURL != nil {
		item.OIDCIssuerURL = strings.TrimSpace(*req.OIDCIssuerURL)
	}
	if req.OIDCClientID != nil {
		item.OIDCClientID = strings.TrimSpace(*req.OIDCClientID)
	}
	if req.OIDCClientSecret != nil && strings.TrimSpace(*req.OIDCClientSecret) != "" {
		item.OIDCClientSecret = *req.OIDCClientSecret
	}
	if req.OIDCRedirectURL != nil {
		item.OIDCRedirectURL = strings.TrimSpace(*req.OIDCRedirectURL)
	}
	if req.OIDCAllowedEmailDomains != nil {
		item.OIDCAllowedEmailDomains = normalizeStringList(*req.OIDCAllowedEmailDomains)
	}
	if req.OIDCAdminRoleClaimPath != nil {
		item.OIDCAdminRoleClaimPath = strings.TrimSpace(*req.OIDCAdminRoleClaimPath)
	}
	if req.OIDCAdminRoleValue != nil {
		item.OIDCAdminRoleValue = strings.TrimSpace(*req.OIDCAdminRoleValue)
	}
	if req.OIDCProviderLabel != nil {
		item.OIDCProviderLabel = strings.TrimSpace(*req.OIDCProviderLabel)
	}
	if req.OIDCAllowEmailLinking != nil {
		item.OIDCAllowEmailLinking = *req.OIDCAllowEmailLinking
	}
	if req.OIDCRequireVerifiedEmail != nil {
		item.OIDCRequireVerifiedEmail = *req.OIDCRequireVerifiedEmail
	}
	if req.OTPEnabled != nil {
		item.OTPEnabled = *req.OTPEnabled
	}
	if req.OTPTokenTTLSeconds != nil {
		item.OTPTokenTTLSeconds = *req.OTPTokenTTLSeconds
	}
	if req.OTPRequestLimit != nil {
		item.OTPRequestLimit = *req.OTPRequestLimit
	}
	if req.OTPRequestWindowSeconds != nil {
		item.OTPRequestWindowSeconds = *req.OTPRequestWindowSeconds
	}
	if req.RequireMFAForAdmins != nil {
		item.RequireMFAForAdmins = *req.RequireMFAForAdmins
	}
	if req.SMTPEnabled != nil {
		item.SMTPEnabled = *req.SMTPEnabled
	}
	if req.SMTPHost != nil {
		item.SMTPHost = strings.TrimSpace(*req.SMTPHost)
	}
	if req.SMTPPort != nil {
		item.SMTPPort = *req.SMTPPort
	}
	if req.SMTPUsername != nil {
		item.SMTPUsername = strings.TrimSpace(*req.SMTPUsername)
	}
	if req.SMTPPassword != nil && strings.TrimSpace(*req.SMTPPassword) != "" {
		item.SMTPPassword = *req.SMTPPassword
	}
	if req.SMTPFromEmail != nil {
		item.SMTPFromEmail = strings.TrimSpace(*req.SMTPFromEmail)
	}
	if req.SMTPFromName != nil {
		item.SMTPFromName = strings.TrimSpace(*req.SMTPFromName)
	}
	if req.SMTPEncryption != nil {
		item.SMTPEncryption = strings.TrimSpace(*req.SMTPEncryption)
	}
	if req.SMTPInsecureSkipVerify != nil {
		item.SMTPInsecureSkipVerify = *req.SMTPInsecureSkipVerify
	}
	if message := s.validateAuthSettings(item); message != "" {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", message)
		return
	}

	if err := s.appSettings.Upsert(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}

	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "update", "app_settings", &item.ID, map[string]any{"id": item.ID})
	writeJSON(w, stdhttp.StatusOK, s.authSettingsResponse(item))
}

func (s *Server) handleSendTestEmail(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req sendTestEmailRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if err := s.auth.SendTestEmail(r.Context(), req.Email); err != nil {
		switch {
		case errors.Is(err, auth.ErrSMTPNotConfigured):
			writeError(w, stdhttp.StatusConflict, "smtp_not_configured", "smtp is not configured")
		default:
			writeError(w, stdhttp.StatusBadGateway, "smtp_delivery_failed", "test email could not be delivered")
		}
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "test_email", "app_settings", nil, map[string]any{"email": req.Email})
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true})
}

func (s *Server) authSettingsResponse(item *domain.AppSettings) map[string]any {
	return map[string]any{
		"id":                             item.ID,
		"frontend_base_url":              item.FrontendBaseURL,
		"auth_brand_name":                item.AuthBrandName,
		"auth_logo_url":                  item.AuthLogoURL,
		"auth_background_color":          item.AuthBackgroundColor,
		"auth_background_accent":         item.AuthBackgroundAccent,
		"auth_panel_color":               item.AuthPanelColor,
		"auth_button_color":              item.AuthButtonColor,
		"auth_text_color":                item.AuthTextColor,
		"auth_muted_text_color":          item.AuthMutedTextColor,
		"auth_login_title":               item.AuthLoginTitle,
		"auth_login_subtitle":            item.AuthLoginSubtitle,
		"auth_route_login_title":         item.AuthRouteLoginTitle,
		"auth_route_login_subtitle":      item.AuthRouteLoginSubtitle,
		"auth_forbidden_title":           item.AuthForbiddenTitle,
		"auth_forbidden_subtitle":        item.AuthForbiddenSubtitle,
		"auth_login_password_label":      item.AuthLoginPasswordLabel,
		"auth_login_oidc_label":          item.AuthLoginOIDCLabel,
		"auth_login_otp_request_label":   item.AuthLoginOTPRequestLabel,
		"auth_login_otp_verify_label":    item.AuthLoginOTPVerifyLabel,
		"auth_route_continue_label":      item.AuthRouteContinueLabel,
		"auth_route_oidc_label":          item.AuthRouteOIDCLabel,
		"auth_route_pin_label":           item.AuthRoutePINLabel,
		"auth_route_email_send_label":    item.AuthRouteEmailSendLabel,
		"auth_route_email_verify_label":  item.AuthRouteEmailVerifyLabel,
		"auth_forbidden_retry_label":     item.AuthForbiddenRetryLabel,
		"oidc_enabled":                   item.OIDCEnabled,
		"oidc_issuer_url":                item.OIDCIssuerURL,
		"oidc_client_id":                 item.OIDCClientID,
		"oidc_client_secret_configured":  strings.TrimSpace(item.OIDCClientSecret) != "",
		"oidc_redirect_url":              item.OIDCRedirectURL,
		"oidc_allowed_email_domains":     item.OIDCAllowedEmailDomains,
		"oidc_admin_role_claim_path":     item.OIDCAdminRoleClaimPath,
		"oidc_admin_role_value":          item.OIDCAdminRoleValue,
		"oidc_provider_label":            item.OIDCProviderLabel,
		"oidc_allow_email_linking":       item.OIDCAllowEmailLinking,
		"oidc_require_verified_email":    item.OIDCRequireVerifiedEmail,
		"otp_enabled":                    item.OTPEnabled,
		"otp_token_ttl_seconds":          item.OTPTokenTTLSeconds,
		"otp_request_limit":              item.OTPRequestLimit,
		"otp_request_window_seconds":     item.OTPRequestWindowSeconds,
		"require_mfa_for_admins":         item.RequireMFAForAdmins,
		"smtp_enabled":                   item.SMTPEnabled,
		"smtp_host":                      item.SMTPHost,
		"smtp_port":                      item.SMTPPort,
		"smtp_username":                  item.SMTPUsername,
		"smtp_password_configured":       strings.TrimSpace(item.SMTPPassword) != "",
		"smtp_from_email":                item.SMTPFromEmail,
		"smtp_from_name":                 item.SMTPFromName,
		"smtp_encryption":                item.SMTPEncryption,
		"smtp_insecure_skip_verify":      item.SMTPInsecureSkipVerify,
		"jwt_ttl_seconds":                int(s.cfg.TokenTTL.Seconds()),
		"refresh_token_ttl_seconds":      int(s.cfg.RefreshTokenTTL.Seconds()),
		"auth_rate_limit_attempts":       s.cfg.AuthRateLimit.LoginAttempts,
		"auth_rate_limit_window_seconds": int(s.cfg.AuthRateLimit.Window.Seconds()),
		"csrf_enabled":                   true,
		"cookie_secure":                  !s.cfg.AllowInsecureDevMode,
		"cookie_http_only":               true,
		"cookie_same_site_session":       "Lax",
		"cookie_same_site_refresh":       "Strict",
		"created_at":                     item.CreatedAt,
		"updated_at":                     item.UpdatedAt,
	}
}

func authUIResponse(item *domain.AppSettings) map[string]any {
	return map[string]any{
		"brand_name":               firstNonEmpty(strings.TrimSpace(item.AuthBrandName), "Portlyn"),
		"logo_url":                 strings.TrimSpace(item.AuthLogoURL),
		"background_color":         firstNonEmpty(strings.TrimSpace(item.AuthBackgroundColor), "#0a0d14"),
		"background_accent":        firstNonEmpty(strings.TrimSpace(item.AuthBackgroundAccent), "#162033"),
		"panel_color":              firstNonEmpty(strings.TrimSpace(item.AuthPanelColor), "#111826"),
		"button_color":             firstNonEmpty(strings.TrimSpace(item.AuthButtonColor), "#2f6fed"),
		"text_color":               firstNonEmpty(strings.TrimSpace(item.AuthTextColor), "#f8fafc"),
		"muted_text_color":         firstNonEmpty(strings.TrimSpace(item.AuthMutedTextColor), "#94a3b8"),
		"login_title":              firstNonEmpty(strings.TrimSpace(item.AuthLoginTitle), "Login"),
		"login_subtitle":           strings.TrimSpace(item.AuthLoginSubtitle),
		"route_login_title":        firstNonEmpty(strings.TrimSpace(item.AuthRouteLoginTitle), "Login"),
		"route_login_subtitle":     strings.TrimSpace(item.AuthRouteLoginSubtitle),
		"forbidden_title":          firstNonEmpty(strings.TrimSpace(item.AuthForbiddenTitle), "Access denied"),
		"forbidden_subtitle":       firstNonEmpty(strings.TrimSpace(item.AuthForbiddenSubtitle), "You do not have permission to access this route."),
		"login_password_label":     firstNonEmpty(strings.TrimSpace(item.AuthLoginPasswordLabel), "Login"),
		"login_oidc_label":         firstNonEmpty(strings.TrimSpace(item.AuthLoginOIDCLabel), "Continue with SSO"),
		"login_otp_request_label":  firstNonEmpty(strings.TrimSpace(item.AuthLoginOTPRequestLabel), "Request code"),
		"login_otp_verify_label":   firstNonEmpty(strings.TrimSpace(item.AuthLoginOTPVerifyLabel), "Verify code"),
		"route_continue_label":     firstNonEmpty(strings.TrimSpace(item.AuthRouteContinueLabel), "Continue"),
		"route_oidc_label":         firstNonEmpty(strings.TrimSpace(item.AuthRouteOIDCLabel), "Continue with SSO"),
		"route_pin_label":          firstNonEmpty(strings.TrimSpace(item.AuthRoutePINLabel), "Unlock"),
		"route_email_send_label":   firstNonEmpty(strings.TrimSpace(item.AuthRouteEmailSendLabel), "Send code"),
		"route_email_verify_label": firstNonEmpty(strings.TrimSpace(item.AuthRouteEmailVerifyLabel), "Verify code"),
		"forbidden_retry_label":    firstNonEmpty(strings.TrimSpace(item.AuthForbiddenRetryLabel), "Try again"),
	}
}

func (s *Server) validateAuthSettings(item *domain.AppSettings) string {
	if item.OIDCEnabled {
		if strings.TrimSpace(item.OIDCIssuerURL) == "" || strings.TrimSpace(item.OIDCClientID) == "" || strings.TrimSpace(item.OIDCClientSecret) == "" || strings.TrimSpace(item.OIDCRedirectURL) == "" {
			return "enabled oidc requires issuer url, client id, client secret and redirect url"
		}
		if !s.cfg.AllowInsecureDevMode {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.OIDCIssuerURL)), "https://") {
				return "oidc issuer url must use https"
			}
			if err := validateOutboundURL(item.OIDCIssuerURL); err != nil {
				return "oidc issuer url is not allowed: " + err.Error()
			}
		}
	}
	if item.SMTPEnabled {
		if strings.TrimSpace(item.SMTPHost) == "" || item.SMTPPort <= 0 || strings.TrimSpace(item.SMTPFromEmail) == "" {
			return "enabled smtp requires host, port and from email"
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

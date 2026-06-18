package auth

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/mail"
	"portlyn/internal/store"
)

func (s *Service) runtimeSettings(ctx context.Context) *domain.AppSettings {
	if s.settings != nil {
		item, err := s.settings.Get(ctx)
		if err == nil {
			return item
		}
	}
	return &domain.AppSettings{
		FrontendBaseURL:          s.fallbackFrontendBaseURL,
		OIDCEnabled:              s.fallbackOIDC.Enabled,
		OIDCIssuerURL:            s.fallbackOIDC.IssuerURL,
		OIDCClientID:             s.fallbackOIDC.ClientID,
		OIDCClientSecret:         s.fallbackOIDC.ClientSecret,
		OIDCRedirectURL:          s.fallbackOIDC.RedirectURL,
		OIDCAllowedEmailDomains:  domain.JSONStringSlice(s.fallbackOIDC.AllowedEmailDomains),
		OIDCAdminRoleClaimPath:   s.fallbackOIDC.AdminRoleClaimPath,
		OIDCAdminRoleValue:       s.fallbackOIDC.AdminRoleValue,
		OIDCProviderLabel:        s.fallbackOIDC.DefaultProviderLabel,
		OIDCAllowEmailLinking:    s.fallbackOIDC.AllowEmailLinking,
		OIDCRequireVerifiedEmail: s.fallbackOIDC.RequireVerifiedEmail,
		OTPEnabled:               s.fallbackOTP.Enabled,
		OTPTokenTTLSeconds:       int(s.fallbackOTP.TokenTTL.Seconds()),
		OTPRequestLimit:          s.fallbackOTP.RequestLimit,
		OTPRequestWindowSeconds:  int(s.fallbackOTP.RequestWindow.Seconds()),
	}
}

func (s *Service) currentFrontendBaseURL(ctx context.Context) string {
	value := strings.TrimRight(strings.TrimSpace(s.runtimeSettings(ctx).FrontendBaseURL), "/")
	if value != "" {
		return value
	}
	return s.fallbackFrontendBaseURL
}

func (s *Service) currentOTPConfig(ctx context.Context) config.OTPConfig {
	settings := s.runtimeSettings(ctx)
	tokenTTL := time.Duration(settings.OTPTokenTTLSeconds) * time.Second
	if tokenTTL <= 0 {
		tokenTTL = s.fallbackOTP.TokenTTL
	}
	requestWindow := time.Duration(settings.OTPRequestWindowSeconds) * time.Second
	if requestWindow <= 0 {
		requestWindow = s.fallbackOTP.RequestWindow
	}
	requestLimit := settings.OTPRequestLimit
	if requestLimit <= 0 {
		requestLimit = s.fallbackOTP.RequestLimit
	}
	return config.OTPConfig{
		Enabled:              settings.OTPEnabled,
		TokenTTL:             tokenTTL,
		RequestLimit:         requestLimit,
		RequestWindow:        requestWindow,
		ResponseIncludesCode: s.allowInsecureDevMode && s.fallbackOTP.ResponseIncludesCode,
	}
}

func (s *Service) currentOIDCConfig(ctx context.Context) config.OIDCConfig {
	settings := s.runtimeSettings(ctx)
	return config.OIDCConfig{
		Enabled:              settings.OIDCEnabled,
		IssuerURL:            strings.TrimSpace(settings.OIDCIssuerURL),
		ClientID:             strings.TrimSpace(settings.OIDCClientID),
		ClientSecret:         settings.OIDCClientSecret,
		RedirectURL:          strings.TrimSpace(settings.OIDCRedirectURL),
		AllowedEmailDomains:  []string(settings.OIDCAllowedEmailDomains),
		AdminRoleClaimPath:   strings.TrimSpace(settings.OIDCAdminRoleClaimPath),
		AdminRoleValue:       strings.TrimSpace(settings.OIDCAdminRoleValue),
		DefaultProviderLabel: firstNonEmpty(strings.TrimSpace(settings.OIDCProviderLabel), "SSO"),
		AllowEmailLinking:    settings.OIDCAllowEmailLinking,
		RequireVerifiedEmail: settings.OIDCRequireVerifiedEmail,
		ManageRoles:          s.fallbackOIDC.ManageRoles,
	}
}

func (s *Service) getOIDCAuthenticator(ctx context.Context) (*OIDCAuthenticator, error) {
	cfg := s.currentOIDCConfig(ctx)
	if !cfg.Enabled {
		return nil, ErrOIDCDisabled
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	key := string(payload)

	s.oidcMu.RLock()
	if s.oidcCache != nil && s.oidcCacheKey == key {
		authenticator := s.oidcCache
		s.oidcMu.RUnlock()
		return authenticator, nil
	}
	s.oidcMu.RUnlock()

	authenticator, err := NewOIDCAuthenticator(cfg, s.oidcStateSecret)
	if err != nil {
		return nil, err
	}

	s.oidcMu.Lock()
	s.oidcCache = authenticator
	s.oidcCacheKey = key
	s.oidcMu.Unlock()
	return authenticator, nil
}

func (s *Service) CurrentAuthConfig(ctx context.Context) map[string]any {
	oidcCfg := s.currentOIDCConfig(ctx)
	otpCfg := s.currentOTPConfig(ctx)
	return map[string]any{
		"oidc_enabled": oidcCfg.Enabled,
		"oidc_label":   oidcCfg.DefaultProviderLabel,
		"otp_enabled":  otpCfg.Enabled,
		"ui":           s.currentAuthUI(ctx),
	}
}

func (s *Service) currentAuthUI(ctx context.Context) map[string]any {
	settings := s.runtimeSettings(ctx)
	return map[string]any{
		"brand_name":               firstNonEmpty(strings.TrimSpace(settings.AuthBrandName), "Portlyn"),
		"logo_url":                 strings.TrimSpace(settings.AuthLogoURL),
		"background_color":         firstNonEmpty(strings.TrimSpace(settings.AuthBackgroundColor), "#0a0d14"),
		"background_accent":        firstNonEmpty(strings.TrimSpace(settings.AuthBackgroundAccent), "#162033"),
		"panel_color":              firstNonEmpty(strings.TrimSpace(settings.AuthPanelColor), "#111826"),
		"button_color":             firstNonEmpty(strings.TrimSpace(settings.AuthButtonColor), "#2f6fed"),
		"text_color":               firstNonEmpty(strings.TrimSpace(settings.AuthTextColor), "#f8fafc"),
		"muted_text_color":         firstNonEmpty(strings.TrimSpace(settings.AuthMutedTextColor), "#94a3b8"),
		"login_title":              firstNonEmpty(strings.TrimSpace(settings.AuthLoginTitle), "Login"),
		"login_subtitle":           strings.TrimSpace(settings.AuthLoginSubtitle),
		"route_login_title":        firstNonEmpty(strings.TrimSpace(settings.AuthRouteLoginTitle), "Login"),
		"route_login_subtitle":     strings.TrimSpace(settings.AuthRouteLoginSubtitle),
		"forbidden_title":          firstNonEmpty(strings.TrimSpace(settings.AuthForbiddenTitle), "Access denied"),
		"forbidden_subtitle":       firstNonEmpty(strings.TrimSpace(settings.AuthForbiddenSubtitle), "You do not have permission to access this route."),
		"login_password_label":     firstNonEmpty(strings.TrimSpace(settings.AuthLoginPasswordLabel), "Login"),
		"login_oidc_label":         firstNonEmpty(strings.TrimSpace(settings.AuthLoginOIDCLabel), "Continue with SSO"),
		"login_otp_request_label":  firstNonEmpty(strings.TrimSpace(settings.AuthLoginOTPRequestLabel), "Request code"),
		"login_otp_verify_label":   firstNonEmpty(strings.TrimSpace(settings.AuthLoginOTPVerifyLabel), "Verify code"),
		"route_continue_label":     firstNonEmpty(strings.TrimSpace(settings.AuthRouteContinueLabel), "Continue"),
		"route_oidc_label":         firstNonEmpty(strings.TrimSpace(settings.AuthRouteOIDCLabel), "Continue with SSO"),
		"route_pin_label":          firstNonEmpty(strings.TrimSpace(settings.AuthRoutePINLabel), "Unlock"),
		"route_email_send_label":   firstNonEmpty(strings.TrimSpace(settings.AuthRouteEmailSendLabel), "Send code"),
		"route_email_verify_label": firstNonEmpty(strings.TrimSpace(settings.AuthRouteEmailVerifyLabel), "Verify code"),
		"forbidden_retry_label":    firstNonEmpty(strings.TrimSpace(settings.AuthForbiddenRetryLabel), "Try again"),
	}
}

func (s *Service) currentSMTPConfig(ctx context.Context) mail.SMTPConfig {
	settings := s.runtimeSettings(ctx)
	return mail.SMTPConfig{
		Enabled:            settings.SMTPEnabled,
		Host:               strings.TrimSpace(settings.SMTPHost),
		Port:               settings.SMTPPort,
		Username:           strings.TrimSpace(settings.SMTPUsername),
		Password:           settings.SMTPPassword,
		FromEmail:          strings.TrimSpace(settings.SMTPFromEmail),
		FromName:           strings.TrimSpace(settings.SMTPFromName),
		Encryption:         firstNonEmpty(strings.TrimSpace(settings.SMTPEncryption), "starttls"),
		InsecureSkipVerify: settings.SMTPInsecureSkipVerify,
	}
}

func (s *Service) settingsStore() *store.AppSettingsStore {
	return s.settings
}

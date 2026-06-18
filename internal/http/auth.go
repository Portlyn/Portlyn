package http

import (
	"errors"
	stdhttp "net/http"

	"portlyn/internal/auth"
	"portlyn/internal/store"
)

func (s *Server) handleRequestOTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req requestOTPRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	result, err := s.auth.RequestOTP(r.Context(), req.Email, s.requestMeta(r))
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "otp_request_failed", "auth", nil, map[string]any{"email": req.Email})
		switch {
		case errors.Is(err, auth.ErrOTPDisabled):
			writeError(w, stdhttp.StatusNotFound, "otp_disabled", "otp login is disabled")
		case errors.Is(err, auth.ErrSMTPNotConfigured):
			writeError(w, stdhttp.StatusConflict, "smtp_not_configured", "smtp is not configured for otp delivery")
		case errors.Is(err, auth.ErrSMTPDeliveryFailed):
			writeError(w, stdhttp.StatusBadGateway, "smtp_delivery_failed", "otp email could not be delivered")
		case errors.Is(err, store.ErrNotFound), errors.Is(err, auth.ErrInactiveUser), errors.Is(err, auth.ErrRateLimited):
			writeJSON(w, stdhttp.StatusOK, map[string]any{"message": "if the account exists, a code has been issued"})
		default:
			s.internalError(w, err)
		}
		return
	}

	_ = s.audit.LogRequest(r.Context(), r, nil, "otp_requested", "auth", nil, map[string]any{"email": req.Email, "expires_at": result.ExpiresAt})
	writeJSON(w, stdhttp.StatusOK, result)
}

func (s *Server) handleVerifyOTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req verifyOTPRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	result, err := s.auth.VerifyOTP(r.Context(), req.Email, req.Token, s.requestMeta(r))
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "otp_login_failed", "auth", nil, map[string]any{"email": req.Email})
		switch {
		case errors.Is(err, auth.ErrOTPDisabled):
			writeError(w, stdhttp.StatusNotFound, "otp_disabled", "otp login is disabled")
		case errors.Is(err, auth.ErrRateLimited):
			writeError(w, stdhttp.StatusTooManyRequests, "rate_limited", "too many verification attempts")
		case errors.Is(err, auth.ErrOTPExpired):
			writeError(w, stdhttp.StatusUnauthorized, "otp_expired", "otp code expired")
		case errors.Is(err, auth.ErrOTPUsed):
			writeError(w, stdhttp.StatusUnauthorized, "otp_used", "otp code was already used")
		case errors.Is(err, auth.ErrInactiveUser):
			writeError(w, stdhttp.StatusForbidden, "inactive_user", "user account is inactive")
		case errors.Is(err, auth.ErrMFASetupRequired):
			writeError(w, stdhttp.StatusForbidden, "mfa_setup_required", "admin mfa is required before this account can sign in")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_otp", "invalid email or otp code")
		default:
			s.internalError(w, err)
		}
		return
	}

	_ = s.audit.LogRequest(r.Context(), r, &result.User.ID, "otp_login_succeeded", "auth", nil, map[string]any{"email": result.User.Email, "method": "otp"})
	s.writeLoginResult(w, r, result)
}

func (s *Server) handleOIDCStart(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	startURL, err := s.auth.StartOIDC(r.Context(), r.URL.Query().Get("next"))
	if err != nil {
		if errors.Is(err, auth.ErrOIDCDisabled) {
			writeError(w, stdhttp.StatusNotFound, "oidc_disabled", "sso is disabled")
			return
		}
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{"url": startURL})
}

func (s *Server) handleOIDCCallback(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		writeError(w, stdhttp.StatusBadRequest, "invalid_callback", "missing code or state")
		return
	}

	result, details, next, err := s.auth.CompleteOIDC(r.Context(), code, state)
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "sso_login_failed", "auth", nil, details)
		switch {
		case errors.Is(err, auth.ErrOIDCDisabled):
			writeError(w, stdhttp.StatusNotFound, "oidc_disabled", "sso is disabled")
		case errors.Is(err, auth.ErrOIDCEmailBlocked):
			writeError(w, stdhttp.StatusForbidden, "email_domain_not_allowed", "email domain is not allowed for sso")
		case errors.Is(err, auth.ErrOIDCEmailUnverified):
			writeError(w, stdhttp.StatusForbidden, "email_not_verified", "oidc email is not verified")
		case errors.Is(err, auth.ErrOIDCLinkDenied):
			writeError(w, stdhttp.StatusForbidden, "oidc_link_denied", "oidc account cannot be linked automatically")
		case errors.Is(err, auth.ErrInactiveUser):
			writeError(w, stdhttp.StatusForbidden, "inactive_user", "user account is inactive")
		case errors.Is(err, auth.ErrMFASetupRequired):
			writeError(w, stdhttp.StatusForbidden, "mfa_setup_required", "admin mfa is required before this account can sign in")
		default:
			writeError(w, stdhttp.StatusUnauthorized, "oidc_failed", "sso login failed")
		}
		return
	}

	_ = s.audit.LogRequest(r.Context(), r, &result.User.ID, "sso_login_succeeded", "auth", nil, details)
	if result.MFARequired {
		writeJSON(w, stdhttp.StatusOK, map[string]any{
			"requires_mfa":   true,
			"mfa_token":      result.MFAToken,
			"mfa_expires_at": result.MFAExpiresAt,
			"user":           result.User,
			"next":           next,
		})
		return
	}
	secure := s.requestSecure(r)
	s.auth.SetSessionCookie(w, result.Token, secure)
	s.auth.SetRefreshCookie(w, result.RefreshToken, secure)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"token": s.responseAuthToken(result.Token), "user": result.User, "next": next})
}

func (s *Server) handleRefreshSession(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	refreshToken := s.auth.RefreshTokenFromRequest(r)
	if refreshToken == "" {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing refresh token")
		return
	}
	result, err := s.auth.RefreshSession(r.Context(), refreshToken, s.requestMeta(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSessionRevoked), errors.Is(err, auth.ErrRefreshExpired), errors.Is(err, auth.ErrInvalidToken):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_refresh_token", "refresh token is invalid or expired")
		default:
			s.internalError(w, err)
		}
		return
	}
	secure := s.requestSecure(r)
	s.auth.SetSessionCookie(w, result.Token, secure)
	s.auth.SetRefreshCookie(w, result.RefreshToken, secure)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"token": s.responseAuthToken(result.Token), "user": result.User})
}

func (s *Server) handleVerifyMFA(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req verifyMFARequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	result, err := s.auth.CompleteMFA(r.Context(), req.MFAToken, req.Code, s.requestMeta(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_mfa_token", "mfa challenge is invalid or expired")
		case errors.Is(err, auth.ErrMFACodeInvalid):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_mfa_code", "invalid authenticator or recovery code")
		case errors.Is(err, auth.ErrRateLimited):
			writeError(w, stdhttp.StatusTooManyRequests, "rate_limited", "too many attempts, please start a new login")
		case errors.Is(err, auth.ErrInactiveUser):
			writeError(w, stdhttp.StatusUnauthorized, "invalid_mfa_token", "mfa challenge is invalid or expired")
		default:
			s.internalError(w, err)
		}
		return
	}
	s.writeLoginResult(w, r, result)
}

func (s *Server) writeLoginResult(w stdhttp.ResponseWriter, r *stdhttp.Request, result *auth.LoginResult) {
	if result == nil {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "login failed")
		return
	}
	if result.MFARequired {
		writeJSON(w, stdhttp.StatusOK, map[string]any{
			"requires_mfa":   true,
			"mfa_token":      result.MFAToken,
			"mfa_expires_at": result.MFAExpiresAt,
			"user":           result.User,
		})
		return
	}
	secure := s.requestSecure(r)
	s.auth.SetSessionCookie(w, result.Token, secure)
	s.auth.SetRefreshCookie(w, result.RefreshToken, secure)
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"token":              s.responseAuthToken(result.Token),
		"user":               result.User,
		"bootstrap_required": result.BootstrapRequired,
	})
}

func (s *Server) handleLogoutSession(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	token := s.auth.SessionTokenFromRequest(r)
	if token != "" {
		if claims, err := s.auth.ParseToken(token); err == nil && claims.SessionID != 0 {
			_ = s.auth.RevokeSession(r.Context(), claims.UserID, claims.SessionID)
		}
	}
	secure := s.requestSecure(r)
	s.auth.ClearSessionCookie(w, secure)
	s.auth.ClearRefreshCookie(w, secure)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true})
}

func (s *Server) responseAuthToken(token string) string {
	if s.cfg.ExposeAuthTokens || s.cfg.AllowInsecureDevMode {
		return token
	}
	return ""
}

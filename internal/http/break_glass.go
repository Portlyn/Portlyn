package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"portlyn/internal/auth"
)

type breakGlassState struct {
	mu        sync.Mutex
	enabled   bool
	token     string
	expiresAt time.Time
	used      bool
}

func (s *Server) handleBreakGlassLogin(w http.ResponseWriter, r *http.Request) {
	var req breakGlassLoginRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	if ok, status, code, message := s.validateBreakGlassRequest(r, req.Token); !ok {
		_ = s.audit.LogRequest(r.Context(), r, nil, "break_glass_login_failed", "auth", nil, map[string]any{
			"email":  req.Email,
			"reason": code,
		})
		writeError(w, status, code, message)
		return
	}

	result, err := s.auth.LoginBreakGlass(r.Context(), req.Email, req.Password, s.requestMeta(r))
	if err != nil {
		_ = s.audit.LogRequest(r.Context(), r, nil, "break_glass_login_failed", "auth", nil, map[string]any{
			"email":  req.Email,
			"reason": err.Error(),
		})
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many break-glass attempts")
		case errors.Is(err, auth.ErrInactiveUser):
			writeError(w, http.StatusForbidden, "inactive_user", "user account is inactive")
		case errors.Is(err, auth.ErrBreakGlassRejected):
			writeError(w, http.StatusForbidden, "break_glass_rejected", "break-glass is restricted to local admin accounts")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		default:
			s.internalError(w, err)
		}
		return
	}

	s.consumeBreakGlassToken()
	_ = s.audit.LogRequest(r.Context(), r, &result.User.ID, "break_glass_login_succeeded", "auth", nil, map[string]any{
		"email": req.Email,
	})
	s.writeLoginResult(w, r, result)
}

func (s *Server) validateBreakGlassRequest(r *http.Request, token string) (bool, int, string, string) {
	if !s.breakGlass.enabled {
		return false, http.StatusNotFound, "break_glass_disabled", "break-glass login is disabled"
	}
	if !s.breakGlassAllowedSource(r) {
		return false, http.StatusForbidden, "break_glass_forbidden_source", "break-glass login is not allowed from this source"
	}
	if !s.requestSecure(r) && !s.cfg.AllowInsecureDevMode {
		return false, http.StatusUpgradeRequired, "insecure_transport", "break-glass login requires secure transport"
	}
	if !s.breakGlassValidToken(token) {
		return false, http.StatusUnauthorized, "invalid_break_glass_token", "break-glass token is invalid or expired"
	}
	return true, 0, "", ""
}

func (s *Server) breakGlassAllowedSource(r *http.Request) bool {
	if !s.requestFromTrustedProxy(r) && (strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" || strings.TrimSpace(r.Header.Get("X-Real-Ip")) != "") {
		return false
	}
	addr, err := netip.ParseAddr(s.clientIPForRequest(r))
	if err != nil {
		return false
	}
	for _, raw := range s.cfg.BreakGlassAllowCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) breakGlassValidToken(token string) bool {
	s.breakGlass.mu.Lock()
	defer s.breakGlass.mu.Unlock()
	if !s.breakGlass.enabled || s.breakGlass.used || strings.TrimSpace(s.breakGlass.token) == "" {
		return false
	}
	if !s.breakGlass.expiresAt.IsZero() && time.Now().UTC().After(s.breakGlass.expiresAt) {
		return false
	}
	left := sha256.Sum256([]byte(strings.TrimSpace(token)))
	right := sha256.Sum256([]byte(strings.TrimSpace(s.breakGlass.token)))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (s *Server) consumeBreakGlassToken() {
	s.breakGlass.mu.Lock()
	defer s.breakGlass.mu.Unlock()
	s.breakGlass.used = true
	s.breakGlass.token = ""
}

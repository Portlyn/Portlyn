package http

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"portlyn/internal/auth"
)

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
		csp := "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; style-src 'self'; script-src 'self'; connect-src 'self' https:"
		if s.cfg.AllowInsecureDevMode {
			csp = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https: http:"
		}
		w.Header().Set("Content-Security-Policy", csp)
		if !s.cfg.AllowInsecureDevMode {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isNodeAuthPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		token := s.ensureCSRFCookie(w, r)
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		headerToken := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if headerToken == "" || token == "" || !hmac.Equal([]byte(headerToken), []byte(token)) || !s.validCSRFCookie(token) {
			writeError(w, http.StatusForbidden, "csrf_failed", "csrf validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(auth.CSRFCookieName); err == nil {
		token := strings.TrimSpace(cookie.Value)
		if s.validCSRFCookie(token) {
			return token
		}
	}
	token, err := s.newCSRFCookieValue(time.Now().UTC().Add(s.cfg.CSRFTokenTTL))
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.requestSecure(r),
		MaxAge:   int(s.cfg.CSRFTokenTTL.Seconds()),
	})
	return token
}

func (s *Server) newCSRFCookieValue(expiresAt time.Time) (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	payload := hex.EncodeToString(random) + "." + strconv.FormatInt(expiresAt.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(s.cfg.CSRFSecret))
	_, _ = mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + signature)), nil
}

func (s *Server) validCSRFCookie(value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return false
	}
	expiresAtUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Unix(expiresAtUnix, 0).Before(time.Now().UTC()) {
		return false
	}
	payload := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(s.cfg.CSRFSecret))
	_, _ = mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[2]), []byte(expected))
}

func (s *Server) isNodeAuthPath(path string) bool {
	normalized := normalizeNodeAuthPath(path)
	if normalized == "/api/v1/nodes/enroll" {
		return true
	}
	matches := nodeAuthPathPattern.FindStringSubmatch(normalized)
	if len(matches) < 2 {
		return false
	}
	_, err := strconv.ParseUint(matches[1], 10, 64)
	return err == nil
}

var nodeAuthPathPattern = regexp.MustCompile(`^/api/v1/nodes/([0-9]+)/(heartbeat|wg-bootstrap|tunnel-targets)$`)

func normalizeNodeAuthPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Path != "" {
		trimmed = parsed.Path
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(trimmed, "/"))
	return cleaned
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (s *Server) requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSafeMethod(r.Method) && s.cfg.RequestBodyLimitBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.RequestBodyLimitBytes)
		}
		next.ServeHTTP(w, r)
	})
}
func decodeStrictJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain a single json document")
	}
	return nil
}

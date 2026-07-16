package auth

import (
	"net/http"

	"portlyn/internal/domain"
)

func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, groupIDs, session, err := s.AuthenticateRequest(r.Context(), r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"missing or invalid session"}}`))
			return
		}

		ctx := ContextWithUser(r.Context(), user)
		ctx = ContextWithGroupIDs(ctx, groupIDs)
		if session != nil {
			ctx = ContextWithSession(ctx, session)
		}
		if LooksLikeAPIToken(bearerTokenFromHeader(r.Header.Get("Authorization"))) {
			ctx = ContextWithAPITokenAuth(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var bootstrapAllowedPaths = map[string]struct{}{
	"/api/v1/me":                              {},
	"/api/v1/me/account-setup":                {},
	"/api/v1/me/password":                     {},
	"/api/v1/me/mfa":                          {},
	"/api/v1/me/mfa/setup":                    {},
	"/api/v1/me/mfa/enable":                   {},
	"/api/v1/me/mfa/recovery-codes":           {},
	"/api/v1/me/passkeys":                     {},
	"/api/v1/me/passkeys/begin-registration":  {},
	"/api/v1/me/passkeys/finish-registration": {},
	"/api/v1/me/bootstrap/dismiss":            {},
	"/api/v1/auth/logout":                     {},
}

func bootstrapPathAllowed(path string) bool {
	if _, ok := bootstrapAllowedPaths[path]; ok {
		return true
	}
	return false
}

func (s *Service) RequireBootstrapComplete(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"missing auth context"}}`))
			return
		}
		if IsAPITokenAuth(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		session, _ := SessionFromContext(r.Context())
		if s.BootstrapAccessAllowed(r.Context(), user, session) {
			next.ServeHTTP(w, r)
			return
		}
		if bootstrapPathAllowed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"bootstrap_required","message":"complete account setup or enroll mfa before accessing this endpoint"}}`))
	})
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"missing auth context"}}`))
				return
			}
			if _, ok := allowed[user.Role]; !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"insufficient permissions"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CanRead(role string) bool {
	return role == domain.RoleAdmin || role == domain.RoleViewer
}

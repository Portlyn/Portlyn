package auth

import (
	"context"
	"errors"
	"log/slog"
	"portlyn/internal/domain"
	"portlyn/internal/store"
	"strings"
)

func (s *Service) StartOIDC(ctx context.Context, next string) (string, error) {
	authenticator, err := s.getOIDCAuthenticator(ctx)
	if err != nil {
		return "", err
	}
	return authenticator.StartURL(next)
}

func (s *Service) CompleteOIDC(ctx context.Context, code, state string) (*LoginResult, map[string]any, string, error) {
	authenticator, err := s.getOIDCAuthenticator(ctx)
	if err != nil {
		return nil, nil, "", err
	}

	claims, next, err := authenticator.Exchange(ctx, code, state)
	if err != nil {
		return nil, nil, "", err
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if authenticator.cfg.RequireVerifiedEmail && !claims.EmailVerified {
		return nil, map[string]any{"email": email, "next": next}, next, ErrOIDCEmailUnverified
	}
	if err := authenticator.ValidateAllowedEmailDomain(email); err != nil {
		return nil, map[string]any{"email": email, "next": next}, next, err
	}

	user, err := s.findOrCreateOIDCUser(ctx, claims, authenticator)
	if err != nil {
		return nil, nil, next, err
	}
	if !user.Active {
		return nil, nil, next, ErrInactiveUser
	}

	result, err := s.completePrimaryLogin(ctx, user, RequestMetadata{})
	if err != nil {
		return nil, nil, next, err
	}
	return result, map[string]any{
		"email":    user.Email,
		"issuer":   authenticator.Issuer(),
		"provider": authenticator.ProviderLabel(),
		"next":     next,
	}, next, nil
}

func (s *Service) findOrCreateOIDCUser(ctx context.Context, claims *OIDCIdentity, authenticator *OIDCAuthenticator) (*domain.User, error) {
	ref := strings.TrimSpace(claims.Subject)
	if ref == "" {
		return nil, ErrOIDCLinkDenied
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	role := domain.RoleViewer
	if authenticator.IsAdmin(claims.Claims) {
		role = domain.RoleAdmin
	}

	if ref != "" {
		user, err := s.users.GetByProviderRef(ctx, domain.AuthProviderOIDC, ref)
		if err == nil {
			user.Email = email
			user.Username = claims.PreferredUsername
			user.DisplayName = oidcDisplayName(claims)
			user.AuthIssuer = authenticator.Issuer()
			columns := map[string]any{
				"email":             email,
				"username":          claims.PreferredUsername,
				"display_name":      oidcDisplayName(claims),
				"auth_provider":     domain.AuthProviderOIDC,
				"auth_provider_ref": ref,
				"auth_issuer":       authenticator.Issuer(),
			}
			if authenticator.cfg.ManageRoles {
				s.logOIDCRoleChange(user, role)
				user.Role = role
				columns["role"] = role
			}
			if err := s.users.UpdateColumns(ctx, user.ID, columns); err != nil {
				return nil, err
			}
			user.AuthProvider = domain.AuthProviderOIDC
			user.AuthProviderRef = ref
			return user, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	if email != "" {
		user, err := s.users.GetByEmail(ctx, email)
		if err == nil {
			if !claims.EmailVerified {
				return nil, ErrOIDCLinkDenied
			}
			if user.AuthProvider == domain.AuthProviderLocal && !authenticator.cfg.AllowEmailLinking {
				return nil, ErrOIDCLinkDenied
			}
			if user.AuthProvider == domain.AuthProviderOIDC && user.AuthProviderRef != "" && ref != "" && user.AuthProviderRef != ref {
				return nil, ErrOIDCLinkDenied
			}
			user.DisplayName = oidcDisplayName(claims)
			user.Username = claims.PreferredUsername
			if user.AuthProvider == "" || user.AuthProvider == domain.AuthProviderLocal {
				user.AuthProvider = domain.AuthProviderOIDC
				user.AuthProviderRef = ref
			}
			user.AuthIssuer = authenticator.Issuer()
			if authenticator.cfg.ManageRoles {
				s.logOIDCRoleChange(user, role)
				user.Role = role
			}
			if err := s.users.Update(ctx, user); err != nil {
				return nil, err
			}
			return user, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	user := &domain.User{
		Email:           email,
		Role:            role,
		Active:          true,
		AuthProvider:    domain.AuthProviderOIDC,
		AuthProviderRef: ref,
		AuthIssuer:      authenticator.Issuer(),
		DisplayName:     oidcDisplayName(claims),
		Username:        claims.PreferredUsername,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func oidcDisplayName(claims *OIDCIdentity) string {
	if name := strings.TrimSpace(claims.Name); name != "" {
		return name
	}
	if username := strings.TrimSpace(claims.PreferredUsername); username != "" {
		return username
	}
	if email := strings.TrimSpace(claims.Email); email != "" {
		if at := strings.IndexByte(email, '@'); at > 0 {
			return email[:at]
		}
		return email
	}
	return ""
}

func (s *Service) logOIDCRoleChange(user *domain.User, newRole string) {
	if user == nil || user.Role == newRole {
		return
	}
	slog.Warn("oidc role change applied on login",
		"user_id", user.ID,
		"email", user.Email,
		"old_role", user.Role,
		"new_role", newRole,
		"admin_demotion", user.Role == domain.RoleAdmin && newRole != domain.RoleAdmin,
		"admin_promotion", user.Role != domain.RoleAdmin && newRole == domain.RoleAdmin,
	)
}

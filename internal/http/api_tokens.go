package http

import (
	stdhttp "net/http"
	"strings"
	"time"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
)

type createAPITokenRequest struct {
	Name          string `json:"name" validate:"required,min=1,max=200"`
	Role          string `json:"role" validate:"omitempty,oneof=admin viewer"`
	ExpiresInDays int    `json:"expires_in_days" validate:"omitempty,min=1,max=3650"`
}

type apiTokenResponse struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type createAPITokenResponse struct {
	apiTokenResponse
	Token string `json:"token"`
}

func toAPITokenResponse(t domain.APIToken) apiTokenResponse {
	status := "active"
	if t.RevokedAt != nil {
		status = "revoked"
	} else if t.ExpiresAt != nil && !t.ExpiresAt.After(time.Now().UTC()) {
		status = "expired"
	}
	return apiTokenResponse{
		ID:         t.ID,
		Name:       t.Name,
		Prefix:     t.Prefix,
		Role:       t.Role,
		Status:     status,
		LastUsedAt: t.LastUsedAt,
		ExpiresAt:  t.ExpiresAt,
		RevokedAt:  t.RevokedAt,
		CreatedAt:  t.CreatedAt,
	}
}

func (s *Server) handleListAPITokens(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.apiTokens.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]apiTokenResponse, 0, len(items))
	for i := range items {
		out = append(out, toAPITokenResponse(items[i]))
	}
	writeJSON(w, stdhttp.StatusOK, out)
}

func (s *Server) handleCreateAPIToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createAPITokenRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = domain.RoleViewer
	}
	prefix, token, hash, err := auth.GenerateAPIToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	item := &domain.APIToken{
		Name:        strings.TrimSpace(req.Name),
		Prefix:      prefix,
		TokenHash:   hash,
		Role:        role,
		CreatedByID: s.currentUserID(r),
	}
	if req.ExpiresInDays > 0 {
		expiresAt := time.Now().UTC().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		item.ExpiresAt = &expiresAt
	}
	if err := s.apiTokens.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "api_token", &item.ID, map[string]any{"name": item.Name, "role": item.Role})
	writeJSON(w, stdhttp.StatusCreated, createAPITokenResponse{apiTokenResponse: toAPITokenResponse(*item), Token: token})
}

func (s *Server) handleRevokeAPIToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.apiTokens.Revoke(r.Context(), id, time.Now().UTC()); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "revoke", "api_token", &id, map[string]any{})
	w.WriteHeader(stdhttp.StatusNoContent)
}

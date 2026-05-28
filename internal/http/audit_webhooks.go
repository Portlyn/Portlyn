package http

import (
	"crypto/rand"
	"encoding/hex"
	stdhttp "net/http"
	"strings"

	"portlyn/internal/domain"
)

type createAuditWebhookRequest struct {
	Name       string   `json:"name" validate:"required,min=2,max=255"`
	URL        string   `json:"url" validate:"required,url"`
	Format     string   `json:"format" validate:"omitempty,oneof=generic slack discord ntfy"`
	EventTypes []string `json:"event_types"`
	Active     *bool    `json:"active"`
}

type updateAuditWebhookRequest struct {
	Name       *string   `json:"name" validate:"omitempty,min=2,max=255"`
	URL        *string   `json:"url" validate:"omitempty,url"`
	Format     *string   `json:"format" validate:"omitempty,oneof=generic slack discord ntfy"`
	EventTypes *[]string `json:"event_types"`
	Active     *bool     `json:"active"`
	Secret     *string   `json:"secret"`
}

func (s *Server) handleListAuditWebhooks(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil {
		writeJSON(w, stdhttp.StatusOK, []domain.AuditWebhook{})
		return
	}
	items, err := s.auditWebhooks.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleCreateAuditWebhook(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webhooks_unavailable", "audit webhooks not initialized")
		return
	}
	var req createAuditWebhookRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	secret, err := randomWebhookSecret()
	if err != nil {
		s.internalError(w, err)
		return
	}
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "generic"
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	item := &domain.AuditWebhook{
		Name:            req.Name,
		URL:             req.URL,
		Format:          format,
		SecretEncrypted: secret,
		SecretPreview:   secret[:8],
		EventTypes:      domain.JSONStringSlice(req.EventTypes),
		Active:          active,
	}
	if err := s.auditWebhooks.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "create", "audit_webhook", &item.ID, map[string]any{"name": item.Name, "url": item.URL})
	writeJSON(w, stdhttp.StatusCreated, map[string]any{
		"webhook": item,
		"secret":  secret,
	})
}

func (s *Server) handleUpdateAuditWebhook(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webhooks_unavailable", "audit webhooks not initialized")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	item, err := s.auditWebhooks.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	var req updateAuditWebhookRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if req.Name != nil {
		item.Name = *req.Name
	}
	if req.URL != nil {
		item.URL = *req.URL
	}
	if req.Format != nil {
		item.Format = *req.Format
	}
	if req.EventTypes != nil {
		item.EventTypes = domain.JSONStringSlice(*req.EventTypes)
	}
	if req.Active != nil {
		item.Active = *req.Active
	}
	if req.Secret != nil {
		item.SecretEncrypted = *req.Secret
		if len(*req.Secret) >= 8 {
			item.SecretPreview = (*req.Secret)[:8]
		}
	}
	if err := s.auditWebhooks.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleDeleteAuditWebhook(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webhooks_unavailable", "audit webhooks not initialized")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.auditWebhooks.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "delete", "audit_webhook", &id, nil)
	w.WriteHeader(stdhttp.StatusNoContent)
}

func randomWebhookSecret() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Server) handleTestAuditWebhook(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil || s.webhookDispatch == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webhooks_unavailable", "audit webhooks not initialized")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	item, err := s.auditWebhooks.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	status, deliverErr := s.webhookDispatch.DeliverTest(*item)
	if deliverErr != nil {
		writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": false, "status": status, "error": deliverErr.Error()})
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true, "status": status})
}

func (s *Server) handleRotateAuditWebhookSecret(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.auditWebhooks == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webhooks_unavailable", "audit webhooks not initialized")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	item, err := s.auditWebhooks.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	secret, err := randomWebhookSecret()
	if err != nil {
		s.internalError(w, err)
		return
	}
	item.SecretEncrypted = secret
	item.SecretPreview = secret[:8]
	if err := s.auditWebhooks.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "rotate_secret", "audit_webhook", &id, nil)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"secret": secret})
}

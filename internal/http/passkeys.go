package http

import (
	stdhttp "net/http"
	"strings"

	"portlyn/internal/auth"
)

func (s *Server) handleListPasskeys(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "")
		return
	}
	if s.webauthn == nil {
		writeJSON(w, stdhttp.StatusOK, []any{})
		return
	}
	items, err := s.webauthn.ListCredentials(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleBeginPasskeyRegistration(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "")
		return
	}
	if s.webauthn == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webauthn_unavailable", "")
		return
	}
	result, err := s.webauthn.BeginRegistration(r.Context(), user.ID)
	if err != nil {
		writeError(w, stdhttp.StatusBadRequest, "webauthn_error", err.Error())
		return
	}
	writeJSON(w, stdhttp.StatusOK, result)
}

type finishPasskeyRegistrationRequest struct {
	SessionID string `json:"session_id" validate:"required"`
	Label     string `json:"label"`
}

func (s *Server) handleFinishPasskeyRegistration(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.webauthn == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webauthn_unavailable", "")
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	label := strings.TrimSpace(r.URL.Query().Get("label"))
	if sessionID == "" {
		writeError(w, stdhttp.StatusBadRequest, "missing_session", "session_id query parameter required")
		return
	}
	credential, err := s.webauthn.FinishRegistration(r.Context(), sessionID, label, r)
	if err != nil {
		writeError(w, stdhttp.StatusBadRequest, "webauthn_error", err.Error())
		return
	}
	user, _ := auth.UserFromContext(r.Context())
	if user != nil {
		_ = s.audit.LogRequest(r.Context(), r, &user.ID, "passkey_registered", "user_credential", &credential.ID, map[string]any{"label": credential.Label})
	}
	writeJSON(w, stdhttp.StatusCreated, credential)
}

func (s *Server) handleDeletePasskey(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "")
		return
	}
	if s.webauthn == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "webauthn_unavailable", "")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.webauthn.DeleteCredential(r.Context(), user.ID, id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, &user.ID, "passkey_deleted", "user_credential", &id, nil)
	w.WriteHeader(stdhttp.StatusNoContent)
}

package http

import (
	"errors"
	stdhttp "net/http"
	"strings"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

func (s *Server) handleListUsers(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.users.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleGetUser(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleCreateUser(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createUserRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	if _, err := s.users.GetByEmail(r.Context(), req.Email); err == nil {
		writeError(w, stdhttp.StatusConflict, "email_in_use", "email is already in use")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, err)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.internalError(w, err)
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	user := &domain.User{
		Email:              strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash:       hash,
		Role:               req.Role,
		Active:             active,
		MustChangePassword: true,
		AuthProvider:       domain.AuthProviderLocal,
	}
	if err := s.users.Create(r.Context(), user); err != nil {
		s.internalError(w, err)
		return
	}
	s.auth.InvalidateUser(user.ID)

	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "user", &user.ID, map[string]any{
		"email":  user.Email,
		"role":   user.Role,
		"active": user.Active,
	})
	writeJSON(w, stdhttp.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := s.loadUser(w, r)
	if !ok {
		return
	}

	var req updateUserRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	originalRole := user.Role
	originalActive := user.Active

	if req.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		if existing, err := s.users.GetByEmail(r.Context(), email); err == nil && existing.ID != user.ID {
			writeError(w, stdhttp.StatusConflict, "email_in_use", "email is already in use")
			return
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, err)
			return
		}
		user.Email = email
	}

	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.Active != nil {
		user.Active = *req.Active
	}

	if err := s.preventRemovingLastActiveAdmin(r, user.ID, originalRole, originalActive, user.Role, user.Active); err != nil {
		writeError(w, stdhttp.StatusConflict, "last_admin_protected", err.Error())
		return
	}

	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			s.internalError(w, err)
			return
		}
		user.PasswordHash = hash
		user.MustChangePassword = true
	}

	if err := s.users.Update(r.Context(), user); err != nil {
		s.internalError(w, err)
		return
	}
	s.auth.InvalidateUser(user.ID)

	if originalRole != user.Role {
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "role_change", "user", &user.ID, map[string]any{
			"from": originalRole,
			"to":   user.Role,
		})
	}
	if originalActive && !user.Active {
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "deactivate", "user", &user.ID, map[string]any{
			"email": user.Email,
		})
	}
	if !originalActive && user.Active {
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "activate", "user", &user.ID, map[string]any{
			"email": user.Email,
		})
	}

	writeJSON(w, stdhttp.StatusOK, user)
}

func (s *Server) handleCompleteAccountSetup(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing auth context")
		return
	}

	var req completeAccountSetupRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	updated, err := s.auth.CompleteAccountSetup(r.Context(), user.ID, req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, stdhttp.StatusConflict, "email_in_use", "email is already in use")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, stdhttp.StatusBadRequest, "invalid_account_setup", "a valid email and password are required")
		default:
			s.internalError(w, err)
		}
		return
	}

	_ = s.audit.Log(r.Context(), &user.ID, "account_setup_completed", "user", &user.ID, map[string]any{
		"email": updated.Email,
	})
	writeJSON(w, stdhttp.StatusOK, updated)
}

func (s *Server) handleChangeOwnPassword(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing auth context")
		return
	}
	var req changePasswordRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if err := s.auth.ChangeOwnPassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, stdhttp.StatusBadRequest, "invalid_current_password", "current password is incorrect")
		default:
			s.internalError(w, err)
		}
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, &user.ID, "password_changed", "user", &user.ID, nil)
	writeJSON(w, stdhttp.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteUser(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	user, ok := s.loadUser(w, r)
	if !ok {
		return
	}

	if err := s.preventRemovingLastActiveAdmin(r, user.ID, user.Role, user.Active, "", false); err != nil {
		writeError(w, stdhttp.StatusConflict, "last_admin_protected", err.Error())
		return
	}

	if err := s.users.Delete(r.Context(), user.ID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	s.auth.InvalidateUser(user.ID)

	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "user", &user.ID, map[string]any{
		"email": user.Email,
	})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) preventRemovingLastActiveAdmin(r *stdhttp.Request, userID uint, originalRole string, originalActive bool, nextRole string, nextActive bool) error {
	if originalRole != domain.RoleAdmin || !originalActive {
		return nil
	}
	if nextRole == domain.RoleAdmin && nextActive {
		return nil
	}

	count, err := s.users.CountActiveAdmins(r.Context(), &userID)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("the last active admin cannot be removed, deactivated, or demoted")
	}
	return nil
}

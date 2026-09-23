package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/domain"
)

func TestAccountSetupOnlyWhilePasswordChangeRequired(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	adminToken := loginAsAdmin(t, server, "setup-admin@example.com", "StrongPass123!")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/account-setup", bytes.NewBufferString(`{"email":"attacker@example.com","password":"AttackerPass123!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected account setup to be rejected after setup, got %d: %s", rec.Code, rec.Body.String())
	}
	user, err := server.users.GetByEmail(context.Background(), "setup-admin@example.com")
	if err != nil {
		t.Fatalf("expected original email to remain: %v", err)
	}
	if err := server.users.UpdateColumns(context.Background(), user.ID, map[string]any{"must_change_password": true}); err != nil {
		t.Fatalf("flag password change: %v", err)
	}
	server.auth.InvalidateUser(user.ID)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/me/account-setup", bytes.NewBufferString(`{"email":"setup-new@example.com","password":"NewStrongPass123!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected account setup to succeed while required, got %d: %s", rec.Code, rec.Body.String())
	}
	updated, err := server.users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if updated.Email != "setup-new@example.com" || updated.MustChangePassword || updated.Role != domain.RoleAdmin || !updated.Active {
		t.Fatalf("unexpected user after setup: %+v", updated)
	}
}

func TestAPITokenRejectedOnSelfServiceRoutes(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	server.auth.SetAPITokenStore(server.apiTokens)

	adminToken := loginAsAdmin(t, server, "token-owner@example.com", "StrongPass123!")

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/api-tokens", bytes.NewBufferString(`{"name":"monitoring","role":"viewer"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+adminToken)
	createRec := httptest.NewRecorder()
	server.Router().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create api token: %d %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("decode api token response: %v %s", err, createRec.Body.String())
	}

	blocked := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/me/account-setup", `{"email":"attacker@example.com","password":"AttackerPass123!"}`},
		{http.MethodPost, "/api/v1/me/password", `{"current_password":"x","new_password":"AttackerPass123!"}`},
		{http.MethodGet, "/api/v1/me/mfa", ""},
		{http.MethodPost, "/api/v1/me/mfa/setup", ""},
		{http.MethodPost, "/api/v1/me/passkeys/begin-registration", ""},
		{http.MethodPost, "/api/v1/me/passkeys/finish-registration", "{}"},
		{http.MethodGet, "/api/v1/me/passkeys", ""},
		{http.MethodGet, "/api/v1/sessions", ""},
		{http.MethodPost, "/api/v1/sessions/revoke-all", ""},
		{http.MethodPost, "/api/v1/route-auth/session-bridge-token", "{}"},
	}
	for _, tc := range blocked {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+created.Token)
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected 403 for api token, got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
	listReq.Header.Set("Authorization", "Bearer "+created.Token)
	listRec := httptest.NewRecorder()
	server.Router().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected api token to keep read access, got %d: %s", listRec.Code, listRec.Body.String())
	}

	sessionsReq := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	sessionsReq.Header.Set("Authorization", "Bearer "+adminToken)
	sessionsRec := httptest.NewRecorder()
	server.Router().ServeHTTP(sessionsRec, sessionsReq)
	if sessionsRec.Code != http.StatusOK {
		t.Fatalf("expected session auth to keep self-service access, got %d: %s", sessionsRec.Code, sessionsRec.Body.String())
	}
}

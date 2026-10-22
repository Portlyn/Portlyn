package http

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/auth"
)

func TestUpdateAuthSettingsAllowsEmptySMTPFromEmail(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	token := loginAsAdmin(t, server, "settings-admin@example.com", "StrongPass123!")

	patch := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/settings/auth", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		csrf := mustIssueCSRFToken(t, server)
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		return rec
	}

	if rec := patch(`{"smtp_enabled":false,"smtp_from_email":""}`); rec.Code != http.StatusOK {
		t.Fatalf("expected empty from email with smtp disabled to save, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := patch(`{"smtp_from_email":"not-an-email"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid from email to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := patch(`{"smtp_enabled":true,"smtp_host":"mail.example.com","smtp_port":587,"smtp_from_email":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected enabled smtp without from email to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

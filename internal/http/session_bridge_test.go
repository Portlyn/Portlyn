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

func requestSessionBridge(t *testing.T, server *Server, token, host string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"host": host})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/route-auth/session-bridge-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	return rec
}

func TestSessionBridgeIsScopedToServiceHost(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()

	token := loginAsAdmin(t, server, "bridge-admin@example.com", "StrongPass123!")

	zone := &domain.Domain{Name: "example.com", Type: "manual"}
	if err := server.domains.Create(ctx, zone); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	for _, item := range []*domain.Service{
		{Name: "app", DomainID: zone.ID, Subdomain: "app", Path: "/", TargetURL: "http://127.0.0.1:9000", TLSMode: "auto", AccessMode: domain.AccessModeAuthenticated, Enabled: true},
		{Name: "open", DomainID: zone.ID, Subdomain: "open", Path: "/", TargetURL: "http://127.0.0.1:9001", TLSMode: "auto", AccessMode: domain.AccessModePublic, Enabled: true},
	} {
		if err := server.services.Create(ctx, item); err != nil {
			t.Fatalf("create service: %v", err)
		}
	}

	for _, host := range []string{"attacker.example", "open.example.com", "localhost"} {
		if rec := requestSessionBridge(t, server, token, host); rec.Code != http.StatusForbidden {
			t.Fatalf("host %q: expected 403, got %d: %s", host, rec.Code, rec.Body.String())
		}
	}

	rec := requestSessionBridge(t, server, token, "APP.example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected bridge token, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := server.auth.ParseSessionBridgeToken(resp.Token)
	if err != nil {
		t.Fatalf("parse bridge: %v", err)
	}
	if claims.Host != "app.example.com" || claims.HostToken == "" || claims.HostToken == token {
		t.Fatalf("unexpected bridge claims: %+v", claims)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+claims.HostToken)
	meRec := httptest.NewRecorder()
	server.Router().ServeHTTP(meRec, req)
	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("admin api must reject host token, got %d", meRec.Code)
	}

	if _, _, _, err := server.auth.AuthenticateHostSessionToken(ctx, claims.HostToken, "app.example.com"); err != nil {
		t.Fatalf("host token should work on its host: %v", err)
	}
	if _, _, _, err := server.auth.AuthenticateHostSessionToken(ctx, claims.HostToken, "open.example.com"); err == nil {
		t.Fatal("host token must not work on another host")
	}
	if !server.auth.IsPortlynCredential(claims.HostToken) || !server.auth.IsPortlynCredential(token) {
		t.Fatal("expected portlyn tokens to be recognised")
	}
	if server.auth.IsPortlynCredential("upstream-own-token") {
		t.Fatal("foreign bearer tokens must not be treated as portlyn credentials")
	}

	_, _, session, err := server.auth.AuthenticateAccessToken(ctx, token)
	if err != nil || session == nil {
		t.Fatalf("load session: %v", err)
	}
	if err := server.auth.RevokeSession(ctx, session.UserID, session.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, _, err := server.auth.AuthenticateHostSessionToken(ctx, claims.HostToken, "app.example.com"); err == nil {
		t.Fatal("host token must stop working once its session is revoked")
	}
}

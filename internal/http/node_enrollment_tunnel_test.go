package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/domain"
	"portlyn/internal/tunnel"
)

func TestNodeEnrollmentKeepsTokenWhileTunnelIsOff(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()
	server.tunnel = tunnel.NewManager(server.nodes, server.clients, server.appSettings)

	plainToken := "ENROLLTOKEN5678"
	item := &domain.NodeEnrollmentToken{Name: "install token", TokenHash: hashOpaqueToken(plainToken), SingleUse: true, Active: true}
	if err := server.enrollmentTokens.Create(ctx, item); err != nil {
		t.Fatalf("create enrollment token: %v", err)
	}

	enroll := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewBufferString(`{"token":"`+plainToken+`","name":"edge-4","version":"1.0.0"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		return rec
	}

	if rec := enroll(); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 while the tunnel is off, got %d: %s", rec.Code, rec.Body.String())
	}
	nodes, err := server.nodes.List(ctx)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected no half-enrolled node, got %d", len(nodes))
	}

	settings, err := server.tunnel.EnsureServerKey(ctx)
	if err != nil {
		t.Fatalf("ensure server key: %v", err)
	}
	settings.TunnelEnabled = true
	settings.TunnelServerEndpoint = "hub.example.com"
	if err := server.appSettings.Upsert(ctx, settings); err != nil {
		t.Fatalf("enable tunnel: %v", err)
	}
	if rec := enroll(); rec.Code != http.StatusCreated {
		t.Fatalf("expected the same token to enroll once the tunnel is on, got %d: %s", rec.Code, rec.Body.String())
	}
}

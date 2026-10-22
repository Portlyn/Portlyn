package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/domain"
)

func TestSessionBridgeAllowsWildcardHostsButPrefersExactOnes(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()

	dom := &domain.Domain{Name: "netinfo.ch", Type: "root"}
	if err := server.domains.Create(ctx, dom); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	for _, item := range []*domain.Service{
		{Name: "catch all", DomainID: dom.ID, Subdomain: "*", Path: "/", TargetURL: "http://10.0.0.1", TLSMode: "offload", AccessMode: domain.AccessModeAuthenticated, Enabled: true},
		{Name: "admins only", DomainID: dom.ID, Subdomain: "isolation", Path: "/", TargetURL: "http://10.0.0.2", TLSMode: "offload", AccessMode: domain.AccessModeRestricted, AllowedRoles: domain.JSONStringSlice{domain.RoleAdmin}, Enabled: true},
	} {
		if err := server.services.Create(ctx, item); err != nil {
			t.Fatalf("create service: %v", err)
		}
	}

	viewer := &domain.User{ID: 9, Email: "viewer@example.com", Role: domain.RoleViewer, Active: true}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/route-auth/session-bridge-token", nil)
	cases := map[string]bool{
		"allowed.netinfo.ch":   true,
		"isolation.netinfo.ch": false,
		"a.b.netinfo.ch":       false,
	}
	for host, want := range cases {
		got, err := server.sessionBridgeHostAllowed(req, viewer, nil, host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got != want {
			t.Errorf("%s: expected %v, got %v", host, want, got)
		}
	}
}

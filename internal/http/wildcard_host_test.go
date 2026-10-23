package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		{Name: "catch all", DomainID: dom.ID, Subdomain: "*", Path: "/", TargetURL: "http://10.0.0.1", TLSMode: "offload", AccessMode: domain.AccessModeAuthenticated, Enabled: true, LoginHosts: domain.JSONStringSlice{"allowed"}},
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
		"blog.netinfo.ch":      false,
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

func TestRouteAccessBridgeRefusesUnlistedWildcardSubdomain(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	service := &domain.Service{
		ID:         7,
		Subdomain:  "*",
		Domain:     domain.Domain{Name: "netinfo.ch"},
		LoginHosts: domain.JSONStringSlice{"allowed"},
	}
	for returnTo, wantErr := range map[string]bool{
		"https://allowed.netinfo.ch/x": false,
		"https://blog.netinfo.ch/x":    true,
		"https://evil.example/x":       true,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/route-auth/pin?returnTo="+url.QueryEscape(returnTo), nil)
		target, err := server.buildRouteAccessBridgeURL(req, service, domain.AccessMethodPIN, "")
		if wantErr != (err != nil) {
			t.Fatalf("%s: expected error %v, got %v", returnTo, wantErr, err)
		}
		if err == nil && !strings.Contains(target, "://allowed.netinfo.ch/_portlyn/route-access?") {
			t.Fatalf("%s: unexpected bridge target %s", returnTo, target)
		}
	}
}

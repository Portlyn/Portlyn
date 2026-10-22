package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/routing"
)

func TestAccessRulePathMatching(t *testing.T) {
	rules, err := compileAccessRules([]domain.AccessRule{
		{Name: "pub", Action: domain.AccessRuleAllow, Paths: []string{"/pub/*/pub"}},
		{Name: "admin", Action: domain.AccessRuleAuthenticate, Paths: []string{"/admin/"}},
		{Name: "deny", Action: domain.AccessRuleDeny, Paths: []string{"deny"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.5")
	cases := map[string]string{
		"/pub/1/pub":       "pub",
		"/pub/1/pub/x.css": "pub",
		"/pub/1":           "",
		"/PUB/1/pub":       "",
		"/admin":           "admin",
		"/admin/users":     "admin",
		"/Admin/users":     "admin",
		"/administrator":   "",
		"/deny":            "deny",
		"/":                "",
	}
	for path, want := range cases {
		got := ""
		if rule := matchAccessRule(rules, ip, path); rule != nil {
			got = rule.Name
		}
		if got != want {
			t.Errorf("path %q: expected rule %q, got %q", path, want, got)
		}
	}
}

func TestAccessRuleSourceMatching(t *testing.T) {
	rules, err := compileAccessRules([]domain.AccessRule{
		{Name: "office", Action: domain.AccessRuleAllow, Sources: []string{"8.8.8.0/24", "!8.8.8.8"}},
		{Name: "not-office", Action: domain.AccessRuleDeny, Sources: []string{"!10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cases := map[string]string{
		"8.8.8.1":  "office",
		"8.8.8.8":  "not-office",
		"10.1.2.3": "",
		"1.1.1.1":  "not-office",
	}
	for raw, want := range cases {
		got := ""
		if rule := matchAccessRule(rules, netip.MustParseAddr(raw), "/"); rule != nil {
			got = rule.Name
		}
		if got != want {
			t.Errorf("ip %s: expected rule %q, got %q", raw, want, got)
		}
	}
}

func TestCompileAccessRulesRejectsBadInput(t *testing.T) {
	if _, err := compileAccessRules([]domain.AccessRule{{Action: "maybe"}}); err == nil {
		t.Fatal("expected unknown action to be rejected")
	}
	if _, err := compileAccessRules([]domain.AccessRule{{Action: domain.AccessRuleDeny, Sources: []string{"!nope"}}}); err == nil {
		t.Fatal("expected invalid source to be rejected")
	}
}

func TestProxyAppliesAccessRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	manager := NewManager(newFakeRoutingStore(routing.RouteConfig{
		ID:              "1",
		ServiceID:       1,
		ServiceName:     "svc",
		Host:            "app.example.com",
		Path:            "/",
		TargetURL:       upstream.URL,
		Service:         domain.Service{ID: 1, Name: "svc", Domain: domain.Domain{Name: "app.example.com"}},
		EffectivePolicy: domain.AccessPolicy{AccessMode: domain.AccessModeAuthenticated},
		AccessRules: []domain.AccessRule{
			{Name: "public files", Action: domain.AccessRuleAllow, Paths: []string{"/pub"}},
			{Name: "everything else", Action: domain.AccessRuleDeny},
		},
	}), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})

	serve := func(path, accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
		req.Host = "app.example.com"
		req.RemoteAddr = "203.0.113.5:12345"
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		manager.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := serve("/pub/file.txt", ""); rec.Code != http.StatusOK || rec.Body.String() != "upstream-ok" {
		t.Fatalf("expected allow rule to skip authentication, got %d: %s", rec.Code, rec.Body.String())
	}
	rec := serve("/secret", "*/*")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected json 403 for non-browser deny, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = serve("/secret", "text/html,application/xhtml+xml")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Access denied") {
		t.Fatalf("expected html 403 for browser deny, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("deny must not redirect")
	}
}

func TestAccessRulesSeePastPathParameters(t *testing.T) {
	rules, err := compileAccessRules([]domain.AccessRule{
		{Name: "pub", Action: domain.AccessRuleAllow, Paths: []string{"/pub"}},
		{Name: "admin", Action: domain.AccessRuleDeny, Paths: []string{"/admin", "/actuator"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.5")
	cases := map[string]string{
		"/admin;x":          "admin",
		"/actuator;x/env":   "admin",
		"/ADMIN;jsessionid": "admin",
		"/pub/a.txt":        "pub",
		"/pub;x/a.txt":      "",
		"/x;/pub":           "",
	}
	for path, want := range cases {
		got := ""
		if rule := matchAccessRule(rules, ip, path); rule != nil {
			got = rule.Name
		}
		if got != want {
			t.Errorf("path %q: expected rule %q, got %q", path, want, got)
		}
	}
}

func TestProxyDenyRuleCannotBeSkippedWithPathParameters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	manager := NewManager(newFakeRoutingStore(routing.RouteConfig{
		ID:              "1",
		ServiceID:       1,
		ServiceName:     "svc",
		Host:            "app.example.com",
		Path:            "/",
		TargetURL:       upstream.URL,
		Service:         domain.Service{ID: 1, Name: "svc", Domain: domain.Domain{Name: "app.example.com"}},
		EffectivePolicy: domain.AccessPolicy{AccessMode: domain.AccessModePublic},
		AccessRules:     []domain.AccessRule{{Name: "no admin", Action: domain.AccessRuleDeny, Paths: []string{"/admin"}}},
	}), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})

	for _, path := range []string{"/admin", "/admin;x", "/admin%3Bx", "/admin;jsessionid=1/users"} {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
		req.Host = "app.example.com"
		req.RemoteAddr = "203.0.113.5:12345"
		rec := httptest.NewRecorder()
		manager.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected %s to be denied, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

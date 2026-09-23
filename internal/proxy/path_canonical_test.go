package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/routing"
)

func TestCanonicalRequestPath(t *testing.T) {
	backslash := string(rune(92))

	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "/", true},
		{"/", "/", true},
		{"/app", "/app", true},
		{"/app/", "/app/", true},
		{"//app//sub/", "/app/sub/", true},
		{"/app" + backslash + "sub", "/app/sub", true},
		{"/app;jsessionid=1/x", "/app;jsessionid=1/x", true},
		{"/.well-known/acme", "/.well-known/acme", true},
		{"/a..b/c", "/a..b/c", true},
		{"/x/../admin", "", false},
		{"/x/./admin", "", false},
		{"/..", "", false},
		{"/x/..;/admin", "", false},
		{"/x/.;a=b/admin", "", false},
		{"/x" + backslash + ".." + backslash + "admin", "", false},
	}

	for _, tc := range cases {
		got, ok := canonicalRequestPath(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("canonicalRequestPath(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestStripPathParams(t *testing.T) {
	cases := map[string]string{
		"/admin;x":           "/admin",
		"/a;b=c/d;e":         "/a/d",
		"/plain/path":        "/plain/path",
		"/app;jsessionid=1/": "/app/",
	}
	for in, want := range cases {
		if got := stripPathParams(in); got != want {
			t.Errorf("stripPathParams(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHandlerRejectsPathsThatEscapeTheMatchedRoute(t *testing.T) {
	var seenPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.EscapedPath()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	route := func(id string, serviceID uint, path, mode string) routing.RouteConfig {
		return routing.RouteConfig{
			ID:              id,
			ServiceID:       serviceID,
			ServiceName:     "svc" + id,
			Host:            "app.example.com",
			Path:            path,
			TargetURL:       upstream.URL,
			Service:         domain.Service{ID: serviceID, Name: "svc" + id, Domain: domain.Domain{Name: "app.example.com"}},
			EffectivePolicy: domain.AccessPolicy{AccessMode: mode},
		}
	}
	manager := NewManager(newFakeRoutingStore(
		route("1", 1, "/", domain.AccessModePublic),
		route("2", 2, "/admin", domain.AccessModeRestricted),
	), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})

	serve := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatalf("parse %q: %v", target, err)
		}
		req.URL.Path = parsed.Path
		req.URL.RawPath = parsed.RawPath
		req.Host = "app.example.com"
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		manager.Handler().ServeHTTP(rec, req)
		return rec
	}

	for _, target := range []string{"/x/../admin/users", "/x/%2e%2e/admin/users", "/x/..;/admin", "/admin;x/users"} {
		if rec := serve(target); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", target, rec.Code, rec.Body.String())
		}
	}

	seenPath = ""
	if rec := serve("/app;jsessionid=1/page"); rec.Code != http.StatusOK {
		t.Fatalf("expected path params within one route to pass, got %d: %s", rec.Code, rec.Body.String())
	}
	if seenPath != "/app;jsessionid=1/page" {
		t.Fatalf("unexpected upstream path %q", seenPath)
	}

	seenPath = ""
	if rec := serve("/docs//guide//"); rec.Code != http.StatusOK {
		t.Fatalf("expected proxy success, got %d: %s", rec.Code, rec.Body.String())
	}
	if seenPath != "/docs/guide/" {
		t.Fatalf("expected the authorized path upstream, got %q", seenPath)
	}
}

func TestValidRouteHost(t *testing.T) {
	valid := []string{"app.example.com", "localhost", "a.b"}
	invalid := []string{"", strings.Repeat("a", 254), strings.Repeat("a.", 127) + "b", "a..b", ".a", "a.", strings.Repeat(".", 500)}
	for _, host := range valid {
		if !validRouteHost(host) {
			t.Errorf("expected %q to be valid", host)
		}
	}
	for i, host := range invalid {
		if validRouteHost(host) {
			t.Errorf("case %d: expected host to be rejected", i)
		}
	}
}

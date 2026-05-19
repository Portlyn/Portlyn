package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/routing"
)

type fakeRoutingStore struct {
	mu           sync.Mutex
	getHostCalls int
	routesByHost map[string][]routing.RouteConfig
	routesByID   map[string]routing.RouteConfig
}

func newFakeRoutingStore(routes ...routing.RouteConfig) *fakeRoutingStore {
	store := &fakeRoutingStore{
		routesByHost: make(map[string][]routing.RouteConfig),
		routesByID:   make(map[string]routing.RouteConfig),
	}
	for _, route := range routes {
		store.routesByHost[normalizeHost(route.Host)] = append(store.routesByHost[normalizeHost(route.Host)], route)
		store.routesByID[route.ID] = route
	}
	return store
}

func (s *fakeRoutingStore) GetRoutesForHost(_ context.Context, host string) ([]routing.RouteConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getHostCalls++
	items := s.routesByHost[normalizeHost(host)]
	out := make([]routing.RouteConfig, len(items))
	copy(out, items)
	return out, nil
}

func (s *fakeRoutingStore) ListRoutes(context.Context, routing.RouteFilter) ([]routing.RouteConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]routing.RouteConfig, 0, len(s.routesByID))
	for _, item := range s.routesByID {
		out = append(out, item)
	}
	return out, nil
}

func (s *fakeRoutingStore) GetRouteByID(_ context.Context, id string) (*routing.RouteConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.routesByID[id]
	if !ok {
		return nil, nil
	}
	copyItem := item
	return &copyItem, nil
}

func (s *fakeRoutingStore) UpsertRoute(_ context.Context, route routing.RouteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routesByID[route.ID] = route
	s.routesByHost[normalizeHost(route.Host)] = []routing.RouteConfig{route}
	return nil
}

func (s *fakeRoutingStore) DeleteRoute(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if route, ok := s.routesByID[id]; ok {
		delete(s.routesByID, id)
		delete(s.routesByHost, normalizeHost(route.Host))
	}
	return nil
}

func (s *fakeRoutingStore) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getHostCalls
}

func TestStripRoutePrefix(t *testing.T) {
	tests := []struct {
		name        string
		routePath   string
		requestPath string
		want        string
	}{
		{name: "root route unchanged", routePath: "/", requestPath: "/favicon.ico", want: "/favicon.ico"},
		{name: "exact prefix becomes root", routePath: "/app", requestPath: "/app", want: "/"},
		{name: "nested path strips prefix", routePath: "/app", requestPath: "/app/favicon.ico", want: "/favicon.ico"},
		{name: "non matching path unchanged", routePath: "/app", requestPath: "/favicon.ico", want: "/favicon.ico"},
		{name: "empty path normalized", routePath: "/app", requestPath: "", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripRoutePrefix(tt.routePath, tt.requestPath)
			if got != tt.want {
				t.Fatalf("stripRoutePrefix(%q, %q) = %q, want %q", tt.routePath, tt.requestPath, got, tt.want)
			}
		})
	}
}

func TestManagerResolveRoutesUsesCache(t *testing.T) {
	ctx := context.Background()
	store := newFakeRoutingStore(testRouteConfig("1", "example.com", "/app"))
	manager := NewManager(store, NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})

	if _, err := manager.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if _, err := manager.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	if got := store.Calls(); got != 1 {
		t.Fatalf("expected store to be called once, got %d", got)
	}
}

func TestManagerInvalidatesRoutesFromBus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryConfigBus()
	cache := NewInMemoryConfigCache()
	store := newFakeRoutingStore(testRouteConfig("1", "example.com", "/app"))
	publisher := NewManager(store, cache, bus, nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})
	subscriber := NewManager(store, cache, bus, nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})
	subscriber.Start(ctx)

	if _, err := subscriber.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}
	if got := store.Calls(); got != 1 {
		t.Fatalf("expected first store call, got %d", got)
	}

	if err := publisher.InvalidateHost(ctx, "example.com"); err != nil {
		t.Fatalf("invalidate host failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if _, err := subscriber.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("resolve after invalidation failed: %v", err)
	}
	if got := store.Calls(); got != 2 {
		t.Fatalf("expected store to be queried again after invalidation, got %d calls", got)
	}
}

func TestManagerInvalidateHostClearsCaches(t *testing.T) {
	ctx := context.Background()
	store := newFakeRoutingStore(testRouteConfig("1", "example.com", "/"))
	cache := NewInMemoryConfigCache()
	manager := NewManager(store, cache, NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
	})

	if _, err := manager.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}
	if err := manager.InvalidateHost(ctx, "example.com"); err != nil {
		t.Fatalf("invalidate host failed: %v", err)
	}
	if _, err := manager.resolveRoutesForHost(ctx, "example.com"); err != nil {
		t.Fatalf("resolve after invalidate failed: %v", err)
	}
	if got := store.Calls(); got != 2 {
		t.Fatalf("expected second store fetch after explicit invalidation, got %d", got)
	}
}

func TestManagerServesBootstrapAdminHosts(t *testing.T) {
	adminUI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer adminUI.Close()

	manager := NewManager(newFakeRoutingStore(), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:         time.Hour,
		LocalCacheCapacity:    16,
		BootstrapAdminEnabled: true,
		AdminUITargetURL:      adminUI.URL,
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/login", nil)
	req.Host = "127.0.0.1"
	recorder := httptest.NewRecorder()

	manager.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected bootstrap admin host to be served by admin UI, got %d", recorder.Code)
	}
}

func TestSanitizePortlynIdentityHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Portlyn-User-Email", "spoof@example.com")
	headers.Set("X-Portlyn-User-Role", "admin")
	headers.Set("X-Portlyn-User-ID", "99")
	headers.Set("X-Portlyn-Client-Cert-SHA256", "deadbeef")
	headers.Set("X-Forwarded-For", "203.0.113.8")

	sanitizePortlynIdentityHeaders(headers)

	if headers.Get("X-Portlyn-User-Email") != "" || headers.Get("X-Portlyn-User-Role") != "" || headers.Get("X-Portlyn-User-ID") != "" || headers.Get("X-Portlyn-Client-Cert-SHA256") != "" {
		t.Fatal("expected all X-Portlyn identity headers to be removed")
	}
	if headers.Get("X-Forwarded-For") == "" {
		t.Fatal("expected unrelated headers to remain untouched")
	}
}

func testRouteConfig(id, host, path string) routing.RouteConfig {
	return routing.RouteConfig{
		ID:          id,
		ServiceID:   1,
		ServiceName: "svc",
		Host:        host,
		Path:        path,
		TargetURL:   "http://upstream.internal",
		Service: domain.Service{
			ID:   1,
			Name: "svc",
			Domain: domain.Domain{
				Name: host,
			},
		},
		EffectivePolicy: domain.AccessPolicy{AccessMode: domain.AccessModePublic},
	}
}

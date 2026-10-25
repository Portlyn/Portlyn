package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"portlyn/internal/accesslog"
	"portlyn/internal/domain"
	"portlyn/internal/routing"
)

func TestProxyRecordsAccessLogWithClientIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	recorder, err := accesslog.New(accesslog.Options{Capacity: 10})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	manager := NewManager(newFakeRoutingStore(routing.RouteConfig{
		ID:              "1",
		ServiceID:       1,
		ServiceName:     "svc",
		Host:            "app.example.com",
		Path:            "/",
		TargetURL:       upstream.URL,
		Service:         domain.Service{ID: 1, Name: "svc", Domain: domain.Domain{Name: "app.example.com"}},
		EffectivePolicy: domain.AccessPolicy{AccessMode: domain.AccessModePublic},
	}), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, nil, nil, nil, ManagerOptions{
		LocalCacheTTL:      time.Hour,
		LocalCacheCapacity: 16,
		TrustedProxyCIDRs:  []string{"10.10.11.14/32"},
		AccessLog:          recorder,
	})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/page", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "10.10.11.14:50236"
	req.Header.Set("X-Forwarded-For", "77.67.9.200")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	manager.Handler().ServeHTTP(rec, req)

	items := recorder.List(accesslog.Filter{}, 10)
	if len(items) != 1 {
		t.Fatalf("expected one access log entry, got %d", len(items))
	}
	got := items[0]
	if got.RemoteAddr != "77.67.9.200" || got.PeerAddr != "10.10.11.14" || got.Status != http.StatusOK || got.ServiceID != 1 || got.Path != "/page" || got.UserAgent != "Mozilla/5.0" {
		t.Fatalf("unexpected entry %+v", got)
	}

	untrusted := httptest.NewRequest(http.MethodGet, "http://app.example.com/page", nil)
	untrusted.Host = "app.example.com"
	untrusted.RemoteAddr = "185.93.1.17:41000"
	untrusted.Header.Set("X-Forwarded-For", "77.67.9.200")
	manager.Handler().ServeHTTP(httptest.NewRecorder(), untrusted)
	items = recorder.List(accesslog.Filter{}, 10)
	var direct *accesslog.Entry
	for i := range items {
		if items[i].PeerAddr == "185.93.1.17" {
			direct = &items[i]
		}
	}
	if direct == nil || direct.RemoteAddr != "185.93.1.17" {
		t.Fatalf("expected untrusted peer to stay the client, got %+v", items)
	}
}

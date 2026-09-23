package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"portlyn/internal/audit"
)

func TestDenialThrottleCollapsesRepeatsAndReportsSuppressed(t *testing.T) {
	throttle := newDenialThrottle(time.Minute, 60)
	start := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	if ok, _ := throttle.allow("a", start); !ok {
		t.Fatal("first denial must be written")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := throttle.allow("a", start.Add(time.Second)); ok {
			t.Fatal("repeat inside the window must be suppressed")
		}
	}
	if ok, _ := throttle.allow("b", start.Add(time.Second)); !ok {
		t.Fatal("other key must still be written")
	}

	ok, suppressed := throttle.allow("a", start.Add(61*time.Second))
	if !ok || suppressed != 5 {
		t.Fatalf("expected write with 5 suppressed, got ok=%v suppressed=%d", ok, suppressed)
	}
	if ok, suppressed := throttle.allow("b", start.Add(62*time.Second)); !ok || suppressed != 0 {
		t.Fatalf("expected clean write for b, got ok=%v suppressed=%d", ok, suppressed)
	}
}

func TestDenialThrottleCapsDistinctKeysPerWindow(t *testing.T) {
	throttle := newDenialThrottle(time.Minute, 3)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	written := 0
	for i := 0; i < 100; i++ {
		if ok, _ := throttle.allow(fmt.Sprintf("198.51.100.%d", i), now); ok {
			written++
		}
	}
	if written != 3 {
		t.Fatalf("expected 3 writes under the cap, got %d", written)
	}
	if len(throttle.current) != 3 {
		t.Fatalf("expected tracked keys to stay at the cap, got %d", len(throttle.current))
	}
}

type countingAuditSink struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (s *countingAuditSink) WriteEvent(_ context.Context, ev audit.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func TestManagerThrottlesDeniedAuditRows(t *testing.T) {
	sink := &countingAuditSink{}
	manager := NewManager(newFakeRoutingStore(), NewInMemoryConfigCache(), NewInMemoryConfigBus(), nil, audit.NewLogger(sink), nil, nil, ManagerOptions{
		LocalCacheTTL:         time.Hour,
		LocalCacheCapacity:    16,
		BootstrapAdminEnabled: true,
	})

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://203.0.113.10/", nil)
		req.Host = "203.0.113.10"
		req.RemoteAddr = "198.51.100.7:54321"
		recorder := httptest.NewRecorder()
		manager.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", recorder.Code)
		}
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("expected one audit row for 50 identical denials, got %d", len(sink.events))
	}
}

package audit

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"portlyn/internal/domain"
)

type fakeAuditBatchWriter struct {
	mu      sync.Mutex
	singles []domain.AuditLog
	batches [][]domain.AuditLog
}

func (w *fakeAuditBatchWriter) Create(_ context.Context, item *domain.AuditLog) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.singles = append(w.singles, *item)
	return nil
}

func (w *fakeAuditBatchWriter) CreateBatch(_ context.Context, items []domain.AuditLog) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := append([]domain.AuditLog(nil), items...)
	w.batches = append(w.batches, cp)
	return nil
}

func TestAsyncSinkFlushesBatches(t *testing.T) {
	writer := &fakeAuditBatchWriter{}
	sink := NewAsyncSink(writer, 8, 2, time.Hour, SyncFallback, nil)
	logger := NewLogger(sink)

	if err := logger.Log(context.Background(), nil, "create", "service", nil, map[string]any{"host": "example.com"}); err != nil {
		t.Fatalf("first log failed: %v", err)
	}
	if err := logger.Log(context.Background(), nil, "update", "service", nil, map[string]any{"host": "example.com"}); err != nil {
		t.Fatalf("second log failed: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		writer.mu.Lock()
		batchCount := len(writer.batches)
		writer.mu.Unlock()
		if batchCount > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	sink.Close()

	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.batches) != 1 {
		t.Fatalf("expected one batch flush, got %d", len(writer.batches))
	}
	if len(writer.batches[0]) != 2 {
		t.Fatalf("expected two audit events in batch, got %d", len(writer.batches[0]))
	}
	if writer.batches[0][0].Details == "" {
		t.Fatalf("expected marshaled details payload")
	}
}

func TestLoggerLogHTTPAccessPersistsRequestMetadata(t *testing.T) {
	writer := &fakeAuditBatchWriter{}
	sink := NewAsyncSink(writer, 8, 10, 10*time.Millisecond, SyncFallback, nil)
	logger := NewLogger(sink)

	req := httptest.NewRequest("GET", "https://example.com/app", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("User-Agent", "portlyn-test")

	if err := logger.LogHTTPAccess(context.Background(), HTTPAccessEvent{
		Request:      req,
		Action:       "proxy_access",
		ResourceType: "service",
		StatusCode:   200,
		Latency:      25 * time.Millisecond,
		Details:      map[string]any{"route": "/app"},
	}); err != nil {
		t.Fatalf("log http access failed: %v", err)
	}
	sink.Close()

	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.batches) == 0 || len(writer.batches[0]) == 0 {
		t.Fatalf("expected flushed audit events")
	}
	got := writer.batches[0][0]
	if got.Method != "GET" || got.Host != "example.com" || got.Path != "/app" {
		t.Fatalf("unexpected request metadata: %#v", got)
	}
}

type captureSink struct {
	events []AuditEvent
}

func (s *captureSink) WriteEvent(_ context.Context, ev AuditEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func TestLogRequestUsesClientIPResolver(t *testing.T) {
	sink := &captureSink{}
	logger := NewLogger(sink)
	req := httptest.NewRequest("GET", "/api/v1/services", nil)
	req.RemoteAddr = "10.10.11.14:50236"

	_ = logger.LogRequest(context.Background(), req, nil, "list", "service", nil, nil)
	logger.SetClientIPResolver(func(*stdhttp.Request) string { return "77.67.9.200" })
	_ = logger.LogRequest(context.Background(), req, nil, "list", "service", nil, nil)
	_ = logger.LogHTTPAccess(context.Background(), HTTPAccessEvent{Request: req, Action: "proxy_access"})

	if len(sink.events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(sink.events))
	}
	if sink.events[0].RemoteAddr != "10.10.11.14:50236" {
		t.Fatalf("expected raw remote addr without resolver, got %q", sink.events[0].RemoteAddr)
	}
	for _, ev := range sink.events[1:] {
		if ev.RemoteAddr != "77.67.9.200" {
			t.Fatalf("expected resolved client ip, got %q", ev.RemoteAddr)
		}
	}
}

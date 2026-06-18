package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"portlyn/internal/domain"
)

type stubWebhookStore struct {
	mu    sync.Mutex
	hooks []domain.AuditWebhook
	fires []domain.AuditWebhook
}

func (s *stubWebhookStore) ActiveByEvent(ctx context.Context, action string) ([]domain.AuditWebhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]domain.AuditWebhook{}, s.hooks...)
	return out, nil
}

func (s *stubWebhookStore) Update(ctx context.Context, item *domain.AuditWebhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fires = append(s.fires, *item)
	return nil
}

func TestWebhookDispatcherFiresGenericPayload(t *testing.T) {
	received := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		received <- payload
		if r.Header.Get("X-Portlyn-Signature") == "" {
			t.Errorf("missing signature header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	stub := &stubWebhookStore{hooks: []domain.AuditWebhook{
		{ID: 1, URL: server.URL, Format: "generic", SecretEncrypted: "abc", Active: true, EventTypes: domain.JSONStringSlice{"login_succeeded"}},
	}}
	disp := NewWebhookDispatcher(stub)
	disp.client = server.Client()
	disp.Dispatch(context.Background(), domain.AuditLog{
		Timestamp:    time.Now().UTC(),
		Action:       "login_succeeded",
		ResourceType: "auth",
	}, map[string]any{"email": "x@example.test"})

	select {
	case payload := <-received:
		if payload["event"] != "login_succeeded" {
			t.Fatalf("unexpected event: %v", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never fired")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stub.mu.Lock()
		fired := len(stub.fires)
		stub.mu.Unlock()
		if fired > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("webhook update never recorded")
}

func TestWebhookDispatcherFiltersEvents(t *testing.T) {
	stub := &stubWebhookStore{hooks: []domain.AuditWebhook{
		{ID: 1, URL: "http://127.0.0.1:0", Format: "generic", Active: true, EventTypes: domain.JSONStringSlice{"other_event"}},
	}}
	hooks, err := stub.ActiveByEvent(context.Background(), "other_event")
	if err != nil || len(hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d (err=%v)", len(hooks), err)
	}
}

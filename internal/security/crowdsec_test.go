package security

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCrowdSecStreamAddsAndRemoves(t *testing.T) {
	stream := decisionsStream{
		New: []Decision{
			{Type: "ban", Scope: "ip", Value: "203.0.113.5", Scenario: "crowdsecurity/ssh-bf"},
			{Type: "ban", Scope: "range", Value: "198.51.100.0/24", Scenario: "crowdsecurity/http-bad-bot"},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k1" {
			t.Errorf("missing api key header")
		}
		_ = json.NewEncoder(w).Encode(stream)
	}))
	defer server.Close()

	cs := NewCrowdSec()
	cs.Configure(server.URL, "k1", time.Second)
	if err := cs.fetchOnce(context.Background(), true); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if blocked, _ := cs.IsBlocked(net.ParseIP("203.0.113.5")); !blocked {
		t.Fatal("expected ip blocked")
	}
	if blocked, _ := cs.IsBlocked(net.ParseIP("198.51.100.42")); !blocked {
		t.Fatal("expected range blocked")
	}
	if blocked, _ := cs.IsBlocked(net.ParseIP("8.8.8.8")); blocked {
		t.Fatal("did not expect 8.8.8.8 blocked")
	}

	deleteStream := decisionsStream{Deleted: []Decision{{Scope: "ip", Value: "203.0.113.5"}}}
	cs.apply(deleteStream)
	if blocked, _ := cs.IsBlocked(net.ParseIP("203.0.113.5")); blocked {
		t.Fatal("expected ip unblocked after deletion")
	}
}

func TestCrowdSecEnabledRequiresKey(t *testing.T) {
	cs := NewCrowdSec()
	if cs.Enabled() {
		t.Fatal("expected disabled without config")
	}
	cs.Configure("http://example.test", "key", 0)
	if !cs.Enabled() {
		t.Fatal("expected enabled with config")
	}
}

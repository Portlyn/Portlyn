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

func TestCrowdSecUsageMetricsReportWindowAndReset(t *testing.T) {
	var received []usageMetricsPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/usage-metrics" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "k1" {
			t.Errorf("missing api key header")
		}
		var payload usageMetricsPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode: %v", err)
		}
		received = append(received, payload)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cs := NewCrowdSec()
	cs.Configure(server.URL, "k1", time.Second)
	cs.SetVersion("1.7.0")
	cs.apply(decisionsStream{New: []Decision{
		{Type: "ban", Scope: "ip", Value: "203.0.113.5", Origin: "crowdsec", Scenario: "crowdsecurity/http-probing"},
		{Type: "ban", Scope: "ip", Value: "2001:db8::1", Origin: "lists", Scenario: "firehol_cybercrime"},
		{Type: "ban", Scope: "range", Value: "198.51.100.0/24", Origin: "CAPI", Scenario: "crowdsecurity/http-bad-bot"},
	}})

	cs.IsBlocked(net.ParseIP("203.0.113.5"))
	cs.IsBlocked(net.ParseIP("203.0.113.5"))
	cs.IsBlocked(net.ParseIP("2001:db8::1"))
	cs.IsBlocked(net.ParseIP("198.51.100.7"))
	cs.IsBlocked(net.ParseIP("192.0.2.1"))

	if supported, err := cs.pushUsageMetrics(context.Background(), 15*time.Minute); !supported || err != nil {
		t.Fatalf("push: supported=%v err=%v", supported, err)
	}
	if len(received) != 1 || len(received[0].RemediationComponents) != 1 {
		t.Fatalf("unexpected payload %+v", received)
	}
	component := received[0].RemediationComponents[0]
	if component.Type != "portlyn" || component.Version != "1.7.0" {
		t.Fatalf("unexpected component %+v", component)
	}
	if component.Metrics[0].Meta.WindowSizeSeconds != 900 {
		t.Fatalf("window = %d", component.Metrics[0].Meta.WindowSizeSeconds)
	}

	values := map[string]float64{}
	for _, item := range component.Metrics[0].Items {
		values[item.Name+"/"+item.Labels["origin"]+"/"+item.Labels["ip_type"]] = item.Value
	}
	want := map[string]float64{
		"processed//":                                    5,
		"dropped/crowdsec/":                              2,
		"dropped/lists:firehol_cybercrime/":              1,
		"dropped/CAPI/":                                  1,
		"active_decisions/crowdsec/ipv4":                 1,
		"active_decisions/lists:firehol_cybercrime/ipv6": 1,
		"active_decisions/CAPI/ipv4":                     1,
	}
	for key, value := range want {
		if values[key] != value {
			t.Fatalf("%s = %v, want %v (all: %v)", key, values[key], value, values)
		}
	}

	if _, err := cs.pushUsageMetrics(context.Background(), 15*time.Minute); err != nil {
		t.Fatalf("second push: %v", err)
	}
	for _, item := range received[1].RemediationComponents[0].Metrics[0].Items {
		if (item.Name == "processed" || item.Name == "dropped") && item.Value != 0 {
			t.Fatalf("expected counters reset after push, got %s=%v", item.Name, item.Value)
		}
	}
}

func TestCrowdSecUsageMetricsKeepCountsOnFailureAndStopOnOldLAPI(t *testing.T) {
	status := http.StatusInternalServerError
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer server.Close()

	cs := NewCrowdSec()
	cs.Configure(server.URL, "k1", time.Second)
	cs.IsBlocked(net.ParseIP("192.0.2.1"))

	if supported, err := cs.pushUsageMetrics(context.Background(), time.Minute); !supported || err == nil {
		t.Fatalf("expected retryable error, got supported=%v err=%v", supported, err)
	}
	if processed, _ := cs.takeWindow(); processed != 1 {
		t.Fatalf("expected counts kept after failed push, got %d", processed)
	}

	status = http.StatusNotFound
	if supported, err := cs.pushUsageMetrics(context.Background(), time.Minute); supported || err != nil {
		t.Fatalf("expected unsupported on 404, got supported=%v err=%v", supported, err)
	}
}

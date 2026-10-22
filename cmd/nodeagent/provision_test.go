package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProvisionRetriesBootstrapWithoutReenrolling(t *testing.T) {
	var enrolls, bootstraps atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/nodes/enroll":
			if enrolls.Add(1) > 1 {
				http.Error(w, `{"error":{"code":"invalid_enrollment_token"}}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"node": map[string]any{"id": 7}, "heartbeat_token": "hb", "heartbeat_url": "/api/v1/nodes/7/heartbeat"})
		case strings.HasSuffix(r.URL.Path, "/wg-bootstrap"):
			if r.Header.Get("Authorization") != "Bearer hb" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if bootstraps.Add(1) < 3 {
				http.Error(w, `{"error":{"code":"tunnel_not_configured"}}`, http.StatusPreconditionFailed)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tunnel_ip": "10.42.0.2", "server_public_key": "pub", "server_endpoint": "hub:51820"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var saved []agentState
	p := &provisioner{
		client:          srv.Client(),
		api:             srv.URL,
		name:            "edge",
		enrollmentToken: func() (string, error) { return "TOKEN", nil },
		save:            func(s *agentState) error { saved = append(saved, *s); return nil },
		retryStart:      time.Millisecond,
	}
	state, err := p.run(context.Background(), nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if !state.provisioned() || state.NodeID != 7 || state.TunnelIP != "10.42.0.2" {
		t.Fatalf("unexpected state %+v", state)
	}
	if enrolls.Load() != 1 {
		t.Fatalf("expected one enrollment, got %d", enrolls.Load())
	}
	if bootstraps.Load() != 3 {
		t.Fatalf("expected bootstrap to be retried until it succeeds, got %d attempts", bootstraps.Load())
	}
	if len(saved) == 0 || saved[0].NodeID != 7 || saved[0].HeartbeatToken != "hb" {
		t.Fatalf("expected the enrollment to be saved before bootstrapping, got %+v", saved)
	}
}

func TestProvisionStopsOnUsedEnrollmentToken(t *testing.T) {
	var enrolls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrolls.Add(1)
		http.Error(w, `{"error":{"code":"invalid_enrollment_token"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &provisioner{
		client:          srv.Client(),
		api:             srv.URL,
		enrollmentToken: func() (string, error) { return "USED", nil },
		save:            func(*agentState) error { return nil },
		retryStart:      time.Millisecond,
	}
	_, err := p.run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected a used-token error, got %v", err)
	}
	if enrolls.Load() != 1 {
		t.Fatalf("expected no retries for a rejected token, got %d attempts", enrolls.Load())
	}
}

func TestProvisionResetsStateWhenNodeIsGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	var last *agentState
	p := &provisioner{
		client:          srv.Client(),
		api:             srv.URL,
		enrollmentToken: func() (string, error) { return "", nil },
		save:            func(s *agentState) error { cp := *s; last = &cp; return nil },
		retryStart:      time.Millisecond,
	}
	_, err := p.run(context.Background(), &agentState{NodeID: 3, HeartbeatToken: "stale", WGPrivateKey: "k", WGPublicKey: "p"})
	if err == nil {
		t.Fatal("expected bootstrap rejection to fail provisioning")
	}
	if last == nil || last.NodeID != 0 || last.HeartbeatToken != "" {
		t.Fatalf("expected the stale enrollment to be cleared, got %+v", last)
	}
}

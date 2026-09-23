package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"portlyn/internal/clientcert"
	"portlyn/internal/domain"
)

func TestNodeEnrollmentAndHeartbeatLifecycle(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	plainToken := "ENROLLTOKEN1234"
	item := &domain.NodeEnrollmentToken{
		Name:      "install token",
		TokenHash: hashOpaqueToken(plainToken),
		SingleUse: true,
		Active:    true,
	}
	if err := server.enrollmentTokens.Create(context.Background(), item); err != nil {
		t.Fatalf("create enrollment token: %v", err)
	}

	enrollReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewBufferString(`{"token":"`+plainToken+`","name":"edge-1","description":"edge node","version":"1.2.3"}`))
	enrollReq.Header.Set("Content-Type", "application/json")
	enrollRec := httptest.NewRecorder()
	server.Router().ServeHTTP(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusCreated {
		t.Fatalf("expected enroll 201, got %d: %s", enrollRec.Code, enrollRec.Body.String())
	}

	var enrollResult struct {
		Node struct {
			ID     uint   `json:"id"`
			Status string `json:"status"`
		} `json:"node"`
		HeartbeatToken string `json:"heartbeat_token"`
		HeartbeatURL   string `json:"heartbeat_url"`
	}
	if err := json.Unmarshal(enrollRec.Body.Bytes(), &enrollResult); err != nil {
		t.Fatalf("decode enroll result: %v", err)
	}
	if enrollResult.Node.ID == 0 || enrollResult.HeartbeatToken == "" || enrollResult.HeartbeatURL == "" {
		t.Fatal("expected enrollment response to include node id, heartbeat token, and heartbeat url")
	}
	if enrollResult.Node.Status != domain.NodeStatusOnline {
		t.Fatalf("expected enrolled node to start online, got %q", enrollResult.Node.Status)
	}

	storedToken, err := server.enrollmentTokens.GetByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("reload enrollment token: %v", err)
	}
	if storedToken.Active {
		t.Fatal("expected single-use enrollment token to be deactivated after enrollment")
	}
	if storedToken.UsedAt == nil {
		t.Fatal("expected single-use enrollment token to have used_at set")
	}

	heartbeatBody := bytes.NewBufferString(`{"version":"1.2.4","load":0.42,"bandwidth_in_kbps":256,"bandwidth_out_kbps":128}`)
	heartbeatReq := httptest.NewRequest(http.MethodPost, enrollResult.HeartbeatURL, heartbeatBody)
	heartbeatReq.Header.Set("Content-Type", "application/json")
	heartbeatReq.Header.Set("Authorization", "Bearer "+enrollResult.HeartbeatToken)
	heartbeatRec := httptest.NewRecorder()
	server.Router().ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusOK {
		t.Fatalf("expected heartbeat 200, got %d: %s", heartbeatRec.Code, heartbeatRec.Body.String())
	}

	node, err := server.nodes.GetByID(context.Background(), enrollResult.Node.ID)
	if err != nil {
		t.Fatalf("reload node: %v", err)
	}
	if node.HeartbeatVersion != "1.2.4" || node.Version != "1.2.4" {
		t.Fatalf("expected heartbeat to update node version, got version=%q heartbeat_version=%q", node.Version, node.HeartbeatVersion)
	}
	if node.LastHeartbeatAt == nil || time.Since(*node.LastHeartbeatAt) > time.Minute {
		t.Fatal("expected node heartbeat timestamp to be refreshed")
	}
	if node.Status != domain.NodeStatusOnline {
		t.Fatalf("expected node to remain online after heartbeat, got %q", node.Status)
	}
}

func TestNodeHeartbeatRejectsInvalidToken(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	now := time.Now().UTC()
	node := &domain.Node{
		Name:               "edge-2",
		Status:             domain.NodeStatusOnline,
		LastSeenAt:         &now,
		LastHeartbeatAt:    &now,
		HeartbeatAuthMode:  "token",
		HeartbeatTokenHash: hashOpaqueToken("REALTOKEN"),
	}
	if err := server.nodes.Create(context.Background(), node); err != nil {
		t.Fatalf("create node: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+strconv.FormatUint(uint64(node.ID), 10)+"/heartbeat", bytes.NewBufferString(`{"status":"online"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer WRONGTOKEN")
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected heartbeat rejection 401, got %d: %s", rec.Code, rec.Body.String())
	}

	reloaded, err := server.nodes.GetByID(context.Background(), node.ID)
	if err != nil {
		t.Fatalf("reload node: %v", err)
	}
	if reloaded.Status != domain.NodeStatusOnline {
		t.Fatalf("expected invalid heartbeat to leave node status untouched, got %q", reloaded.Status)
	}
	if reloaded.LastHeartbeatCode != http.StatusUnauthorized || reloaded.LastHeartbeatError != "invalid_token" || reloaded.HeartbeatFailedAt == nil {
		t.Fatalf("expected invalid heartbeat to record the failure, got code=%d error=%q failed_at=%v", reloaded.LastHeartbeatCode, reloaded.LastHeartbeatError, reloaded.HeartbeatFailedAt)
	}
	if reloaded.HeartbeatTokenHash != node.HeartbeatTokenHash || reloaded.LastHeartbeatAt == nil {
		t.Fatalf("expected invalid heartbeat to leave the rest of the node untouched")
	}
}

func TestNodeHeartbeatForDeletedNodeDoesNotRecreateIt(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	now := time.Now().UTC()
	node := &domain.Node{
		Name:               "edge-deleted",
		Status:             domain.NodeStatusOnline,
		LastSeenAt:         &now,
		HeartbeatAuthMode:  "token",
		HeartbeatTokenHash: hashOpaqueToken("REALTOKEN"),
	}
	if err := server.nodes.Create(context.Background(), node); err != nil {
		t.Fatalf("create node: %v", err)
	}
	if err := server.nodes.Delete(context.Background(), node.ID); err != nil {
		t.Fatalf("delete node: %v", err)
	}

	node.LastHeartbeatAt = &now
	if err := server.nodes.UpdateHeartbeat(context.Background(), node); err == nil {
		t.Fatal("expected heartbeat update of a deleted node to fail")
	}
	if _, err := server.nodes.GetByID(context.Background(), node.ID); err == nil {
		t.Fatal("expected deleted node to stay deleted")
	}
}

func TestNodeEnrollmentRejectsInsecureTransportWhenHardened(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.AllowInsecureDevMode = false
	server.cfg.NodeRequireHTTPS = true
	server.cfg.NodeTrustForwardedProto = false

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewBufferString(`{"token":"x","name":"edge-1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected enroll to require https and return 426, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNodeHeartbeatMTLSHeaderFallbackDisabledByDefault(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	now := time.Now().UTC()
	node := &domain.Node{
		Name:              "edge-mtls-no-fallback",
		Status:            domain.NodeStatusOnline,
		LastSeenAt:        &now,
		LastHeartbeatAt:   &now,
		HeartbeatAuthMode: "mtls",
		MTLSCertSHA256:    strings.Repeat("a", 64),
	}
	if err := server.nodes.Create(context.Background(), node); err != nil {
		t.Fatalf("create node: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+strconv.FormatUint(uint64(node.ID), 10)+"/heartbeat", bytes.NewBufferString(`{"status":"online"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Portlyn-Client-Cert-SHA256", strings.Repeat("a", 64))
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected heartbeat rejection 401 without tls cert and fallback disabled, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNodeHeartbeatMTLSHeaderFallbackRequiresTrustedForwardedProto(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.NodeAllowMTLSHeaderFallback = true
	server.cfg.NodeTrustForwardedProto = true
	server.cfg.NodeRequireHTTPS = true
	server.cfg.AllowInsecureDevMode = false
	server.cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}

	now := time.Now().UTC()
	node := &domain.Node{
		Name:              "edge-mtls-header",
		Status:            domain.NodeStatusOnline,
		LastSeenAt:        &now,
		LastHeartbeatAt:   &now,
		HeartbeatAuthMode: "mtls",
		MTLSCertSHA256:    strings.Repeat("b", 64),
	}
	if err := server.nodes.Create(context.Background(), node); err != nil {
		t.Fatalf("create node: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+strconv.FormatUint(uint64(node.ID), 10)+"/heartbeat", bytes.NewBufferString(`{"status":"online"}`))
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Portlyn-Client-Cert-SHA256", strings.Repeat("b", 64))
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected heartbeat 200 when trusted proxy fallback is explicitly enabled, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNodeHeartbeatMTLSHeaderFromLoopbackRequiresSignature(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.NodeAllowMTLSHeaderFallback = true
	server.cfg.NodeTrustForwardedProto = true
	server.cfg.NodeRequireHTTPS = true
	server.cfg.AllowInsecureDevMode = false
	server.cfg.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}

	now := time.Now().UTC()
	fingerprint := strings.Repeat("c", 64)
	node := &domain.Node{
		Name:              "edge-mtls-loopback",
		Status:            domain.NodeStatusOnline,
		LastSeenAt:        &now,
		LastHeartbeatAt:   &now,
		HeartbeatAuthMode: "mtls",
		MTLSCertSHA256:    fingerprint,
	}
	if err := server.nodes.Create(context.Background(), node); err != nil {
		t.Fatalf("create node: %v", err)
	}

	send := func(signature string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/"+strconv.FormatUint(uint64(node.ID), 10)+"/heartbeat", bytes.NewBufferString(`{"status":"online"}`))
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set(clientcert.FingerprintHeader, fingerprint)
		if signature != "" {
			req.Header.Set(clientcert.SignatureHeader, signature)
		}
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(""); code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned fingerprint header from loopback to be rejected, got %d", code)
	}
	if code := send(clientcert.Sign("some-other-secret", fingerprint)); code != http.StatusUnauthorized {
		t.Fatalf("expected fingerprint signed with the wrong secret to be rejected, got %d", code)
	}
	if code := send(clientcert.Sign(server.cfg.SessionBridgeSecret, fingerprint)); code != http.StatusOK {
		t.Fatalf("expected signed fingerprint header from loopback to be accepted, got %d", code)
	}
}

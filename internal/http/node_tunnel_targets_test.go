package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"portlyn/internal/domain"
	"portlyn/internal/tunnel"
)

func TestNodeTunnelTargetsReportHubAndAllowedSources(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()

	server.tunnel = tunnel.NewManager(server.nodes, server.clients, server.appSettings)
	settings, err := server.tunnel.EnsureServerKey(ctx)
	if err != nil {
		t.Fatalf("ensure server key: %v", err)
	}

	node := &domain.Node{
		Name:               "edge-targets",
		Status:             domain.NodeStatusOnline,
		HeartbeatAuthMode:  "token",
		HeartbeatTokenHash: hashOpaqueToken("NODETOKEN"),
		WGPublicKey:        "nodepub",
		WGTunnelIP:         "10.42.0.2",
	}
	if err := server.nodes.Create(ctx, node); err != nil {
		t.Fatalf("create node: %v", err)
	}
	nodeID := strconv.FormatUint(uint64(node.ID), 10)
	for _, client := range []domain.Client{
		{Name: "allowed", WGPublicKey: "clientpub1", WGTunnelIP: "10.42.0.10", AllowedNodeIDs: nodeID, Enabled: true},
		{Name: "other", WGPublicKey: "clientpub2", WGTunnelIP: "10.42.0.11", AllowedNodeIDs: "", Enabled: true},
		{Name: "disabled", WGPublicKey: "clientpub3", WGTunnelIP: "10.42.0.12", AllowedNodeIDs: nodeID, Enabled: true},
	} {
		item := client
		if err := server.clients.Create(ctx, &item); err != nil {
			t.Fatalf("create client: %v", err)
		}
		if item.Name == "disabled" {
			item.Enabled = false
			if err := server.clients.Update(ctx, &item); err != nil {
				t.Fatalf("disable client: %v", err)
			}
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/"+nodeID+"/tunnel-targets", nil)
	req.Header.Set("Authorization", "Bearer NODETOKEN")
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ServerTunnelIP string   `json:"server_tunnel_ip"`
		AllowedSources []string `json:"allowed_sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ServerTunnelIP != settings.TunnelServerTunnelIP {
		t.Fatalf("server_tunnel_ip = %q, want %q", body.ServerTunnelIP, settings.TunnelServerTunnelIP)
	}
	if len(body.AllowedSources) != 1 || body.AllowedSources[0] != "10.42.0.10" {
		t.Fatalf("allowed_sources = %v, want [10.42.0.10]", body.AllowedSources)
	}
}

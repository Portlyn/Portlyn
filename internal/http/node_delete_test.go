package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"portlyn/internal/domain"
	"portlyn/internal/tunnel"
)

func TestDeleteNodeDropsTunnelPeer(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()

	configPath := filepath.Join(t.TempDir(), "wg0.conf")
	settings, err := server.appSettings.Get(ctx)
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	settings.TunnelConfigPath = configPath
	if err := server.appSettings.Upsert(ctx, settings); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}
	server.tunnel = tunnel.NewManager(server.nodes, server.clients, server.appSettings)
	if _, err := server.tunnel.EnsureServerKey(ctx); err != nil {
		t.Fatalf("ensure server key: %v", err)
	}

	keys, err := tunnel.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	node := &domain.Node{
		Name:              "edge-revoked",
		Status:            domain.NodeStatusOnline,
		HeartbeatAuthMode: "token",
		WGPublicKey:       keys.PublicKey,
		WGTunnelIP:        "10.42.0.9",
	}
	if err := server.nodes.Create(ctx, node); err != nil {
		t.Fatalf("create node: %v", err)
	}
	if err := server.tunnel.WriteServerConfig(ctx); err != nil {
		t.Fatalf("write server config: %v", err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(before), keys.PublicKey) {
		t.Fatal("expected node peer in server config before delete")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/"+strconv.FormatUint(uint64(node.ID), 10), nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", strconv.FormatUint(uint64(node.ID), 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	rec := httptest.NewRecorder()
	server.handleDeleteNode(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(after), keys.PublicKey) {
		t.Fatal("expected deleted node peer to be removed from server config")
	}
}

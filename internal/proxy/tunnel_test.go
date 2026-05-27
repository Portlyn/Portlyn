package proxy

import (
	"testing"

	"portlyn/internal/domain"
)

func TestRewriteTargetForTunnelReplacesHost(t *testing.T) {
	nodeID := uint(7)
	service := domain.Service{
		NodeID: &nodeID,
		Node:   &domain.Node{ID: 7, WGTunnelIP: "10.42.0.3"},
	}
	got, via := rewriteTargetForTunnel("http://gitea.lan:3000/", service)
	if !via {
		t.Fatal("expected tunnel rewrite")
	}
	if got != "http://10.42.0.3:3000/" {
		t.Fatalf("unexpected target: %s", got)
	}
}

func TestRewriteTargetForTunnelNoNodeReturnsOriginal(t *testing.T) {
	got, via := rewriteTargetForTunnel("http://example.test/", domain.Service{})
	if via {
		t.Fatal("expected no rewrite")
	}
	if got != "http://example.test/" {
		t.Fatalf("unexpected target: %s", got)
	}
}

func TestRewriteTargetForTunnelMissingTunnelIPReturnsOriginal(t *testing.T) {
	nodeID := uint(1)
	service := domain.Service{
		NodeID: &nodeID,
		Node:   &domain.Node{ID: 1},
	}
	got, via := rewriteTargetForTunnel("https://app/", service)
	if via {
		t.Fatal("expected no rewrite without tunnel ip")
	}
	if got != "https://app/" {
		t.Fatalf("unexpected target: %s", got)
	}
}

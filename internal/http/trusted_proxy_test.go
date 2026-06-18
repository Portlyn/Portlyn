package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestSecureIgnoresSpoofedForwardedProto(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-Proto", "https")

	if server.requestSecure(req) {
		t.Fatal("expected spoofed X-Forwarded-Proto to be ignored without trusted proxy config")
	}
}

func TestRequestSecureTrustsForwardedProtoFromConfiguredProxy(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-Proto", "https")

	if !server.requestSecure(req) {
		t.Fatal("expected X-Forwarded-Proto to be trusted from configured proxy CIDR")
	}
}

func TestClientIPIgnoresSpoofedForwardedFor(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.5")

	if got := server.clientIPForRequest(req); got != "203.0.113.10" {
		t.Fatalf("expected remote addr client ip, got %q", got)
	}
}

func TestClientIPUsesRightmostUntrustedForwardedFor(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.5")

	if got := server.clientIPForRequest(req); got != "198.51.100.5" {
		t.Fatalf("expected rightmost untrusted client ip, got %q", got)
	}
}

func TestClientIPSkipsTrustedHopsInForwardedFor(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.9.9.9")

	if got := server.clientIPForRequest(req); got != "203.0.113.7" {
		t.Fatalf("expected client ip before trusted hops, got %q", got)
	}
}

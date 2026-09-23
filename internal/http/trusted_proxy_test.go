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

func TestBreakGlassSourceUsesForwardedClientIP(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	server.cfg.BreakGlassAllowCIDRs = []string{"127.0.0.1/32", "::1/128"}
	server.cfg.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}

	proxied := httptest.NewRequest(http.MethodPost, "/api/v1/auth/break-glass/login", nil)
	proxied.RemoteAddr = "127.0.0.1:40000"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.9")
	if server.breakGlassAllowedSource(proxied) {
		t.Fatal("expected remote client behind the internal proxy to be rejected")
	}

	local := httptest.NewRequest(http.MethodPost, "/api/v1/auth/break-glass/login", nil)
	local.RemoteAddr = "127.0.0.1:40001"
	if !server.breakGlassAllowedSource(local) {
		t.Fatal("expected direct loopback request to be allowed")
	}

	server.cfg.TrustedProxyCIDRs = nil
	untrusted := httptest.NewRequest(http.MethodPost, "/api/v1/auth/break-glass/login", nil)
	untrusted.RemoteAddr = "127.0.0.1:40002"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.9")
	if server.breakGlassAllowedSource(untrusted) {
		t.Fatal("expected forwarded request from an untrusted hop to be rejected")
	}
}

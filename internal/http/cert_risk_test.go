package http

import (
	"testing"
	"time"

	"portlyn/internal/acme"
	"portlyn/internal/domain"
)

func TestApplyCertRiskEscalatesBootstrap(t *testing.T) {
	label, reasons := applyCertRisk("low", nil, acme.CertInfo{Source: acme.CertSourceBootstrap, IsBootstrap: true})
	if label != "medium" {
		t.Fatalf("bootstrap on low should escalate to medium, got %q", label)
	}
	if len(reasons) != 1 || reasons[0] != "edge serving self-signed bootstrap certificate" {
		t.Fatalf("unexpected reasons: %v", reasons)
	}

	if label, _ := applyCertRisk("medium", nil, acme.CertInfo{IsBootstrap: true}); label != "high" {
		t.Fatalf("bootstrap on medium should escalate to high, got %q", label)
	}
}

func TestApplyCertRiskExpiry(t *testing.T) {
	soon := time.Now().Add(3 * 24 * time.Hour)
	label, reasons := applyCertRisk("low", nil, acme.CertInfo{Source: acme.CertSourceManaged, ExpiresAt: &soon, DaysRemaining: 3})
	if label != "medium" {
		t.Fatalf("cert expiring in 3d should escalate low->medium, got %q", label)
	}
	if len(reasons) != 1 {
		t.Fatalf("expected one expiry reason, got %v", reasons)
	}

	later := time.Now().Add(10 * 24 * time.Hour)
	if label, _ := applyCertRisk("low", nil, acme.CertInfo{Source: acme.CertSourceManaged, ExpiresAt: &later, DaysRemaining: 10}); label != "low" {
		t.Fatalf("cert expiring in 10d should not escalate, got %q", label)
	}

	healthy := time.Now().Add(60 * 24 * time.Hour)
	if _, reasons := applyCertRisk("low", nil, acme.CertInfo{Source: acme.CertSourceManaged, ExpiresAt: &healthy, DaysRemaining: 60}); len(reasons) != 0 {
		t.Fatalf("healthy cert should add no reasons, got %v", reasons)
	}
}

func TestUpstreamScheme(t *testing.T) {
	cases := map[string]string{
		"https://backend:8443": "https",
		"http://10.0.0.5:8000": "http",
		"backend:8000":         "",
		"":                     "",
	}
	for in, want := range cases {
		if got := upstreamScheme(in); got != want {
			t.Errorf("upstreamScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpstreamTLSClientConfigPrefersCAPin(t *testing.T) {
	if cfg := upstreamTLSClientConfig(domain.Service{}); cfg != nil {
		t.Fatalf("no CA and no skip_verify should yield nil config, got %v", cfg)
	}

	skip := upstreamTLSClientConfig(domain.Service{UpstreamSkipVerify: true})
	if skip == nil || !skip.InsecureSkipVerify {
		t.Fatalf("skip_verify should produce InsecureSkipVerify config")
	}

	// An invalid CA falls through to skip_verify when set.
	fallback := upstreamTLSClientConfig(domain.Service{UpstreamSkipVerify: true, UpstreamCAPEM: "not-a-pem"})
	if fallback == nil || !fallback.InsecureSkipVerify {
		t.Fatalf("invalid CA with skip_verify should fall back to InsecureSkipVerify")
	}
}

func TestValidateUpstreamCAPEM(t *testing.T) {
	if err := validateUpstreamCAPEM(""); err != nil {
		t.Fatalf("empty PEM should be valid (no pinning), got %v", err)
	}
	if err := validateUpstreamCAPEM("garbage"); err == nil {
		t.Fatalf("garbage PEM should be rejected")
	}
}

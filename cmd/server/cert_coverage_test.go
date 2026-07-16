package main

import (
	"testing"

	"portlyn/internal/domain"
)

func TestWildcardForHost(t *testing.T) {
	cases := map[string]string{
		"app.example.com": "*.example.com",
		"a.b.example.com": "*.b.example.com",
		"example.com":     "",
		"localhost":       "",
	}
	for host, want := range cases {
		if got := wildcardForHost(host); got != want {
			t.Errorf("wildcardForHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestHostCoveredByCertificate(t *testing.T) {
	wildcard := []domain.Certificate{{PrimaryDomain: "*.example.com"}}
	exact := []domain.Certificate{{PrimaryDomain: "app.example.com"}}
	other := []domain.Certificate{{PrimaryDomain: "other.example.com"}}

	if !hostCoveredByCertificate("app.example.com", wildcard) {
		t.Error("wildcard should cover a subdomain")
	}
	if !hostCoveredByCertificate("app.example.com", exact) {
		t.Error("exact cert should cover its host")
	}
	if hostCoveredByCertificate("app.example.com", other) {
		t.Error("an unrelated cert should not cover the host")
	}
	if hostCoveredByCertificate("app.example.com", nil) {
		t.Error("no certs means not covered")
	}
	if hostCoveredByCertificate("deep.app.example.com", wildcard) {
		t.Error("a single-label wildcard should not cover a two-level subdomain")
	}
}

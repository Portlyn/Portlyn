package domain

import "testing"

func TestWildcardForHost(t *testing.T) {
	cases := map[string]string{
		"app.example.com": "*.example.com",
		"a.b.example.com": "*.b.example.com",
		"example.com":     "",
		"localhost":       "",
	}
	for host, want := range cases {
		if got := WildcardForHost(host); got != want {
			t.Errorf("WildcardForHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestHostCoveredByCertificates(t *testing.T) {
	wildcard := []Certificate{{PrimaryDomain: "*.example.com"}}
	exact := []Certificate{{PrimaryDomain: "app.example.com"}}
	other := []Certificate{{PrimaryDomain: "other.example.com"}}
	wildcardSAN := []Certificate{{PrimaryDomain: "example.com", SANs: []CertificateSAN{{DomainName: "*.example.com"}}}}

	if !HostCoveredByCertificates("app.example.com", wildcard) {
		t.Error("wildcard should cover a subdomain")
	}
	if !HostCoveredByCertificates("app.example.com", exact) {
		t.Error("exact cert should cover its host")
	}
	if !HostCoveredByCertificates("app.example.com", wildcardSAN) {
		t.Error("a wildcard SAN should cover a subdomain")
	}
	if !HostCoveredByCertificates("example.com", wildcardSAN) {
		t.Error("the primary domain next to a wildcard SAN should be covered")
	}
	if HostCoveredByCertificates("app.example.com", other) {
		t.Error("an unrelated cert should not cover the host")
	}
	if HostCoveredByCertificates("app.example.com", nil) {
		t.Error("no certs means not covered")
	}
	if HostCoveredByCertificates("deep.app.example.com", wildcard) {
		t.Error("a single-label wildcard should not cover a two-level subdomain")
	}
}

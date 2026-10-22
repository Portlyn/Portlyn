package http

import (
	"context"
	"testing"

	"portlyn/internal/domain"
)

func TestWildcardCertificateKeepsBaseDomain(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	dom := &domain.Domain{Name: "example.com", Type: "root"}
	if err := server.domains.Create(context.Background(), dom); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	provider := &domain.DNSProvider{Name: "cf", Type: domain.DNSProviderTypeCloudflare, IsActive: true}
	if err := server.dnsProviders.Create(context.Background(), provider); err != nil {
		t.Fatalf("create dns provider: %v", err)
	}

	cases := map[string]domain.Certificate{
		"base as primary":           {PrimaryDomain: "example.com"},
		"base with wildcard as SAN": {PrimaryDomain: "example.com", SANs: []domain.CertificateSAN{{DomainName: "*.example.com"}}},
		"wildcard with base as SAN": {PrimaryDomain: "*.example.com", SANs: []domain.CertificateSAN{{DomainName: "example.com"}}},
	}
	for name, item := range cases {
		item.DomainID = dom.ID
		item.Type = domain.CertificateTypeWildcard
		item.ChallengeType = domain.CertificateChallengeDNS01
		item.DNSProviderID = &provider.ID
		if err := server.validateAndHydrateCertificate(context.Background(), &item); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if item.PrimaryDomain != "*.example.com" || len(item.SANs) != 1 || item.SANs[0].DomainName != "example.com" {
			t.Fatalf("%s: expected *.example.com with example.com as SAN, got %q %v", name, item.PrimaryDomain, sanNames(item.SANs))
		}
	}
}

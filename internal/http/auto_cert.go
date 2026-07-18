package http

import (
	"context"
	"time"

	"portlyn/internal/domain"
)

// autoIssueCertificateForDomain implicitly requests a Let's Encrypt certificate
// when a domain is created and a usable DNS provider is on file. dns-01 is used
// because it does not require the domain's A/AAAA records to already point at the
// edge, so issuance can complete before traffic is cut over. Returns the created
// certificate (already persisted, issuance running asynchronously) or nil when
// auto-issuance is disabled, ACME is unavailable, or no provider can be picked.
func (s *Server) autoIssueCertificateForDomain(ctx context.Context, dom *domain.Domain, explicitProviderID *uint, enabled bool) *domain.Certificate {
	if !enabled || dom == nil || s.acme == nil || !s.acme.ACMEReady() {
		return nil
	}

	provider := s.pickAutoCertProvider(ctx, explicitProviderID)
	if provider == nil {
		return nil
	}

	providerID := provider.ID
	cert := &domain.Certificate{
		DomainID:          dom.ID,
		PrimaryDomain:     dom.Name,
		Type:              domain.CertificateTypeSingle,
		Status:            domain.CertificateStatusPending,
		ChallengeType:     domain.CertificateChallengeDNS01,
		Issuer:            domain.CertificateIssuerLetsEncryptProd,
		RenewalWindowDays: 30,
		IsAutoRenew:       true,
		DNSProviderID:     &providerID,
	}
	if err := s.certificates.Create(ctx, cert); err != nil {
		s.logger.Warn("auto certificate: create failed", "domain", dom.Name, "error", err)
		return nil
	}

	certID := cert.ID
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		item, err := s.certificates.GetByID(bg, certID)
		if err != nil {
			s.logger.Warn("auto certificate: reload failed", "id", certID, "error", err)
			return
		}
		if _, err := s.acme.SyncCertificate(bg, item); err != nil {
			s.logger.Warn("auto certificate: issuance failed", "id", certID, "domain", dom.Name, "error", err)
		}
	}()

	return cert
}

// pickAutoCertProvider resolves the DNS provider to use for auto-issuance. An
// explicit id must exist and be active; otherwise exactly one active provider
// must be on file, since guessing between several would bind the wrong zone.
func (s *Server) pickAutoCertProvider(ctx context.Context, explicitProviderID *uint) *domain.DNSProvider {
	providers, err := s.dnsProviders.List(ctx)
	if err != nil {
		s.logger.Warn("auto certificate: listing dns providers failed", "error", err)
		return nil
	}

	if explicitProviderID != nil {
		for i := range providers {
			if providers[i].ID == *explicitProviderID && providers[i].IsActive {
				return &providers[i]
			}
		}
		return nil
	}

	var chosen *domain.DNSProvider
	for i := range providers {
		if !providers[i].IsActive {
			continue
		}
		if chosen != nil {
			return nil
		}
		chosen = &providers[i]
	}
	return chosen
}

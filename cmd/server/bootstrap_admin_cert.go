package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

func skippableCertHost(host string) bool {
	return host == "" || host == "localhost" || strings.HasPrefix(host, "127.")
}

func wildcardForHost(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return ""
	}
	return "*." + strings.Join(labels[1:], ".")
}

func hostCoveredByCertificate(host string, certs []domain.Certificate) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	wildcard := wildcardForHost(host)
	for i := range certs {
		primary := strings.ToLower(strings.TrimSpace(certs[i].PrimaryDomain))
		if primary == host {
			return true
		}
		if wildcard != "" && primary == wildcard {
			return true
		}
	}
	return false
}

func activeCertChallenge(ctx context.Context, dnsProviders *store.DNSProviderStore, logger *slog.Logger) (string, *uint) {
	if providers, err := dnsProviders.List(ctx); err != nil {
		logger.Warn("certificate dns provider lookup failed", "error", err)
	} else {
		for i := range providers {
			if providers[i].IsActive {
				id := providers[i].ID
				return domain.CertificateChallengeDNS01, &id
			}
		}
	}
	return domain.CertificateChallengeHTTP01, nil
}

func enqueuePendingCertificate(ctx context.Context, certificates *store.CertificateStore, domainID uint, host, challengeType string, dnsProviderID *uint, logger *slog.Logger) {
	cert := &domain.Certificate{
		DomainID:      domainID,
		PrimaryDomain: host,
		Type:          domain.CertificateTypeSingle,
		Status:        domain.CertificateStatusPending,
		ChallengeType: challengeType,
		DNSProviderID: dnsProviderID,
		Issuer:        "letsencrypt_prod",
		IsAutoRenew:   true,
	}
	if err := certificates.Create(ctx, cert); err != nil {
		logger.Warn("certificate enqueue failed", "host", host, "error", err)
		return
	}
	logger.Info("certificate enqueued", "host", host, "challenge", challengeType)
}

func bootstrapAdminCertificate(ctx context.Context, cfg config.Config, domains *store.DomainStore, certificates *store.CertificateStore, dnsProviders *store.DNSProviderStore, logger *slog.Logger) {
	if !cfg.ACMEEnabled {
		return
	}
	host := hostnameFromURL(cfg.FrontendBaseURL)
	if skippableCertHost(host) {
		return
	}

	existing, err := domains.GetByName(ctx, host)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		logger.Warn("admin domain lookup failed", "host", host, "error", err)
		return
	}

	var dom *domain.Domain
	if existing != nil {
		dom = existing
	} else {
		dom = &domain.Domain{Name: host, Type: "single"}
		if err := domains.Create(ctx, dom); err != nil {
			logger.Warn("admin domain create failed", "host", host, "error", err)
			return
		}
		logger.Info("admin domain registered", "host", host)
	}

	certs, err := certificates.List(ctx)
	if err != nil {
		logger.Warn("certificate list failed", "error", err)
		return
	}
	if hostCoveredByCertificate(host, certs) {
		return
	}

	challengeType, dnsProviderID := activeCertChallenge(ctx, dnsProviders, logger)
	enqueuePendingCertificate(ctx, certificates, dom.ID, host, challengeType, dnsProviderID, logger)
}

func ensureServiceCertificates(ctx context.Context, cfg config.Config, services *store.ServiceStore, certificates *store.CertificateStore, dnsProviders *store.DNSProviderStore, logger *slog.Logger) {
	if !cfg.ACMEEnabled {
		return
	}
	items, err := services.List(ctx)
	if err != nil {
		logger.Warn("service list for certificate enrollment failed", "error", err)
		return
	}
	certs, err := certificates.List(ctx)
	if err != nil {
		logger.Warn("certificate list for enrollment failed", "error", err)
		return
	}

	challengeType, dnsProviderID := activeCertChallenge(ctx, dnsProviders, logger)
	for i := range items {
		service := items[i]
		if service.TLSMode != "offload" {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(domain.ServiceHost(service)))
		if skippableCertHost(host) || service.DomainID == 0 {
			continue
		}
		if hostCoveredByCertificate(host, certs) {
			continue
		}
		enqueuePendingCertificate(ctx, certificates, service.DomainID, host, challengeType, dnsProviderID, logger)
		certs = append(certs, domain.Certificate{PrimaryDomain: host})
	}
}

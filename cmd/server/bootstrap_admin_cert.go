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

func bootstrapAdminCertificate(ctx context.Context, cfg config.Config, domains *store.DomainStore, certificates *store.CertificateStore, dnsProviders *store.DNSProviderStore, logger *slog.Logger) {
	if !cfg.ACMEEnabled {
		return
	}
	host := hostnameFromURL(cfg.FrontendBaseURL)
	if host == "" || host == "localhost" || strings.HasPrefix(host, "127.") {
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
		dom = &domain.Domain{
			Name: host,
			Type: "single",
		}
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
	for _, c := range certs {
		if c.PrimaryDomain == host {
			return
		}
	}

	challengeType := domain.CertificateChallengeHTTP01
	var dnsProviderID *uint
	if providers, err := dnsProviders.List(ctx); err != nil {
		logger.Warn("admin certificate dns provider lookup failed", "error", err)
	} else {
		for i := range providers {
			if providers[i].IsActive {
				id := providers[i].ID
				dnsProviderID = &id
				challengeType = domain.CertificateChallengeDNS01
				break
			}
		}
	}

	cert := &domain.Certificate{
		DomainID:      dom.ID,
		PrimaryDomain: host,
		Type:          domain.CertificateTypeSingle,
		Status:        domain.CertificateStatusPending,
		ChallengeType: challengeType,
		DNSProviderID: dnsProviderID,
		Issuer:        "letsencrypt_prod",
		IsAutoRenew:   true,
	}
	if err := certificates.Create(ctx, cert); err != nil {
		logger.Warn("admin certificate create failed", "host", host, "error", err)
		return
	}
	logger.Info("admin certificate enqueued", "host", host, "challenge", cert.ChallengeType)
}

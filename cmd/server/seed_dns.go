package main

import (
	"context"
	"log/slog"
	"strings"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
	"portlyn/internal/store"
)

func seedDNSProviderFromEnv(ctx context.Context, cfg config.Config, dnsProviders *store.DNSProviderStore, logger *slog.Logger) {
	if cfg.ACMEDNSProvider == "" {
		return
	}
	count, err := dnsProviders.Count(ctx)
	if err != nil {
		logger.Warn("dns provider seed: count failed", "error", err)
		return
	}
	if count > 0 {
		return
	}

	providerConfig := map[string]string{}
	for k, v := range cfg.ACMEDNSConfig {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			providerConfig[k] = trimmed
		}
	}

	encrypted, err := secureconfig.EncryptJSONV2([]byte(cfg.DataEncryptionSecret), providerConfig)
	if err != nil {
		logger.Error("dns provider seed: encrypt config failed", "error", err)
		return
	}

	item := &domain.DNSProvider{
		Name:                "default",
		Type:                cfg.ACMEDNSProvider,
		ConfigEncrypted:     encrypted,
		ConfigHint:          "Seeded from ACME_DNS_PROVIDER environment configuration.",
		IsActive:            true,
		HasStoredSecret:     len(providerConfig) > 0,
		SupportedChallenges: domain.JSONStringSlice{domain.CertificateChallengeDNS01},
	}
	if err := dnsProviders.Create(ctx, item); err != nil {
		logger.Error("dns provider seed: create failed", "error", err, "type", cfg.ACMEDNSProvider)
		return
	}
	logger.Info("seeded dns provider from environment", "type", cfg.ACMEDNSProvider)
}

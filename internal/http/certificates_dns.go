package http

import (
	"context"
	"fmt"
	stdhttp "net/http"
	"strings"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

func (s *Server) validateAndHydrateCertificate(ctx context.Context, item *domain.Certificate) error {
	baseDomain, err := s.domains.GetByID(ctx, item.DomainID)
	if err != nil {
		return err
	}
	item.Domain = *baseDomain
	if item.PrimaryDomain == "" {
		item.PrimaryDomain = normalizeHostname(baseDomain.Name)
	} else {
		item.PrimaryDomain = normalizeHostname(item.PrimaryDomain)
	}

	names, err := normalizeCertificateNames(item.PrimaryDomain, item.SANs)
	if err != nil {
		return err
	}
	item.PrimaryDomain = names[0]
	item.SANs = toCertificateSANs(names[1:])

	if item.Type == "" {
		if len(item.SANs) > 0 {
			item.Type = domain.CertificateTypeMultiSAN
		} else {
			item.Type = domain.CertificateTypeSingle
		}
	}
	if item.Type == domain.CertificateTypeWildcard && !strings.HasPrefix(item.PrimaryDomain, "*.") {
		item.PrimaryDomain = "*." + strings.TrimPrefix(item.PrimaryDomain, "*.")
	}
	if item.Type != domain.CertificateTypeWildcard && strings.HasPrefix(item.PrimaryDomain, "*.") {
		return fmt.Errorf("wildcard primary domains require certificate type wildcard")
	}
	if item.Type == domain.CertificateTypeWildcard && item.ChallengeType != domain.CertificateChallengeDNS01 {
		return fmt.Errorf("wildcard certificates require dns-01 challenge")
	}
	if item.ChallengeType == domain.CertificateChallengeHTTP01 && hasWildcardName(item.PrimaryDomain, item.SANs) {
		return fmt.Errorf("http-01 challenge does not support wildcard names")
	}
	if item.ChallengeType == domain.CertificateChallengeDNS01 {
		if item.DNSProviderID == nil || *item.DNSProviderID == 0 {
			return fmt.Errorf("dns-01 challenge requires an active DNS provider")
		}
		provider, providerErr := s.dnsProviders.GetByID(ctx, *item.DNSProviderID)
		if providerErr != nil {
			return providerErr
		}
		if !provider.IsActive {
			return fmt.Errorf("selected DNS provider is not active")
		}
		item.DNSProvider = sanitizeDNSProvider(s.dataSecrets(), provider)
	} else {
		item.DNSProviderID = nil
		item.DNSProvider = nil
	}
	if item.RenewalWindowDays == 0 {
		item.RenewalWindowDays = 30
	}
	if item.Issuer == "" {
		item.Issuer = domain.CertificateIssuerLetsEncryptProd
	}
	if item.Status == "" {
		item.Status = domain.CertificateStatusPending
	}
	return nil
}

func normalizeCertificateNames(primary string, sans []domain.CertificateSAN) ([]string, error) {
	seen := map[string]struct{}{}
	names := make([]string, 0, len(sans)+1)
	for _, candidate := range append([]string{primary}, sanNames(sans)...) {
		name := normalizeHostname(candidate)
		if name == "" {
			continue
		}
		if !isValidCertificateDNSName(name) {
			return nil, fmt.Errorf("invalid certificate domain %q", candidate)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate certificate domain %q", candidate)
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one valid certificate domain is required")
	}
	return names, nil
}

func toCertificateSANs(names []string) []domain.CertificateSAN {
	items := make([]domain.CertificateSAN, 0, len(names))
	for _, name := range names {
		items = append(items, domain.CertificateSAN{DomainName: name})
	}
	return items
}

func sanNames(items []domain.CertificateSAN) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.DomainName)
	}
	return out
}

func hasWildcardName(primary string, sans []domain.CertificateSAN) bool {
	if strings.HasPrefix(primary, "*.") {
		return true
	}
	for _, item := range sans {
		if strings.HasPrefix(item.DomainName, "*.") {
			return true
		}
	}
	return false
}

func isValidCertificateDNSName(value string) bool {
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func sanitizeDNSProvider(secrets [][]byte, item *domain.DNSProvider) *domain.DNSProvider {
	if item == nil {
		return nil
	}
	out := *item
	config, err := secureconfig.DecryptJSONAuto(secrets, item.ConfigEncrypted)
	if err == nil {
		out.MaskedConfig = domain.JSONObject(secureconfig.MaskConfig(config))
	}
	out.ConfigEncrypted = ""
	return &out
}

func sanitizeDNSProviders(secrets [][]byte, items []domain.DNSProvider) []domain.DNSProvider {
	out := make([]domain.DNSProvider, 0, len(items))
	for i := range items {
		item := sanitizeDNSProvider(secrets, &items[i])
		if item != nil {
			out = append(out, *item)
		}
	}
	return out
}

func providerConfigHint(providerType string) string {
	switch providerType {
	case domain.DNSProviderTypeCloudflare:
		return "Requires api_token with Zone DNS edit permission."
	case domain.DNSProviderTypeHetzner:
		return "Requires dns_api_token for the target zone."
	case domain.DNSProviderTypeRoute53:
		return "Supports AWS env-chain auth or explicit keys. For explicit credentials use access_key_id, secret_access_key, optional session_token, and optional region/hosted_zone_id/profile."
	case domain.DNSProviderTypeDO:
		return "Requires api_token for DigitalOcean DNS."
	default:
		return ""
	}
}

func requiredProviderKeys(providerType string) []string {
	switch providerType {
	case domain.DNSProviderTypeCloudflare:
		return []string{"api_token"}
	case domain.DNSProviderTypeHetzner:
		return []string{"dns_api_token"}
	case domain.DNSProviderTypeRoute53:
		return nil
	case domain.DNSProviderTypeDO:
		return []string{"api_token"}
	default:
		return nil
	}
}

func normalizeProviderConfig(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		out[trimmedKey] = strings.TrimSpace(value)
	}
	return out
}

func validateProviderConfig(providerType string, config map[string]string) error {
	keys := requiredProviderKeys(providerType)
	for _, key := range keys {
		if strings.TrimSpace(config[key]) == "" {
			return fmt.Errorf("provider config field %q is required", key)
		}
	}
	return nil
}

func (s *Server) handleListDNSProviders(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.dnsProviders.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, sanitizeDNSProviders(s.dataSecrets(), items))
}

func (s *Server) handleGetDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDNSProvider(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, sanitizeDNSProvider(s.dataSecrets(), item))
}

func (s *Server) handleCreateDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createDNSProviderRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	config := normalizeProviderConfig(req.Config)
	if err := validateProviderConfig(req.Type, config); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}
	encrypted, err := s.dataEncryptJSON(config)
	if err != nil {
		s.internalError(w, err)
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	item := &domain.DNSProvider{
		Name:                strings.TrimSpace(req.Name),
		Type:                req.Type,
		ConfigEncrypted:     encrypted,
		ConfigHint:          providerConfigHint(req.Type),
		IsActive:            active,
		HasStoredSecret:     len(config) > 0,
		SupportedChallenges: domain.JSONStringSlice{domain.CertificateChallengeDNS01},
	}
	if err := s.dnsProviders.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "dns_provider", &item.ID, map[string]any{"name": item.Name, "type": item.Type})
	writeJSON(w, stdhttp.StatusCreated, sanitizeDNSProvider(s.dataSecrets(), item))
}

func (s *Server) handleUpdateDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDNSProvider(w, r)
	if !ok {
		return
	}
	var req updateDNSProviderRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if req.Name != nil {
		item.Name = strings.TrimSpace(*req.Name)
	}
	if req.Type != nil {
		item.Type = *req.Type
		item.ConfigHint = providerConfigHint(item.Type)
	}
	if req.Active != nil {
		item.IsActive = *req.Active
	}
	if req.Config != nil {
		config := normalizeProviderConfig(req.Config)
		if err := validateProviderConfig(item.Type, config); err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
			return
		}
		encrypted, err := s.dataEncryptJSON(config)
		if err != nil {
			s.internalError(w, err)
			return
		}
		item.ConfigEncrypted = encrypted
		item.HasStoredSecret = len(config) > 0
	} else if item.ConfigEncrypted != "" {
		config, err := s.dataDecryptJSON(item.ConfigEncrypted)
		if err != nil {
			s.internalError(w, err)
			return
		}
		if err := validateProviderConfig(item.Type, config); err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
			return
		}
	}
	if err := s.dnsProviders.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "dns_provider", &item.ID, map[string]any{"name": item.Name, "type": item.Type})
	writeJSON(w, stdhttp.StatusOK, sanitizeDNSProvider(s.dataSecrets(), item))
}

func (s *Server) handleDeleteDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.dnsProviders.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "dns_provider", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) handleTestDNSProvider(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDNSProvider(w, r)
	if !ok {
		return
	}
	config, err := s.dataDecryptJSON(item.ConfigEncrypted)
	if err != nil {
		s.internalError(w, err)
		return
	}
	testErr := validateProviderConfig(item.Type, config)
	now := time.Now().UTC()
	item.LastTestedAt = &now
	if testErr != nil {
		item.LastTestStatus = "failed"
		item.LastTestError = testErr.Error()
	} else {
		item.LastTestStatus = "ok"
		item.LastTestError = ""
	}
	if err := s.dnsProviders.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "test", "dns_provider", &item.ID, map[string]any{"dns_provider_id": item.ID})
	if testErr != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", testErr.Error())
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"id":            item.ID,
		"status":        item.LastTestStatus,
		"tested_at":     item.LastTestedAt,
		"provider":      item.Name,
		"provider_type": item.Type,
	})
}

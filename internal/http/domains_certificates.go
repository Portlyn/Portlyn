package http

import (
	stdhttp "net/http"
	"portlyn/internal/domain"
	"portlyn/internal/store"
	"strconv"
	"strings"
)

func (s *Server) handleListDomains(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.domains.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleCreateDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createDomainRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	item := &domain.Domain{
		Name:        normalizeHostname(req.Name),
		Type:        req.Type,
		Provider:    req.Provider,
		Notes:       req.Notes,
		IPAllowlist: normalizeStringList(req.IPAllowlist),
		IPBlocklist: normalizeStringList(req.IPBlocklist),
	}
	if err := s.domains.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "domain", &item.ID, item)

	autoCert := req.AutoCertificate == nil || *req.AutoCertificate
	if cert := s.autoIssueCertificateForDomain(r.Context(), item, req.DNSProviderID, autoCert); cert != nil {
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "auto_create", "certificate", &cert.ID, map[string]any{
			"certificate_id": cert.ID,
			"domain":         item.Name,
			"trigger":        "domain_create",
		})
		w.Header().Set("X-Portlyn-Auto-Certificate-Id", strconv.FormatUint(uint64(cert.ID), 10))
	}
	writeJSON(w, stdhttp.StatusCreated, item)
}

func (s *Server) handleGetDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleUpdateDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	previousHost := normalizeHostname(item.Name)
	affectedServices, err := s.services.ListByDomainID(r.Context(), item.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}

	var req updateDomainRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if req.Name != nil {
		item.Name = normalizeHostname(*req.Name)
	}
	if req.Type != nil {
		item.Type = *req.Type
	}
	if req.Provider != nil {
		item.Provider = *req.Provider
	}
	if req.Notes != nil {
		item.Notes = *req.Notes
	}
	if req.IPAllowlist != nil {
		item.IPAllowlist = normalizeStringList(*req.IPAllowlist)
	}
	if req.IPBlocklist != nil {
		item.IPBlocklist = normalizeStringList(*req.IPBlocklist)
	}

	if err := s.domains.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	if err := s.invalidateServiceHostsForDomain(r.Context(), previousHost, item.Name, affectedServices); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "domain", &item.ID, item)
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleDeleteDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	affectedServices, err := s.services.ListByDomainID(r.Context(), item.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	id := item.ID
	host := normalizeHostname(item.Name)
	if err := s.domains.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if err := s.invalidateServiceHostsForDomain(r.Context(), host, "", affectedServices); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "domain", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) handleListCertificates(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.certificates.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	for i := range items {
		items[i].DNSProvider = sanitizeDNSProvider(s.dataSecrets(), items[i].DNSProvider)
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleCreateCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createCertificateRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if _, err := s.domains.GetByID(r.Context(), req.DomainID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if len(req.DNSProviderConfig) > 0 {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", "inline dns_provider_config is not supported; create a DNS provider resource and reference it")
		return
	}

	item := &domain.Certificate{
		DomainID:          req.DomainID,
		PrimaryDomain:     req.PrimaryDomain,
		Type:              req.Type,
		Status:            domain.CertificateStatusPending,
		ChallengeType:     req.ChallengeType,
		Issuer:            req.Issuer,
		IsAutoRenew:       req.IsAutoRenew,
		RenewalWindowDays: req.RenewalWindowDays,
		DNSProviderID:     req.DNSProviderID,
	}
	if req.ExpiresAt != nil {
		item.ExpiresAt = req.ExpiresAt.UTC()
	}
	for _, name := range req.SANs {
		item.SANs = append(item.SANs, domain.CertificateSAN{DomainName: name})
	}
	if err := s.validateAndHydrateCertificate(r.Context(), item); err != nil {
		if err == store.ErrNotFound {
			s.handleStoreError(w, err)
			return
		}
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := s.certificates.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	if err := s.certificates.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	if parseBoolQuery(r, "sync") {
		if _, err := s.acme.SyncCertificate(r.Context(), item); err != nil {
			s.internalError(w, err)
			return
		}
	}
	item, _ = s.certificates.GetByID(r.Context(), item.ID)
	if item != nil {
		item.DNSProvider = sanitizeDNSProvider(s.dataSecrets(), item.DNSProvider)
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "certificate", &item.ID, item)
	writeJSON(w, stdhttp.StatusCreated, item)
}

func (s *Server) handleGetCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	item.DNSProvider = sanitizeDNSProvider(s.dataSecrets(), item.DNSProvider)
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleUpdateCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}

	var req updateCertificateRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if len(req.DNSProviderConfig) > 0 {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", "inline dns_provider_config is not supported; create or update a DNS provider resource instead")
		return
	}
	if req.DomainID != nil {
		if _, err := s.domains.GetByID(r.Context(), *req.DomainID); err != nil {
			s.handleStoreError(w, err)
			return
		}
		item.DomainID = *req.DomainID
	}
	if req.Type != nil {
		item.Type = *req.Type
	}
	if req.PrimaryDomain != nil {
		item.PrimaryDomain = *req.PrimaryDomain
	}
	if req.ChallengeType != nil {
		item.ChallengeType = *req.ChallengeType
	}
	if req.Issuer != nil {
		item.Issuer = *req.Issuer
	}
	if req.ExpiresAt != nil {
		item.ExpiresAt = *req.ExpiresAt
	}
	if req.IsAutoRenew != nil {
		item.IsAutoRenew = *req.IsAutoRenew
	}
	if req.RenewalWindowDays != nil {
		item.RenewalWindowDays = *req.RenewalWindowDays
	}
	if req.DNSProviderID != nil {
		item.DNSProviderID = req.DNSProviderID
	}
	if req.SANs != nil {
		item.SANs = item.SANs[:0]
		for _, name := range *req.SANs {
			item.SANs = append(item.SANs, domain.CertificateSAN{DomainName: name})
		}
	}
	if err := s.validateAndHydrateCertificate(r.Context(), item); err != nil {
		if err == store.ErrNotFound {
			s.handleStoreError(w, err)
			return
		}
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := s.certificates.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	item, _ = s.certificates.GetByID(r.Context(), item.ID)
	if item != nil {
		item.DNSProvider = sanitizeDNSProvider(s.dataSecrets(), item.DNSProvider)
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "certificate", &item.ID, item)
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleDeleteCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	item, err := s.certificates.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	names := certificateDomainNames(item)
	if err := s.certificates.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if err := s.acme.PurgeCertificateData(r.Context(), names); err != nil {
		s.logger.Warn("certificate delete: purging stored and certmagic data failed", "id", id, "error", err)
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "certificate", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func certificateDomainNames(item *domain.Certificate) []string {
	names := make([]string, 0, len(item.SANs)+1)
	if primary := strings.TrimSpace(item.PrimaryDomain); primary != "" {
		names = append(names, primary)
	} else if strings.TrimSpace(item.Domain.Name) != "" {
		names = append(names, strings.TrimSpace(item.Domain.Name))
	}
	for _, san := range item.SANs {
		if name := strings.TrimSpace(san.DomainName); name != "" {
			names = append(names, name)
		}
	}
	return names
}

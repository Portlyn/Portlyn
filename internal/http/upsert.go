package http

import (
	"errors"
	stdhttp "net/http"
	"strconv"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

// handleUpsertDomain upserts a domain by its FQDN (name). A repeated apply of the
// same desired state is a no-op update rather than a conflict, which makes
// declarative automation robust. Returns 201 when created, 200 when updated.
func (s *Server) handleUpsertDomain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createDomainRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	name := normalizeHostname(req.Name)
	existing, err := s.domains.GetByName(r.Context(), name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, err)
		return
	}

	if existing != nil {
		affectedServices, listErr := s.services.ListByDomainID(r.Context(), existing.ID)
		if listErr != nil {
			s.internalError(w, listErr)
			return
		}
		existing.Type = req.Type
		existing.Provider = req.Provider
		existing.Notes = req.Notes
		existing.IPAllowlist = normalizeStringList(req.IPAllowlist)
		existing.IPBlocklist = normalizeStringList(req.IPBlocklist)
		if err := s.domains.Update(r.Context(), existing); err != nil {
			s.internalError(w, err)
			return
		}
		if err := s.invalidateServiceHostsForDomain(r.Context(), name, name, affectedServices); err != nil {
			s.internalError(w, err)
			return
		}
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "upsert", "domain", &existing.ID, existing)
		writeJSON(w, stdhttp.StatusOK, existing)
		return
	}

	item := &domain.Domain{
		Name:        name,
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
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "upsert", "domain", &item.ID, item)
	autoCert := req.AutoCertificate == nil || *req.AutoCertificate
	if cert := s.autoIssueCertificateForDomain(r.Context(), item, req.DNSProviderID, autoCert); cert != nil {
		_ = s.audit.Log(r.Context(), s.currentUserID(r), "auto_create", "certificate", &cert.ID, map[string]any{
			"certificate_id": cert.ID,
			"domain":         item.Name,
			"trigger":        "domain_upsert",
		})
		w.Header().Set("X-Portlyn-Auto-Certificate-Id", strconv.FormatUint(uint64(cert.ID), 10))
	}
	writeJSON(w, stdhttp.StatusCreated, item)
}

// handleUpsertService upserts a service by its route identity (domain + subdomain
// + path). A repeated apply updates in place instead of erroring, enabling
// declarative "apply desired state" automation. Returns 201 when created, 200
// when updated.
func (s *Server) handleUpsertService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createServiceRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if _, err := s.domains.GetByID(r.Context(), req.DomainID); err != nil {
		s.handleStoreError(w, err)
		return
	}
	subdomain, err := domain.NormalizeSubdomain(req.Subdomain)
	if err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}

	existing, findErr := s.services.FindByRoute(r.Context(), req.DomainID, subdomain, req.Path)
	if findErr != nil && !errors.Is(findErr, store.ErrNotFound) {
		s.internalError(w, findErr)
		return
	}

	var existingConfig domain.JSONObject
	if existing != nil {
		existingConfig = existing.AccessMethodConfig
	}
	item := buildServiceFromCreateRequest(req, subdomain, existingConfig)
	if err := validateServiceTargetURL(item.TargetURL); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := validateUpstreamCAPEM(item.UpstreamCAPEM); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}

	created := existing == nil
	if existing != nil {
		item.ID = existing.ID
		item.CreatedAt = existing.CreatedAt
		item.DeploymentRevision = existing.DeploymentRevision
		item.LastDeployedAt = existing.LastDeployedAt
		if err := s.services.Update(r.Context(), item); err != nil {
			s.internalError(w, err)
			return
		}
	} else {
		if err := s.services.Create(r.Context(), item); err != nil {
			s.internalError(w, err)
			return
		}
	}
	if err := s.services.ReplaceServiceGroups(r.Context(), item.ID, req.ServiceGroupIDs); err != nil {
		s.internalError(w, err)
		return
	}

	deployed, err := s.proxy.ApplyServiceChange(r.Context(), item.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "upsert", "service", &deployed.ID, deployed)

	status := stdhttp.StatusOK
	if created {
		status = stdhttp.StatusCreated
	}
	writeJSON(w, status, serviceResponse(*deployed, s.evaluateServiceHealth(r.Context(), *deployed), s.certInfoForService(r.Context(), *deployed)))
}

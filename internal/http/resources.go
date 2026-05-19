package http

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	stdhttp "net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/proxy"
	"portlyn/internal/store"
)

type serviceHealthInfo struct {
	Status    string
	Error     string
	Reason    string
	CheckedAt time.Time
}

func (s *Server) handleListNodes(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.nodes.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	for i := range items {
		s.evaluateNodeStatus(&items[i])
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleCreateNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createNodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	item := &domain.Node{
		Name:              req.Name,
		Description:       req.Description,
		LastSeenAt:        req.LastSeenAt,
		Version:           req.Version,
		Status:            req.Status,
		HeartbeatAuthMode: "token",
	}
	if strings.EqualFold(strings.TrimSpace(req.AuthMode), "mtls") {
		item.HeartbeatAuthMode = "mtls"
		item.MTLSCertSHA256 = strings.ToLower(strings.TrimSpace(req.MTLSSHA256))
	}
	if item.HeartbeatAuthMode == "mtls" && item.MTLSCertSHA256 == "" {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", "mtls_cert_sha256 is required when heartbeat_auth_mode is mtls")
		return
	}
	if err := s.nodes.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "node", &item.ID, item)
	writeJSON(w, stdhttp.StatusCreated, item)
}

func (s *Server) handleGetNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	s.evaluateNodeStatus(item)
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleUpdateNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadNode(w, r)
	if !ok {
		return
	}

	var req updateNodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if req.Name != nil {
		item.Name = *req.Name
	}
	if req.Description != nil {
		item.Description = *req.Description
	}
	if req.LastSeenAt != nil {
		item.LastSeenAt = req.LastSeenAt
	}
	if req.Version != nil {
		item.Version = *req.Version
	}
	if req.Status != nil {
		item.Status = *req.Status
	}
	if req.AuthMode != nil {
		item.HeartbeatAuthMode = strings.ToLower(strings.TrimSpace(*req.AuthMode))
	}
	if req.MTLSSHA256 != nil {
		item.MTLSCertSHA256 = strings.ToLower(strings.TrimSpace(*req.MTLSSHA256))
	}
	if item.HeartbeatAuthMode == "mtls" && item.MTLSCertSHA256 == "" {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", "mtls_cert_sha256 is required when heartbeat_auth_mode is mtls")
		return
	}

	if err := s.nodes.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "node", &item.ID, item)
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleDeleteNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.nodes.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "node", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) handleHeartbeatNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if !s.requireNodeSecureTransport(w, r) {
		return
	}

	node, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if !s.authorizeNodeHeartbeat(r, node) {
		now := time.Now().UTC()
		node.LastHeartbeatIP = s.clientIPForRequest(r)
		node.LastHeartbeatCode = stdhttp.StatusUnauthorized
		node.LastHeartbeatError = "invalid_token"
		node.HeartbeatFailedAt = &now
		if node.Status != domain.NodeStatusOffline {
			node.Status = domain.NodeStatusOffline
		}
		_ = s.nodes.UpdateHeartbeat(r.Context(), node)
		_ = s.audit.LogRequest(r.Context(), r, nil, "node_heartbeat_rejected", "node", &node.ID, map[string]any{
			"node_id":      node.ID,
			"remote_addr":  s.clientIPForRequest(r),
			"status_code":  stdhttp.StatusUnauthorized,
			"auth_mode":    node.HeartbeatAuthMode,
			"node_version": node.Version,
		})
		if !s.enforceNodeRateLimit(w, r, "node_heartbeat_auth_fail", s.cfg.NodeHeartbeatAuthFailRateLimit, s.cfg.NodeHeartbeatAuthFailRateWindow) {
			return
		}
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing or invalid node token")
		return
	}

	var req heartbeatNodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}

	now := time.Now().UTC()
	node.LastHeartbeatAt = &now
	node.LastSeenAt = &now
	node.Status = domain.NodeStatusOnline
	node.LastHeartbeatIP = s.clientIPForRequest(r)
	node.LastHeartbeatCode = stdhttp.StatusOK
	node.LastHeartbeatError = ""
	node.HeartbeatFailedAt = nil
	node.HeartbeatVersion = node.Version
	if req.Version != nil {
		node.Version = *req.Version
		node.HeartbeatVersion = *req.Version
	}
	if req.Status != nil {
		node.Status = *req.Status
	}
	if req.Load != nil {
		node.Load = *req.Load
	}
	if req.BandwidthInKbps != nil {
		node.BandwidthInKbps = *req.BandwidthInKbps
	}
	if req.BandwidthOutKbps != nil {
		node.BandwidthOutKbps = *req.BandwidthOutKbps
	}

	if err := s.nodes.UpdateHeartbeat(r.Context(), node); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, nil, "node_heartbeat_accepted", "node", &node.ID, map[string]any{
		"node_id":      node.ID,
		"remote_addr":  node.LastHeartbeatIP,
		"status_code":  stdhttp.StatusOK,
		"auth_mode":    node.HeartbeatAuthMode,
		"node_version": node.HeartbeatVersion,
	})
	writeJSON(w, stdhttp.StatusOK, node)
}

func (s *Server) authorizeNodeHeartbeat(r *stdhttp.Request, node *domain.Node) bool {
	if strings.EqualFold(strings.TrimSpace(node.HeartbeatAuthMode), "mtls") {
		return verifyNodeMTLS(r, node.MTLSCertSHA256, s.cfg.NodeAllowMTLSHeaderFallback && s.cfg.NodeTrustForwardedProto)
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if token != "" && node.HeartbeatTokenHash != "" && hmac.Equal([]byte(node.HeartbeatTokenHash), []byte(hashOpaqueToken(token))) {
			return true
		}
	}
	return false
}

func hashOpaqueToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func verifyNodeMTLS(r *stdhttp.Request, expectedFingerprint string, allowHeaderFallback bool) bool {
	expected := strings.ToLower(strings.TrimSpace(expectedFingerprint))
	if expected == "" {
		return false
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		return expected == hex.EncodeToString(sum[:])
	}
	if !allowHeaderFallback {
		return false
	}
	forwarded := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Portlyn-Client-Cert-SHA256")))
	return forwarded != "" && forwarded == expected
}

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
	if err := s.certificates.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "certificate", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) handleListServices(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.services.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	healthByServiceID := s.evaluateServicesHealth(r.Context(), items)
	user, _ := auth.UserFromContext(r.Context())
	groupIDs, _ := auth.GroupIDsFromContext(r.Context())
	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if user != nil && user.Role == domain.RoleViewer {
			if !viewerCanAccessService(user, groupIDs, item) {
				continue
			}
			response = append(response, viewerServiceResponse(item, healthByServiceID[item.ID]))
			continue
		}
		response = append(response, serviceResponse(item, healthByServiceID[item.ID]))
	}
	writeJSON(w, stdhttp.StatusOK, response)
}

func (s *Server) evaluateServicesHealth(ctx context.Context, items []domain.Service) map[uint]serviceHealthInfo {
	results := make(map[uint]serviceHealthInfo, len(items))
	if len(items) == 0 {
		return results
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			health := s.evaluateServiceHealth(ctx, item)
			mu.Lock()
			results[item.ID] = health
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func (s *Server) evaluateServiceHealth(ctx context.Context, item domain.Service) serviceHealthInfo {
	checkedAt := time.Now().UTC()
	if item.LastDeployedAt == nil {
		return serviceHealthInfo{Status: "pending", Reason: "not_deployed", CheckedAt: checkedAt}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	err := probeHTTPHealthTarget(probeCtx, &stdhttp.Client{Timeout: 1500 * time.Millisecond}, HTTPHealthTarget{
		Name: item.Name,
		URL:  item.TargetURL,
	})
	if err != nil {
		return serviceHealthInfo{
			Status:    "unhealthy",
			Error:     err.Error(),
			Reason:    "target_probe_failed",
			CheckedAt: checkedAt,
		}
	}
	return serviceHealthInfo{Status: "healthy", Reason: "target_reachable", CheckedAt: checkedAt}
}

func viewerCanAccessService(user *domain.User, groupIDs []uint, item domain.Service) bool {
	if user == nil {
		return false
	}
	policy, method, _, _ := proxy.EffectiveAccessForService(item)
	switch method {
	case domain.AccessMethodOIDCOnly:
		if user.AuthProvider != domain.AuthProviderOIDC || !user.Active {
			return false
		}
	}
	switch policy.AccessMode {
	case "", domain.AccessModePublic, domain.AccessModeAuthenticated:
		return true
	case domain.AccessModeRestricted:
		return restrictedPolicyAllowsUser(user, groupIDs, policy)
	default:
		return false
	}
}

func restrictedPolicyAllowsUser(user *domain.User, groupIDs []uint, policy domain.AccessPolicy) bool {
	if user == nil {
		return false
	}
	for _, role := range policy.AllowedRoles {
		if role == user.Role {
			return true
		}
	}
	groupSet := make(map[uint]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		groupSet[id] = struct{}{}
	}
	for _, groupID := range policy.AllowedGroups {
		if _, ok := groupSet[groupID]; ok {
			return true
		}
	}
	return len(policy.AllowedRoles) == 0 && len(policy.AllowedGroups) == 0
}

func viewerServiceResponse(item domain.Service, health serviceHealthInfo) map[string]any {
	policy, method, effectiveConfig, inheritedFrom := proxy.EffectiveAccessForService(item)
	riskScore, riskReasons := serviceRiskAssessment(item, policy.AccessMode, method, effectiveConfig, nil)
	return map[string]any{
		"id":                             item.ID,
		"name":                           item.Name,
		"domain_id":                      item.DomainID,
		"domain":                         item.Domain,
		"path":                           item.Path,
		"target_url":                     "",
		"tls_mode":                       "",
		"auth_policy":                    item.AuthPolicy,
		"access_mode":                    policy.AccessMode,
		"allowed_roles":                  []string{},
		"allowed_groups":                 []uint{},
		"allowed_service_groups":         []uint{},
		"use_group_policy":               item.UseGroupPolicy,
		"access_method":                  normalizeOptionalAccessMethod(item.AccessMethod),
		"access_method_config":           sanitizeAccessMethodConfig(method, effectiveConfig),
		"effective_access_mode":          policy.AccessMode,
		"effective_access_method":        method,
		"effective_access_method_config": sanitizeAccessMethodConfig(method, effectiveConfig),
		"access_message":                 strings.TrimSpace(item.AccessMessage),
		"service_groups":                 []map[string]any{},
		"inherited_from_group":           serviceGroupBrief(inheritedFrom),
		"service_overrides_group":        strings.TrimSpace(item.AccessMethod) != "",
		"risk_score":                     riskScore,
		"risk_reasons":                   riskReasons,
		"ip_allowlist":                   []string{},
		"ip_blocklist":                   []string{},
		"access_windows":                 []domain.AccessWindow{},
		"last_deployed_at":               item.LastDeployedAt,
		"deployment_revision":            item.DeploymentRevision,
		"service_status":                 health.Status,
		"service_status_error":           health.Error,
		"service_status_checked_at":      health.CheckedAt,
		"created_at":                     item.CreatedAt,
		"updated_at":                     item.UpdatedAt,
	}
}

func (s *Server) handleCreateService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
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

	item := &domain.Service{
		Name:                 req.Name,
		DomainID:             req.DomainID,
		Subdomain:            subdomain,
		Path:                 req.Path,
		TargetURL:            req.TargetURL,
		TLSMode:              req.TLSMode,
		AuthPolicy:           req.AuthPolicy,
		AccessMode:           req.AccessPolicy.AccessMode,
		AllowedRoles:         normalizeStringList(req.AccessPolicy.AllowedRoles),
		AllowedGroups:        domain.JSONUintSlice(req.AccessPolicy.AllowedGroups),
		AllowedServiceGroups: domain.JSONUintSlice(req.AccessPolicy.AllowedServiceGroups),
		UseGroupPolicy:       req.UseGroupPolicy,
		AccessMethod:         normalizeOptionalAccessMethod(req.AccessMethod),
		AccessMethodConfig:   buildAccessMethodConfig(req.AccessMethod, req.AccessMethodConfig, nil),
		AccessMessage:        strings.TrimSpace(req.AccessMessage),
		IPAllowlist:          normalizeStringList(req.IPAllowlist),
		IPBlocklist:          normalizeStringList(req.IPBlocklist),
		AccessWindows:        toAccessWindows(req.AccessWindows),
	}
	if err := s.services.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
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
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "service", &deployed.ID, deployed)

	writeJSON(w, stdhttp.StatusCreated, serviceResponse(*deployed, s.evaluateServiceHealth(r.Context(), *deployed)))
}

func (s *Server) handleGetService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, serviceResponse(*item, s.evaluateServiceHealth(r.Context(), *item)))
}

func (s *Server) handleUpdateService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}
	previousHost := domain.ServiceHost(*item)

	var req updateServiceRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	if req.Name != nil {
		item.Name = *req.Name
	}
	if req.DomainID != nil {
		if _, err := s.domains.GetByID(r.Context(), *req.DomainID); err != nil {
			s.handleStoreError(w, err)
			return
		}
		item.DomainID = *req.DomainID
	}
	if req.Subdomain != nil {
		subdomain, err := domain.NormalizeSubdomain(*req.Subdomain)
		if err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
			return
		}
		item.Subdomain = subdomain
	}
	if req.Path != nil {
		item.Path = *req.Path
	}
	if req.TargetURL != nil {
		item.TargetURL = *req.TargetURL
	}
	if req.TLSMode != nil {
		item.TLSMode = *req.TLSMode
	}
	if req.AuthPolicy != nil {
		item.AuthPolicy = *req.AuthPolicy
	}
	if req.AccessPolicy != nil {
		item.AccessMode = req.AccessPolicy.AccessMode
		item.AllowedRoles = normalizeStringList(req.AccessPolicy.AllowedRoles)
		item.AllowedGroups = domain.JSONUintSlice(req.AccessPolicy.AllowedGroups)
		item.AllowedServiceGroups = domain.JSONUintSlice(req.AccessPolicy.AllowedServiceGroups)
	}
	if req.UseGroupPolicy != nil {
		item.UseGroupPolicy = *req.UseGroupPolicy
	}
	if req.AccessMethod != nil {
		item.AccessMethod = normalizeOptionalAccessMethod(*req.AccessMethod)
	}
	if req.AccessMethodConfig != nil || req.AccessMethod != nil {
		method := item.AccessMethod
		if req.AccessMethod != nil {
			method = *req.AccessMethod
		}
		item.AccessMethodConfig = buildAccessMethodConfig(method, derefAccessMethodConfig(req.AccessMethodConfig), item.AccessMethodConfig)
	}
	if req.AccessMessage != nil {
		item.AccessMessage = strings.TrimSpace(*req.AccessMessage)
	}
	if req.IPAllowlist != nil {
		item.IPAllowlist = normalizeStringList(*req.IPAllowlist)
	}
	if req.IPBlocklist != nil {
		item.IPBlocklist = normalizeStringList(*req.IPBlocklist)
	}
	if req.AccessWindows != nil {
		item.AccessWindows = toAccessWindows(*req.AccessWindows)
	}

	if err := s.services.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	if req.ServiceGroupIDs != nil {
		if err := s.services.ReplaceServiceGroups(r.Context(), item.ID, *req.ServiceGroupIDs); err != nil {
			s.internalError(w, err)
			return
		}
	}

	deployed, err := s.proxy.ApplyServiceChange(r.Context(), item.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if previousHost != "" && domain.ServiceHost(*deployed) != previousHost {
		if err := s.proxy.InvalidateHost(r.Context(), previousHost); err != nil {
			s.internalError(w, err)
			return
		}
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "service", &deployed.ID, deployed)

	writeJSON(w, stdhttp.StatusOK, serviceResponse(*deployed, s.evaluateServiceHealth(r.Context(), *deployed)))
}

func (s *Server) handleDeleteService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}
	id := item.ID
	host := domain.ServiceHost(*item)
	if err := s.services.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	if err := s.proxy.InvalidateHost(r.Context(), host); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "delete", "service", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) invalidateServiceHostsForDomain(ctx context.Context, previousDomainName, currentDomainName string, services []domain.Service) error {
	hosts := make(map[string]struct{})
	addHost := func(value string) {
		if normalized := normalizeHostname(value); normalized != "" {
			hosts[normalized] = struct{}{}
		}
	}
	addHost(previousDomainName)
	addHost(currentDomainName)
	for _, service := range services {
		addHost(domain.ServiceHostname(previousDomainName, service.Subdomain))
		addHost(domain.ServiceHostname(currentDomainName, service.Subdomain))
	}
	for host := range hosts {
		if err := s.proxy.InvalidateHost(ctx, host); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleListAuditLogs(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	params := store.AuditListParams{
		Limit:        parseIntQuery(r, "limit", 50),
		Offset:       parseIntQuery(r, "offset", 0),
		ResourceType: r.URL.Query().Get("resource_type"),
		ActionLike:   r.URL.Query().Get("action_like"),
		RequestID:    strings.TrimSpace(r.URL.Query().Get("request_id")),
		Method:       strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method"))),
		Host:         strings.TrimSpace(r.URL.Query().Get("host")),
	}
	if rawUserID := r.URL.Query().Get("user_id"); rawUserID != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(rawUserID), 10, strconv.IntSize); err == nil {
			value := uint(parsed)
			params.UserID = &value
		}
	}
	if rawResourceID := r.URL.Query().Get("resource_id"); rawResourceID != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(rawResourceID), 10, strconv.IntSize); err == nil {
			value := uint(parsed)
			params.ResourceID = &value
		}
	}
	if rawStatusCode := r.URL.Query().Get("status_code"); rawStatusCode != "" {
		if parsed, err := strconv.Atoi(rawStatusCode); err == nil {
			params.StatusCode = &parsed
		}
	}
	if rawFrom := r.URL.Query().Get("from"); rawFrom != "" {
		if parsed, ok := parseAuditTimeQuery(rawFrom); ok {
			params.From = parsed
		}
	}
	if rawTo := r.URL.Query().Get("to"); rawTo != "" {
		if parsed, ok := parseAuditTimeQuery(rawTo); ok {
			params.To = parsed
		}
	}

	items, total, err := s.auditStore.List(r.Context(), params)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  params.Limit,
		"offset": params.Offset,
	})
}

func parseIntQuery(r *stdhttp.Request, key string, fallback int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func normalizeStringList(values []string) domain.JSONStringSlice {
	out := make(domain.JSONStringSlice, 0, len(values))
	for _, value := range values {
		if trimmed := domainString(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func toAccessWindows(values []accessWindowRequest) domain.AccessWindowList {
	out := make(domain.AccessWindowList, 0, len(values))
	for _, value := range values {
		out = append(out, domain.AccessWindow{
			Name:       domainString(value.Name),
			DaysOfWeek: normalizeStringList(value.DaysOfWeek),
			StartTime:  domainString(value.StartTime),
			EndTime:    domainString(value.EndTime),
			Timezone:   domainString(value.Timezone),
		})
	}
	return out
}

func domainString(value string) string {
	return strings.TrimSpace(value)
}

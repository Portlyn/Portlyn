package http

import (
	"context"
	stdhttp "net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"portlyn/internal/acme"
	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/geoip"
	"portlyn/internal/proxy"
	"portlyn/internal/store"
)

type serviceHealthInfo struct {
	Status    string
	Error     string
	Reason    string
	CheckedAt time.Time
}

const (
	nodeHeartbeatRateLimit  = 60
	nodeHeartbeatRateWindow = time.Minute
)

func (s *Server) handleListServices(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.services.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	user, _ := auth.UserFromContext(r.Context())
	groupIDs, _ := auth.GroupIDsFromContext(r.Context())
	isViewer := user != nil && user.Role == domain.RoleViewer
	visible := make([]domain.Service, 0, len(items))
	for _, item := range items {
		if isViewer && !viewerCanAccessService(user, groupIDs, item) {
			continue
		}
		visible = append(visible, item)
	}

	healthByServiceID := s.evaluateServicesHealth(r.Context(), visible)
	response := make([]map[string]any, 0, len(visible))
	for _, item := range visible {
		cert := s.certInfoForService(r.Context(), item)
		if isViewer {
			response = append(response, viewerServiceResponse(item, healthByServiceID[item.ID], cert))
		} else {
			response = append(response, serviceResponse(item, healthByServiceID[item.ID], cert))
		}
	}
	writeJSON(w, stdhttp.StatusOK, response)
}

func (s *Server) evaluateServicesHealth(ctx context.Context, items []domain.Service) map[uint]serviceHealthInfo {
	results := make(map[uint]serviceHealthInfo, len(items))
	if len(items) == 0 {
		return results
	}

	const maxConcurrentServiceHealthProbes = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, maxConcurrentServiceHealthProbes)
	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			health := s.evaluateServiceHealth(ctx, item)
			mu.Lock()
			results[item.ID] = health
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func (s *Server) certInfoForService(ctx context.Context, item domain.Service) acme.CertInfo {
	if s.acme == nil {
		return acme.CertInfo{Source: acme.CertSourceNone, Issuer: "none"}
	}
	return s.acme.ActiveCertInfo(ctx, domain.ServiceHost(item))
}

func (s *Server) evaluateServiceHealth(ctx context.Context, item domain.Service) serviceHealthInfo {
	checkedAt := time.Now().UTC()
	if item.LastDeployedAt == nil {
		return serviceHealthInfo{Status: "pending", Reason: "not_deployed", CheckedAt: checkedAt}
	}
	if err := validateServiceTargetURL(item.TargetURL); err != nil {
		return serviceHealthInfo{
			Status:    "unhealthy",
			Error:     err.Error(),
			Reason:    "invalid_target_url",
			CheckedAt: checkedAt,
		}
	}

	probeURL := item.TargetURL
	noRedirect := func(_ *stdhttp.Request, _ []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse }
	transport := &stdhttp.Transport{}
	if tlsConfig := upstreamTLSClientConfig(item); tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	client := &stdhttp.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: noRedirect, Transport: transport}
	if item.NodeID != nil && item.Node != nil && s.tunnel != nil {
		tunnelIP := strings.TrimSpace(item.Node.WGTunnelIP)
		if srv := s.tunnel.Server(); tunnelIP != "" && srv != nil && srv.Started() {
			if u, parseErr := url.Parse(item.TargetURL); parseErr == nil && u.Host != "" {
				if port := u.Port(); port != "" {
					u.Host = tunnelIP + ":" + port
				} else {
					u.Host = tunnelIP
				}
				probeURL = u.String()
			}
			tunnelTransport := &stdhttp.Transport{DialContext: srv.DialContext}
			if tlsConfig := upstreamTLSClientConfig(item); tlsConfig != nil {
				tunnelTransport.TLSClientConfig = tlsConfig
			}
			client = &stdhttp.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: noRedirect, Transport: tunnelTransport}
		}
	}

	probeHost := ""
	if item.PassHostHeader {
		probeHost = domain.ServiceHost(item)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	err := probeHTTPHealthTarget(probeCtx, client, HTTPHealthTarget{
		Name: item.Name,
		URL:  probeURL,
		Host: probeHost,
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

func viewerServiceResponse(item domain.Service, health serviceHealthInfo, cert acme.CertInfo) map[string]any {
	policy, method, effectiveConfig, inheritedFrom := proxy.EffectiveAccessForService(item)
	riskScore, riskReasons := serviceRiskAssessment(item, policy.AccessMode, method, effectiveConfig, nil)
	riskScore, riskReasons = applyCertRisk(riskScore, riskReasons, cert)
	return map[string]any{
		"id":                     item.ID,
		"name":                   item.Name,
		"domain_id":              item.DomainID,
		"domain":                 item.Domain,
		"path":                   item.Path,
		"target_url":             "",
		"tls_mode":               "",
		"auth_policy":            item.AuthPolicy,
		"access_mode":            policy.AccessMode,
		"allowed_roles":          []string{},
		"allowed_groups":         []uint{},
		"allowed_service_groups": []uint{},
		"access_policy": map[string]any{
			"access_mode":            policy.AccessMode,
			"allowed_roles":          []string{},
			"allowed_groups":         []uint{},
			"allowed_service_groups": []uint{},
		},
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
		"active_cert_source":             cert.Source,
		"active_cert_issuer":             cert.Issuer,
		"active_cert_expires":            cert.ExpiresAt,
		"active_cert_is_bootstrap":       cert.IsBootstrap,
		"active_cert_days_remaining":     cert.DaysRemaining,
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

	item := buildServiceFromCreateRequest(req, subdomain, nil)
	if item.NodeID == nil && strings.TrimSpace(req.Node) != "" {
		nodeID, ok := s.resolveNodeName(w, r.Context(), req.Node)
		if !ok {
			return
		}
		item.NodeID = nodeID
	}
	if err := validateServiceTargetURL(item.TargetURL); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := validateUpstreamCAPEM(item.UpstreamCAPEM); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
		return
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

	writeJSON(w, stdhttp.StatusCreated, serviceResponse(*deployed, s.evaluateServiceHealth(r.Context(), *deployed), s.certInfoForService(r.Context(), *deployed)))
}

func buildServiceFromCreateRequest(req createServiceRequest, subdomain string, existingConfig domain.JSONObject) *domain.Service {
	return &domain.Service{
		Name:                 req.Name,
		DomainID:             req.DomainID,
		Subdomain:            subdomain,
		Path:                 req.Path,
		TargetURL:            req.TargetURL,
		TLSMode:              req.TLSMode,
		PassHostHeader:       req.PassHostHeader,
		UpstreamSkipVerify:   req.UpstreamSkipVerify,
		UpstreamCAPEM:        strings.TrimSpace(req.UpstreamCAPEM),
		UpstreamServerName:   strings.TrimSpace(req.UpstreamServerName),
		AuthPolicy:           req.AuthPolicy,
		AccessMode:           req.AccessPolicy.AccessMode,
		AllowedRoles:         normalizeStringList(req.AccessPolicy.AllowedRoles),
		AllowedGroups:        domain.JSONUintSlice(req.AccessPolicy.AllowedGroups),
		AllowedServiceGroups: domain.JSONUintSlice(req.AccessPolicy.AllowedServiceGroups),
		UseGroupPolicy:       req.UseGroupPolicy,
		AccessMethod:         normalizeOptionalAccessMethod(req.AccessMethod),
		AccessMethodConfig:   buildAccessMethodConfig(req.AccessMethod, req.AccessMethodConfig, existingConfig),
		AccessMessage:        strings.TrimSpace(req.AccessMessage),
		IPAllowlist:          normalizeStringList(req.IPAllowlist),
		IPBlocklist:          normalizeStringList(req.IPBlocklist),
		AllowedCountries:     normalizeCountryList(req.AllowedCountries),
		BlockedCountries:     normalizeCountryList(req.BlockedCountries),
		AccessWindows:        toAccessWindows(req.AccessWindows),
		NodeID:               req.NodeID,
	}
}

func (s *Server) handleGetService(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadService(w, r)
	if !ok {
		return
	}
	writeJSON(w, stdhttp.StatusOK, serviceResponse(*item, s.evaluateServiceHealth(r.Context(), *item), s.certInfoForService(r.Context(), *item)))
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
		if err := validateServiceTargetURL(item.TargetURL); err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
			return
		}
	}
	if req.TLSMode != nil {
		item.TLSMode = *req.TLSMode
	}
	if req.PassHostHeader != nil {
		item.PassHostHeader = *req.PassHostHeader
	}
	if req.UpstreamSkipVerify != nil {
		item.UpstreamSkipVerify = *req.UpstreamSkipVerify
	}
	if req.UpstreamCAPEM != nil {
		trimmed := strings.TrimSpace(*req.UpstreamCAPEM)
		if err := validateUpstreamCAPEM(trimmed); err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", err.Error())
			return
		}
		item.UpstreamCAPEM = trimmed
	}
	if req.UpstreamServerName != nil {
		item.UpstreamServerName = strings.TrimSpace(*req.UpstreamServerName)
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
	if req.AllowedCountries != nil {
		item.AllowedCountries = normalizeCountryList(*req.AllowedCountries)
	}
	if req.BlockedCountries != nil {
		item.BlockedCountries = normalizeCountryList(*req.BlockedCountries)
	}
	if req.AccessWindows != nil {
		item.AccessWindows = toAccessWindows(*req.AccessWindows)
	}
	if req.ClearNodeID != nil && *req.ClearNodeID {
		item.NodeID = nil
	} else if req.NodeID != nil {
		nodeIDCopy := *req.NodeID
		item.NodeID = &nodeIDCopy
	} else if req.Node != nil {
		nodeID, ok := s.resolveNodeName(w, r.Context(), *req.Node)
		if !ok {
			return
		}
		item.NodeID = nodeID
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

	writeJSON(w, stdhttp.StatusOK, serviceResponse(*deployed, s.evaluateServiceHealth(r.Context(), *deployed), s.certInfoForService(r.Context(), *deployed)))
}

var targetHostResolver func(host string) ([]netip.Addr, error)

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
	if s.exposureReports != nil {
		_ = s.exposureReports.DeleteByServiceID(r.Context(), id)
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

func (s *Server) handleVerifyAuditChain(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	result, err := s.auditStore.VerifyChain(r.Context())
	if err != nil {
		writeJSON(w, stdhttp.StatusOK, map[string]any{
			"valid":  false,
			"reason": err.Error(),
		})
		return
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"valid":       true,
		"verified":    result.Verified,
		"latest_id":   result.LatestID,
		"latest_hash": result.LatestHash,
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

func parseBoolQuery(r *stdhttp.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "1", "true", "yes", "wait":
		return true
	default:
		return false
	}
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

func normalizeCountryList(values []string) domain.JSONStringSlice {
	return domain.JSONStringSlice(geoip.NormalizeCountryList(values))
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

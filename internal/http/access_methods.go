package http

import (
	"strings"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
	"portlyn/internal/proxy"
)

func normalizeOptionalAccessMethod(value string) string {
	switch strings.TrimSpace(value) {
	case "", domain.AccessMethodSession:
		return strings.TrimSpace(value)
	case domain.AccessMethodOIDCOnly:
		return domain.AccessMethodOIDCOnly
	case domain.AccessMethodPIN:
		return domain.AccessMethodPIN
	case domain.AccessMethodEmailCode:
		return domain.AccessMethodEmailCode
	default:
		return ""
	}
}

func derefAccessMethodConfig(value *accessMethodConfigRequest) accessMethodConfigRequest {
	if value == nil {
		return accessMethodConfigRequest{}
	}
	return *value
}

func buildAccessMethodConfig(method string, req accessMethodConfigRequest, existing domain.JSONObject) domain.JSONObject {
	method = proxyMethod(method)
	out := cloneJSONObject(existing)
	switch method {
	case domain.AccessMethodPIN:
		pin := strings.TrimSpace(req.PIN)
		if pin != "" {
			hash, err := auth.HashPassword(pin)
			if err == nil {
				out["pin_hash"] = hash
			}
		}
		if hint := strings.TrimSpace(req.Hint); hint != "" {
			out["hint"] = hint
		} else {
			delete(out, "hint")
		}
	case domain.AccessMethodEmailCode:
		if hint := strings.TrimSpace(req.Hint); hint != "" {
			out["hint"] = hint
		} else {
			delete(out, "hint")
		}
		if allowed := strings.TrimSpace(req.AllowedEmailDomain); allowed != "" {
			out["allowed_email_domain"] = strings.TrimPrefix(strings.ToLower(allowed), "@")
		} else {
			delete(out, "allowed_email_domain")
		}
		if allowedEmails := normalizeAllowedEmails(req.AllowedEmails); len(allowedEmails) > 0 {
			out["allowed_emails"] = allowedEmails
		} else {
			delete(out, "allowed_emails")
		}
	default:
		return domain.JSONObject{}
	}
	return out
}

func sanitizeAccessMethodConfig(method string, value domain.JSONObject) domain.JSONObject {
	method = proxyMethod(method)
	out := domain.JSONObject{}
	switch method {
	case domain.AccessMethodPIN:
		if pinHash := strings.TrimSpace(stringValueFromAny(value["pin_hash"])); pinHash != "" {
			out["pin_configured"] = true
		}
		if hint := strings.TrimSpace(stringValueFromAny(value["hint"])); hint != "" {
			out["hint"] = hint
		}
	case domain.AccessMethodEmailCode:
		if hint := strings.TrimSpace(stringValueFromAny(value["hint"])); hint != "" {
			out["hint"] = hint
		}
		if allowed := strings.TrimSpace(stringValueFromAny(value["allowed_email_domain"])); allowed != "" {
			out["allowed_email_domain"] = strings.TrimPrefix(strings.ToLower(allowed), "@")
		}
		if allowedEmails := stringSliceFromAny(value["allowed_emails"]); len(allowedEmails) > 0 {
			out["allowed_emails"] = normalizeAllowedEmails(allowedEmails)
		}
	}
	return out
}

func publicAccessMethodConfig(method string, value domain.JSONObject) domain.JSONObject {
	method = proxyMethod(method)
	out := domain.JSONObject{}
	switch method {
	case domain.AccessMethodPIN:
		if pinHash := strings.TrimSpace(stringValueFromAny(value["pin_hash"])); pinHash != "" {
			out["pin_configured"] = true
		}
		if hint := strings.TrimSpace(stringValueFromAny(value["hint"])); hint != "" {
			out["hint"] = hint
		}
	case domain.AccessMethodEmailCode:
		if hint := strings.TrimSpace(stringValueFromAny(value["hint"])); hint != "" {
			out["hint"] = hint
		}
		if domainPresent := strings.TrimSpace(stringValueFromAny(value["allowed_email_domain"])); domainPresent != "" {
			out["domain_restricted"] = true
		}
		if allowedEmails := stringSliceFromAny(value["allowed_emails"]); len(allowedEmails) > 0 {
			out["email_restricted"] = true
		}
	}
	return out
}

func serviceResponse(item domain.Service, health serviceHealthInfo) map[string]any {
	policy, method, effectiveConfig, inheritedFrom := proxy.EffectiveAccessForService(item)
	riskScore, riskReasons := serviceRiskAssessment(item, policy.AccessMode, method, effectiveConfig, nil)
	return map[string]any{
		"id":                             item.ID,
		"name":                           item.Name,
		"domain_id":                      item.DomainID,
		"domain":                         item.Domain,
		"subdomain":                      item.Subdomain,
		"hostname":                       domain.ServiceHost(item),
		"path":                           item.Path,
		"target_url":                     item.TargetURL,
		"tls_mode":                       item.TLSMode,
		"pass_host_header":               item.PassHostHeader,
		"upstream_skip_verify":           item.UpstreamSkipVerify,
		"auth_policy":                    item.AuthPolicy,
		"access_mode":                    item.AccessMode,
		"allowed_roles":                  item.AllowedRoles,
		"allowed_groups":                 item.AllowedGroups,
		"allowed_service_groups":         item.AllowedServiceGroups,
		"use_group_policy":               item.UseGroupPolicy,
		"access_method":                  normalizeOptionalAccessMethod(item.AccessMethod),
		"access_method_config":           sanitizeAccessMethodConfig(item.AccessMethod, item.AccessMethodConfig),
		"effective_access_mode":          policy.AccessMode,
		"effective_access_method":        method,
		"effective_access_method_config": sanitizeAccessMethodConfig(method, effectiveConfig),
		"access_message":                 strings.TrimSpace(item.AccessMessage),
		"service_groups":                 serviceGroupsResponse(item.ServiceGroups),
		"inherited_from_group":           serviceGroupBrief(inheritedFrom),
		"service_overrides_group":        strings.TrimSpace(item.AccessMethod) != "",
		"risk_score":                     riskScore,
		"risk_reasons":                   riskReasons,
		"ip_allowlist":                   item.IPAllowlist,
		"ip_blocklist":                   item.IPBlocklist,
		"allowed_countries":              item.AllowedCountries,
		"blocked_countries":              item.BlockedCountries,
		"access_windows":                 item.AccessWindows,
		"node_id":                        item.NodeID,
		"last_deployed_at":               item.LastDeployedAt,
		"deployment_revision":            item.DeploymentRevision,
		"service_status":                 health.Status,
		"service_status_error":           health.Error,
		"service_status_checked_at":      health.CheckedAt,
		"created_at":                     item.CreatedAt,
		"updated_at":                     item.UpdatedAt,
	}
}

func serviceGroupsResponse(items []domain.ServiceGroup) []map[string]any {
	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		response = append(response, serviceGroupResponse(item))
	}
	return response
}

func serviceGroupResponse(item domain.ServiceGroup) map[string]any {
	return map[string]any{
		"id":                    item.ID,
		"name":                  item.Name,
		"description":           item.Description,
		"default_access_policy": item.DefaultAccessPolicy,
		"access_method":         normalizeOptionalAccessMethod(item.AccessMethod),
		"access_method_config":  sanitizeAccessMethodConfig(item.AccessMethod, item.AccessMethodConfig),
		"services":              serviceGroupServices(item.Services),
		"service_count":         len(item.Services),
		"created_at":            item.CreatedAt,
		"updated_at":            item.UpdatedAt,
	}
}

func serviceGroupServices(items []domain.Service) []map[string]any {
	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		_, method, _, inheritedFrom := proxy.EffectiveAccessForService(item)
		riskScore := riskScoreLabel(item, method)
		response = append(response, map[string]any{
			"id":                      item.ID,
			"name":                    item.Name,
			"domain_id":               item.DomainID,
			"domain":                  item.Domain,
			"subdomain":               item.Subdomain,
			"hostname":                domain.ServiceHost(item),
			"path":                    item.Path,
			"access_mode":             item.AccessMode,
			"access_method":           normalizeOptionalAccessMethod(item.AccessMethod),
			"effective_access_method": method,
			"inherited_from_group":    serviceGroupBrief(inheritedFrom),
			"risk_score":              riskScore,
		})
	}
	return response
}

func serviceRiskAssessment(item domain.Service, accessMode, method string, config domain.JSONObject, settings *domain.AppSettings) (string, []string) {
	score := 0
	reasons := make([]string, 0)
	if accessMode == domain.AccessModePublic {
		score += 3
		reasons = append(reasons, "public access")
	}
	if accessMode == domain.AccessModeAuthenticated {
		score++
	}
	switch method {
	case domain.AccessMethodPIN:
		score += 2
		reasons = append(reasons, "shared pin access")
	case domain.AccessMethodEmailCode:
		score += 2
		reasons = append(reasons, "email code access")
	case domain.AccessMethodSession:
		score++
	}
	if len(item.IPAllowlist) == 0 && len(item.IPBlocklist) == 0 {
		score++
	}
	target := strings.ToLower(strings.TrimSpace(item.TargetURL + " " + item.Name + " " + item.Path))
	if strings.Contains(target, "/admin") || strings.Contains(target, "admin") || strings.Contains(target, ":22") || strings.Contains(target, ":5432") || strings.Contains(target, ":3306") {
		score += 2
		reasons = append(reasons, "admin-like target")
	}
	if settings != nil {
		if method == domain.AccessMethodOIDCOnly && !settings.OIDCEnabled {
			score += 2
			reasons = append(reasons, "oidc_only without active oidc")
		}
		if method == domain.AccessMethodEmailCode && (!settings.OTPEnabled || !settings.SMTPEnabled || strings.TrimSpace(settings.SMTPHost) == "") {
			score += 2
			reasons = append(reasons, "email code without smtp/otp")
		}
	}
	switch {
	case score >= 5:
		return "high", reasons
	case score >= 3:
		return "medium", reasons
	default:
		return "low", reasons
	}
}

func riskScoreLabel(item domain.Service, method string) string {
	score, _ := serviceRiskAssessment(item, item.AccessMode, method, item.AccessMethodConfig, nil)
	return score
}

func serviceGroupBrief(item *domain.ServiceGroup) map[string]any {
	if item == nil {
		return nil
	}
	return map[string]any{
		"id":   item.ID,
		"name": item.Name,
	}
}

func stringValueFromAny(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := stringValueFromAny(item); strings.TrimSpace(value) != "" {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func normalizeAllowedEmails(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func cloneJSONObject(value domain.JSONObject) domain.JSONObject {
	if len(value) == 0 {
		return domain.JSONObject{}
	}
	out := make(domain.JSONObject, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func proxyMethod(value string) string {
	_, method, _, _ := proxy.EffectiveAccessForService(domain.Service{AccessMethod: value})
	return method
}

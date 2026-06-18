package http

import (
	"context"
	"net/http"
	"strings"
	"time"

	"portlyn/internal/secureconfig"
)

func (s *Server) MigrateDNSProviderSecrets(ctx context.Context) (int, error) {
	items, err := s.dnsProviders.List(ctx)
	if err != nil {
		return 0, err
	}
	updated := 0
	for i := range items {
		item := &items[i]
		if strings.TrimSpace(item.ConfigEncrypted) == "" {
			continue
		}
		if secureconfig.IsEncryptedJSONLatest(item.ConfigEncrypted) {
			continue
		}
		config, err := s.dataDecryptJSON(item.ConfigEncrypted)
		if err != nil {
			continue
		}
		encrypted, err := s.dataEncryptJSON(config)
		if err != nil {
			return updated, err
		}
		item.ConfigEncrypted = encrypted
		if err := s.dnsProviders.Update(ctx, item); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

type rotationStatusResponse struct {
	DataEncryption map[string]any `json:"data_encryption"`
}

func (s *Server) handleRotationStatus(w http.ResponseWriter, r *http.Request) {
	items, err := s.dnsProviders.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}

	reEncryptCandidates := 0
	decryptFailures := 0
	activeSecretOnly := [][]byte{[]byte(s.cfg.DataEncryptionSecret)}
	allSecrets := s.dataSecrets()

	for _, item := range items {
		if strings.TrimSpace(item.ConfigEncrypted) == "" {
			continue
		}
		if secureconfig.IsEncryptedJSONLatest(item.ConfigEncrypted) {
			if _, err := s.dataDecryptJSONWithActiveKey(item.ConfigEncrypted); err == nil {
				continue
			}
		}
		if _, err := s.dataDecryptJSON(item.ConfigEncrypted); err == nil {
			reEncryptCandidates++
			continue
		}
		decryptFailures++
	}

	writeJSON(w, http.StatusOK, rotationStatusResponse{
		DataEncryption: map[string]any{
			"legacy_keys_configured":    max(0, len(allSecrets)-1),
			"dns_provider_total":        len(items),
			"reencrypt_candidates":      reEncryptCandidates,
			"decrypt_failures":          decryptFailures,
			"active_key_reencrypt_safe": len(activeSecretOnly) == 1,
		},
	})
}

func (s *Server) handleReencryptDataKey(w http.ResponseWriter, r *http.Request) {
	var req reencryptDataKeyRequest
	if r.ContentLength > 0 {
		if !s.decodeAndValidate(w, r, &req) {
			return
		}
	}
	if queryDryRun := strings.TrimSpace(r.URL.Query().Get("dry_run")); queryDryRun != "" {
		req.DryRun = strings.EqualFold(queryDryRun, "true") || queryDryRun == "1"
	}

	items, err := s.dnsProviders.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}

	processed := 0
	updated := 0
	skipped := 0
	failures := 0
	failedIDs := make([]uint, 0)

	for i := range items {
		item := &items[i]
		if strings.TrimSpace(item.ConfigEncrypted) == "" {
			skipped++
			continue
		}
		processed++
		if secureconfig.IsEncryptedJSONLatest(item.ConfigEncrypted) {
			if _, err := s.dataDecryptJSONWithActiveKey(item.ConfigEncrypted); err == nil {
				skipped++
				continue
			}
		}
		config, err := s.dataDecryptJSON(item.ConfigEncrypted)
		if err != nil {
			failures++
			failedIDs = append(failedIDs, item.ID)
			continue
		}
		if req.DryRun {
			updated++
			continue
		}
		encrypted, err := s.dataEncryptJSON(config)
		if err != nil {
			failures++
			failedIDs = append(failedIDs, item.ID)
			continue
		}
		item.ConfigEncrypted = encrypted
		if err := s.dnsProviders.Update(r.Context(), item); err != nil {
			failures++
			failedIDs = append(failedIDs, item.ID)
			continue
		}
		updated++
	}

	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "security_rotation_reencrypt_data_key", "security", nil, map[string]any{
		"dry_run":   req.DryRun,
		"processed": processed,
		"updated":   updated,
		"skipped":   skipped,
		"failures":  failures,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run":   req.DryRun,
		"processed": processed,
		"updated":   updated,
		"skipped":   skipped,
		"failures":  failures,
		"failed_ids": func() []uint {
			if len(failedIDs) > 20 {
				return failedIDs[:20]
			}
			return failedIDs
		}(),
	})
}

func (s *Server) handleSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	windowStart := now.Add(-s.cfg.AlertWindow)

	loginFails, err := s.auditStore.CountByActionLikeSince(r.Context(), "%login_failed%", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	otpFails, err := s.auditStore.CountByActionLikeSince(r.Context(), "%otp_login_failed%", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	ssoFails, err := s.auditStore.CountByActionLikeSince(r.Context(), "%sso_login_failed%", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	totalLoginFails := loginFails + otpFails + ssoFails

	nodeHeartbeatFails, err := s.auditStore.CountByActionLikeSince(r.Context(), "node_heartbeat_rejected", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	auditAnomalies, err := s.auditStore.CountByActionLikeSince(r.Context(), "%mfa_reset%", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	roleChanges, err := s.auditStore.CountByActionLikeSince(r.Context(), "%role_change%", windowStart)
	if err != nil {
		s.internalError(w, err)
		return
	}
	auditAnomalies += roleChanges

	alerts := make([]map[string]any, 0)
	if totalLoginFails >= int64(s.cfg.AlertLoginFailSpikeThreshold) {
		alerts = append(alerts, map[string]any{
			"code":        "login_fail_spike",
			"severity":    "high",
			"value":       totalLoginFails,
			"threshold":   s.cfg.AlertLoginFailSpikeThreshold,
			"window":      s.cfg.AlertWindow.String(),
			"description": "Login failure spike detected",
		})
	}
	if nodeHeartbeatFails >= int64(s.cfg.AlertNodeHeartbeatFailThreshold) {
		alerts = append(alerts, map[string]any{
			"code":        "node_heartbeat_auth_fail_spike",
			"severity":    "high",
			"value":       nodeHeartbeatFails,
			"threshold":   s.cfg.AlertNodeHeartbeatFailThreshold,
			"window":      s.cfg.AlertWindow.String(),
			"description": "Node heartbeat auth-fail spike detected",
		})
	}
	if auditAnomalies >= int64(s.cfg.AlertAuditAnomalyThreshold) {
		alerts = append(alerts, map[string]any{
			"code":        "audit_anomaly_burst",
			"severity":    "medium",
			"value":       auditAnomalies,
			"threshold":   s.cfg.AlertAuditAnomalyThreshold,
			"window":      s.cfg.AlertWindow.String(),
			"description": "Audit anomaly burst detected",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window_start": windowStart,
		"window_end":   now,
		"alerts":       alerts,
		"metrics": map[string]any{
			"login_failures":         totalLoginFails,
			"node_heartbeat_rejects": nodeHeartbeatFails,
			"audit_anomalies":        auditAnomalies,
		},
	})
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}

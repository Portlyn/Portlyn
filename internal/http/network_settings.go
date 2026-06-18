package http

import (
	"context"
	stdhttp "net/http"
	"strings"
	"time"
)

type networkSettingsResponse struct {
	GeoIPDBPath           string `json:"geoip_db_path"`
	GeoIPAvailable        bool   `json:"geoip_available"`
	CrowdSecEnabled       bool   `json:"crowdsec_enabled"`
	CrowdSecAPIURL        string `json:"crowdsec_api_url"`
	CrowdSecKeyConfigured bool   `json:"crowdsec_api_key_configured"`
	CrowdSecPollSeconds   int    `json:"crowdsec_poll_interval_secs"`
	CrowdSecActive        bool   `json:"crowdsec_active"`
	CrowdSecIPDecisions   int    `json:"crowdsec_ip_decisions"`
	CrowdSecRangeRules    int    `json:"crowdsec_range_decisions"`
}

type updateNetworkSettingsRequest struct {
	GeoIPDBPath         *string `json:"geoip_db_path"`
	CrowdSecEnabled     *bool   `json:"crowdsec_enabled"`
	CrowdSecAPIURL      *string `json:"crowdsec_api_url"`
	CrowdSecAPIKey      *string `json:"crowdsec_api_key"`
	CrowdSecPollSeconds *int    `json:"crowdsec_poll_interval_secs" validate:"omitempty,gte=10,lte=3600"`
}

func (s *Server) networkSettingsPayload() (networkSettingsResponse, error) {
	settings, err := s.appSettings.Get(s.crowdsecContext())
	if err != nil {
		return networkSettingsResponse{}, err
	}
	resp := networkSettingsResponse{
		GeoIPDBPath:           settings.GeoIPDBPath,
		CrowdSecEnabled:       settings.CrowdSecEnabled,
		CrowdSecAPIURL:        settings.CrowdSecAPIURL,
		CrowdSecKeyConfigured: strings.TrimSpace(settings.CrowdSecAPIKeyEncrypted) != "",
		CrowdSecPollSeconds:   settings.CrowdSecPollIntervalSecs,
	}
	if s.geoip != nil {
		resp.GeoIPAvailable = s.geoip.Available()
	}
	if s.crowdsec != nil {
		resp.CrowdSecActive = s.crowdsec.Enabled()
		ips, ranges := s.crowdsec.Stats()
		resp.CrowdSecIPDecisions = ips
		resp.CrowdSecRangeRules = ranges
	}
	return resp, nil
}

func (s *Server) crowdsecContext() context.Context {
	if s.crowdsecCtx != nil {
		return s.crowdsecCtx
	}
	return context.Background()
}

func (s *Server) handleGetNetworkSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	resp, err := s.networkSettingsPayload()
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, resp)
}

func (s *Server) handleUpdateNetworkSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req updateNetworkSettingsRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	settings, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	if req.GeoIPDBPath != nil {
		settings.GeoIPDBPath = strings.TrimSpace(*req.GeoIPDBPath)
	}
	if req.CrowdSecEnabled != nil {
		settings.CrowdSecEnabled = *req.CrowdSecEnabled
	}
	if req.CrowdSecAPIURL != nil {
		trimmed := strings.TrimSpace(*req.CrowdSecAPIURL)
		if trimmed != "" {
			if err := validateServiceTargetURL(trimmed); err != nil {
				writeError(w, stdhttp.StatusBadRequest, "invalid_crowdsec_url", "crowdsec_api_url is not a valid or permitted URL")
				return
			}
		}
		settings.CrowdSecAPIURL = trimmed
	}
	if req.CrowdSecAPIKey != nil && strings.TrimSpace(*req.CrowdSecAPIKey) != "" {
		settings.CrowdSecAPIKeyEncrypted = strings.TrimSpace(*req.CrowdSecAPIKey)
	}
	if req.CrowdSecPollSeconds != nil {
		settings.CrowdSecPollIntervalSecs = *req.CrowdSecPollSeconds
	}
	if settings.CrowdSecPollIntervalSecs <= 0 {
		settings.CrowdSecPollIntervalSecs = 60
	}
	if err := s.appSettings.Upsert(r.Context(), settings); err != nil {
		s.internalError(w, err)
		return
	}

	reloaded, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.applyNetworkSecurity(reloaded.GeoIPDBPath, reloaded.CrowdSecEnabled, reloaded.CrowdSecAPIURL, reloaded.CrowdSecAPIKeyEncrypted, reloaded.CrowdSecPollIntervalSecs)

	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "update", "network_settings", nil, map[string]any{
		"geoip_configured": strings.TrimSpace(reloaded.GeoIPDBPath) != "",
		"crowdsec_enabled": reloaded.CrowdSecEnabled,
	})

	resp, err := s.networkSettingsPayload()
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, resp)
}

func (s *Server) applyNetworkSecurity(geoipPath string, crowdsecEnabled bool, crowdsecURL, crowdsecKey string, pollSeconds int) {
	if s.geoip != nil {
		if err := s.geoip.Load(strings.TrimSpace(geoipPath)); err != nil {
			s.logger.Warn("geoip reload failed", "path", geoipPath, "error", err)
		}
	}
	if s.crowdsec != nil {
		s.crowdsec.Stop()
		if crowdsecEnabled && strings.TrimSpace(crowdsecURL) != "" && strings.TrimSpace(crowdsecKey) != "" {
			interval := time.Duration(pollSeconds) * time.Second
			s.crowdsec.Configure(crowdsecURL, crowdsecKey, interval)
			s.crowdsec.Start(s.crowdsecContext())
		}
	}
}

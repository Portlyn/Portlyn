package http

import (
	"errors"
	stdhttp "net/http"
	"strings"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/tunnel"
)

type tunnelStatusResponse struct {
	Enabled             bool   `json:"enabled"`
	Configured          bool   `json:"configured"`
	ServerPublicKey     string `json:"server_public_key,omitempty"`
	ServerEndpoint      string `json:"server_endpoint,omitempty"`
	ListenPort          int    `json:"listen_port,omitempty"`
	CIDR                string `json:"cidr,omitempty"`
	ServerTunnelIP      string `json:"server_tunnel_ip,omitempty"`
	ConfigPath          string `json:"config_path,omitempty"`
	ConfiguredPeerCount int    `json:"configured_peer_count"`
	ConnectedPeerCount  int    `json:"connected_peer_count"`
}

type updateTunnelSettingsRequest struct {
	Enabled        *bool   `json:"enabled,omitempty"`
	ServerEndpoint *string `json:"server_endpoint,omitempty"`
	ListenPort     *int    `json:"listen_port,omitempty" validate:"omitempty,min=1,max=65535"`
	CIDR           *string `json:"cidr,omitempty"`
	ServerTunnelIP *string `json:"server_tunnel_ip,omitempty"`
	ConfigPath     *string `json:"config_path,omitempty"`
}

type bootstrapNodeRequest struct {
	ForceReissue bool     `json:"force_reissue,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
}

type bootstrapNodeResponse struct {
	NodeID          uint      `json:"node_id"`
	PublicKey       string    `json:"public_key"`
	PrivateKey      string    `json:"private_key"`
	Address         string    `json:"address"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerEndpoint  string    `json:"server_endpoint"`
	AllowedIPs      []string  `json:"allowed_ips"`
	PersistentKeep  int       `json:"persistent_keepalive"`
	ConfigText      string    `json:"config_text"`
	IssuedAt        time.Time `json:"issued_at"`
}

func (s *Server) handleGetTunnelSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	settings, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	resp := tunnelStatusFromSettings(settings)
	if s.nodes != nil {
		items, err := s.nodes.List(r.Context())
		if err == nil {
			for _, item := range items {
				if strings.TrimSpace(item.WGPublicKey) != "" {
					resp.ConfiguredPeerCount++
				}
				if item.TunnelStatus == domain.TunnelStatusConnected {
					resp.ConnectedPeerCount++
				}
			}
		}
	}
	writeJSON(w, stdhttp.StatusOK, resp)
}

func tunnelStatusFromSettings(settings *domain.AppSettings) tunnelStatusResponse {
	return tunnelStatusResponse{
		Enabled:         settings.TunnelEnabled,
		Configured:      strings.TrimSpace(settings.TunnelServerPublicKey) != "" && strings.TrimSpace(settings.TunnelServerEndpoint) != "",
		ServerPublicKey: settings.TunnelServerPublicKey,
		ServerEndpoint:  settings.TunnelServerEndpoint,
		ListenPort:      settings.TunnelListenPort,
		CIDR:            settings.TunnelCIDR,
		ServerTunnelIP:  settings.TunnelServerTunnelIP,
		ConfigPath:      settings.TunnelConfigPath,
	}
}

func (s *Server) handleUpdateTunnelSettings(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req updateTunnelSettingsRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	settings, err := s.appSettings.Get(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	if req.Enabled != nil {
		settings.TunnelEnabled = *req.Enabled
	}
	if req.ServerEndpoint != nil {
		settings.TunnelServerEndpoint = strings.TrimSpace(*req.ServerEndpoint)
	}
	if req.ListenPort != nil {
		settings.TunnelListenPort = *req.ListenPort
	}
	if req.CIDR != nil {
		settings.TunnelCIDR = strings.TrimSpace(*req.CIDR)
	}
	if req.ServerTunnelIP != nil {
		settings.TunnelServerTunnelIP = strings.TrimSpace(*req.ServerTunnelIP)
	}
	if req.ConfigPath != nil {
		settings.TunnelConfigPath = strings.TrimSpace(*req.ConfigPath)
	}
	if err := s.appSettings.Upsert(r.Context(), settings); err != nil {
		s.internalError(w, err)
		return
	}
	if settings.TunnelEnabled && s.tunnel != nil {
		if _, err := s.tunnel.EnsureServerKey(r.Context()); err != nil {
			s.internalError(w, err)
			return
		}
		if err := s.tunnel.WriteServerConfig(r.Context()); err != nil {
			s.logger.Warn("failed to write tunnel server config", "error", err)
		}
		if server := s.tunnel.Server(); server != nil && !server.Started() {
			refreshed, err := s.appSettings.Get(r.Context())
			if err == nil {
				if startErr := server.Start(r.Context(), refreshed); startErr != nil {
					s.logger.Warn("failed to start tunnel server", "error", startErr)
				} else if items, err := s.nodes.List(r.Context()); err == nil {
					_ = server.ApplyPeers(items)
				}
			}
		}
	}
	if !settings.TunnelEnabled && s.tunnel != nil {
		if server := s.tunnel.Server(); server != nil && server.Started() {
			server.Stop()
		}
	}
	settings, err = s.appSettings.Get(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "update", "tunnel_settings", nil, map[string]any{
		"enabled":     settings.TunnelEnabled,
		"endpoint":    settings.TunnelServerEndpoint,
		"listen_port": settings.TunnelListenPort,
		"cidr":        settings.TunnelCIDR,
	})
	writeJSON(w, stdhttp.StatusOK, tunnelStatusFromSettings(settings))
}

func (s *Server) handleBootstrapNodeTunnel(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.tunnel == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "tunnel_unavailable", "tunnel manager is not configured")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req bootstrapNodeRequest
	_ = decodeStrictJSON(r, &req)
	result, err := s.tunnel.BootstrapNode(r.Context(), id, tunnel.BootstrapOptions{
		ForceReissue:     req.ForceReissue,
		ClientAllowedIPs: req.AllowedIPs,
	})
	if err != nil {
		if errors.Is(err, tunnel.ErrNodeAlreadyProvisioned) {
			writeError(w, stdhttp.StatusConflict, "node_already_provisioned", "node already has a tunnel assignment; pass force_reissue=true to replace it")
			return
		}
		if errors.Is(err, tunnel.ErrPoolExhausted) {
			writeError(w, stdhttp.StatusConflict, "pool_exhausted", "tunnel ip pool is exhausted")
			return
		}
		if errors.Is(err, tunnel.ErrInvalidServerSettings) {
			writeError(w, stdhttp.StatusPreconditionFailed, "tunnel_not_configured", "tunnel server settings are incomplete")
			return
		}
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "tunnel_bootstrap", "node", &id, map[string]any{
		"tunnel_ip": result.Node.WGTunnelIP,
	})
	writeJSON(w, stdhttp.StatusOK, bootstrapNodeResponse{
		NodeID:          result.Node.ID,
		PublicKey:       result.ClientBundle.PublicKey,
		PrivateKey:      result.ClientBundle.PrivateKey,
		Address:         result.ClientBundle.Address,
		ServerPublicKey: result.ClientBundle.ServerPublicKey,
		ServerEndpoint:  result.ClientBundle.ServerEndpoint,
		AllowedIPs:      result.ClientBundle.AllowedIPs,
		PersistentKeep:  result.ClientBundle.Keepalive,
		ConfigText:      result.ClientConfig,
		IssuedAt:        time.Now().UTC(),
	})
}

func (s *Server) handleRevokeNodeTunnel(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.tunnel == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "tunnel_unavailable", "tunnel manager is not configured")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.tunnel.RevokeNode(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "tunnel_revoke", "node", &id, nil)
	w.WriteHeader(stdhttp.StatusNoContent)
}

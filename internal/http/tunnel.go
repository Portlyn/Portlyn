package http

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"

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
	PublicKey    string   `json:"public_key,omitempty"`
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
				if startErr := server.Start(context.Background(), refreshed); startErr != nil {
					s.logger.Warn("failed to start tunnel server", "error", startErr)
				} else {
					_ = s.tunnel.ApplyPeers(r.Context())
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

type tunnelTargetItem struct {
	ServiceID  uint   `json:"service_id"`
	ListenPort int    `json:"listen_port"`
	LocalAddr  string `json:"local_addr"`
}

type tunnelTargetsResponse struct {
	Targets           []tunnelTargetItem `json:"targets"`
	AdvertisedSubnets []string           `json:"advertised_subnets"`
}

func (s *Server) handleNodeSelfBootstrap(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if !s.requireNodeSecureTransport(w, r) {
		return
	}
	if s.tunnel == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "tunnel_unavailable", "tunnel manager is not configured")
		return
	}
	node, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if !s.authorizeNodeHeartbeat(r, node) {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing or invalid node token")
		return
	}
	var req bootstrapNodeRequest
	_ = decodeStrictJSON(r, &req)
	if strings.TrimSpace(req.PublicKey) == "" {
		writeError(w, stdhttp.StatusBadRequest, "missing_public_key", "public_key is required")
		return
	}
	if err := tunnel.ValidatePublicKey(strings.TrimSpace(req.PublicKey)); err != nil {
		writeError(w, stdhttp.StatusBadRequest, "invalid_public_key", "public_key is not a valid wireguard key")
		return
	}
	result, err := s.tunnel.BootstrapNode(r.Context(), node.ID, tunnel.BootstrapOptions{
		ForceReissue:     true,
		ClientAllowedIPs: req.AllowedIPs,
		ClientPublicKey:  strings.TrimSpace(req.PublicKey),
	})
	if err != nil {
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
	_ = s.audit.LogRequest(r.Context(), r, nil, "tunnel_self_bootstrap", "node", &node.ID, map[string]any{
		"tunnel_ip": result.Node.WGTunnelIP,
	})
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"node_id":            result.Node.ID,
		"tunnel_ip":          result.Node.WGTunnelIP,
		"server_public_key":  result.ClientBundle.ServerPublicKey,
		"server_endpoint":    result.ClientBundle.ServerEndpoint,
		"allowed_ips":        result.ClientBundle.AllowedIPs,
		"keepalive":          result.ClientBundle.Keepalive,
		"advertised_subnets": result.AdvertisedSubnets,
	})
}

func (s *Server) handleNodeTunnelTargets(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if !s.requireNodeSecureTransport(w, r) {
		return
	}
	node, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if !s.authorizeNodeHeartbeat(r, node) {
		writeError(w, stdhttp.StatusUnauthorized, "unauthorized", "missing or invalid node token")
		return
	}
	services, err := s.services.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	targets := make([]tunnelTargetItem, 0)
	for _, svc := range services {
		if svc.NodeID == nil || *svc.NodeID != node.ID {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(svc.TargetURL))
		if err != nil {
			continue
		}
		portStr := parsed.Port()
		if portStr == "" {
			if strings.EqualFold(parsed.Scheme, "https") {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		host := parsed.Hostname()
		if host == "" {
			host = "127.0.0.1"
		}
		targets = append(targets, tunnelTargetItem{
			ServiceID:  svc.ID,
			ListenPort: port,
			LocalAddr:  net.JoinHostPort(host, portStr),
		})
	}
	writeJSON(w, stdhttp.StatusOK, tunnelTargetsResponse{
		Targets:           targets,
		AdvertisedSubnets: splitSubnetCSV(node.AdvertisedSubnets),
	})
}

func splitSubnetCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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

package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	stdhttp "net/http"
	"portlyn/internal/domain"
	"strings"
	"time"
)

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
	if req.AdvertisedSubnets != nil {
		normalized, err := normalizeSubnetCSV(*req.AdvertisedSubnets)
		if err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", "advertised_subnets must be valid CIDRs")
			return
		}
		item.AdvertisedSubnets = normalized
	}
	if err := s.nodes.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "create", "node", &item.ID, item)
	if s.tunnel != nil {
		_ = s.tunnel.ApplyPeers(r.Context())
	}
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
	if req.AdvertisedSubnets != nil {
		normalized, err := normalizeSubnetCSV(*req.AdvertisedSubnets)
		if err != nil {
			writeError(w, stdhttp.StatusBadRequest, "validation_error", "advertised_subnets must be valid CIDRs")
			return
		}
		item.AdvertisedSubnets = normalized
	}

	if err := s.nodes.Update(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.Log(r.Context(), s.currentUserID(r), "update", "node", &item.ID, item)
	if s.tunnel != nil {
		_ = s.tunnel.ApplyPeers(r.Context())
	}
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

	if !s.enforceNodeRateLimit(w, r, fmt.Sprintf("node_heartbeat:%d", node.ID), nodeHeartbeatRateLimit, nodeHeartbeatRateWindow) {
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
	if req.WGLastHandshake != nil {
		t := req.WGLastHandshake.UTC()
		node.WGLastHandshake = &t
	}
	if req.WGRxBytes != nil {
		node.WGRxBytes = *req.WGRxBytes
	}
	if req.WGTxBytes != nil {
		node.WGTxBytes = *req.WGTxBytes
	}
	if req.TunnelStatus != nil {
		node.TunnelStatus = *req.TunnelStatus
	} else if node.WGLastHandshake != nil && time.Since(*node.WGLastHandshake) < 3*time.Minute {
		node.TunnelStatus = domain.TunnelStatusConnected
	} else if node.WGPublicKey != "" && node.TunnelStatus != domain.TunnelStatusProvisioned {
		node.TunnelStatus = domain.TunnelStatusStale
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
		headerFallback := s.cfg.NodeAllowMTLSHeaderFallback &&
			s.cfg.NodeTrustForwardedProto &&
			s.requestFromTrustedProxy(r)
		return verifyNodeMTLS(r, node.MTLSCertSHA256, headerFallback)
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

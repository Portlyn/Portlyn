package http

import (
	"crypto/rand"
	"encoding/hex"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"portlyn/internal/domain"
)

func (s *Server) handleListNodeEnrollmentTokens(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	items, err := s.enrollmentTokens.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleCreateNodeEnrollmentToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var req createNodeEnrollmentTokenRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	plainToken, err := randomEnrollmentToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	var expiresAt *time.Time
	if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
		value := time.Now().UTC().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &value
	}
	singleUse := true
	if req.SingleUse != nil {
		singleUse = *req.SingleUse
	}
	item := &domain.NodeEnrollmentToken{
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		TokenHash:   hashOpaqueToken(plainToken),
		ExpiresAt:   expiresAt,
		SingleUse:   singleUse,
		Active:      true,
	}
	if err := s.enrollmentTokens.Create(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "create", "node_enrollment_token", &item.ID, map[string]any{"name": item.Name})
	setupAPIBase := s.nodeAgentAPIBaseHint()
	writeJSON(w, stdhttp.StatusCreated, map[string]any{
		"id":            item.ID,
		"name":          item.Name,
		"description":   item.Description,
		"single_use":    item.SingleUse,
		"active":        item.Active,
		"expires_at":    item.ExpiresAt,
		"created_at":    item.CreatedAt,
		"token":         plainToken,
		"setup_command": "curl -fsSL " + setupAPIBase + "/install.sh | sudo sh -s -- --token " + plainToken,
	})
}

func (s *Server) handleDeleteNodeEnrollmentToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.enrollmentTokens.Delete(r.Context(), id); err != nil {
		s.handleStoreError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "delete", "node_enrollment_token", &id, map[string]any{"id": id})
	w.WriteHeader(stdhttp.StatusNoContent)
}

func (s *Server) handleEnrollNode(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if !s.requireNodeSecureTransport(w, r) {
		return
	}
	if !s.enforceNodeRateLimit(w, r, "node_enroll", s.cfg.NodeEnrollRateLimit, s.cfg.NodeEnrollRateWindow) {
		return
	}

	var req enrollNodeRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	now := time.Now().UTC()
	token, err := s.enrollmentTokens.GetActiveByHash(r.Context(), hashOpaqueToken(req.Token), now)
	if err != nil {
		writeError(w, stdhttp.StatusUnauthorized, "invalid_enrollment_token", "invalid or expired enrollment token")
		return
	}
	heartbeatToken, err := randomEnrollmentToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	node := &domain.Node{
		Name:               strings.TrimSpace(req.Name),
		Description:        strings.TrimSpace(req.Description),
		EnrollmentTokenID:  &token.ID,
		HeartbeatAuthMode:  "token",
		Version:            strings.TrimSpace(req.Version),
		Status:             domain.NodeStatusOnline,
		LastSeenAt:         &now,
		LastHeartbeatAt:    &now,
		LastHeartbeatIP:    s.clientIPForRequest(r),
		LastHeartbeatCode:  stdhttp.StatusCreated,
		HeartbeatVersion:   strings.TrimSpace(req.Version),
		HeartbeatTokenHash: hashOpaqueToken(heartbeatToken),
	}
	enrolled, err := s.nodes.EnrollWithToken(r.Context(), node, token.ID, token.SingleUse, now, func(created *domain.Node) {
		created.HeartbeatEndpoint = "/api/v1/nodes/" + strconv.FormatUint(uint64(created.ID), 10) + "/heartbeat"
	})
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !enrolled {
		writeError(w, stdhttp.StatusUnauthorized, "invalid_enrollment_token", "invalid or expired enrollment token")
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, nil, "enroll", "node", &node.ID, map[string]any{"node_id": node.ID, "enrollment_token_id": token.ID})
	writeJSON(w, stdhttp.StatusCreated, map[string]any{
		"node":            node,
		"heartbeat_token": heartbeatToken,
		"heartbeat_url":   "/api/v1/nodes/" + strconv.FormatUint(uint64(node.ID), 10) + "/heartbeat",
	})
}

func randomEnrollmentToken() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}

func (s *Server) nodeAgentAPIBaseHint() string {
	base := strings.TrimSpace(s.cfg.FrontendBaseURL)
	if base == "" {
		if s.cfg.AllowInsecureDevMode {
			return "http://localhost:8080"
		}
		return "https://localhost"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		if s.cfg.AllowInsecureDevMode {
			return "http://localhost:8080"
		}
		return "https://localhost"
	}
	if s.cfg.AllowInsecureDevMode {
		if parsed.Scheme == "" {
			parsed.Scheme = "http"
		}
		return parsed.Scheme + "://" + parsed.Host
	}
	return "https://" + parsed.Host
}

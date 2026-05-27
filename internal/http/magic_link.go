package http

import (
	stdhttp "net/http"
	"strings"
	"time"

	"portlyn/internal/domain"
)

type issueMagicLinkRequest struct {
	TTLSeconds *int    `json:"ttl_seconds" validate:"omitempty,gte=60,lte=2592000"`
	Label      *string `json:"label" validate:"omitempty,max=255"`
}

type issueMagicLinkResponse struct {
	URL       string    `json:"url"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleIssueMagicLink(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	service, err := s.services.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	var req issueMagicLinkRequest
	_ = decodeStrictJSON(r, &req)
	ttl := 2 * time.Hour
	if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
		ttl = time.Duration(*req.TTLSeconds) * time.Second
	}
	label := ""
	if req.Label != nil {
		label = *req.Label
	}
	result, err := s.auth.IssueMagicLink(r.Context(), service.ID, ttl, s.requestMeta(r), label)
	if err != nil {
		s.internalError(w, err)
		return
	}
	host := domain.ServiceHost(*service)
	scheme := "https"
	if s.cfg.AllowInsecureDevMode {
		scheme = "http"
	}
	servicePath := strings.TrimSuffix(service.Path, "/")
	if servicePath == "" {
		servicePath = "/"
	} else if !strings.HasPrefix(servicePath, "/") {
		servicePath = "/" + servicePath
	}
	url := scheme + "://" + host + "/_portlyn/magic/" + result.Token + "?service=" + intToString(int(service.ID))
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "magic_link_issued", "service", &service.ID, map[string]any{
		"service_id": service.ID,
		"ttl":        ttl.String(),
		"label":      label,
	})
	writeJSON(w, stdhttp.StatusCreated, issueMagicLinkResponse{
		URL:       url,
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
	})
}

func intToString(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

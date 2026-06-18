package http

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) nodeTransportSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.cfg.NodeTrustForwardedProto || !s.requestFromTrustedProxy(r) {
		return false
	}
	return strings.EqualFold(forwardedProtoHeader(r), "https")
}

func (s *Server) requireNodeSecureTransport(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.NodeRequireHTTPS || s.cfg.AllowInsecureDevMode {
		return true
	}
	if s.nodeTransportSecure(r) {
		return true
	}
	writeErrorRequest(w, r, http.StatusUpgradeRequired, "insecure_transport", "node endpoints require https transport")
	return false
}

func (s *Server) enforceNodeRateLimit(w http.ResponseWriter, r *http.Request, bucket string, limit int, window time.Duration) bool {
	if s.nodeRateLimiter == nil || limit <= 0 || window <= 0 {
		return true
	}
	key := bucket + ":" + nodeRateLimitClientKey(r, s.cfg.NodeTrustForwardedProto && s.requestFromTrustedProxy(r), s.cfg.TrustedProxyCIDRs)
	allowed, _, reset, err := s.nodeRateLimiter.Allow(r.Context(), key, limit, window)
	if err != nil {
		s.logger.Error("node rate limit check failed", "bucket", bucket, "error", err)
		return true
	}
	if allowed {
		return true
	}
	retryAfter := int(time.Until(reset).Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeErrorRequest(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
	return false
}

func forwardedProtoHeader(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func nodeRateLimitClientKey(r *http.Request, trustForwarded bool, trustedCIDRs []string) string {
	if trustForwarded {
		if addr, ok := clientIPFromForwardedChain(r.Header.Get("X-Forwarded-For"), trustedCIDRs); ok {
			return addr.String()
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

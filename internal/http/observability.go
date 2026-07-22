package http

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"portlyn/internal/auth"
)

func (s *Server) accessLogMiddleware(channel string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startedAt := time.Now()
			writer := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(writer, r)

			statusCode := writer.Status()
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			latency := time.Since(startedAt)
			requestID := middleware.GetReqID(r.Context())
			clientIP := s.clientIPForRequest(r)
			args := []any{
				"component", "http_api",
				"kind", channel + "_access",
				"request_id", requestID,
				"trace_id", requestID,
				"method", r.Method,
				"host", r.Host,
				"path", r.URL.Path,
				"status", statusCode,
				"latency_ms", latency.Milliseconds(),
				"bytes", writer.BytesWritten(),
				"remote_addr", clientIP,
				"user_agent", r.UserAgent(),
			}

			if user, ok := auth.UserFromContext(r.Context()); ok && user != nil {
				args = append(args, "user_id", user.ID, "user_role", user.Role)
			}

			s.logger.Info("request completed", args...)
			if s.metrics != nil {
				s.metrics.ObserveAPIRequest(r.URL.Path, statusCode, latency)
			}
		})
	}
}

func parseAuditTimeQuery(raw string) (*time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, false
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		utc := parsed.UTC()
		return &utc, true
	}
	if unixValue, err := strconv.ParseInt(value, 10, 64); err == nil {
		timestamp := time.Unix(unixValue, 0).UTC()
		if unixValue > 1_000_000_000_000 {
			timestamp = time.UnixMilli(unixValue).UTC()
		}
		return &timestamp, true
	}
	return nil, false
}

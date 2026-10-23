package http

import (
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"

	"portlyn/internal/accesslog"
)

func (s *Server) SetAccessLog(recorder *accesslog.Recorder) {
	s.accessLog = recorder
}

func (s *Server) handleListAccessLogs(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	query := r.URL.Query()
	filter := accesslog.Filter{
		Host:    strings.TrimSpace(query.Get("host")),
		Status:  strings.TrimSpace(query.Get("status")),
		IP:      strings.TrimSpace(query.Get("ip")),
		Query:   strings.TrimSpace(query.Get("q")),
		Outcome: strings.TrimSpace(query.Get("outcome")),
	}
	if raw := strings.TrimSpace(query.Get("service_id")); raw != "" {
		if id, err := strconv.ParseUint(raw, 10, strconv.IntSize); err == nil {
			filter.ServiceID = uint(id)
		}
	}
	if raw := strings.TrimSpace(query.Get("before")); raw != "" {
		if before, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			filter.Before = before
		}
	}
	items := s.accessLog.List(filter, parseIntQuery(r, "limit", 200))
	if items == nil {
		items = []accesslog.Entry{}
	}
	writeJSON(w, stdhttp.StatusOK, map[string]any{
		"items":   items,
		"enabled": s.accessLog != nil,
	})
}

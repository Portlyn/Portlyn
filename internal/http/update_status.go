package http

import (
	stdhttp "net/http"

	"portlyn/internal/updatecheck"
)

func (s *Server) SetUpdateChecker(checker *updatecheck.Checker) {
	s.updates = checker
}

func (s *Server) handleUpdateStatus(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.updates == nil {
		writeJSON(w, stdhttp.StatusOK, updatecheck.Status{CurrentVersion: s.cfg.AppVersion})
		return
	}
	writeJSON(w, stdhttp.StatusOK, s.updates.Status(r.Context()))
}

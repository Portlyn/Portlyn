package http

import (
	stdhttp "net/http"
)

func (s *Server) handleListExposureReports(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.exposureReports == nil {
		writeJSON(w, stdhttp.StatusOK, []any{})
		return
	}
	items, err := s.exposureReports.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, items)
}

func (s *Server) handleGetExposureReport(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if s.exposureReports == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "scanner_unavailable", "exposure scanner not initialized")
		return
	}
	item, err := s.exposureReports.GetByServiceID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleRunExposureScan(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if s.exposureScanner == nil {
		writeError(w, stdhttp.StatusServiceUnavailable, "scanner_unavailable", "exposure scanner not initialized")
		return
	}
	id, ok := s.parseIDParam(w, r, "id")
	if !ok {
		return
	}
	service, err := s.services.GetByID(r.Context(), id)
	if err != nil {
		s.handleStoreError(w, err)
		return
	}
	report := s.exposureScanner.ScanService(r.Context(), *service)
	if report == nil {
		writeError(w, stdhttp.StatusUnprocessableEntity, "scan_failed", "could not produce report")
		return
	}
	if s.exposureReports != nil {
		if err := s.exposureReports.Upsert(r.Context(), report); err != nil {
			s.internalError(w, err)
			return
		}
	}
	writeJSON(w, stdhttp.StatusOK, report)
}

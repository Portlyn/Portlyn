package http

import (
	stdhttp "net/http"
	"time"
)

func (s *Server) handleRetryCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	item.FailureCount = 0
	if _, err := s.acme.SyncCertificate(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "retry", "certificate", &item.ID, map[string]any{"certificate_id": item.ID})
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleRenewCertificate(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	item.FailureCount = 0
	if _, err := s.acme.SyncCertificate(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "renew", "certificate", &item.ID, map[string]any{"certificate_id": item.ID})
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleSyncCertificateStatus(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	if _, err := s.acme.SyncCertificate(r.Context(), item); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "sync_status", "certificate", &item.ID, map[string]any{"certificate_id": item.ID})
	writeJSON(w, stdhttp.StatusOK, item)
}

func (s *Server) handleImportCertificatePEM(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	item, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	var req importCertificatePEMRequest
	if !s.decodeAndValidate(w, r, &req) {
		return
	}
	updated, err := s.acme.ImportPEMCertificate(r.Context(), item, req.CertificatePEM, req.PrivateKeyPEM, req.IssuerKey)
	if err != nil {
		writeError(w, stdhttp.StatusBadRequest, "invalid_certificate", err.Error())
		return
	}
	_ = s.audit.LogRequest(r.Context(), r, s.currentUserID(r), "import_pem", "certificate", &item.ID, map[string]any{"certificate_id": item.ID})
	writeJSON(w, stdhttp.StatusOK, updated)
}

func ptrTime(value time.Time) *time.Time {
	return &value
}

package http

import (
	"encoding/json"
	stdhttp "net/http"
	"time"
)

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Status    int       `json:"status"`
	RequestID string    `json:"request_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func writeJSON(w stdhttp.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w stdhttp.ResponseWriter, status int, code, message string) {
	writeErrorRequest(w, nil, status, code, message)
}

func writeErrorRequest(w stdhttp.ResponseWriter, r *stdhttp.Request, status int, code, message string) {
	requestID := ""
	if r != nil {
		requestID = r.Header.Get("X-Request-Id")
	}
	writeJSON(w, status, errorEnvelope{
		Error: apiError{
			Code:      code,
			Message:   message,
			Status:    status,
			RequestID: requestID,
			Timestamp: time.Now().UTC(),
		},
	})
}

package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"portlyn/internal/domain"
)

type stubServices struct{ items []domain.Service }

func (s *stubServices) List(ctx context.Context) ([]domain.Service, error) {
	return s.items, nil
}

type stubReports struct {
	mu      sync.Mutex
	reports []domain.ServiceExposureReport
}

func (s *stubReports) Upsert(ctx context.Context, report *domain.ServiceExposureReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, *report)
	return nil
}

func (s *stubReports) List(ctx context.Context) ([]domain.ServiceExposureReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.ServiceExposureReport(nil), s.reports...), nil
}

func (s *stubReports) GetByServiceID(ctx context.Context, id uint) (*domain.ServiceExposureReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reports {
		if r.ServiceID == id {
			c := r
			return &c, nil
		}
	}
	return nil, nil
}

func TestScannerScanServiceCollectsFindings(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tls.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(tls.URL, "https://"))
	if host == "" {
		t.Fatalf("could not parse %s", tls.URL)
	}
	if host == "127.0.0.1" {
		host = "localhost"
	}

	service := domain.Service{
		ID:         1,
		Name:       "test",
		Path:       "/",
		AccessMode: domain.AccessModeAuthenticated,
		Domain:     domain.Domain{Name: host + ":" + port},
	}
	scanner := NewScanner(&stubServices{items: []domain.Service{service}}, &stubReports{}, nil)
	report := scanner.ScanService(context.Background(), service)
	if report == nil {
		t.Fatal("expected report")
	}
	if report.HTTPSValid {
		t.Fatalf("expected self-signed cert to be reported invalid, got %+v", report)
	}
	foundInvalid := false
	for _, f := range report.Findings {
		if f == "https_invalid" {
			foundInvalid = true
			break
		}
	}
	if !foundInvalid {
		t.Fatalf("expected https_invalid finding, got %+v", report.Findings)
	}
	if !report.AuthEnforced {
		t.Fatal("expected auth enforced")
	}
	if !report.HSTSPresent {
		t.Fatal("expected HSTS present")
	}
	if !report.XFrameOptions {
		t.Fatal("expected x-frame-options present")
	}
	if report.Score <= 0 || report.Score > 100 {
		t.Fatalf("unexpected score: %d", report.Score)
	}
}

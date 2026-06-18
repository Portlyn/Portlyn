package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"portlyn/internal/domain"
)

func verifyTLSChain(host string, state *tls.ConnectionState) bool {
	if state == nil || len(state.PeerCertificates) == 0 {
		return false
	}
	serverName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Intermediates: intermediates,
	})
	return err == nil
}

type ServiceProvider interface {
	List(ctx context.Context) ([]domain.Service, error)
}

type ReportStore interface {
	Upsert(ctx context.Context, report *domain.ServiceExposureReport) error
	List(ctx context.Context) ([]domain.ServiceExposureReport, error)
	GetByServiceID(ctx context.Context, serviceID uint) (*domain.ServiceExposureReport, error)
}

type Scanner struct {
	mu         sync.Mutex
	services   ServiceProvider
	reports    ReportStore
	logger     *slog.Logger
	httpClient *http.Client
	interval   time.Duration
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func NewScanner(services ServiceProvider, reports ReportStore, logger *slog.Logger) *Scanner {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	return &Scanner{
		services: services,
		reports:  reports,
		logger:   logger,
		httpClient: &http.Client{
			Timeout:   12 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		interval: 6 * time.Hour,
	}
}

func (s *Scanner) SetInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	s.interval = interval
}

func (s *Scanner) Start(ctx context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	innerCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop(innerCtx)
}

func (s *Scanner) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

func (s *Scanner) loop(ctx context.Context) {
	defer s.wg.Done()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.RunOnce(ctx)
			timer.Reset(s.interval)
		}
	}
}

func (s *Scanner) RunOnce(ctx context.Context) {
	services, err := s.services.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("exposure scanner: list services", "error", err)
		}
		return
	}
	for _, service := range services {
		report := s.ScanService(ctx, service)
		if report == nil {
			continue
		}
		if err := s.reports.Upsert(ctx, report); err != nil && s.logger != nil {
			s.logger.Warn("exposure scanner: upsert report", "service_id", service.ID, "error", err)
		}
	}
}

func (s *Scanner) ScanService(ctx context.Context, service domain.Service) *domain.ServiceExposureReport {
	host := domain.ServiceHost(service)
	if strings.TrimSpace(host) == "" {
		return nil
	}
	report := &domain.ServiceExposureReport{
		ServiceID:       service.ID,
		CheckedAt:       time.Now().UTC(),
		GeoIPConfigured: len(service.AllowedCountries) > 0 || len(service.BlockedCountries) > 0,
	}
	findings := []string{}

	if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
		report.DNSResolvable = true
	} else {
		findings = append(findings, "dns_not_resolvable")
	}

	httpURL := "http://" + host + service.Path
	httpsURL := "https://" + host + service.Path

	if resp, err := s.do(ctx, http.MethodHead, httpURL); err == nil {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(strings.ToLower(location), "https://") {
				report.HTTPSRedirect = true
			}
		}
		resp.Body.Close()
	}

	if resp, err := s.do(ctx, http.MethodGet, httpsURL); err == nil {
		report.HTTPSValid = verifyTLSChain(host, resp.TLS)
		if report.HTTPSValid {
			cert := resp.TLS.PeerCertificates[0]
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			if daysLeft < 0 {
				daysLeft = 0
			}
			report.HTTPSExpiresIn = daysLeft
			if daysLeft < 14 {
				findings = append(findings, "https_expiring_soon")
			}
		} else {
			findings = append(findings, "https_invalid")
		}
		report.HSTSPresent = strings.TrimSpace(resp.Header.Get("Strict-Transport-Security")) != ""
		report.CSPPresent = strings.TrimSpace(resp.Header.Get("Content-Security-Policy")) != ""
		report.XFrameOptions = strings.TrimSpace(resp.Header.Get("X-Frame-Options")) != ""
		if service.AccessMode != domain.AccessModePublic {
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusFound, http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusSeeOther:
				report.AuthEnforced = true
			default:
				findings = append(findings, "auth_not_enforced")
			}
		} else {
			report.AuthEnforced = true
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	} else {
		findings = append(findings, "https_unreachable")
		report.LastError = err.Error()
	}

	if !report.HSTSPresent && service.AccessMode != domain.AccessModePublic {
		findings = append(findings, "hsts_missing")
	}
	if !report.CSPPresent {
		findings = append(findings, "csp_missing")
	}
	if !report.XFrameOptions {
		findings = append(findings, "x_frame_options_missing")
	}
	if !report.HTTPSRedirect {
		findings = append(findings, "http_not_redirecting_https")
	}
	if service.AccessMode == domain.AccessModePublic {
		findings = append(findings, "service_is_public")
	}

	report.Score = computeScore(report, findings)
	report.Findings = findings
	return report
}

func (s *Scanner) do(ctx context.Context, method, url string) (*http.Response, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("empty url")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "portlyn-exposure-scanner/1")
	return s.httpClient.Do(req)
}

func computeScore(report *domain.ServiceExposureReport, findings []string) int {
	score := 100
	if !report.DNSResolvable {
		score -= 40
	}
	if !report.HTTPSValid {
		score -= 30
	}
	if !report.AuthEnforced {
		score -= 25
	}
	if !report.HSTSPresent {
		score -= 5
	}
	if !report.CSPPresent {
		score -= 5
	}
	if !report.XFrameOptions {
		score -= 3
	}
	if !report.HTTPSRedirect {
		score -= 8
	}
	if report.HTTPSExpiresIn > 0 && report.HTTPSExpiresIn < 14 {
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	_ = fmt.Sprintf
	return score
}

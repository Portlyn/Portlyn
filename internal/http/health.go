package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"portlyn/internal/domain"
)

const (
	HealthLevelOK    = "ok"
	HealthLevelWarn  = "warn"
	HealthLevelError = "error"
)

type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
}

type StatusCondition struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Level     string    `json:"level"`
	Summary   string    `json:"summary"`
	Reason    string    `json:"reason,omitempty"`
	Required  bool      `json:"required"`
	CheckedAt time.Time `json:"checked_at"`
}

type HealthEnvelope struct {
	Status    string            `json:"status"`
	Kind      string            `json:"kind"`
	Version   string            `json:"version"`
	CheckedAt time.Time         `json:"checked_at"`
	HTTPAddr  string            `json:"http_addr,omitempty"`
	HTTPSAddr string            `json:"https_addr,omitempty"`
	ProxyTLS  string            `json:"proxy_tls"`
	Livez     StatusCondition   `json:"livez"`
	Readyz    []StatusCondition `json:"readyz"`
	Services  []StatusCondition `json:"services,omitempty"`
	Cluster   []StatusCondition `json:"cluster,omitempty"`
	Summary   map[string]int    `json:"summary"`
	Warnings  []string          `json:"warnings,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
}

type dbHealthCheck struct {
	ping func(context.Context) error
}

func NewDBHealthCheck(ping func(context.Context) error) HealthCheck {
	return dbHealthCheck{ping: ping}
}

func (c dbHealthCheck) Name() string { return "database" }

func (c dbHealthCheck) Check(ctx context.Context) error {
	if c.ping == nil {
		return errors.New("database ping is not configured")
	}
	return c.ping(ctx)
}

type namedCheck struct {
	name string
	fn   func(context.Context) error
}

type HTTPHealthTarget struct {
	Name string
	URL  string
}

type httpTargetsHealthCheck struct {
	name   string
	list   func(context.Context) ([]HTTPHealthTarget, error)
	client *http.Client
}

func NewNamedHealthCheck(name string, fn func(context.Context) error) HealthCheck {
	return namedCheck{name: name, fn: fn}
}

func NewHTTPTargetsHealthCheck(name string, list func(context.Context) ([]HTTPHealthTarget, error), client *http.Client) HealthCheck {
	return httpTargetsHealthCheck{name: name, list: list, client: client}
}

func (c namedCheck) Name() string { return c.name }

func (c namedCheck) Check(ctx context.Context) error {
	if c.fn == nil {
		return errors.New("health check is not configured")
	}
	return c.fn(ctx)
}

func (c httpTargetsHealthCheck) Name() string { return c.name }

func (c httpTargetsHealthCheck) Check(ctx context.Context) error {
	if c.list == nil {
		return errors.New("health check target list is not configured")
	}
	client := c.client
	if client == nil {
		client = &http.Client{Timeout: 1500 * time.Millisecond}
	}
	targets, err := c.list(ctx)
	if err != nil {
		return err
	}
	failures := make([]string, 0)
	for _, target := range targets {
		if err := probeHTTPHealthTarget(ctx, client, target); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target.Name, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func probeHTTPHealthTarget(ctx context.Context, client *http.Client, target HTTPHealthTarget) error {
	if strings.TrimSpace(target.URL) == "" {
		return errors.New("target url is empty")
	}
	if err := validateServiceTargetURL(target.URL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
			resp = nil
		} else if resp.StatusCode >= http.StatusInternalServerError {
			return fmt.Errorf("returned status %d", resp.StatusCode)
		} else {
			return nil
		}
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return err
	}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("returned status %d", resp.StatusCode)
	}
	return nil
}

func ServiceTargetsFromDomain(services []domain.Service) []HTTPHealthTarget {
	targets := make([]HTTPHealthTarget, 0, len(services))
	for _, service := range services {
		name := strings.TrimSpace(service.Name)
		if domainName := strings.TrimSpace(domain.ServiceHost(service)); domainName != "" {
			name = fmt.Sprintf("%s (%s%s)", name, domainName, strings.TrimSpace(service.Path))
		}
		targets = append(targets, HTTPHealthTarget{Name: name, URL: strings.TrimSpace(service.TargetURL)})
	}
	return targets
}

func (s *Server) healthVersion() string {
	if s.cfg.HealthExposeVersion {
		return s.cfg.AppVersion
	}
	return ""
}

func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	condition := StatusCondition{
		Name:      "process",
		Scope:     "livez",
		Level:     HealthLevelOK,
		Summary:   "process is serving requests",
		Required:  true,
		CheckedAt: time.Now().UTC(),
	}
	if s.metrics != nil {
		s.metrics.SetHealthState("livez", "process", condition.Level)
	}
	writeJSON(w, http.StatusOK, HealthEnvelope{
		Status:    HealthLevelOK,
		Kind:      "liveness",
		Version:   s.healthVersion(),
		CheckedAt: condition.CheckedAt,
		ProxyTLS:  boolStatus(s.acme != nil && s.acme.HasHTTPS()),
		Livez:     condition,
		Summary:   map[string]int{"ok": 1},
		RequestID: requestIDFromRequest(r),
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	s.writeHealth(w, r, "readiness")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.writeHealth(w, r, "health")
}

func (s *Server) writeHealth(w http.ResponseWriter, r *http.Request, kind string) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	ready := s.evaluateReadiness(ctx)
	services := s.evaluateServiceStatus(ctx)
	cluster := s.evaluateClusterStatus(ctx)
	summary := summarizeConditions(append(append([]StatusCondition{}, ready...), append(services, cluster...)...))
	status := overallHealthLevel(summary)
	statusCode := http.StatusOK
	if kind == "readiness" && summary[HealthLevelError] > 0 {
		statusCode = http.StatusServiceUnavailable
	}
	if kind == "health" && summary[HealthLevelError] > 0 {
		statusCode = http.StatusServiceUnavailable
	}

	for _, condition := range append(append(append([]StatusCondition{}, ready...), services...), cluster...) {
		if s.metrics != nil {
			s.metrics.SetHealthState(condition.Scope, condition.Name, condition.Level)
		}
	}

	writeJSON(w, statusCode, HealthEnvelope{
		Status:    status,
		Kind:      kind,
		Version:   s.healthVersion(),
		CheckedAt: time.Now().UTC(),
		HTTPAddr:  s.cfg.ProxyHTTPAddr,
		HTTPSAddr: s.cfg.ProxyHTTPSAddr,
		ProxyTLS:  boolStatus(s.acme != nil && s.acme.HasHTTPS()),
		Livez: StatusCondition{
			Name:      "process",
			Scope:     "livez",
			Level:     HealthLevelOK,
			Summary:   "process is serving requests",
			Required:  true,
			CheckedAt: time.Now().UTC(),
		},
		Readyz:    ready,
		Services:  services,
		Cluster:   cluster,
		Summary:   summary,
		RequestID: requestIDFromRequest(r),
	})
}

func (s *Server) evaluateReadiness(ctx context.Context) []StatusCondition {
	results := make([]StatusCondition, 0, len(s.healthChecks))
	for _, check := range s.healthChecks {
		condition := StatusCondition{
			Name:      check.Name(),
			Scope:     "readyz",
			Level:     HealthLevelOK,
			Summary:   "dependency is healthy",
			Required:  true,
			CheckedAt: time.Now().UTC(),
		}
		started := time.Now()
		if err := check.Check(ctx); err != nil {
			condition.Level = HealthLevelError
			condition.Summary = err.Error()
			condition.Reason = "dependency_failed"
		}
		if s.metrics != nil && check.Name() == "database" {
			s.metrics.ObserveDBLatency("ping", time.Since(started))
		}
		results = append(results, condition)
	}
	return results
}

func (s *Server) evaluateServiceStatus(ctx context.Context) []StatusCondition {
	if s.services == nil {
		return nil
	}
	items, err := s.services.List(ctx)
	if err != nil {
		return []StatusCondition{{
			Name:      "service_inventory",
			Scope:     "services",
			Level:     HealthLevelError,
			Summary:   err.Error(),
			Reason:    "service_list_failed",
			Required:  false,
			CheckedAt: time.Now().UTC(),
		}}
	}
	healthByID := s.evaluateServicesHealth(ctx, items)
	out := make([]StatusCondition, 0, len(items))
	for _, item := range items {
		health := healthByID[item.ID]
		level := HealthLevelOK
		switch health.Status {
		case "pending", "degraded":
			level = HealthLevelWarn
		case "unhealthy":
			level = HealthLevelError
		}
		out = append(out, StatusCondition{
			Name:      item.Name,
			Scope:     "services",
			Level:     level,
			Summary:   firstNonEmpty(health.Reason, health.Error, health.Status),
			Reason:    health.Reason,
			Required:  false,
			CheckedAt: health.CheckedAt,
		})
	}
	return out
}

func (s *Server) evaluateClusterStatus(ctx context.Context) []StatusCondition {
	conditions := append([]StatusCondition{}, s.bootWarnings...)
	now := time.Now().UTC()
	if s.acme != nil {
		acmeStatus := s.acme.Status(ctx)
		conditions = append(conditions, StatusCondition{
			Name:      "acme",
			Scope:     "cluster",
			Level:     acmeStatus.Level,
			Summary:   acmeStatus.Summary,
			Reason:    acmeStatus.Reason,
			Required:  false,
			CheckedAt: now,
		})
	}
	if s.nodes != nil {
		nodes, err := s.nodes.List(ctx)
		if err != nil {
			conditions = append(conditions, StatusCondition{Name: "nodes", Scope: "cluster", Level: HealthLevelWarn, Summary: err.Error(), Reason: "node_list_failed", CheckedAt: now})
		} else {
			_, offline, _ := s.nodeStatusSummary(nodes)
			level := HealthLevelOK
			summary := "all nodes online"
			reason := ""
			if offline > 0 {
				level = HealthLevelWarn
				summary = fmt.Sprintf("%d node(s) offline", offline)
				reason = "offline_nodes"
			}
			conditions = append(conditions, StatusCondition{Name: "nodes", Scope: "cluster", Level: level, Summary: summary, Reason: reason, CheckedAt: now})
		}
	}
	return conditions
}

func summarizeConditions(conditions []StatusCondition) map[string]int {
	summary := map[string]int{HealthLevelOK: 0, HealthLevelWarn: 0, HealthLevelError: 0}
	for _, condition := range conditions {
		summary[condition.Level]++
	}
	return summary
}

func overallHealthLevel(summary map[string]int) string {
	if summary[HealthLevelError] > 0 {
		return HealthLevelError
	}
	if summary[HealthLevelWarn] > 0 {
		return HealthLevelWarn
	}
	return HealthLevelOK
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-Request-Id"))
}

func boolStatus(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu         sync.Mutex
	counters   map[string]*metricFamily
	histograms map[string]*histogramFamily
	gauges     map[string]*gaugeFamily
}

type metricFamily struct {
	help   string
	values map[string]float64
}

type gaugeFamily struct {
	help   string
	values map[string]float64
}

type histogramFamily struct {
	help    string
	buckets []float64
	values  map[string]*histogramValue
}

type histogramValue struct {
	count   uint64
	sum     float64
	buckets []uint64
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*metricFamily),
		histograms: make(map[string]*histogramFamily),
		gauges:     make(map[string]*gaugeFamily),
	}
}

func (r *Registry) IncCounter(name, help string, labels map[string]string, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	family := r.counters[name]
	if family == nil {
		family = &metricFamily{help: help, values: make(map[string]float64)}
		r.counters[name] = family
	}
	family.values[labelKey(labels)] += delta
}

func (r *Registry) SetGauge(name, help string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	family := r.gauges[name]
	if family == nil {
		family = &gaugeFamily{help: help, values: make(map[string]float64)}
		r.gauges[name] = family
	}
	family.values[labelKey(labels)] = value
}

func (r *Registry) ObserveHistogram(name, help string, labels map[string]string, value float64, buckets []float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	family := r.histograms[name]
	if family == nil {
		family = &histogramFamily{help: help, buckets: append([]float64(nil), buckets...), values: make(map[string]*histogramValue)}
		r.histograms[name] = family
	}
	key := labelKey(labels)
	entry := family.values[key]
	if entry == nil {
		entry = &histogramValue{buckets: make([]uint64, len(family.buckets))}
		family.values[key] = entry
	}
	entry.count++
	entry.sum += value
	for i, bucket := range family.buckets {
		if value <= bucket {
			entry.buckets[i]++
		}
	}
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(r.render()))
	})
}

func (r *Registry) render() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lines []string
	appendFamilies := func(names []string, kind string, fn func(name string) []string) {
		sort.Strings(names)
		for _, name := range names {
			lines = append(lines, fmt.Sprintf("# HELP %s %s", name, sanitizeHelp(fn(name)[0])))
			lines = append(lines, fmt.Sprintf("# TYPE %s %s", name, kind))
			lines = append(lines, fn(name)[1:]...)
		}
	}

	counterNames := sortedKeys(r.counters)
	appendFamilies(counterNames, "counter", func(name string) []string {
		family := r.counters[name]
		out := []string{family.help}
		for _, key := range sortedKeys(family.values) {
			out = append(out, fmt.Sprintf("%s%s %s", name, labelsFromKey(key), strconv.FormatFloat(family.values[key], 'f', -1, 64)))
		}
		return out
	})

	gaugeNames := sortedKeys(r.gauges)
	appendFamilies(gaugeNames, "gauge", func(name string) []string {
		family := r.gauges[name]
		out := []string{family.help}
		for _, key := range sortedKeys(family.values) {
			out = append(out, fmt.Sprintf("%s%s %s", name, labelsFromKey(key), strconv.FormatFloat(family.values[key], 'f', -1, 64)))
		}
		return out
	})

	histogramNames := sortedKeys(r.histograms)
	appendFamilies(histogramNames, "histogram", func(name string) []string {
		family := r.histograms[name]
		out := []string{family.help}
		for _, key := range sortedKeys(family.values) {
			entry := family.values[key]
			cumulative := uint64(0)
			for i, bucket := range family.buckets {
				cumulative += entry.buckets[i]
				out = append(out, fmt.Sprintf("%s_bucket%s %d", name, mergeLabelString(key, "le", strconv.FormatFloat(bucket, 'f', -1, 64)), cumulative))
			}
			out = append(out, fmt.Sprintf("%s_bucket%s %d", name, mergeLabelString(key, "le", "+Inf"), entry.count))
			out = append(out, fmt.Sprintf("%s_sum%s %s", name, labelsFromKey(key), strconv.FormatFloat(entry.sum, 'f', -1, 64)))
			out = append(out, fmt.Sprintf("%s_count%s %d", name, labelsFromKey(key), entry.count))
		}
		return out
	})

	return strings.Join(lines, "\n") + "\n"
}

type Metrics struct {
	registry *Registry
}

func NewMetrics() *Metrics {
	return &Metrics{registry: NewRegistry()}
}

func (m *Metrics) Handler() http.Handler {
	return m.registry.Handler()
}

func (m *Metrics) ObserveProxyRequest(service, outcome string, status int, latency time.Duration) {
	labels := map[string]string{"service": defaultLabel(service, "unknown"), "outcome": defaultLabel(outcome, "unknown"), "status": strconv.Itoa(status)}
	m.registry.IncCounter("portlyn_proxy_requests_total", "Proxy requests by service, outcome and status.", labels, 1)
	m.registry.ObserveHistogram("portlyn_proxy_latency_seconds", "Proxy request latency in seconds.", labels, latency.Seconds(), defaultLatencyBuckets())
}

func (m *Metrics) ObserveAPIRequest(route string, status int, latency time.Duration) {
	labels := map[string]string{"route": defaultLabel(route, "unknown"), "status": strconv.Itoa(status)}
	m.registry.IncCounter("portlyn_api_requests_total", "API requests by route and status.", labels, 1)
	m.registry.ObserveHistogram("portlyn_api_latency_seconds", "API request latency in seconds.", labels, latency.Seconds(), defaultLatencyBuckets())
}

func (m *Metrics) ObserveRateLimit(keyspace string) {
	m.registry.IncCounter("portlyn_rate_limit_hits_total", "Rate limit hits by keyspace.", map[string]string{"keyspace": defaultLabel(keyspace, "unknown")}, 1)
}

func (m *Metrics) ObserveReputationBlock() {
	m.registry.IncCounter("portlyn_reputation_blocked_total", "Requests blocked by the reputation (CrowdSec) engine.", map[string]string{}, 1)
}

func (m *Metrics) ObserveAuthAttempt(method, outcome string) {
	labels := map[string]string{"method": defaultLabel(method, "unknown"), "outcome": defaultLabel(outcome, "unknown")}
	m.registry.IncCounter("portlyn_auth_attempts_total", "Authentication attempts by method and outcome.", labels, 1)
}

func (m *Metrics) ObserveConfigPropagation(source string, latency time.Duration, cacheHit bool) {
	labels := map[string]string{"source": defaultLabel(source, "unknown"), "cache_hit": strconv.FormatBool(cacheHit)}
	m.registry.IncCounter("portlyn_config_events_total", "Configuration propagation events.", labels, 1)
	m.registry.ObserveHistogram("portlyn_config_rebuild_duration_seconds", "Configuration propagation duration in seconds.", labels, latency.Seconds(), defaultLatencyBuckets())
}

func (m *Metrics) ObserveACMEOperation(operation, outcome string, latency time.Duration) {
	labels := map[string]string{"operation": defaultLabel(operation, "unknown"), "outcome": defaultLabel(outcome, "unknown")}
	m.registry.IncCounter("portlyn_acme_operations_total", "ACME operations by type and outcome.", labels, 1)
	if latency > 0 {
		m.registry.ObserveHistogram("portlyn_acme_operation_duration_seconds", "ACME operation duration in seconds.", labels, latency.Seconds(), defaultLatencyBuckets())
	}
}

func (m *Metrics) SetCertificateExpiry(domain string, expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	seconds := time.Until(expiresAt).Seconds()
	m.registry.SetGauge("portlyn_certificate_expiry_seconds", "Seconds until certificate expiry.", map[string]string{"domain": defaultLabel(domain, "unknown")}, seconds)
}

func (m *Metrics) ObserveDBLatency(operation string, latency time.Duration) {
	m.registry.ObserveHistogram("portlyn_db_operation_duration_seconds", "Database operation duration in seconds.", map[string]string{"operation": defaultLabel(operation, "unknown")}, latency.Seconds(), defaultLatencyBuckets())
}

func (m *Metrics) SetHealthState(scope, name, level string) {
	m.registry.SetGauge("portlyn_health_state", "Health state encoded as ok=2, warn=1, error=0.", map[string]string{"scope": defaultLabel(scope, "unknown"), "name": defaultLabel(name, "unknown"), "level": defaultLabel(level, "unknown")}, healthLevelValue(level))
}

func healthLevelValue(level string) float64 {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "ok":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

func defaultLatencyBuckets() []float64 {
	return []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
}

func defaultLabel(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}

func labelsFromKey(key string) string {
	if key == "" {
		return ""
	}
	parts := strings.Split(key, ",")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 {
			continue
		}
		labels = append(labels, fmt.Sprintf(`%s=%q`, pair[0], pair[1]))
	}
	return "{" + strings.Join(labels, ",") + "}"
}

func mergeLabelString(existing, key, value string) string {
	if existing == "" {
		return fmt.Sprintf(`{%s=%q}`, key, value)
	}
	return strings.TrimRight(labelsFromKey(existing), "}") + fmt.Sprintf(`,%s=%q}`, key, value)
}

func sanitizeHelp(help string) string {
	if strings.TrimSpace(help) == "" {
		return "Portlyn metric."
	}
	return strings.TrimSpace(help)
}

func sortedKeys[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

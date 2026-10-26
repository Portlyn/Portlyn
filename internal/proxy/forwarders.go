package proxy

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"portlyn/internal/domain"
)

const (
	forwarderWindow      = 10 * time.Minute
	forwarderMinRequests = 20
	forwarderMinShare    = 0.2
	forwarderMaxKeys     = 4096
)

var forwardingHeaders = []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "Cf-Connecting-Ip", "True-Client-Ip"}

type forwarderKey struct {
	host   string
	prefix netip.Prefix
}

type forwarderDetector struct {
	mu          sync.Mutex
	windowStart time.Time
	totals      map[string]int64
	hits        map[forwarderKey]int64
	headers     map[forwarderKey]string
	report      domain.ForwarderReport
	now         func() time.Time
}

func newForwarderDetector() *forwarderDetector {
	d := &forwarderDetector{now: time.Now}
	d.reset(d.now())
	return d
}

func (d *forwarderDetector) reset(now time.Time) {
	d.windowStart = now
	d.totals = make(map[string]int64)
	d.hits = make(map[forwarderKey]int64)
	d.headers = make(map[forwarderKey]string)
}

func forwardingHeader(r *http.Request) string {
	for _, name := range forwardingHeaders {
		if r.Header.Get(name) != "" {
			return name
		}
	}
	return ""
}

func forwarderPrefix(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	prefix, _ := addr.Prefix(bits)
	return prefix
}

func (d *forwarderDetector) observe(host string, peer netip.Addr, trusted bool, header string) {
	if host == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.totals[host]; !ok && len(d.totals) >= forwarderMaxKeys {
		return
	}
	d.totals[host]++
	if trusted || header == "" || !peer.IsValid() {
		return
	}
	key := forwarderKey{host: host, prefix: forwarderPrefix(peer)}
	if _, ok := d.hits[key]; !ok {
		if len(d.hits) >= forwarderMaxKeys {
			return
		}
		d.headers[key] = header
	}
	d.hits[key]++
}

func (d *forwarderDetector) rotate() domain.ForwarderReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	findings := make([]domain.ForwarderFinding, 0)
	for key, count := range d.hits {
		total := d.totals[key.host]
		if count < forwarderMinRequests || total == 0 {
			continue
		}
		share := float64(count) / float64(total)
		if share < forwarderMinShare {
			continue
		}
		findings = append(findings, domain.ForwarderFinding{
			Host:     key.host,
			Prefix:   key.prefix.String(),
			Header:   d.headers[key],
			Requests: count,
			Total:    total,
			Percent:  share * 100,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		return findings[i].Requests > findings[j].Requests
	})
	d.report = domain.ForwarderReport{CheckedAt: now.UTC(), Window: forwarderWindow.String(), Findings: findings}
	d.reset(now)
	return d.report
}

func (d *forwarderDetector) current() domain.ForwarderReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.report
}

func (m *Manager) observeForwarder(r *http.Request, host string) {
	if m.forwarders == nil {
		return
	}
	peer, err := parseClientIP(r.RemoteAddr)
	if err != nil {
		return
	}
	m.forwarders.observe(host, peer, m.requestFromTrustedProxy(r), forwardingHeader(r))
}

func (m *Manager) ForwarderReport() domain.ForwarderReport {
	if m.forwarders == nil {
		return domain.ForwarderReport{}
	}
	return m.forwarders.current()
}

func (m *Manager) SetForwarderReportHook(hook func(context.Context, domain.ForwarderReport)) {
	m.forwarderHook = hook
}

func (m *Manager) runForwarderDetection(ctx context.Context) {
	ticker := time.NewTicker(forwarderWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		report := m.forwarders.rotate()
		if m.logger != nil {
			for _, finding := range report.Findings {
				m.logger.Warn(finding.Message(),
					"component", "proxy",
					"kind", "untrusted_forwarder",
					"host", finding.Host,
					"peer_prefix", finding.Prefix,
					"header", finding.Header,
					"requests", finding.Requests,
					"total", finding.Total)
			}
		}
		if m.forwarderHook != nil {
			m.forwarderHook(ctx, report)
		}
	}
}

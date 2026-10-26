package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestForwarderDetectorFlagsUntrustedCDN(t *testing.T) {
	d := newForwarderDetector()
	edge := netip.MustParseAddr("185.93.1.17")
	other := netip.MustParseAddr("203.0.113.9")
	for range 30 {
		d.observe("www.example.com", edge, false, "X-Forwarded-For")
	}
	for range 70 {
		d.observe("www.example.com", other, false, "")
	}

	report := d.rotate()
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", report.Findings)
	}
	finding := report.Findings[0]
	if finding.Prefix != "185.93.1.0/24" || finding.Requests != 30 || finding.Total != 100 || finding.Percent != 30 {
		t.Fatalf("unexpected finding %+v", finding)
	}
	if !strings.Contains(finding.Message(), "30% of requests to www.example.com come from 185.93.1.0/24") {
		t.Fatalf("unexpected message %q", finding.Message())
	}

	if report := d.rotate(); len(report.Findings) != 0 {
		t.Fatalf("expected findings to clear in an empty window, got %+v", report.Findings)
	}
}

func TestForwarderDetectorIgnoresTrustedAndRareForwarders(t *testing.T) {
	d := newForwarderDetector()
	cdn := netip.MustParseAddr("2a02:6ea0:c000::5")
	spoofer := netip.MustParseAddr("198.51.100.4")
	for range 50 {
		d.observe("www.example.com", cdn, true, "X-Forwarded-For")
	}
	for range 5 {
		d.observe("www.example.com", spoofer, false, "X-Forwarded-For")
	}
	if report := d.rotate(); len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", report.Findings)
	}
}

func TestForwarderDetectorUsesSlash48ForIPv6(t *testing.T) {
	d := newForwarderDetector()
	for i := range 25 {
		addr := netip.MustParseAddr("2a02:6ea0:c000:" + string(rune('1'+i%5)) + "::1")
		d.observe("cdn.example.com", addr, false, "X-Forwarded-For")
	}
	report := d.rotate()
	if len(report.Findings) != 1 || report.Findings[0].Prefix != "2a02:6ea0:c000::/48" {
		t.Fatalf("unexpected findings %+v", report.Findings)
	}
}

func TestForwardingHeaderDetection(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil)
	if forwardingHeader(r) != "" {
		t.Fatal("expected no forwarding header")
	}
	r.Header.Set("Cf-Connecting-Ip", "192.0.2.10")
	if got := forwardingHeader(r); got != "Cf-Connecting-Ip" {
		t.Fatalf("got %q", got)
	}
}

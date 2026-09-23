package observability

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestLabelValuesAreEscaped(t *testing.T) {
	m := NewMetrics()
	m.ObserveAPIRequest("/api/x,a\nb=c", 404, time.Millisecond)
	m.ObserveAPIRequest(`/api/x",status="500`, 404, time.Millisecond)
	m.ObserveAPIRequest(`/api/x\`, 404, time.Millisecond)
	body := scrape(t, m)

	for _, want := range []string{
		`portlyn_api_requests_total{route="/api/x,a\nb=c",status="404"} 1`,
		`portlyn_api_requests_total{route="/api/x\",status=\"500",status="404"} 1`,
		`portlyn_api_requests_total{route="/api/x\\",status="404"} 1`,
		`portlyn_api_latency_seconds_bucket{route="/api/x,a\nb=c",status="404",le="+Inf"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in\n%s", want, body)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if !strings.HasPrefix(line, "portlyn_") && !strings.HasPrefix(line, "# ") {
			t.Errorf("unexpected line %q", line)
		}
	}
}

func TestInvalidLabelNamesAreDropped(t *testing.T) {
	r := NewRegistry()
	r.IncCounter("portlyn_test_total", "Test.", map[string]string{"ok": "1", "bad\nname": "x", "a=b": "y", "__reserved": "z", "9lives": "w"}, 1)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `portlyn_test_total{ok="1"} 1`) {
		t.Fatalf("unexpected output:\n%s", rec.Body.String())
	}
}

func TestSeriesPerFamilyAreCapped(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < maxSeriesPerFamily+50; i++ {
		labels := map[string]string{"n": strconv.Itoa(i)}
		r.IncCounter("portlyn_test_total", "Test.", labels, 1)
		r.SetGauge("portlyn_test_gauge", "Test.", labels, 1)
		r.ObserveHistogram("portlyn_test_seconds", "Test.", labels, 0.1, defaultLatencyBuckets())
	}
	r.IncCounter("portlyn_test_total", "Test.", map[string]string{"n": "0"}, 1)
	if got := len(r.counters["portlyn_test_total"].values); got != maxSeriesPerFamily {
		t.Fatalf("counter series = %d, want %d", got, maxSeriesPerFamily)
	}
	if got := len(r.gauges["portlyn_test_gauge"].values); got != maxSeriesPerFamily {
		t.Fatalf("gauge series = %d, want %d", got, maxSeriesPerFamily)
	}
	if got := len(r.histograms["portlyn_test_seconds"].values); got != maxSeriesPerFamily {
		t.Fatalf("histogram series = %d, want %d", got, maxSeriesPerFamily)
	}
	if got := r.counters["portlyn_test_total"].values[labelKey(map[string]string{"n": "0"})]; got != 2 {
		t.Fatalf("existing series stopped counting: %v", got)
	}
}

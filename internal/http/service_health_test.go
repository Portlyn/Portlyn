package http

import (
	"strings"
	"testing"

	"portlyn/internal/acme"
	"portlyn/internal/domain"
)

func TestViewerServiceResponseHidesProbeError(t *testing.T) {
	item := domain.Service{Name: "internal", TargetURL: "http://10.0.0.5:8080"}
	health := serviceHealthInfo{
		Status: "unhealthy",
		Error:  `Get "http://10.0.0.5:8080/": dial tcp 10.0.0.5:8080: connect: connection refused`,
		Reason: "target_probe_failed",
	}
	resp := viewerServiceResponse(item, health, acme.CertInfo{})
	got, _ := resp["service_status_error"].(string)
	if strings.Contains(got, "10.0.0.5") {
		t.Fatalf("viewer response leaked the upstream target: %q", got)
	}
	if got != "target_probe_failed" {
		t.Fatalf("expected generic reason, got %q", got)
	}

	healthy := viewerServiceResponse(item, serviceHealthInfo{Status: "healthy", Reason: "target_reachable"}, acme.CertInfo{})
	if got, _ := healthy["service_status_error"].(string); got != "" {
		t.Fatalf("expected empty error for healthy service, got %q", got)
	}
}

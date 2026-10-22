package http

import (
	"strings"
	"testing"
)

func TestFormatValidationErrorUsesJSONNames(t *testing.T) {
	v := newRequestValidator()

	err := v.Struct(createDomainRequest{Name: "*.example.com", Type: "root"})
	if msg := formatValidationError(err); !strings.Contains(msg, "wildcard hostnames are not supported") {
		t.Fatalf("expected wildcard hint, got %q", msg)
	}

	err = v.Struct(createDomainRequest{Name: "example.com", Type: "other"})
	if msg := formatValidationError(err); msg != "invalid or missing fields: type" {
		t.Fatalf("expected json field name, got %q", msg)
	}
}

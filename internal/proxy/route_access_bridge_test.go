package proxy

import (
	"testing"
)

func TestSanitizeReturnPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		host     string
		scheme   string
		expected string
	}{
		{"relative path stays", "/issues", "gitea.example.com", "https", "/issues"},
		{"matching host gets scheme rewrite", "http://gitea.example.com/issues", "gitea.example.com", "https", "https://gitea.example.com/issues"},
		{"different host is rejected", "https://attacker.example.com/", "gitea.example.com", "https", ""},
		{"empty input returns empty", "", "gitea.example.com", "https", ""},
		{"host with port is normalized", "https://gitea.example.com:8443/path", "gitea.example.com", "https", "https://gitea.example.com:8443/path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeReturnPath(tt.input, tt.host, tt.scheme)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

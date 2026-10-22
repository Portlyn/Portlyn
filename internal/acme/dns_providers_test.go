package acme

import "testing"

func TestNormalizeAPIToken(t *testing.T) {
	cases := map[string]string{
		"abc123":          "abc123",
		"  abc123\n":      "abc123",
		`"abc123"`:        "abc123",
		"'abc123'":        "abc123",
		"Bearer abc123":   "abc123",
		`"bearer abc123"`: "abc123",
		"":                "",
		"Bearer":          "Bearer",
	}
	for raw, want := range cases {
		if got := normalizeAPIToken(raw); got != want {
			t.Errorf("normalizeAPIToken(%q) = %q, want %q", raw, got, want)
		}
	}
}

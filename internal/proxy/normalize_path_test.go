package proxy

import "testing"

func TestNormalizePath(t *testing.T) {
	backslash := string(rune(92))

	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"   ", "/"},
		{"/", "/"},
		{"app", "/app"},
		{"/app/", "/app"},
		{"/app///", "/app"},
		{"//evil.example", "/evil.example"},
		{"////evil.example", "/evil.example"},
		{"/" + backslash + "evil.example", "/evil.example"},
		{backslash + backslash + "evil.example", "/evil.example"},
		{"/app" + backslash + "sub", "/app/sub"},
	}

	for _, tc := range cases {
		if got := normalizePath(tc.in); got != tc.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A normalized path ends up in a Location header on the magic link route, so it
// must never come back as protocol-relative.
func TestNormalizePathIsNeverProtocolRelative(t *testing.T) {
	backslash := string(rune(92))
	inputs := []string{
		"//evil.example",
		"/" + backslash + "evil.example",
		backslash + "/evil.example",
		"///evil.example",
		"  //evil.example  ",
	}

	for _, in := range inputs {
		got := normalizePath(in)
		if len(got) > 1 && (got[1] == '/' || got[1] == '\\') {
			t.Errorf("normalizePath(%q) = %q, which a browser reads as another host", in, got)
		}
	}
}

func TestSafeRedirectPath(t *testing.T) {
	backslash := string(rune(92))

	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/app", "/app"},
		{"/app/sub", "/app/sub"},
		{"//evil.example", "/"},
		{"/" + backslash + "evil.example", "/"},
		{"https://evil.example", "/"},
		{"app", "/"},
		{"  /app  ", "/app"},
	}

	for _, tc := range cases {
		if got := safeRedirectPath(tc.in); got != tc.want {
			t.Errorf("safeRedirectPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

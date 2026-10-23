package domain

import "testing"

func TestNormalizeSubdomain(t *testing.T) {
	value, err := NormalizeSubdomain(" Pangolin.App ")
	if err != nil {
		t.Fatalf("normalize subdomain: %v", err)
	}
	if value != "pangolin.app" {
		t.Fatalf("unexpected normalized subdomain %q", value)
	}
}

func TestServiceHostname(t *testing.T) {
	if got := ServiceHostname("schnittert.cloud", "pangolin"); got != "pangolin.schnittert.cloud" {
		t.Fatalf("unexpected hostname %q", got)
	}
	if got := ServiceHostname("schnittert.cloud", ""); got != "schnittert.cloud" {
		t.Fatalf("unexpected root hostname %q", got)
	}
}

func TestNormalizeSubdomainWildcard(t *testing.T) {
	for _, value := range []string{"*", "*.lab"} {
		if got, err := NormalizeSubdomain(value); err != nil || got != value {
			t.Fatalf("expected %q to be accepted, got %q %v", value, got, err)
		}
	}
	for _, value := range []string{"a.*", "*a", "**", "a.*.b"} {
		if _, err := NormalizeSubdomain(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"app.example.com", "app.example.com", true},
		{"app.example.com", "APP.example.com", true},
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*.example.com", false},
		{"*.lab.example.com", "x.lab.example.com", true},
	}
	for _, tc := range cases {
		if got := HostMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("HostMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestLoginAllowedOnHost(t *testing.T) {
	wildcard := Service{Subdomain: "*", Domain: Domain{Name: "netinfo.ch"}, LoginHosts: JSONStringSlice{"allowed"}}
	if !LoginAllowedOnHost(wildcard, "allowed.netinfo.ch") {
		t.Fatal("expected a listed subdomain to allow login")
	}
	if LoginAllowedOnHost(wildcard, "blog.netinfo.ch") {
		t.Fatal("expected an unlisted subdomain to refuse login")
	}
	exact := Service{Subdomain: "app", Domain: Domain{Name: "netinfo.ch"}}
	if !LoginAllowedOnHost(exact, "app.netinfo.ch") {
		t.Fatal("exact services always allow login")
	}
}

func TestNormalizeLoginHosts(t *testing.T) {
	got, err := NormalizeLoginHosts([]string{" Allowed ", "", "allowed", "isolation"})
	if err != nil || len(got) != 2 || got[0] != "allowed" || got[1] != "isolation" {
		t.Fatalf("unexpected result %v %v", got, err)
	}
	for _, bad := range []string{"a.b", "*", "-x", "a b"} {
		if _, err := NormalizeLoginHosts([]string{bad}); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

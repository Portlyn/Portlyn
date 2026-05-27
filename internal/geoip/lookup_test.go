package geoip

import "testing"

func TestCountryAllowed(t *testing.T) {
	tests := []struct {
		name    string
		country string
		allowed []string
		blocked []string
		want    bool
	}{
		{"empty country always allowed", "", nil, []string{"RU"}, true},
		{"block matches", "RU", nil, []string{"RU"}, false},
		{"block case insensitive", "ru", nil, []string{"RU"}, false},
		{"allowed list pass", "DE", []string{"DE", "AT"}, nil, true},
		{"allowed list fail", "US", []string{"DE", "AT"}, nil, false},
		{"block beats allow", "RU", []string{"RU", "DE"}, []string{"RU"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := CountryAllowed(tt.country, tt.allowed, tt.blocked)
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNormalizeCountryList(t *testing.T) {
	got := NormalizeCountryList([]string{" de ", "DE", "fr", ""})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique, got %v", got)
	}
	if got[0] != "DE" || got[1] != "FR" {
		t.Fatalf("unexpected normalization: %v", got)
	}
}

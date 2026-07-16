package http

import "testing"

func TestValidateOutboundURLBlocksNumericEncodedMetadata(t *testing.T) {
	cases := []string{
		"http://0251.0376.0251.0376/",
		"http://2852039166/",
		"http://0xA9.0xFE.0xA9.0xFE/",
		"http://0x7f.0.0.1/",
	}
	for _, raw := range cases {
		if err := validateOutboundURL(raw, false); err == nil {
			t.Errorf("expected %s to be rejected as a blocked address", raw)
		}
		if err := validateOutboundURL(raw, true); err == nil {
			t.Errorf("expected %s to stay blocked even with allowPrivate (loopback/metadata)", raw)
		}
	}
}

func TestValidateOutboundURLAllowPrivate(t *testing.T) {
	if err := validateOutboundURL("http://10.0.1.160/", false); err == nil {
		t.Error("expected private issuer to be blocked by default")
	}
	if err := validateOutboundURL("http://10.0.1.160/", true); err != nil {
		t.Errorf("expected private issuer to be allowed with allowPrivate, got %v", err)
	}
	if err := validateOutboundURL("http://127.0.0.1/", true); err == nil {
		t.Error("expected loopback to stay blocked even with allowPrivate")
	}
}

func TestParseLegacyIPv4(t *testing.T) {
	cases := map[string]string{
		"2852039166":          "169.254.169.254",
		"0251.0376.0251.0376": "169.254.169.254",
		"0x7f.0.0.1":          "127.0.0.1",
		"0xA9FEA9FE":          "169.254.169.254",
	}
	for input, want := range cases {
		addr, ok := parseLegacyIPv4(input)
		if !ok {
			t.Errorf("expected %s to parse as a legacy IPv4", input)
			continue
		}
		if addr.String() != want {
			t.Errorf("parseLegacyIPv4(%s) = %s, want %s", input, addr.String(), want)
		}
	}
	for _, input := range []string{"example.com", "api.v2.service", "169.254.169.254.5"} {
		if _, ok := parseLegacyIPv4(input); ok {
			t.Errorf("expected %s to not parse as a legacy IPv4", input)
		}
	}
}

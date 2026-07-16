package netguard

import (
	"net/netip"
	"testing"
)

func TestBlockedAllowPrivate(t *testing.T) {
	cases := []struct {
		addr           string
		blockedStrict  bool
		blockedPrivate bool
	}{
		{"8.8.8.8", false, false},
		{"192.168.1.10", true, false},
		{"10.0.1.160", true, false},
		{"172.16.5.5", true, false},
		{"127.0.0.1", true, true},
		{"169.254.169.254", true, true},
		{"::1", true, true},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		if got := Blocked(addr, false); got != c.blockedStrict {
			t.Errorf("Blocked(%s, allowPrivate=false) = %v, want %v", c.addr, got, c.blockedStrict)
		}
		if got := Blocked(addr, true); got != c.blockedPrivate {
			t.Errorf("Blocked(%s, allowPrivate=true) = %v, want %v", c.addr, got, c.blockedPrivate)
		}
	}
}

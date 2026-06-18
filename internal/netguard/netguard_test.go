package netguard

import (
	"net/netip"
	"testing"
)

func TestIsBlockedAddrStrictBlocksPrivateAndLoopback(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.0.0.5", "172.16.3.4", "192.168.1.10", "169.254.169.254", "fc00::1"}
	for _, raw := range blocked {
		addr := netip.MustParseAddr(raw)
		if !IsBlockedAddrStrict(addr) {
			t.Errorf("expected %s to be blocked in strict mode", raw)
		}
	}
}

func TestIsBlockedAddrStrictAllowsPublic(t *testing.T) {
	allowed := []string{"1.1.1.1", "203.0.113.10", "2606:4700:4700::1111"}
	for _, raw := range allowed {
		addr := netip.MustParseAddr(raw)
		if IsBlockedAddrStrict(addr) {
			t.Errorf("expected %s to be allowed in strict mode", raw)
		}
	}
}

func TestIsBlockedAddrAllowsPrivateForProxyUpstreams(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.5")
	if IsBlockedAddr(addr) {
		t.Errorf("expected private address to be allowed for non-strict proxy upstreams")
	}
}

func TestIsBlockedAddrBlocksEmbeddedMetadata(t *testing.T) {
	blocked := []string{
		"64:ff9b::a9fe:a9fe",
		"2002:a9fe:a9fe::1",
		"100.64.0.1",
		"::ffff:169.254.169.254",
	}
	for _, raw := range blocked {
		addr := netip.MustParseAddr(raw)
		if !IsBlockedAddr(addr) {
			t.Errorf("expected %s to be blocked (embeds/maps to a blocked address)", raw)
		}
	}
}

func TestIsBlockedAddrAllowsNAT64ToPublic(t *testing.T) {
	addr := netip.MustParseAddr("64:ff9b::1010:1010")
	if IsBlockedAddr(addr) {
		t.Errorf("expected NAT64 mapping to a public IPv4 to be allowed in non-strict mode")
	}
}

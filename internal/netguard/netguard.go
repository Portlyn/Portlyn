package netguard

import (
	"net/netip"
	"strings"
)

var BlockedHostNames = map[string]struct{}{
	"metadata.google.internal":   {},
	"metadata":                   {},
	"metadata.goog":              {},
	"instance-data":              {},
	"instance-data.ec2.internal": {},
}

var blockedCIDRs = func() []netip.Prefix {
	raw := []string{
		"169.254.0.0/16",
		"fe80::/10",
		"fd00:ec2::/32",
		"224.0.0.0/4",
		"ff00::/8",
		"255.255.255.255/32",
		"0.0.0.0/8",
		"::/128",
		"100.64.0.0/10",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p)
		}
	}
	return out
}()

var (
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
)

func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFourPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	default:
		return netip.Addr{}, false
	}
}

func canonicalAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if embedded, ok := embeddedIPv4(addr); ok {
		return embedded
	}
	return addr
}

func IsBlockedHostName(host string) bool {
	_, blocked := BlockedHostNames[strings.ToLower(strings.TrimSpace(host))]
	return blocked
}

func IsBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = canonicalAddr(addr)
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range blockedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func IsBlockedAddrStrict(addr netip.Addr) bool {
	if IsBlockedAddr(addr) {
		return true
	}
	addr = canonicalAddr(addr)
	return addr.IsLoopback() || addr.IsPrivate()
}

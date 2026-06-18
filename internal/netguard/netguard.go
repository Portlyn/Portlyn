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
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p)
		}
	}
	return out
}()

func IsBlockedHostName(host string) bool {
	_, blocked := BlockedHostNames[strings.ToLower(strings.TrimSpace(host))]
	return blocked
}

func IsBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
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

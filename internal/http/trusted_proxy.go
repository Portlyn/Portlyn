package http

import (
	"net"
	stdhttp "net/http"
	"net/netip"
	"strings"
)

func (s *Server) requestSecure(r *stdhttp.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.requestFromTrustedProxy(r) {
		return false
	}
	return strings.EqualFold(firstForwardedValue(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (s *Server) requestFromTrustedProxy(r *stdhttp.Request) bool {
	if r == nil || len(s.cfg.TrustedProxyCIDRs) == 0 {
		return false
	}
	addr, ok := remoteAddrFromRequest(r)
	if !ok {
		return false
	}
	return addrInTrustedCIDRs(addr, s.cfg.TrustedProxyCIDRs)
}

func (s *Server) clientIPForRequest(r *stdhttp.Request) string {
	if s.requestFromTrustedProxy(r) {
		if addr, ok := clientIPFromForwardedChain(r.Header.Get("X-Forwarded-For"), s.cfg.TrustedProxyCIDRs); ok {
			return addr.String()
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" {
			if parsed, err := netip.ParseAddr(realIP); err == nil {
				return parsed.String()
			}
		}
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func remoteAddrFromRequest(r *stdhttp.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	return addr, err == nil
}

func firstForwardedValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}

func addrInTrustedCIDRs(addr netip.Addr, cidrs []string) bool {
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func clientIPFromForwardedChain(header string, trustedCIDRs []string) (netip.Addr, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if !addrInTrustedCIDRs(addr, trustedCIDRs) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

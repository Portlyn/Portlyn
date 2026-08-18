package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"portlyn/internal/domain"
	"portlyn/internal/netguard"
	"strconv"
	"strings"
)

func validateUpstreamCAPEM(pemData string) error {
	if strings.TrimSpace(pemData) == "" {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return fmt.Errorf("upstream_ca_pem must contain at least one valid PEM certificate")
	}
	return nil
}

func upstreamTLSClientConfig(item domain.Service) *tls.Config {
	serverName := upstreamServerName(item)
	if ca := strings.TrimSpace(item.UpstreamCAPEM); ca != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(ca)) {
			return &tls.Config{RootCAs: pool, ServerName: serverName}
		}
	}
	if item.UpstreamSkipVerify {
		return &tls.Config{InsecureSkipVerify: true}
	}
	if serverName != "" {
		return &tls.Config{ServerName: serverName}
	}
	return nil
}

func upstreamServerName(item domain.Service) string {
	if override := strings.TrimSpace(item.UpstreamServerName); override != "" {
		return override
	}
	if u, err := url.Parse(strings.TrimSpace(item.TargetURL)); err == nil {
		return u.Hostname()
	}
	return ""
}

func resolveTargetHost(host string) ([]netip.Addr, error) {
	if targetHostResolver != nil {
		return targetHostResolver(host)
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, a.Unmap())
		}
	}
	return addrs, nil
}

func parseLegacyIPv4(host string) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return netip.Addr{}, false
		}
		base := 10
		switch {
		case len(part) > 2 && (part[0:2] == "0x" || part[0:2] == "0X"):
			base = 16
			part = part[2:]
		case len(part) > 1 && part[0] == '0':
			base = 8
			part = part[1:]
		}
		if part == "" {
			part = "0"
		}
		v, err := strconv.ParseUint(part, base, 64)
		if err != nil {
			return netip.Addr{}, false
		}
		values[i] = v
	}
	var n uint64
	switch len(values) {
	case 1:
		n = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return netip.Addr{}, false
		}
		n = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return netip.Addr{}, false
		}
		n = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, v := range values {
			if v > 0xff {
				return netip.Addr{}, false
			}
		}
		n = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	if n > 0xffffffff {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

func validateServiceTargetURL(raw string) error {
	return validateTargetURL(raw, netguard.IsBlockedAddr, false)
}

func validateOutboundURL(raw string, allowPrivate bool) error {
	return validateTargetURL(raw, func(addr netip.Addr) bool { return netguard.Blocked(addr, allowPrivate) }, true)
}

func validateTargetURL(raw string, blocked func(netip.Addr) bool, strictResolve bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("target_url must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("target_url scheme must be http or https")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return fmt.Errorf("target_url host must not be empty")
	}
	if netguard.IsBlockedHostName(host) {
		return fmt.Errorf("target_url host is blocked for security reasons")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if blocked(addr) {
			return fmt.Errorf("target_url host is blocked for security reasons")
		}
		return nil
	}

	if addr, ok := parseLegacyIPv4(host); ok {
		if blocked(addr) {
			return fmt.Errorf("target_url host is blocked for security reasons")
		}
		return nil
	}

	addrs, err := resolveTargetHost(host)
	if err != nil {
		if strictResolve {
			return fmt.Errorf("target_url host could not be resolved")
		}
		return nil
	}
	for _, addr := range addrs {
		if blocked(addr) {
			return fmt.Errorf("target_url host resolves to a blocked address")
		}
	}
	return nil
}

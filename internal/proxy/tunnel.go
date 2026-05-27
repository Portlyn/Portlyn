package proxy

import (
	"net/url"
	"strings"

	"portlyn/internal/domain"
)

func rewriteTargetForTunnel(rawTarget string, service domain.Service) (string, bool) {
	if service.NodeID == nil || service.Node == nil {
		return rawTarget, false
	}
	tunnelIP := strings.TrimSpace(service.Node.WGTunnelIP)
	if tunnelIP == "" {
		return rawTarget, false
	}
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil {
		return rawTarget, false
	}
	if parsed.Host == "" {
		return rawTarget, false
	}
	port := parsed.Port()
	if port != "" {
		parsed.Host = tunnelIP + ":" + port
	} else {
		parsed.Host = tunnelIP
	}
	return parsed.String(), true
}

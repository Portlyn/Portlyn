package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"portlyn/internal/domain"
	"portlyn/internal/netguard"
	"strings"
	"syscall"
	"time"
)

func makeDialControl(blockPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("unresolved dial address %q", host)
		}
		blocked := netguard.IsBlockedAddr(addr)
		if blockPrivate {
			blocked = netguard.IsBlockedAddrStrict(addr)
		}
		if blocked {
			return fmt.Errorf("connection to blocked address %s denied", host)
		}
		return nil
	}
}

func insecureUpstreamTransport(base *http.Transport) *http.Transport {
	transport := base.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	return transport
}

func pinnedUpstreamTransport(base *http.Transport, caPEM, serverName string) *http.Transport {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil
	}
	transport := cloneTransportTLS(base)
	transport.TLSClientConfig.RootCAs = pool
	transport.TLSClientConfig.InsecureSkipVerify = false
	if serverName != "" {
		transport.TLSClientConfig.ServerName = serverName
	}
	return transport
}

func serverNameUpstreamTransport(base *http.Transport, serverName string) *http.Transport {
	transport := cloneTransportTLS(base)
	transport.TLSClientConfig.ServerName = serverName
	return transport
}

func cloneTransportTLS(base *http.Transport) *http.Transport {
	transport := base.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	return transport
}

func upstreamTLSServerName(svc domain.Service, originalTargetURL string) string {
	if override := strings.TrimSpace(svc.UpstreamServerName); override != "" {
		return override
	}
	if u, err := url.Parse(strings.TrimSpace(originalTargetURL)); err == nil {
		return u.Hostname()
	}
	return ""
}

func reverseProxyForTarget(target *url.URL, transport *http.Transport, routePath string, protoForRequest func(*http.Request) string, clientIPForRequest func(*http.Request) string, passHostHeader bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &retryTransport{base: transport, retries: 1, backoff: 100 * time.Millisecond}
	originalDirector := proxy.Director
	normalizedRoutePath := normalizePath(routePath)

	proxy.Director = func(req *http.Request) {
		incomingHost := req.Host
		incomingProto := directProto(req)
		if protoForRequest != nil {
			incomingProto = protoForRequest(req)
		}
		var authoritativeClientIP string
		if clientIPForRequest != nil {
			authoritativeClientIP = clientIPForRequest(req)
		}
		originalURI := req.URL.RequestURI()
		req.URL.Path = stripRoutePrefix(normalizedRoutePath, req.URL.Path)
		if req.URL.RawPath != "" {
			req.URL.RawPath = stripRoutePrefix(normalizedRoutePath, req.URL.RawPath)
		}
		if authoritativeClientIP != "" {
			req.Header.Set("X-Forwarded-For", authoritativeClientIP)
		} else {
			req.Header.Del("X-Forwarded-For")
		}
		originalDirector(req)
		if passHostHeader {
			req.Host = incomingHost
		} else {
			req.Host = target.Host
		}
		if authoritativeClientIP != "" {
			req.Header.Set("X-Real-Ip", authoritativeClientIP)
		} else {
			req.Header.Del("X-Real-Ip")
		}
		req.Header.Set("X-Forwarded-Host", normalizeHost(incomingHost))
		req.Header.Set("X-Forwarded-Proto", incomingProto)
		req.Header.Set("X-Forwarded-Uri", originalURI)
		if normalizedRoutePath != "/" {
			req.Header.Set("X-Forwarded-Prefix", normalizedRoutePath)
		} else {
			req.Header.Del("X-Forwarded-Prefix")
		}
	}

	return proxy
}

func (m *Manager) isTargetDegraded(target string) (bool, string) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	state := m.breakers[target]
	if state == nil {
		return false, ""
	}
	if time.Now().UTC().Before(state.degradedUntil) {
		return true, firstNonEmpty(state.lastError, "circuit_open")
	}
	return false, ""
}

func (m *Manager) recordTargetFailure(target string, err error) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	state := m.breakers[target]
	if state == nil {
		state = &targetCircuitState{}
		m.breakers[target] = state
	}
	state.consecutiveFailures++
	if err != nil {
		state.lastError = err.Error()
	}
	if state.consecutiveFailures >= 3 {
		state.degradedUntil = time.Now().UTC().Add(30 * time.Second)
	}
}

func (m *Manager) recordTargetSuccess(target string) {
	m.breakersMu.Lock()
	defer m.breakersMu.Unlock()
	delete(m.breakers, target)
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	attempts := 1 + t.retries
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		resp, err := base.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isIdempotentMethod(req.Method) || attempt+1 >= attempts {
			break
		}
		time.Sleep(t.backoff)
	}
	return nil, lastErr
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

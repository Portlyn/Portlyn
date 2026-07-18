package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

const (
	CertSourceManaged   = "managed"
	CertSourceStatic    = "static"
	CertSourceBootstrap = "bootstrap"
	CertSourceNone      = "none"
)

type CertInfo struct {
	Source        string     `json:"source"`
	Issuer        string     `json:"issuer"`
	ExpiresAt     *time.Time `json:"expires_at"`
	IsBootstrap   bool       `json:"is_bootstrap"`
	DaysRemaining int        `json:"days_remaining"`
}

func (m *Manager) ActiveCertInfo(ctx context.Context, host string) CertInfo {
	serverName := normalizeDomain(host)
	if serverName != "" {
		if cert, err := m.tlsStore.GetCertificate(ctx, serverName); err == nil && cert != nil {
			return certInfoFromTLS(cert, CertSourceManaged)
		}
		if wildcardName := wildcardDomainForHost(serverName); wildcardName != "" {
			if cert, err := m.tlsStore.GetCertificate(ctx, wildcardName); err == nil && cert != nil {
				return certInfoFromTLS(cert, CertSourceManaged)
			}
		}
	}

	m.mu.RLock()
	staticLeaf := m.staticLeaf
	m.mu.RUnlock()
	if staticLeaf != nil {
		expires := staticLeaf.NotAfter.UTC()
		return CertInfo{
			Source:        CertSourceStatic,
			Issuer:        issuerCommonName(staticLeaf),
			ExpiresAt:     &expires,
			IsBootstrap:   isSelfSigned(staticLeaf),
			DaysRemaining: daysUntil(expires),
		}
	}

	if m.httpMagic == nil && m.staticCert == nil {
		return CertInfo{Source: CertSourceNone, Issuer: "none"}
	}
	return CertInfo{
		Source:      CertSourceBootstrap,
		Issuer:      "Portlyn bootstrap (self-signed)",
		IsBootstrap: true,
	}
}

func certInfoFromTLS(cert *tls.Certificate, source string) CertInfo {
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf == nil {
		return CertInfo{Source: source, Issuer: "unknown"}
	}
	expires := leaf.NotAfter.UTC()
	return CertInfo{
		Source:        source,
		Issuer:        issuerCommonName(leaf),
		ExpiresAt:     &expires,
		IsBootstrap:   isSelfSigned(leaf),
		DaysRemaining: daysUntil(expires),
	}
}

func issuerCommonName(leaf *x509.Certificate) string {
	if cn := strings.TrimSpace(leaf.Issuer.CommonName); cn != "" {
		return cn
	}
	if len(leaf.Issuer.Organization) > 0 {
		if org := strings.TrimSpace(leaf.Issuer.Organization[0]); org != "" {
			return org
		}
	}
	return "unknown"
}

func isSelfSigned(leaf *x509.Certificate) bool {
	if leaf.Issuer.String() == leaf.Subject.String() {
		return true
	}
	for _, org := range leaf.Subject.Organization {
		if strings.EqualFold(strings.TrimSpace(org), "Portlyn bootstrap") {
			return true
		}
	}
	return false
}

func daysUntil(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func (m *Manager) ACMEReady() bool {
	return m.httpMagic != nil
}

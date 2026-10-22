package domain

import "strings"

func WildcardForHost(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return ""
	}
	return "*." + strings.Join(labels[1:], ".")
}

func HostCoveredByCertificates(host string, certs []Certificate) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	wildcard := WildcardForHost(host)
	covers := func(name string) bool {
		name = strings.ToLower(strings.TrimSpace(name))
		return name == host || (wildcard != "" && name == wildcard)
	}
	for i := range certs {
		if covers(certs[i].PrimaryDomain) {
			return true
		}
		for _, san := range certs[i].SANs {
			if covers(san.DomainName) {
				return true
			}
		}
	}
	return false
}

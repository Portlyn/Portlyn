package domain

import (
	"fmt"
	"strings"
)

func NormalizeSubdomain(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", nil
	}
	labels := strings.Split(normalized, ".")
	for i, label := range labels {
		if label == "*" && i == 0 {
			continue
		}
		if len(label) == 0 {
			return "", fmt.Errorf("subdomain must not contain empty labels")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("subdomain labels must be 63 characters or fewer")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("subdomain labels must not start or end with a hyphen")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("subdomain may only contain letters, digits, hyphens, and dots, plus * as the first label")
			}
		}
	}
	return normalized, nil
}

func ServiceHostname(rootDomain, subdomain string) string {
	root := strings.ToLower(strings.TrimSpace(rootDomain))
	if root == "" {
		return ""
	}
	prefix, err := NormalizeSubdomain(subdomain)
	if err != nil || prefix == "" {
		return root
	}
	return prefix + "." + root
}

func ServiceHost(service Service) string {
	return ServiceHostname(service.Domain.Name, service.Subdomain)
}

func IsWildcardHost(host string) bool {
	return strings.HasPrefix(host, "*.")
}

func HostMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if !IsWildcardHost(pattern) {
		return pattern == host
	}
	label, parent, ok := strings.Cut(host, ".")
	return ok && label != "" && label != "*" && "*."+parent == pattern
}

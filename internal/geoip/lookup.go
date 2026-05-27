package geoip

import (
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

type Lookup struct {
	mu     sync.RWMutex
	reader *geoip2.Reader
	path   string
}

func NewLookup() *Lookup {
	return &Lookup{}
}

func (l *Lookup) Load(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		if l.reader != nil {
			_ = l.reader.Close()
			l.reader = nil
			l.path = ""
		}
		return nil
	}
	if l.reader != nil && l.path == trimmed {
		return nil
	}
	reader, err := geoip2.Open(trimmed)
	if err != nil {
		return err
	}
	if l.reader != nil {
		_ = l.reader.Close()
	}
	l.reader = reader
	l.path = trimmed
	return nil
}

func (l *Lookup) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reader != nil {
		_ = l.reader.Close()
		l.reader = nil
	}
}

func (l *Lookup) Available() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.reader != nil
}

func (l *Lookup) CountryISO(ip net.IP) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.reader == nil || ip == nil {
		return ""
	}
	record, err := l.reader.Country(ip)
	if err != nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(record.Country.IsoCode))
}

func NormalizeCountryList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.ToUpper(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func CountryAllowed(country string, allowed, blocked []string) (bool, string) {
	if country == "" {
		return true, ""
	}
	for _, c := range blocked {
		if strings.EqualFold(c, country) {
			return false, "blocked_country"
		}
	}
	if len(allowed) == 0 {
		return true, ""
	}
	for _, c := range allowed {
		if strings.EqualFold(c, country) {
			return true, ""
		}
	}
	return false, "country_not_allowed"
}

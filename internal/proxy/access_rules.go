package proxy

import (
	"fmt"
	"net/netip"
	"strings"

	"portlyn/internal/domain"
)

type compiledAccessRule struct {
	Index    int
	Name     string
	Action   string
	Include  []netip.Prefix
	Exclude  []netip.Prefix
	Patterns [][]string
	AnyPath  bool
}

func compileAccessRules(rules []domain.AccessRule) ([]compiledAccessRule, error) {
	out := make([]compiledAccessRule, 0, len(rules))
	for i, rule := range rules {
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		switch action {
		case domain.AccessRuleAllow, domain.AccessRuleAuthenticate, domain.AccessRuleDeny:
		default:
			return nil, fmt.Errorf("access rule %d: unknown action %q", i+1, rule.Action)
		}
		include, exclude, err := ParseAccessRuleSources(rule.Sources)
		if err != nil {
			return nil, fmt.Errorf("access rule %d: %w", i+1, err)
		}
		compiled := compiledAccessRule{
			Index:   i + 1,
			Name:    strings.TrimSpace(rule.Name),
			Action:  action,
			Include: include,
			Exclude: exclude,
		}
		for _, raw := range rule.Paths {
			pattern, ok := compileAccessRulePath(raw)
			if !ok {
				continue
			}
			compiled.Patterns = append(compiled.Patterns, pattern)
		}
		compiled.AnyPath = len(compiled.Patterns) == 0
		out = append(out, compiled)
	}
	return out, nil
}

func ParseAccessRuleSources(values []string) ([]netip.Prefix, []netip.Prefix, error) {
	var include, exclude []netip.Prefix
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		negate := strings.HasPrefix(value, "!")
		value = strings.TrimSpace(strings.TrimPrefix(value, "!"))
		prefixes, err := compileCIDRs([]string{value})
		if err != nil || len(prefixes) == 0 {
			return nil, nil, fmt.Errorf("invalid source %q", raw)
		}
		if negate {
			exclude = append(exclude, prefixes...)
		} else {
			include = append(include, prefixes...)
		}
	}
	return include, exclude, nil
}

func compileAccessRulePath(raw string) ([]string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, false
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = strings.TrimRight(value, "/")
	if value == "" {
		return []string{}, true
	}
	return strings.Split(strings.TrimPrefix(value, "/"), "/"), true
}

func (r compiledAccessRule) matches(ip netip.Addr, path string) bool {
	if len(r.Include) > 0 && !matchesAnyPrefix(ip, r.Include) {
		return false
	}
	if matchesAnyPrefix(ip, r.Exclude) {
		return false
	}
	if r.AnyPath {
		return true
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		segments = nil
	}
	for _, pattern := range r.Patterns {
		if accessRulePathMatches(pattern, segments, r.Action != domain.AccessRuleAllow) {
			return true
		}
	}
	return false
}

func accessRulePathMatches(pattern, segments []string, foldCase bool) bool {
	if len(segments) < len(pattern) {
		return false
	}
	for i, part := range pattern {
		switch {
		case part == "*":
		case foldCase && strings.EqualFold(part, segments[i]):
		case part == segments[i]:
		default:
			return false
		}
	}
	return true
}

func FirstMatchingAccessRule(rules []domain.AccessRule, ip netip.Addr, path string) (int, bool) {
	compiled, err := compileAccessRules(rules)
	if err != nil {
		return 0, false
	}
	if rule := matchAccessRule(compiled, ip, path); rule != nil {
		return rule.Index, true
	}
	return 0, false
}

func matchAccessRule(rules []compiledAccessRule, ip netip.Addr, path string) *compiledAccessRule {
	stripped := stripPathParams(path)
	for i := range rules {
		raw := rules[i].matches(ip, path)
		plain := raw
		if stripped != path {
			plain = rules[i].matches(ip, stripped)
		}
		hit := raw || plain
		if rules[i].Action == domain.AccessRuleAllow {
			hit = raw && plain
		}
		if hit {
			return &rules[i]
		}
	}
	return nil
}

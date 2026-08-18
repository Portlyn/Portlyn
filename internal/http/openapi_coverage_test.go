package http

import (
	"os"
	"sort"
	"strings"
	"testing"

	stdhttp "net/http"

	"github.com/go-chi/chi/v5"
	yaml "go.yaml.in/yaml/v3"
)

const (
	openAPIPath   = "../../openapi.yaml"
	openAPIPrefix = "/api/v1"
)

var httpMethodKeys = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

var openAPIExcluded = map[string]bool{
	"GET /healthz":    true,
	"GET /readyz":     true,
	"GET /livez":      true,
	"GET /metrics":    true,
	"GET /install.sh": true,
}

func TestOpenAPIMatchesRoutes(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()

	registered := registeredRoutes(t, server)
	documented := documentedOperations(t)

	var undocumented []string
	for route := range registered {
		if documented[route] {
			continue
		}
		undocumented = append(undocumented, route)
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Errorf("routes are missing from openapi.yaml:\n  %s", strings.Join(undocumented, "\n  "))
	}

	var stale []string
	for route := range documented {
		if !registered[route] {
			stale = append(stale, route)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("openapi.yaml documents operations that no longer exist:\n  %s", strings.Join(stale, "\n  "))
	}

}

func registeredRoutes(t *testing.T, server *Server) map[string]bool {
	t.Helper()
	routes, ok := server.Router().(chi.Routes)
	if !ok {
		t.Fatal("router does not expose chi.Routes")
	}

	found := make(map[string]bool)
	err := chi.Walk(routes, func(method string, route string, _ stdhttp.Handler, _ ...func(stdhttp.Handler) stdhttp.Handler) error {
		key := method + " " + normalizeRoute(route)
		if openAPIExcluded[key] {
			return nil
		}
		found[key] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no routes found")
	}
	return found
}

func documentedOperations(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read %s: %v", openAPIPath, err)
	}

	var spec struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", openAPIPath, err)
	}

	documented := make(map[string]bool)
	for path, operations := range spec.Paths {
		for method := range operations {
			if !httpMethodKeys[strings.ToLower(method)] {
				continue
			}
			full := path
			if !strings.HasPrefix(full, openAPIPrefix) {
				full = openAPIPrefix + full
			}
			documented[strings.ToUpper(method)+" "+normalizeRoute(full)] = true
		}
	}
	return documented
}

func normalizeRoute(route string) string {
	route = strings.ReplaceAll(route, "/*/", "/")
	route = strings.TrimSuffix(route, "/*")
	if len(route) > 1 {
		route = strings.TrimSuffix(route, "/")
	}
	if route == "" {
		return "/"
	}
	return route
}

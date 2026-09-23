package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRouteLabelUsesPattern(t *testing.T) {
	var got string
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			got = routeLabel(req)
		})
	})
	r.Get("/livez", func(http.ResponseWriter, *http.Request) {})
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/services/{id}", func(http.ResponseWriter, *http.Request) {})
	})

	cases := map[string]string{
		"/livez":                  "/livez",
		"/api/v1/services/42":     "/api/v1/services/{id}",
		"/api/v1/services/x%0Ay=": "/api/v1/services/{id}",
		"/nope/x,a%0Ab=c":         "unmatched",
	}
	for path, want := range cases {
		got = ""
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		if got != want {
			t.Errorf("%s: route label = %q, want %q", path, got, want)
		}
	}

	got = ""
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/unknown/thing", nil))
	if got == "/api/v1/unknown/thing" {
		t.Errorf("raw path leaked into the route label")
	}
}

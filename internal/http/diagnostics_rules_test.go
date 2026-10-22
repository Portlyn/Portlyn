package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"portlyn/internal/auth"
	"portlyn/internal/domain"
)

func TestExplainServiceAccessReportsAccessRule(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	ctx := context.Background()
	token := loginAsAdmin(t, server, "explain-admin@example.com", "StrongPass123!")

	dom := &domain.Domain{Name: "example.com", Type: "root"}
	if err := server.domains.Create(ctx, dom); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	now := time.Now().UTC()
	service := &domain.Service{
		Name:           "app",
		DomainID:       dom.ID,
		Path:           "/",
		TargetURL:      "http://10.0.0.5:8080",
		TLSMode:        "offload",
		AccessMode:     domain.AccessModeAuthenticated,
		Enabled:        true,
		LastDeployedAt: &now,
		AccessRules: domain.AccessRuleList{
			{Name: "public files", Action: domain.AccessRuleAllow, Paths: []string{"/pub"}},
			{Name: "block admin", Action: domain.AccessRuleDeny, Paths: []string{"/admin"}},
		},
	}
	if err := server.services.Create(ctx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}

	explain := func(path string) explainResponse {
		body := `{"client_ip":"203.0.113.5","path":"` + path + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/services/"+strconv.FormatUint(uint64(service.ID), 10)+"/explain", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		csrf := mustIssueCSRFToken(t, server)
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("explain failed: %d %s", rec.Code, rec.Body.String())
		}
		var out explainResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	if out := explain("/pub/a.txt"); !out.Allowed {
		t.Fatalf("expected allow rule to permit anonymous access, got %+v", out)
	}
	if out := explain("/admin"); out.Allowed || out.Decision != "deny_access_rule" {
		t.Fatalf("expected deny rule decision, got %+v", out)
	}
	if out := explain("/other"); out.Allowed || out.Decision != "deny_unauthenticated" {
		t.Fatalf("expected normal policy without a matching rule, got %+v", out)
	}
}

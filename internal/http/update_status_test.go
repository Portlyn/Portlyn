package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"portlyn/internal/auth"
	"portlyn/internal/updatecheck"
)

func TestUpdateCheckFollowsTheSetting(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	token := loginAsAdmin(t, server, "update-admin@example.com", "StrongPass123!")

	checker := updatecheck.New(updatecheck.Options{
		Repo:           "portlyn/Portlyn",
		CurrentVersion: "v1.5.1",
		Enabled: func(ctx context.Context) bool {
			settings, err := server.appSettings.Get(ctx)
			return err != nil || !settings.UpdateCheckDisabled
		},
		Resolve: func(context.Context, string) (string, error) { return "v1.6.0", nil },
	})
	server.SetUpdateChecker(checker)
	checker.CheckNow(context.Background())

	status := func() updatecheck.Status {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/update", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status failed: %d %s", rec.Code, rec.Body.String())
		}
		var out updatecheck.Status
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	if got := status(); !got.Enabled || !got.UpdateAvailable || got.LatestVersion != "v1.6.0" {
		t.Fatalf("expected an available update, got %+v", got)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/settings/auth", bytes.NewBufferString(`{"update_check_enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	csrf := mustIssueCSRFToken(t, server)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrf})
	rec := httptest.NewRecorder()
	server.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable failed: %d %s", rec.Code, rec.Body.String())
	}
	var settings map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &settings)
	if settings["update_check_enabled"] != false {
		t.Fatalf("expected the setting to be off, got %v", settings["update_check_enabled"])
	}

	if got := status(); got.Enabled || got.UpdateAvailable {
		t.Fatalf("expected no update info while the check is off, got %+v", got)
	}
}

package http

import "testing"

func TestLocalhostAdminCanLogIn(t *testing.T) {
	server, cleanup := newIntegrationServer(t)
	defer cleanup()
	if token := loginAsAdmin(t, server, "admin@localhost", "StrongPass123!"); token == "" {
		t.Fatal("expected a session token")
	}
}

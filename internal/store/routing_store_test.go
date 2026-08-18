package store

import (
	"context"
	"path/filepath"
	"testing"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func TestRoutingStoreResolvesServiceSubdomainHost(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
		JWTSecret:      "12345678901234567890123456789012",
	}
	db, err := NewDatabase(cfg)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	ctx := context.Background()
	domainStore := NewDomainStore(db)
	serviceStore := NewServiceStore(db)
	routingStore := NewRoutingStore(db)

	rootDomain := &domain.Domain{Name: "schnittert.cloud", Type: "root"}
	if err := domainStore.Create(ctx, rootDomain); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	service := &domain.Service{
		Name:      "Pangolin",
		DomainID:  rootDomain.ID,
		Subdomain: "pangolin",
		Path:      "/",
		TargetURL: "http://127.0.0.1:3000",
		TLSMode:   "offload",
	}
	if err := serviceStore.Create(ctx, service); err != nil {
		t.Fatalf("create service: %v", err)
	}

	routes, err := routingStore.GetRoutesForHost(ctx, "pangolin.schnittert.cloud")
	if err != nil {
		t.Fatalf("get routes for host: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Host != "pangolin.schnittert.cloud" {
		t.Fatalf("unexpected route host %q", routes[0].Host)
	}
}

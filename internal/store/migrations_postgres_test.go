package store

import (
	"context"
	"os"
	"sync"
	"testing"

	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func newPostgresTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("PORTLYN_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("set PORTLYN_TEST_POSTGRES_URL to run the postgres migration tests")
	}
	db, err := NewDatabase(config.Config{DatabaseDriver: "postgres", DatabaseURL: dsn})
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func dropEverything(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").Error; err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

func TestPostgresMigrateFromEmpty(t *testing.T) {
	db := newPostgresTestDB(t)
	dropEverything(t, db)
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, table := range []string{"users", "services", "domains", "nodes", "schema_migrations"} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("expected table %q after migrate", table)
		}
	}

	pending, err := Pending(ctx, db)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected nothing pending, got %v", pending)
	}
}

// Several hubs starting at once must not migrate over each other. The advisory
// lock only exists on the postgres path, so this is where it gets exercised.
func TestPostgresConcurrentMigrateIsSerialized(t *testing.T) {
	db := newPostgresTestDB(t)
	dropEverything(t, db)

	const runners = 5
	errs := make([]error, runners)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range runners {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = Migrate(context.Background(), db)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}

	var applied int64
	if err := db.Model(&SchemaMigration{}).Count(&applied).Error; err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if int(applied) != len(migrations) {
		t.Fatalf("expected %d rows in schema_migrations, got %d", len(migrations), applied)
	}
}

// Data written before an upgrade has to survive it.
func TestPostgresMigrateKeepsExistingRows(t *testing.T) {
	db := newPostgresTestDB(t)
	dropEverything(t, db)
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	users := NewUserStore(db)
	user := &domain.User{Email: "before-upgrade@example.test", PasswordHash: "hash", Role: domain.RoleAdmin, Active: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	domains := NewDomainStore(db)
	dom := &domain.Domain{Name: "before-upgrade.example.test", Type: "root"}
	if err := domains.Create(ctx, dom); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	found, err := users.GetByEmail(ctx, user.Email)
	if err != nil {
		t.Fatalf("user gone after migrate: %v", err)
	}
	if found.Role != domain.RoleAdmin || !found.Active {
		t.Fatalf("user changed across migrate: %+v", found)
	}

	storedDomain, err := domains.GetByID(ctx, dom.ID)
	if err != nil {
		t.Fatalf("domain gone after migrate: %v", err)
	}
	if storedDomain.Name != dom.Name {
		t.Fatalf("domain changed across migrate: %+v", storedDomain)
	}
}

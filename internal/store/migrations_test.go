package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"gorm.io/gorm"

	"portlyn/internal/config"
)

func newMigrationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(config.Config{
		DatabaseDriver: "sqlite",
		DatabasePath:   filepath.Join(dir, "portlyn.db"),
	})
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

type probeTable struct {
	ID   uint `gorm:"primaryKey"`
	Note string
}

func (probeTable) TableName() string { return "probe_table" }

func TestMigrateAppliesEveryMigrationOnce(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	var count int64
	if err := db.Model(&SchemaMigration{}).Count(&count).Error; err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if int(count) != len(migrations) {
		t.Fatalf("expected %d applied migrations, got %d", len(migrations), count)
	}

	pending, err := Pending(ctx, db)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending migrations, got %v", pending)
	}
}

func TestStatusReportsAppliedAndPending(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	list := []Migration{
		{ID: "9001_probe", Up: func(tx *gorm.DB) error { return tx.AutoMigrate(&probeTable{}) }},
		{ID: "9002_never_applied", Up: func(tx *gorm.DB) error { return nil }},
	}

	if err := migrateList(ctx, db, list[:1]); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	states, err := statusList(ctx, db, list)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("expected 2 states, got %d", len(states))
	}
	if !states[0].Applied || states[0].AppliedAt == nil {
		t.Fatal("expected the first migration to be reported as applied")
	}
	if states[1].Applied {
		t.Fatal("expected the second migration to be reported as pending")
	}
}

func TestMigrationRollsBackAndReapplies(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	list := []Migration{{
		ID:   "9001_probe",
		Up:   func(tx *gorm.DB) error { return tx.AutoMigrate(&probeTable{}) },
		Down: func(tx *gorm.DB) error { return tx.Migrator().DropTable(&probeTable{}) },
	}}

	if err := migrateList(ctx, db, list); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !db.Migrator().HasTable(&probeTable{}) {
		t.Fatal("expected probe_table after migrate")
	}

	if err := rollbackList(ctx, db, list, "9001_probe"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if db.Migrator().HasTable(&probeTable{}) {
		t.Fatal("expected probe_table to be gone after rollback")
	}

	states, err := statusList(ctx, db, list)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if states[0].Applied {
		t.Fatal("expected the migration to be pending again after rollback")
	}

	if err := migrateList(ctx, db, list); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	if !db.Migrator().HasTable(&probeTable{}) {
		t.Fatal("expected probe_table to come back")
	}
}

func TestRollbackRefusesWithoutDownStep(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	list := []Migration{{ID: "9001_probe", Up: func(tx *gorm.DB) error { return nil }}}
	if err := migrateList(ctx, db, list); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	err := rollbackList(ctx, db, list, "9001_probe")
	if !errors.Is(err, ErrNoRollback) {
		t.Fatalf("expected ErrNoRollback, got %v", err)
	}
}

func TestRollbackRefusesUnappliedMigration(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	list := []Migration{{
		ID:   "9001_probe",
		Up:   func(tx *gorm.DB) error { return nil },
		Down: func(tx *gorm.DB) error { return nil },
	}}

	err := rollbackList(ctx, db, list, "9001_probe")
	if !errors.Is(err, ErrMigrationNotApplied) {
		t.Fatalf("expected ErrMigrationNotApplied, got %v", err)
	}
}

func TestFailedMigrationIsNotRecorded(t *testing.T) {
	db := newMigrationTestDB(t)
	ctx := context.Background()

	boom := errors.New("boom")
	list := []Migration{
		{ID: "9001_probe", Up: func(tx *gorm.DB) error { return tx.AutoMigrate(&probeTable{}) }},
		{ID: "9002_fails", Up: func(tx *gorm.DB) error { return boom }},
	}

	err := migrateList(ctx, db, list)
	if !errors.Is(err, boom) {
		t.Fatalf("expected the migration error to surface, got %v", err)
	}

	states, err := statusList(ctx, db, list)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !states[0].Applied {
		t.Fatal("expected the first migration to stay applied")
	}
	if states[1].Applied {
		t.Fatal("expected the failed migration not to be recorded")
	}
}

func TestMigrationIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool, len(migrations))
	for _, m := range migrations {
		if m.ID == "" {
			t.Fatal("migration with empty ID")
		}
		if seen[m.ID] {
			t.Fatalf("duplicate migration ID %q", m.ID)
		}
		if m.Up == nil {
			t.Fatalf("migration %q has no Up step", m.ID)
		}
		seen[m.ID] = true
	}
}

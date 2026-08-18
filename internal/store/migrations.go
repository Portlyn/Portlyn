package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type SchemaMigration struct {
	ID        string    `gorm:"primaryKey;size:128" json:"id"`
	AppliedAt time.Time `gorm:"not null" json:"applied_at"`
}

func (SchemaMigration) TableName() string { return "schema_migrations" }

type Migration struct {
	ID   string
	Up   func(*gorm.DB) error
	Down func(*gorm.DB) error
}

type MigrationState struct {
	ID        string     `json:"id"`
	Applied   bool       `json:"applied"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}

var ErrNoRollback = errors.New("migration cannot be rolled back")

var ErrMigrationNotApplied = errors.New("migration was not applied")

// Arbitrary but fixed, so every instance competes for the same lock.
const migrationLockKey int64 = 6013274119057

// Append-only and ordered. Never edit an ID or the body of a shipped migration.
var migrations = []Migration{
	{
		ID: "0001_baseline_schema",
		Up: func(db *gorm.DB) error {
			return db.AutoMigrate(
				&domain.User{},
				&domain.APIToken{},
				&domain.Group{},
				&domain.GroupMembership{},
				&domain.Node{},
				&domain.NodeEnrollmentToken{},
				&domain.Client{},
				&domain.Domain{},
				&domain.Certificate{},
				&domain.CertificateSAN{},
				&domain.DNSProvider{},
				&domain.ServiceGroup{},
				&domain.ServiceGroupMembership{},
				&domain.Service{},
				&domain.LoginToken{},
				&domain.Session{},
				&domain.AuditLog{},
				&domain.AppSettings{},
				&domain.StoredTLSCertificate{},
				&domain.DistributedKV{},
				&domain.DistributedLock{},
				&domain.AuditWebhook{},
				&domain.UserCredential{},
				&domain.ServiceExposureReport{},
			)
		},
	},
}

// Each migration commits together with its bookkeeping row, so a crash
// mid-upgrade never leaves one half recorded.
func Migrate(ctx context.Context, db *gorm.DB) error {
	return migrateList(ctx, db, migrations)
}

func migrateList(ctx context.Context, db *gorm.DB, list []Migration) error {
	return withMigrationLock(ctx, db, func() error {
		if err := db.WithContext(ctx).AutoMigrate(&SchemaMigration{}); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
		applied, err := appliedMigrations(ctx, db)
		if err != nil {
			return err
		}
		for _, m := range list {
			if _, done := applied[m.ID]; done {
				continue
			}
			if err := runMigration(ctx, db, m); err != nil {
				return fmt.Errorf("migration %s: %w", m.ID, err)
			}
		}
		return nil
	})
}

func Rollback(ctx context.Context, db *gorm.DB, id string) error {
	return rollbackList(ctx, db, migrations, id)
}

func rollbackList(ctx context.Context, db *gorm.DB, list []Migration, id string) error {
	return withMigrationLock(ctx, db, func() error {
		if err := db.WithContext(ctx).AutoMigrate(&SchemaMigration{}); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
		var target *Migration
		for i := range list {
			if list[i].ID == id {
				target = &list[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("unknown migration %q", id)
		}
		applied, err := appliedMigrations(ctx, db)
		if err != nil {
			return err
		}
		if _, done := applied[id]; !done {
			return fmt.Errorf("%s: %w", id, ErrMigrationNotApplied)
		}
		if target.Down == nil {
			return fmt.Errorf("%s: %w", id, ErrNoRollback)
		}
		return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := target.Down(tx); err != nil {
				return err
			}
			return tx.Where("id = ?", id).Delete(&SchemaMigration{}).Error
		})
	})
}

func Status(ctx context.Context, db *gorm.DB) ([]MigrationState, error) {
	return statusList(ctx, db, migrations)
}

func statusList(ctx context.Context, db *gorm.DB, list []Migration) ([]MigrationState, error) {
	if err := db.WithContext(ctx).AutoMigrate(&SchemaMigration{}); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return nil, err
	}
	states := make([]MigrationState, 0, len(list))
	for _, m := range list {
		state := MigrationState{ID: m.ID}
		if at, done := applied[m.ID]; done {
			state.Applied = true
			appliedAt := at
			state.AppliedAt = &appliedAt
		}
		states = append(states, state)
	}
	return states, nil
}

func Pending(ctx context.Context, db *gorm.DB) ([]string, error) {
	states, err := Status(ctx, db)
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, state := range states {
		if !state.Applied {
			pending = append(pending, state.ID)
		}
	}
	return pending, nil
}

func runMigration(ctx context.Context, db *gorm.DB, m Migration) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := m.Up(tx); err != nil {
			return err
		}
		return tx.Create(&SchemaMigration{ID: m.ID, AppliedAt: time.Now().UTC()}).Error
	})
}

func appliedMigrations(ctx context.Context, db *gorm.DB) (map[string]time.Time, error) {
	var rows []SchemaMigration
	if err := db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	applied := make(map[string]time.Time, len(rows))
	for _, row := range rows {
		applied[row.ID] = row.AppliedAt
	}
	return applied, nil
}

// SQLite has a single writer, so only Postgres needs the lock.
func withMigrationLock(ctx context.Context, db *gorm.DB, fn func() error) error {
	if db.Dialector == nil || db.Dialector.Name() != "postgres" {
		return fn()
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	return fn()
}

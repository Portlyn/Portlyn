package store

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"portlyn/internal/config"
	"portlyn/internal/domain"
)

func gormLogLevel(value string) gormlogger.LogLevel {
	switch value {
	case "silent", "off", "none":
		return gormlogger.Silent
	case "error":
		return gormlogger.Error
	case "info", "debug":
		return gormlogger.Info
	default:
		return gormlogger.Warn
	}
}

func NewDatabase(cfg config.Config) (*gorm.DB, error) {
	dbLogger := gormlogger.New(log.New(os.Stderr, "", log.LstdFlags), gormlogger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  gormLogLevel(cfg.DatabaseLogLevel),
		IgnoreRecordNotFoundError: true,
	})
	gormConfig := &gorm.Config{
		PrepareStmt: true,
		Logger:      dbLogger,
	}

	var (
		db  *gorm.DB
		err error
	)

	switch cfg.DatabaseDriver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DatabaseURL), gormConfig)
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.DatabasePath), gormConfig)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.DatabaseDriver)
	}
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	maxOpenConns := runtime.NumCPU() * 2
	if maxOpenConns < 4 {
		maxOpenConns = 4
	}
	if maxOpenConns > 16 {
		maxOpenConns = 16
	}
	maxIdleConns := maxOpenConns / 2
	if maxIdleConns < 2 {
		maxIdleConns = 2
	}

	if cfg.DatabaseDriver == "sqlite" {
		maxOpenConns = 1
		maxIdleConns = 1
	}

	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	if cfg.DatabaseDriver == "sqlite" {
		pragmas := []string{
			"PRAGMA journal_mode = WAL",
			"PRAGMA synchronous = NORMAL",
			"PRAGMA foreign_keys = ON",
			"PRAGMA busy_timeout = 5000",
			"PRAGMA temp_store = MEMORY",
		}
		for _, pragma := range pragmas {
			if execErr := db.Exec(pragma).Error; execErr != nil {
				return nil, fmt.Errorf("apply sqlite pragma %q: %w", pragma, execErr)
			}
		}
	}

	return db, nil
}

func AutoMigrate(db *gorm.DB) error {
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
}

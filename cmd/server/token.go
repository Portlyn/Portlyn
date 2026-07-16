package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"portlyn/internal/auth"
	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/store"
)

func runTokenSubcommand(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("usage: portlyn token create --name NAME [--role admin|viewer] [--expires-days N]")
	}
	flags := flag.NewFlagSet("token create", flag.ContinueOnError)
	name := flags.String("name", "", "token name")
	role := flags.String("role", "viewer", "admin or viewer")
	expiresDays := flags.Int("expires-days", 0, "optional expiry in days")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("--name is required")
	}
	if *role != domain.RoleAdmin && *role != domain.RoleViewer {
		return fmt.Errorf("--role must be admin or viewer")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	prefix, token, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return err
	}
	item := &domain.APIToken{
		Name:      strings.TrimSpace(*name),
		Prefix:    prefix,
		TokenHash: hash,
		Role:      *role,
	}
	if *expiresDays > 0 {
		expiresAt := time.Now().UTC().Add(time.Duration(*expiresDays) * 24 * time.Hour)
		item.ExpiresAt = &expiresAt
	}
	if err := store.NewAPITokenStore(db).Create(context.Background(), item); err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	fmt.Println(token)
	return nil
}

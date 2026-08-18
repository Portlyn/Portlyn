package main

import (
	"context"
	"fmt"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func runMigrateSubcommand(args []string) error {
	action := "up"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()

	ctx := context.Background()

	switch action {
	case "up":
		pending, err := store.Pending(ctx, db)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			fmt.Println("schema is up to date")
			return nil
		}
		for _, id := range pending {
			fmt.Println("applying", id)
		}
		if err := store.Migrate(ctx, db); err != nil {
			return err
		}
		fmt.Printf("applied %d migration(s)\n", len(pending))
		return nil

	case "status":
		states, err := store.Status(ctx, db)
		if err != nil {
			return err
		}
		for _, state := range states {
			if state.Applied {
				fmt.Printf("applied  %s  %s\n", state.ID, state.AppliedAt.Format("2006-01-02 15:04:05"))
				continue
			}
			fmt.Printf("pending  %s\n", state.ID)
		}
		return nil

	case "down":
		if len(args) == 0 {
			return fmt.Errorf("usage: portlyn migrate down <migration-id>")
		}
		if err := store.Rollback(ctx, db, args[0]); err != nil {
			return err
		}
		fmt.Println("rolled back", args[0])
		return nil

	default:
		return fmt.Errorf("unknown action %q (use up, status or down)", action)
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func runAuditSubcommand(args []string) error {
	if len(args) == 0 || args[0] != "compact" {
		return fmt.Errorf("usage: portlyn audit compact [--yes] [--no-vacuum]")
	}
	flags := flag.NewFlagSet("audit compact", flag.ContinueOnError)
	assumeYes := flags.Bool("yes", false, "skip the confirmation prompt")
	noVacuum := flags.Bool("no-vacuum", false, "skip VACUUM (disk space is not reclaimed)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	auditStore := store.NewAuditStore(db, []byte(cfg.AuditHMACSecret))

	if !*assumeYes {
		fmt.Println("Audit compaction removes high-volume access rows (API access, and proxy access")
		fmt.Println("that is not a denial) and re-chains the surviving security events from genesis.")
		fmt.Println("Historical hashes are rewritten. Stop the server and back up the database first.")
		fmt.Print("Proceed? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return fmt.Errorf("aborted")
		}
	}

	fmt.Println("compacting audit log...")
	result, err := auditStore.Compact(context.Background())
	if err != nil {
		return fmt.Errorf("compact: %w", err)
	}
	fmt.Printf("scanned=%d removed=%d kept=%d\n", result.Scanned, result.Removed, result.Kept)

	if *noVacuum {
		fmt.Println("skipped VACUUM (--no-vacuum); disk space not reclaimed")
	} else {
		fmt.Println("reclaiming disk space (VACUUM)...")
		if err := auditStore.Vacuum(context.Background()); err != nil {
			return fmt.Errorf("vacuum: %w", err)
		}
	}

	verify, err := auditStore.VerifyChain(context.Background())
	if err != nil {
		return fmt.Errorf("post-compaction verification failed: %w", err)
	}
	fmt.Printf("verified=%d latest_id=%d\n", verify.Verified, verify.LatestID)
	fmt.Println("done")
	return nil
}

const (
	auditRetentionFirstRun = time.Minute
	auditRetentionInterval = time.Hour
)

func runAuditRetention(ctx context.Context, auditStore *store.AuditStore, days int, logger *slog.Logger) {
	timer := time.NewTimer(auditRetentionFirstRun)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		before := time.Now().UTC().AddDate(0, 0, -days)
		result, err := auditStore.PruneBefore(ctx, before)
		switch {
		case err != nil && ctx.Err() == nil:
			logger.Error("audit retention failed", "error", err)
		case result.Removed > 0:
			logger.Info("audit retention pruned entries", "removed", result.Removed, "anchor_id", result.LastID, "older_than", before)
		}
		timer.Reset(auditRetentionInterval)
	}
}

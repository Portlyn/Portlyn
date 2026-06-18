package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"portlyn/internal/selfupdate"
)

const (
	updateRepo        = "portlyn/Portlyn"
	updateAssetPrefix = "portlyn"
	updateDefaultUnit = "portlyn.service"
	updateSANRegex    = `^https://github\.com/portlyn/Portlyn/`
	updateOIDCIssuer  = "https://token.actions.githubusercontent.com"
)

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	checkOnly := fs.Bool("check", false, "only check whether an update is available")
	targetVersion := fs.String("version", "", "specific release tag to install (default: latest)")
	noRestart := fs.Bool("no-restart", false, "skip systemctl restart after the swap")
	unit := fs.String("unit", updateDefaultUnit, "systemd unit name to restart")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runSelfUpdate(updateConfig{
		assetPrefix:   updateAssetPrefix,
		repo:          updateRepo,
		unit:          *unit,
		identity:      selfupdate.CosignIdentity{SANRegex: updateSANRegex, OIDCIssuer: updateOIDCIssuer},
		currentVer:    version,
		checkOnly:     *checkOnly,
		targetVersion: strings.TrimSpace(*targetVersion),
		noRestart:     *noRestart,
	})
}

type updateConfig struct {
	assetPrefix   string
	repo          string
	unit          string
	identity      selfupdate.CosignIdentity
	currentVer    string
	checkOnly     bool
	targetVersion string
	noRestart     bool
}

func runSelfUpdate(cfg updateConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		rel selfupdate.Release
		err error
	)
	if cfg.targetVersion != "" {
		rel, err = selfupdate.ResolveByTag(ctx, cfg.repo, cfg.targetVersion)
	} else {
		rel, err = selfupdate.ResolveLatest(ctx, cfg.repo)
	}
	if err != nil {
		return err
	}

	if cfg.checkOnly {
		if rel.Tag == cfg.currentVer {
			fmt.Printf("Already up to date (current: %s).\n", cfg.currentVer)
			return nil
		}
		fmt.Printf("Update available: %s (current: %s)\n", rel.Tag, cfg.currentVer)
		return nil
	}

	if rel.Tag == cfg.currentVer && cfg.targetVersion == "" {
		fmt.Printf("Already up to date (current: %s).\n", cfg.currentVer)
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if err := selfupdate.RequireWritable(exe); err != nil {
		return err
	}

	asset := selfupdate.AssetName(cfg.assetPrefix)
	fmt.Printf("Downloading %s ...\n", asset)
	var binary bytes.Buffer
	if _, err := selfupdate.DownloadAsset(ctx, rel.AssetBaseURL, asset, &binary); err != nil {
		return err
	}

	fmt.Println("Downloading checksums.txt ...")
	checksums, err := selfupdate.DownloadString(ctx, rel.AssetBaseURL, "checksums.txt")
	if err != nil {
		return err
	}
	if err := selfupdate.VerifySHA256(binary.Bytes(), checksums, asset); err != nil {
		return err
	}
	fmt.Println("SHA-256 OK.")

	bundleJSON, err := selfupdate.DownloadString(ctx, rel.AssetBaseURL, "checksums.txt.bundle.json")
	if err != nil {
		return fmt.Errorf("fetch sigstore bundle: %w", err)
	}
	if err := selfupdate.VerifyCosignBundle([]byte(checksums), bundleJSON, cfg.identity); err != nil {
		return fmt.Errorf("sigstore verification failed: %w", err)
	}
	fmt.Println("Sigstore signature OK.")

	info, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat executable: %w", err)
	}
	backup, err := selfupdate.AtomicSwap(exe, &binary, info.Mode())
	if err != nil {
		return err
	}
	fmt.Printf("Installed %s. Previous binary backed up at %s.\n", rel.Tag, backup)

	if cfg.noRestart {
		fmt.Println("Restart skipped (--no-restart). Restart manually with: sudo systemctl restart " + cfg.unit)
		return nil
	}
	fmt.Printf("Restarting %s ...\n", cfg.unit)
	if err := selfupdate.RestartSystemd(ctx, cfg.unit); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
		fmt.Println("Restart it manually with: sudo systemctl restart " + cfg.unit)
		return nil
	}
	fmt.Println("Updated successfully.")
	return nil
}

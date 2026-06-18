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
	updateAssetPrefix = "portlyn-nodeagent"
	updateDefaultUnit = "portlyn-nodeagent.service"
	updateSANRegex    = `^https://github\.com/portlyn/Portlyn/`
	updateOIDCIssuer  = "https://token.actions.githubusercontent.com"
)

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	checkOnly := fs.Bool("check", false, "only check whether an update is available")
	targetVersion := fs.String("version", "", "specific release tag to install (default: latest)")
	noRestart := fs.Bool("no-restart", false, "skip systemctl restart after the swap")
	unit := fs.String("unit", updateDefaultUnit, "systemd unit name to restart")
	allowDowngrade := fs.Bool("allow-downgrade", false, "permit installing an older release than the current one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		rel selfupdate.Release
		err error
	)
	target := strings.TrimSpace(*targetVersion)
	if target != "" {
		rel, err = selfupdate.ResolveByTag(ctx, updateRepo, target)
	} else {
		rel, err = selfupdate.ResolveLatest(ctx, updateRepo)
	}
	if err != nil {
		return err
	}

	if *checkOnly {
		if rel.Tag == version {
			fmt.Printf("Already up to date (current: %s).\n", version)
			return nil
		}
		fmt.Printf("Update available: %s (current: %s)\n", rel.Tag, version)
		return nil
	}

	if rel.Tag == version && target == "" {
		fmt.Printf("Already up to date (current: %s).\n", version)
		return nil
	}

	if !*allowDowngrade {
		if cmp, ok := selfupdate.CompareVersions(rel.Tag, version); ok && cmp < 0 {
			return fmt.Errorf("refusing to install %s which is older than current %s; pass --allow-downgrade to override", rel.Tag, version)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if err := selfupdate.RequireWritable(exe); err != nil {
		return err
	}

	asset := selfupdate.AssetName(updateAssetPrefix)
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
	identity := selfupdate.CosignIdentity{SANRegex: updateSANRegex, OIDCIssuer: updateOIDCIssuer}
	if err := selfupdate.VerifyCosignBundle([]byte(checksums), bundleJSON, identity); err != nil {
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

	if *noRestart {
		fmt.Println("Restart skipped (--no-restart). Restart manually with: sudo systemctl restart " + *unit)
		return nil
	}
	fmt.Printf("Restarting %s ...\n", *unit)
	if err := selfupdate.RestartSystemd(ctx, *unit); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
		fmt.Println("Restart it manually with: sudo systemctl restart " + *unit)
		return nil
	}
	fmt.Println("Updated successfully.")
	return nil
}

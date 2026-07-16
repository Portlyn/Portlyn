package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"portlyn/internal/selfupdate"
)

func runVerifyRelease(args []string) error {
	flags := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	checksums := flags.String("checksums", "", "path to checksums.txt")
	bundlePath := flags.String("bundle", "", "path to checksums.txt.bundle.json")
	asset := flags.String("asset", "", "optional path to a downloaded asset to check against checksums.txt")
	assetName := flags.String("asset-name", "", "name of the asset as listed in checksums.txt (defaults to basename of --asset)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *checksums == "" || *bundlePath == "" {
		return fmt.Errorf("--checksums and --bundle are required")
	}

	checksumsData, err := os.ReadFile(*checksums)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}
	bundleData, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	identity := selfupdate.CosignIdentity{SANRegex: updateSANRegex, OIDCIssuer: updateOIDCIssuer}
	if err := selfupdate.VerifyCosignBundle(checksumsData, string(bundleData), identity); err != nil {
		return err
	}
	fmt.Println("signature OK: checksums.txt is authentically signed by the Portlyn release workflow")

	if *asset != "" {
		name := *assetName
		if name == "" {
			name = filepath.Base(*asset)
		}
		assetData, err := os.ReadFile(*asset)
		if err != nil {
			return fmt.Errorf("read asset: %w", err)
		}
		if err := selfupdate.VerifySHA256(assetData, string(checksumsData), name); err != nil {
			return err
		}
		fmt.Printf("checksum OK: %s matches checksums.txt\n", name)
	}
	return nil
}

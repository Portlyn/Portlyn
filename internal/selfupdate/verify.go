package selfupdate

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

//go:embed sigstore_trusted_root.json
var sigstoreTrustedRootJSON []byte

func VerifySHA256(payload []byte, checksumsTxt, assetName string) error {
	expected, err := lookupChecksum(checksumsTxt, assetName)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	actual := fmt.Sprintf("%x", sum[:])
	if expected != actual {
		return fmt.Errorf("sha256 mismatch for %s: expected %s, got %s", assetName, expected, actual)
	}
	return nil
}

func lookupChecksum(checksumsTxt, assetName string) (string, error) {
	for _, line := range strings.Split(checksumsTxt, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == assetName || strings.TrimPrefix(fields[1], "*") == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", assetName)
}

type CosignIdentity struct {
	SANRegex   string
	OIDCIssuer string
}

func VerifyCosignBundle(payload []byte, bundleJSON string, identity CosignIdentity) error {
	if strings.TrimSpace(bundleJSON) == "" {
		return fmt.Errorf("empty sigstore bundle")
	}
	if !json.Valid([]byte(bundleJSON)) {
		return fmt.Errorf("bundle is not valid JSON")
	}
	if strings.Contains(bundleJSON, `"base64Signature"`) {
		return fmt.Errorf("release is signed with the legacy Cosign bundle format (base64Signature); update the release workflow to use cosign sign-blob --new-bundle-format")
	}
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON([]byte(bundleJSON)); err != nil {
		return fmt.Errorf("parse sigstore bundle: %w", err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(sigstoreTrustedRootJSON)
	if err != nil {
		return fmt.Errorf("load trusted root: %w", err)
	}
	trustedMaterial := root.TrustedMaterialCollection{trustedRoot}

	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	certID, err := verify.NewShortCertificateIdentity(identity.OIDCIssuer, "", "", identity.SANRegex)
	if err != nil {
		return fmt.Errorf("certificate identity: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithCertificateIdentity(certID))

	verifier, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}
	if _, err := verifier.Verify(b, policy); err != nil {
		return fmt.Errorf("sigstore verification failed: %w", err)
	}
	return nil
}

func ChecksumHex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

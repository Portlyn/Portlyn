package selfupdate

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVerifySHA256Success(t *testing.T) {
	payload := []byte("hello world\n")
	checksums := "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  hello.txt\n"
	if err := VerifySHA256(payload, checksums, "hello.txt"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerifySHA256MissingEntry(t *testing.T) {
	err := VerifySHA256([]byte("x"), "deadbeef  other.txt\n", "missing.txt")
	if err == nil || !strings.Contains(err.Error(), "no checksum entry") {
		t.Fatalf("expected no-entry error, got %v", err)
	}
}

func TestVerifySHA256Mismatch(t *testing.T) {
	checksums := "0000000000000000000000000000000000000000000000000000000000000000  hello.txt\n"
	err := VerifySHA256([]byte("hello world\n"), checksums, "hello.txt")
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected mismatch, got %v", err)
	}
}

func TestVerifySHA256IgnoresAsteriskPrefix(t *testing.T) {
	payload := []byte("hello world\n")
	checksums := "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  *hello.txt\n"
	if err := VerifySHA256(payload, checksums, "hello.txt"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerifyCosignBundleRejectsEmpty(t *testing.T) {
	err := VerifyCosignBundle([]byte("data"), "", CosignIdentity{})
	if err == nil {
		t.Fatal("expected error on empty bundle")
	}
}

func TestVerifyCosignBundleRejectsInvalidJSON(t *testing.T) {
	err := VerifyCosignBundle([]byte("data"), "{not json", CosignIdentity{})
	if err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("expected JSON error, got %v", err)
	}
}

func loadReleaseFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	checksums, err := os.ReadFile("testdata/v1.4.0-checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := os.ReadFile("testdata/v1.4.0-checksums.txt.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	return checksums, string(bundleJSON)
}

func TestVerifyCosignBundleAcceptsReleaseWorkflow(t *testing.T) {
	checksums, bundleJSON := loadReleaseFixture(t)
	for _, tag := range []string{"v1.4.0", ""} {
		if err := VerifyCosignBundle(checksums, bundleJSON, ReleaseIdentity(tag)); err != nil {
			t.Fatalf("tag %q: expected ok, got %v", tag, err)
		}
	}
}

func TestVerifyCosignBundleRejectsOtherTag(t *testing.T) {
	checksums, bundleJSON := loadReleaseFixture(t)
	if err := VerifyCosignBundle(checksums, bundleJSON, ReleaseIdentity("v1.5.0")); err == nil {
		t.Fatal("expected a v1.4.0 signature to be rejected for v1.5.0")
	}
}

func TestVerifyCosignBundleRejectsOtherRepository(t *testing.T) {
	checksums, bundleJSON := loadReleaseFixture(t)
	id := ReleaseIdentity("v1.4.0")
	id.SourceRepositoryURI = "https://github.com/attacker/Portlyn"
	if err := VerifyCosignBundle(checksums, bundleJSON, id); err == nil {
		t.Fatal("expected a foreign source repository to be rejected")
	}
}

func TestVerifyCosignBundleRejectsIncompleteIdentity(t *testing.T) {
	checksums, bundleJSON := loadReleaseFixture(t)
	id := ReleaseIdentity("v1.4.0")
	id.SourceRepositoryURI = ""
	if err := VerifyCosignBundle(checksums, bundleJSON, id); err == nil {
		t.Fatal("expected an identity without a source repository to be rejected")
	}
}

func TestReleaseSANRegex(t *testing.T) {
	re := regexp.MustCompile(ReleaseSANRegex)
	good := []string{
		"https://github.com/Portlyn/Portlyn/.github/workflows/release.yml@refs/tags/v1.4.0",
		"https://github.com/Portlyn/Portlyn/.github/workflows/release.yml@refs/tags/v2.0.0-rc.1",
	}
	bad := []string{
		"https://github.com/Portlyn/Portlyn/.github/workflows/ci.yml@refs/tags/v1.4.0",
		"https://github.com/Portlyn/Portlyn/.github/workflows/security.yml@refs/heads/main",
		"https://github.com/Portlyn/Portlyn/.github/workflows/release.yml@refs/heads/main",
		"https://github.com/Portlyn/Portlyn/.github/workflows/release.yml@refs/tags/v1.4.0/x",
		"https://github.com/Portlyn/PortlynEvil/.github/workflows/release.yml@refs/tags/v1.4.0",
		"https://github.com/evil/x/.github/workflows/y.yml@https://github.com/Portlyn/Portlyn/.github/workflows/release.yml@refs/tags/v1.4.0",
	}
	for _, s := range good {
		if !re.MatchString(s) {
			t.Errorf("expected match: %s", s)
		}
	}
	for _, s := range bad {
		if re.MatchString(s) {
			t.Errorf("unexpected match: %s", s)
		}
	}
}

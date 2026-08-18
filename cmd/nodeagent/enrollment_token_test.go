package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEnrollmentTokenPrefersFlag(t *testing.T) {
	t.Setenv("PORTLYN_ENROLLMENT_TOKEN", "from-env")

	got, err := resolveEnrollmentToken("  from-flag  ", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-flag" {
		t.Fatalf("got %q, want from-flag", got)
	}
}

func TestResolveEnrollmentTokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	got, err := resolveEnrollmentToken("", path)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-file" {
		t.Fatalf("got %q, want from-file", got)
	}
}

func TestResolveEnrollmentTokenFromSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, systemdCredentialName), []byte("from-credential"), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	got, err := resolveEnrollmentToken("", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-credential" {
		t.Fatalf("got %q, want from-credential", got)
	}
}

func TestResolveEnrollmentTokenFallsBackToEnv(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	t.Setenv("PORTLYN_ENROLLMENT_TOKEN", "from-env")

	got, err := resolveEnrollmentToken("", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("got %q, want from-env", got)
	}
}

func TestResolveEnrollmentTokenReportsMissingFile(t *testing.T) {
	if _, err := resolveEnrollmentToken("", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a missing token file")
	}
}

func TestResolveEnrollmentTokenRejectsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	if _, err := resolveEnrollmentToken("", path); err == nil {
		t.Fatal("expected an error for an empty token file")
	}
}

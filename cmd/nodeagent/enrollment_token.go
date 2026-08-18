package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const systemdCredentialName = "enrollment-token"

// Order: explicit flag, explicit file, systemd credential, environment. A token
// on the command line ends up in the process list and in the unit file, so the
// installer uses the credential path instead.
func resolveEnrollmentToken(flagValue, filePath string) (string, error) {
	if value := strings.TrimSpace(flagValue); value != "" {
		return value, nil
	}

	if path := strings.TrimSpace(filePath); path != "" {
		return readTokenFile(path)
	}

	if dir := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY")); dir != "" {
		path := filepath.Join(dir, systemdCredentialName)
		if _, err := os.Stat(path); err == nil {
			return readTokenFile(path)
		}
	}

	return strings.TrimSpace(os.Getenv("PORTLYN_ENROLLMENT_TOKEN")), nil
}

func readTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s: empty", path)
	}
	return token, nil
}

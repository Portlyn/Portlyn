package main

import (
	"strings"
	"testing"
)

func activeEnvLines(t *testing.T, text string) map[string]string {
	t.Helper()
	active := map[string]string{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("line is neither a comment nor an assignment: %q", line)
		}
		key = strings.TrimSpace(key)
		if _, dup := active[key]; dup {
			t.Fatalf("%s is assigned twice, the later one silently wins", key)
		}
		active[key] = value
	}
	return active
}

func testAnswers() initAnswers {
	return initAnswers{
		Domain:        "example.com",
		AdminEmail:    "admin@example.com",
		AdminPassword: "a-password",
		ACMEEmail:     "acme@example.com",
		DataDir:       "/var/lib/portlyn",
		HTTPSEnabled:  true,
	}
}

func TestBuildEnvFileAssignsEveryKeyOnce(t *testing.T) {
	text, err := buildEnvFile(testAnswers())
	if err != nil {
		t.Fatalf("build env: %v", err)
	}

	active := activeEnvLines(t, text)

	for _, key := range generatedSecretKeys {
		if strings.TrimSpace(active[key]) == "" {
			t.Fatalf("%s is missing or empty", key)
		}
	}
	if active["FRONTEND_BASE_URL"] != "https://example.com" {
		t.Fatalf("unexpected FRONTEND_BASE_URL %q", active["FRONTEND_BASE_URL"])
	}
}

// A dropped '#' would turn documentation into a setting that overrides the
// built-in default for everyone who runs init.
func TestOptionalEnvReferenceIsFullyCommented(t *testing.T) {
	for _, raw := range strings.Split(optionalEnvReference, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t.Fatalf("reference block contains an active assignment: %q", line)
	}
}

func TestStartHintMatchesHowTheServerIsRun(t *testing.T) {
	withUnit := startHint(true)
	if !strings.Contains(withUnit, "systemctl start portlyn") {
		t.Fatalf("a systemd install should be told to use systemctl, got %q", withUnit)
	}
	if strings.Contains(withUnit, "\n  portlyn\n") {
		t.Fatalf("a systemd install must not be told to run the binary directly, got %q", withUnit)
	}

	withoutUnit := startHint(false)
	if !strings.Contains(withoutUnit, "\n  portlyn\n") {
		t.Fatalf("without systemd the binary is the way to start, got %q", withoutUnit)
	}
	if strings.Contains(withoutUnit, "systemctl") {
		t.Fatalf("without systemd there is nothing to systemctl, got %q", withoutUnit)
	}
}

func TestBuildEnvFileIsDeterministic(t *testing.T) {
	first, err := buildEnvFile(testAnswers())
	if err != nil {
		t.Fatalf("build env: %v", err)
	}
	second, err := buildEnvFile(testAnswers())
	if err != nil {
		t.Fatalf("build env: %v", err)
	}

	keyOrder := func(text string) []string {
		var keys []string
		for _, raw := range strings.Split(text, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, _ := strings.Cut(line, "=")
			keys = append(keys, key)
		}
		return keys
	}

	firstKeys := strings.Join(keyOrder(first), ",")
	secondKeys := strings.Join(keyOrder(second), ",")
	if firstKeys != secondKeys {
		t.Fatalf("key order differs between runs:\n%s\n%s", firstKeys, secondKeys)
	}
}

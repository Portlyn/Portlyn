package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"portlyn/internal/config"
	"portlyn/internal/store"
)

func runDoctor(args []string) error {
	quiet := false
	for _, a := range args {
		switch a {
		case "--quiet", "-q":
			quiet = true
		case "check":
		default:
			return fmt.Errorf("unknown argument %q (usage: portlyn doctor [--quiet])", a)
		}
	}

	cfg, _ := config.Load()
	if noEnvContext() {
		fmt.Println("No .env found here and the secret variables are empty, so everything below will look broken.")
		fmt.Println("If Portlyn runs as a service, load its environment first, for example:")
		fmt.Println("  set -a; . /var/lib/portlyn/.env; set +a; portlyn doctor")
		fmt.Println()
	}
	issues := cfg.ValidationIssues()
	if !hasValidationErrors(issues) {
		issues = append(issues, forwarderIssues(cfg)...)
	}
	errCount := printValidationIssues(os.Stdout, issues, quiet)
	if errCount > 0 {
		return fmt.Errorf("%d configuration error(s) must be fixed before Portlyn can start", errCount)
	}
	return nil
}

func hasValidationErrors(issues []config.ValidationIssue) bool {
	for _, issue := range issues {
		if issue.Level == "error" {
			return true
		}
	}
	return false
}

const forwarderReportMaxAge = time.Hour

func forwarderIssues(cfg config.Config) []config.ValidationIssue {
	if cfg.DatabaseDriver == "sqlite" {
		if _, err := os.Stat(cfg.DatabasePath); err != nil {
			return nil
		}
	}
	db, err := store.NewDatabase(cfg)
	if err != nil {
		return nil
	}
	if sqlDB, err := db.DB(); err == nil {
		defer sqlDB.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := store.NewForwarderReportStore(db).Load(ctx)
	if err != nil || report == nil || time.Since(report.CheckedAt) > forwarderReportMaxAge {
		return nil
	}
	issues := make([]config.ValidationIssue, 0, len(report.Findings))
	for _, finding := range report.Findings {
		issues = append(issues, config.ValidationIssue{
			Level:   "warn",
			Field:   "TRUSTED_PROXY_CIDRS",
			Code:    "untrusted_forwarder",
			Message: finding.Message(),
			Hint:    "add the CDN's published ranges (or " + finding.Prefix + " if it is your own proxy) to TRUSTED_PROXY_CIDRS",
		})
	}
	return issues
}

func noEnvContext() bool {
	if _, err := os.Stat(".env"); err == nil {
		return false
	}
	for _, key := range []string{
		"JWT_SECRET", "JWT_SIGNING_SECRET", "SESSION_BRIDGE_SECRET", "OIDC_STATE_SECRET",
		"MFA_ENCRYPTION_SECRET", "CSRF_SECRET", "DATA_ENCRYPTION_SECRET", "AUDIT_HMAC_SECRET",
	} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return false
		}
	}
	return true
}

func printValidationIssues(w io.Writer, issues []config.ValidationIssue, quiet bool) int {
	errors := make([]config.ValidationIssue, 0)
	warnings := make([]config.ValidationIssue, 0)
	for _, issue := range issues {
		if issue.Level == "error" {
			errors = append(errors, issue)
		} else {
			warnings = append(warnings, issue)
		}
	}
	sort.SliceStable(errors, func(i, j int) bool { return errors[i].Field < errors[j].Field })
	sort.SliceStable(warnings, func(i, j int) bool { return warnings[i].Field < warnings[j].Field })

	if len(errors) == 0 && (quiet || len(warnings) == 0) {
		fmt.Fprintln(w, "config OK: no problems detected")
		return 0
	}

	if len(errors) > 0 {
		fmt.Fprintf(w, "Found %d configuration error(s):\n\n", len(errors))
		for _, issue := range errors {
			printIssue(w, "ERROR", issue)
		}
	}
	if !quiet && len(warnings) > 0 {
		fmt.Fprintf(w, "Found %d warning(s):\n\n", len(warnings))
		for _, issue := range warnings {
			printIssue(w, "warn", issue)
		}
	}
	if len(errors) == 0 {
		fmt.Fprintln(w, "No blocking errors. Portlyn can start.")
	}
	return len(errors)
}

func printIssue(w io.Writer, label string, issue config.ValidationIssue) {
	fmt.Fprintf(w, "  [%s] %s: %s\n", label, issue.Field, issue.Message)
	if hint := strings.TrimSpace(issue.Hint); hint != "" {
		fmt.Fprintf(w, "         fix: %s\n", hint)
	}
	fmt.Fprintln(w)
}

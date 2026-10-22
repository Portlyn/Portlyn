package updatecheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStatusReportsNewerRelease(t *testing.T) {
	calls := 0
	checker := New(Options{
		Repo:           "portlyn/Portlyn",
		CurrentVersion: "v1.5.1",
		Resolve: func(context.Context, string) (string, error) {
			calls++
			return "v1.6.0", nil
		},
	})

	if status := checker.Status(context.Background()); status.UpdateAvailable || status.LatestVersion != "" {
		t.Fatalf("expected no result before the first check, got %+v", status)
	}
	checker.CheckNow(context.Background())
	status := checker.Status(context.Background())
	if !status.UpdateAvailable || status.LatestVersion != "v1.6.0" || status.ReleaseURL != "https://github.com/portlyn/Portlyn/releases/tag/v1.6.0" {
		t.Fatalf("unexpected status %+v", status)
	}
	if calls != 1 {
		t.Fatalf("expected one lookup, got %d", calls)
	}
}

func TestStatusIgnoresOlderOrSameRelease(t *testing.T) {
	for _, latest := range []string{"v1.5.1", "v1.4.0"} {
		checker := New(Options{
			CurrentVersion: "v1.5.1",
			Resolve:        func(context.Context, string) (string, error) { return latest, nil },
		})
		checker.CheckNow(context.Background())
		if checker.Status(context.Background()).UpdateAvailable {
			t.Fatalf("%s should not count as an update", latest)
		}
	}
}

func TestDisabledCheckerNeverCallsOut(t *testing.T) {
	checker := New(Options{
		CurrentVersion: "v1.5.1",
		Enabled:        func(context.Context) bool { return false },
		Resolve: func(context.Context, string) (string, error) {
			t.Fatal("disabled checker must not contact GitHub")
			return "", nil
		},
	})
	checker.CheckNow(context.Background())
	if status := checker.Status(context.Background()); status.Enabled || status.UpdateAvailable {
		t.Fatalf("unexpected status %+v", status)
	}
}

func TestFailedCheckKeepsLastResult(t *testing.T) {
	fail := false
	checker := New(Options{
		CurrentVersion: "v1.5.1",
		Resolve: func(context.Context, string) (string, error) {
			if fail {
				return "", errors.New("offline")
			}
			return "v1.6.0", nil
		},
	})
	checker.CheckNow(context.Background())
	fail = true
	checker.CheckNow(context.Background())
	if !checker.Status(context.Background()).UpdateAvailable {
		t.Fatal("expected the last successful result to stay")
	}
}

func TestStartSkipsDevBuilds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker := New(Options{
		CurrentVersion: "dev",
		Resolve: func(context.Context, string) (string, error) {
			t.Error("dev builds must not check for updates")
			return "", nil
		},
	})
	checker.Start(ctx)
	time.Sleep(20 * time.Millisecond)
}

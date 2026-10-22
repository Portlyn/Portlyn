package updatecheck

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"portlyn/internal/selfupdate"
)

const (
	InstallDocker = "docker"
	InstallBinary = "binary"
)

type Status struct {
	Enabled         bool       `json:"enabled"`
	CurrentVersion  string     `json:"current_version"`
	LatestVersion   string     `json:"latest_version,omitempty"`
	UpdateAvailable bool       `json:"update_available"`
	ReleaseURL      string     `json:"release_url,omitempty"`
	CheckedAt       *time.Time `json:"checked_at,omitempty"`
	InstallMethod   string     `json:"install_method"`
}

type Options struct {
	Repo           string
	CurrentVersion string
	Interval       time.Duration
	FirstDelay     time.Duration
	Enabled        func(ctx context.Context) bool
	Resolve        func(ctx context.Context, repo string) (string, error)
	Logger         *slog.Logger
}

type Checker struct {
	opts          Options
	installMethod string

	mu        sync.RWMutex
	latest    string
	checkedAt time.Time
}

func New(opts Options) *Checker {
	if opts.Interval <= 0 {
		opts.Interval = 12 * time.Hour
	}
	if opts.Resolve == nil {
		opts.Resolve = func(ctx context.Context, repo string) (string, error) {
			release, err := selfupdate.ResolveLatest(ctx, repo)
			return release.Tag, err
		}
	}
	if opts.Enabled == nil {
		opts.Enabled = func(context.Context) bool { return true }
	}
	return &Checker{opts: opts, installMethod: detectInstallMethod()}
}

func detectInstallMethod() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return InstallDocker
	}
	return InstallBinary
}

func (c *Checker) Start(ctx context.Context) {
	if _, ok := selfupdate.CompareVersions(c.opts.CurrentVersion, c.opts.CurrentVersion); !ok {
		return
	}
	go func() {
		timer := time.NewTimer(c.opts.FirstDelay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			c.CheckNow(ctx)
			timer.Reset(c.opts.Interval)
		}
	}()
}

func (c *Checker) CheckNow(ctx context.Context) {
	if !c.opts.Enabled(ctx) {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tag, err := c.opts.Resolve(checkCtx, c.opts.Repo)
	if err != nil {
		if c.opts.Logger != nil {
			c.opts.Logger.Debug("update check failed", "error", err)
		}
		return
	}
	c.mu.Lock()
	c.latest = tag
	c.checkedAt = time.Now().UTC()
	c.mu.Unlock()
}

func (c *Checker) Status(ctx context.Context) Status {
	status := Status{
		Enabled:        c.opts.Enabled(ctx),
		CurrentVersion: c.opts.CurrentVersion,
		InstallMethod:  c.installMethod,
	}
	if !status.Enabled {
		return status
	}
	c.mu.RLock()
	latest, checkedAt := c.latest, c.checkedAt
	c.mu.RUnlock()
	if latest == "" {
		return status
	}
	status.LatestVersion = latest
	status.CheckedAt = &checkedAt
	status.ReleaseURL = "https://github.com/" + c.opts.Repo + "/releases/tag/" + latest
	if cmp, ok := selfupdate.CompareVersions(latest, c.opts.CurrentVersion); ok && cmp > 0 {
		status.UpdateAvailable = true
	}
	return status
}

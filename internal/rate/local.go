package rate

import (
	"context"
	"sync"
	"time"
)

const (
	localSweepInterval = 5 * time.Minute
	localStaleAfter    = time.Hour
)

type LocalLimiter struct {
	mu        sync.Mutex
	buckets   map[string][]time.Time
	lastSweep time.Time
}

func NewLocalLimiter() *LocalLimiter {
	return &LocalLimiter{
		buckets:   make(map[string][]time.Time),
		lastSweep: time.Now().UTC(),
	}
}

func (l *LocalLimiter) sweepLocked(now time.Time) {
	staleCutoff := now.Add(-localStaleAfter)
	for key, items := range l.buckets {
		if len(items) == 0 || !items[len(items)-1].After(staleCutoff) {
			delete(l.buckets, key)
		}
	}
}

func (l *LocalLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, int, time.Time, error) {
	if limit <= 0 || window <= 0 {
		return true, 0, time.Now().UTC(), nil
	}

	now := time.Now().UTC()
	cutoff := now.Add(-window)

	l.mu.Lock()
	defer l.mu.Unlock()

	items := l.buckets[key][:0]
	for _, ts := range l.buckets[key] {
		if ts.After(cutoff) {
			items = append(items, ts)
		}
	}
	items = append(items, now)
	l.buckets[key] = items

	if now.Sub(l.lastSweep) >= localSweepInterval {
		l.sweepLocked(now)
		l.lastSweep = now
	}

	remaining := limit - len(items)
	if remaining < 0 {
		remaining = 0
	}
	reset := now.Add(window)
	if len(items) > 0 {
		reset = items[0].Add(window)
	}
	return len(items) <= limit, remaining, reset, nil
}

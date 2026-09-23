package proxy

import (
	"sync"
	"time"
)

type denialThrottle struct {
	mu          sync.Mutex
	window      time.Duration
	limit       int
	windowStart time.Time
	written     int
	current     map[string]int
	previous    map[string]int
}

func newDenialThrottle(window time.Duration, limit int) *denialThrottle {
	return &denialThrottle{
		window:   window,
		limit:    limit,
		current:  make(map[string]int),
		previous: make(map[string]int),
	}
}

func (t *denialThrottle) allow(key string, now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if now.Sub(t.windowStart) >= t.window {
		previous := make(map[string]int)
		if now.Sub(t.windowStart) < 2*t.window {
			for k, suppressed := range t.current {
				if suppressed > 0 {
					previous[k] = suppressed
				}
			}
		}
		t.previous = previous
		t.current = make(map[string]int)
		t.windowStart = now
		t.written = 0
	}

	if _, seen := t.current[key]; seen {
		t.current[key]++
		return false, 0
	}
	if t.written >= t.limit {
		return false, 0
	}
	t.written++
	t.current[key] = 0
	suppressed := t.previous[key]
	delete(t.previous, key)
	return true, suppressed
}

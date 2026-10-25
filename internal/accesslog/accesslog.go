package accesslog

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Entry struct {
	Time        time.Time `json:"time"`
	RequestID   string    `json:"request_id"`
	Method      string    `json:"method"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	Status      int       `json:"status"`
	LatencyMs   int64     `json:"latency_ms"`
	Bytes       int       `json:"bytes"`
	RemoteAddr  string    `json:"remote_addr"`
	PeerAddr    string    `json:"peer_addr"`
	UserAgent   string    `json:"user_agent"`
	Referer     string    `json:"referer,omitempty"`
	Outcome     string    `json:"outcome"`
	Reason      string    `json:"reason"`
	ServiceID   uint      `json:"service_id,omitempty"`
	ServiceName string    `json:"service_name,omitempty"`
	UserID      *uint     `json:"user_id,omitempty"`
	UserEmail   string    `json:"user_email,omitempty"`
	AccessRule  string    `json:"access_rule,omitempty"`
}

type Filter struct {
	Host      string
	ServiceID uint
	Status    string
	IP        string
	Query     string
	Outcome   string
	Before    time.Time
}

type Options struct {
	Capacity     int
	FilePath     string
	MaxFileBytes int64
	MaxFiles     int
	Logger       *slog.Logger
}

type Recorder struct {
	mu      sync.RWMutex
	entries []Entry
	next    int
	full    bool

	file    *rotatingFile
	queue   chan Entry
	done    chan struct{}
	dropped atomic.Uint64
	logger  *slog.Logger
}

func New(opts Options) (*Recorder, error) {
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = 2000
	}
	r := &Recorder{entries: make([]Entry, capacity), logger: opts.Logger}
	if path := strings.TrimSpace(opts.FilePath); path != "" {
		file, err := openRotatingFile(path, opts.MaxFileBytes, opts.MaxFiles)
		if err != nil {
			return nil, err
		}
		r.file = file
		r.queue = make(chan Entry, 4096)
		r.done = make(chan struct{})
		go r.writeLoop()
	}
	return r, nil
}

func (r *Recorder) Record(entry Entry) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.entries[r.next] = entry
	r.next = (r.next + 1) % len(r.entries)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()

	if r.queue != nil {
		select {
		case r.queue <- entry:
		default:
			r.dropped.Add(1)
		}
	}
}

func (r *Recorder) List(filter Filter, limit int) []Entry {
	if r == nil {
		return nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	size := r.next
	if r.full {
		size = len(r.entries)
	}
	var out []Entry
	for i := 0; i < size && len(out) < limit; i++ {
		index := (r.next - 1 - i + len(r.entries)) % len(r.entries)
		entry := r.entries[index]
		if filter.matches(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func (r *Recorder) Close() {
	if r == nil || r.queue == nil {
		return
	}
	close(r.queue)
	<-r.done
}

func (r *Recorder) writeLoop() {
	defer close(r.done)
	defer r.file.Close()
	for entry := range r.queue {
		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		if err := r.file.WriteLine(line); err != nil && r.logger != nil {
			r.logger.Warn("access log write failed", "error", err)
		}
		if dropped := r.dropped.Swap(0); dropped > 0 && r.logger != nil {
			r.logger.Warn("access log dropped entries because the disk was too slow", "count", dropped)
		}
	}
}

func (f Filter) matches(entry Entry) bool {
	if entry.Time.IsZero() {
		return false
	}
	if !f.Before.IsZero() && !entry.Time.Before(f.Before) {
		return false
	}
	if f.ServiceID != 0 && entry.ServiceID != f.ServiceID {
		return false
	}
	if f.Host != "" && !strings.Contains(entry.Host, strings.ToLower(f.Host)) {
		return false
	}
	if f.IP != "" && !strings.HasPrefix(entry.RemoteAddr, f.IP) {
		return false
	}
	if f.Outcome != "" && entry.Outcome != f.Outcome {
		return false
	}
	if f.Status != "" && !statusMatches(f.Status, entry.Status) {
		return false
	}
	if f.Query != "" {
		query := strings.ToLower(f.Query)
		if !strings.Contains(strings.ToLower(entry.Path), query) &&
			!strings.Contains(strings.ToLower(entry.UserAgent), query) &&
			!strings.Contains(strings.ToLower(entry.UserEmail), query) {
			return false
		}
	}
	return true
}

func statusMatches(filter string, status int) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if len(filter) == 3 && strings.HasSuffix(filter, "xx") && filter[0] >= '1' && filter[0] <= '5' {
		return status/100 == int(filter[0]-'0')
	}
	value, err := strconv.Atoi(filter)
	return err == nil && value == status
}

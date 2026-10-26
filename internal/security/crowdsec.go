package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"portlyn/internal/netguard"
)

type CrowdSec struct {
	mu         sync.RWMutex
	apiURL     string
	apiKey     string
	httpClient *http.Client
	interval   time.Duration
	startup    bool
	logger     *slog.Logger
	version    string
	startedAt  time.Time

	syncMu      sync.RWMutex
	lastSuccess time.Time
	synced      bool

	decisionsMu     sync.RWMutex
	ipDecisions     map[string]decisionEntry
	prefixDecisions []decisionPrefix

	processed atomic.Uint64
	droppedMu sync.Mutex
	dropped   map[string]uint64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type decisionEntry struct {
	reason string
	origin string
}

type decisionPrefix struct {
	prefix netip.Prefix
	reason string
	origin string
}

type Decision struct {
	ID       int    `json:"id"`
	Duration string `json:"duration"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
}

type decisionsStream struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

func NewCrowdSec() *CrowdSec {
	return &CrowdSec{
		httpClient:  &http.Client{Timeout: 10 * time.Second, Transport: ssrfGuardedTransport()},
		ipDecisions: make(map[string]decisionEntry),
		dropped:     make(map[string]uint64),
		interval:    60 * time.Second,
	}
}

func ssrfGuardedTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("crowdsec target resolved to an unparseable address")
			}
			if netguard.IsBlockedAddr(addr) {
				return fmt.Errorf("crowdsec target resolves to a blocked address")
			}
			return nil
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return transport
}

func (c *CrowdSec) SetLogger(logger *slog.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

func (c *CrowdSec) Configure(apiURL, apiKey string, interval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	c.apiKey = strings.TrimSpace(apiKey)
	if interval > 0 {
		c.interval = interval
	}
}

func (c *CrowdSec) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiURL != "" && c.apiKey != ""
}

func (c *CrowdSec) Start(ctx context.Context) {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return
	}
	if c.apiURL == "" || c.apiKey == "" {
		c.mu.Unlock()
		return
	}
	innerCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.startup = true
	c.startedAt = time.Now().UTC()
	c.mu.Unlock()

	c.wg.Add(2)
	go c.loop(innerCtx)
	go c.metricsLoop(innerCtx)
}

func (c *CrowdSec) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
}

func (c *CrowdSec) loop(ctx context.Context) {
	defer c.wg.Done()
	if err := c.fetchOnce(ctx, true); err != nil {
		c.mu.Lock()
		c.startup = false
		logger := c.logger
		c.mu.Unlock()
		if logger != nil {
			logger.Warn("crowdsec initial decision sync failed; reputation blocking is inactive until a sync succeeds", "error", err)
		}
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.fetchOnce(ctx, false); err != nil {
				c.mu.RLock()
				logger := c.logger
				c.mu.RUnlock()
				if logger != nil {
					logger.Warn("crowdsec decision sync failed; reputation decisions may be stale", "error", err)
				}
			}
		}
	}
}

func (c *CrowdSec) fetchOnce(ctx context.Context, startup bool) error {
	c.mu.RLock()
	apiURL := c.apiURL
	apiKey := c.apiKey
	c.mu.RUnlock()
	if apiURL == "" || apiKey == "" {
		return errors.New("not configured")
	}
	url := apiURL + "/v1/decisions/stream"
	if startup {
		url += "?startup=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("User-Agent", "portlyn-crowdsec/1")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("crowdsec: status %d", resp.StatusCode)
	}
	var stream decisionsStream
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		return err
	}
	c.apply(stream)
	c.syncMu.Lock()
	c.lastSuccess = time.Now().UTC()
	c.synced = true
	c.syncMu.Unlock()
	return nil
}

func (c *CrowdSec) Healthy() bool {
	c.mu.RLock()
	interval := c.interval
	c.mu.RUnlock()
	staleAfter := 3 * interval
	if staleAfter < time.Minute {
		staleAfter = time.Minute
	}
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	if !c.synced {
		return false
	}
	return time.Since(c.lastSuccess) <= staleAfter
}

func (c *CrowdSec) apply(stream decisionsStream) {
	c.decisionsMu.Lock()
	defer c.decisionsMu.Unlock()
	for _, dec := range stream.Deleted {
		c.removeLocked(dec)
	}
	for _, dec := range stream.New {
		c.addLocked(dec)
	}
}

func (c *CrowdSec) addLocked(dec Decision) {
	value := strings.TrimSpace(dec.Value)
	if value == "" {
		return
	}
	reason := dec.Scenario
	if reason == "" {
		reason = dec.Origin
	}
	origin := decisionOrigin(dec)
	if strings.EqualFold(dec.Scope, "ip") {
		c.ipDecisions[value] = decisionEntry{reason: reason, origin: origin}
		return
	}
	if strings.EqualFold(dec.Scope, "range") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return
		}
		c.prefixDecisions = append(c.prefixDecisions, decisionPrefix{prefix: prefix.Masked(), reason: reason, origin: origin})
	}
}

func decisionOrigin(dec Decision) string {
	origin := strings.TrimSpace(dec.Origin)
	if strings.EqualFold(origin, "lists") && dec.Scenario != "" {
		return "lists:" + dec.Scenario
	}
	if origin == "" {
		return "unknown"
	}
	return origin
}

func (c *CrowdSec) removeLocked(dec Decision) {
	value := strings.TrimSpace(dec.Value)
	if value == "" {
		return
	}
	if strings.EqualFold(dec.Scope, "ip") {
		delete(c.ipDecisions, value)
		return
	}
	if strings.EqualFold(dec.Scope, "range") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return
		}
		prefix = prefix.Masked()
		filtered := c.prefixDecisions[:0]
		for _, item := range c.prefixDecisions {
			if item.prefix != prefix {
				filtered = append(filtered, item)
			}
		}
		c.prefixDecisions = filtered
	}
}

func (c *CrowdSec) IsBlocked(ip net.IP) (bool, string) {
	if ip == nil {
		return false, ""
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return false, ""
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	c.recordProcessed()
	c.decisionsMu.RLock()
	entry, ok := c.ipDecisions[ip.String()]
	if !ok {
		for _, prefix := range c.prefixDecisions {
			if prefix.prefix.Contains(addr) {
				entry, ok = decisionEntry{reason: prefix.reason, origin: prefix.origin}, true
				break
			}
		}
	}
	c.decisionsMu.RUnlock()
	if !ok {
		return false, ""
	}
	c.recordDropped(entry.origin)
	return true, entry.reason
}

func (c *CrowdSec) Stats() (int, int) {
	c.decisionsMu.RLock()
	defer c.decisionsMu.RUnlock()
	return len(c.ipDecisions), len(c.prefixDecisions)
}

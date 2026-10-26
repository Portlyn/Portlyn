package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const usageMetricsInterval = 15 * time.Minute

type usageMetricsPayload struct {
	RemediationComponents []remediationComponentMetrics `json:"remediation_components"`
}

type remediationComponentMetrics struct {
	Type                string            `json:"type"`
	Version             string            `json:"version"`
	UTCStartupTimestamp int64             `json:"utc_startup_timestamp"`
	FeatureFlags        []string          `json:"feature_flags"`
	OS                  *usageMetricsOS   `json:"os,omitempty"`
	Metrics             []detailedMetrics `json:"metrics"`
}

type usageMetricsOS struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type detailedMetrics struct {
	Meta  metricsMeta         `json:"meta"`
	Items []metricsDetailItem `json:"items"`
}

type metricsMeta struct {
	WindowSizeSeconds int64 `json:"window_size_seconds"`
	UTCNowTimestamp   int64 `json:"utc_now_timestamp"`
}

type metricsDetailItem struct {
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Unit   string            `json:"unit"`
	Labels map[string]string `json:"labels,omitempty"`
}

func (c *CrowdSec) SetVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = strings.TrimSpace(version)
}

func (c *CrowdSec) recordProcessed() {
	c.processed.Add(1)
}

func (c *CrowdSec) recordDropped(origin string) {
	c.droppedMu.Lock()
	c.dropped[origin]++
	c.droppedMu.Unlock()
}

func (c *CrowdSec) takeWindow() (uint64, map[string]uint64) {
	processed := c.processed.Swap(0)
	c.droppedMu.Lock()
	dropped := c.dropped
	c.dropped = make(map[string]uint64)
	c.droppedMu.Unlock()
	return processed, dropped
}

func (c *CrowdSec) restoreWindow(processed uint64, dropped map[string]uint64) {
	c.processed.Add(processed)
	c.droppedMu.Lock()
	for origin, value := range dropped {
		c.dropped[origin] += value
	}
	c.droppedMu.Unlock()
}

func (c *CrowdSec) buildUsageMetrics(now time.Time, window time.Duration, processed uint64, dropped map[string]uint64) usageMetricsPayload {
	c.mu.RLock()
	version := c.version
	startedAt := c.startedAt
	c.mu.RUnlock()
	if version == "" {
		version = "dev"
	}

	items := []metricsDetailItem{{Name: "processed", Value: float64(processed), Unit: "request"}}
	for origin, value := range dropped {
		items = append(items, metricsDetailItem{
			Name:   "dropped",
			Value:  float64(value),
			Unit:   "request",
			Labels: map[string]string{"origin": origin, "remediation": "ban"},
		})
	}
	for key, value := range c.activeDecisions() {
		items = append(items, metricsDetailItem{
			Name:   "active_decisions",
			Value:  float64(value),
			Unit:   "ip",
			Labels: map[string]string{"origin": key.origin, "ip_type": key.ipType},
		})
	}

	return usageMetricsPayload{RemediationComponents: []remediationComponentMetrics{{
		Type:                "portlyn",
		Version:             version,
		UTCStartupTimestamp: startedAt.Unix(),
		FeatureFlags:        []string{},
		OS:                  hostOS(),
		Metrics: []detailedMetrics{{
			Meta: metricsMeta{
				WindowSizeSeconds: int64(window.Seconds()),
				UTCNowTimestamp:   now.Unix(),
			},
			Items: items,
		}},
	}}}
}

type activeDecisionKey struct {
	origin string
	ipType string
}

func (c *CrowdSec) activeDecisions() map[activeDecisionKey]int {
	c.decisionsMu.RLock()
	defer c.decisionsMu.RUnlock()
	counts := make(map[activeDecisionKey]int)
	for value, entry := range c.ipDecisions {
		ipType := "ipv4"
		if strings.Contains(value, ":") {
			ipType = "ipv6"
		}
		counts[activeDecisionKey{origin: entry.origin, ipType: ipType}]++
	}
	for _, item := range c.prefixDecisions {
		ipType := "ipv4"
		if item.prefix.Addr().Is6() {
			ipType = "ipv6"
		}
		counts[activeDecisionKey{origin: item.origin, ipType: ipType}]++
	}
	return counts
}

func (c *CrowdSec) pushUsageMetrics(ctx context.Context, window time.Duration) (bool, error) {
	c.mu.RLock()
	apiURL := c.apiURL
	apiKey := c.apiKey
	c.mu.RUnlock()
	if apiURL == "" || apiKey == "" {
		return true, nil
	}

	processed, dropped := c.takeWindow()
	body, err := json.Marshal(c.buildUsageMetrics(time.Now().UTC(), window, processed, dropped))
	if err != nil {
		c.restoreWindow(processed, dropped)
		return true, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/usage-metrics", bytes.NewReader(body))
	if err != nil {
		c.restoreWindow(processed, dropped)
		return true, err
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "portlyn-crowdsec/1")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.restoreWindow(processed, dropped)
		return true, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return false, nil
	case resp.StatusCode >= 400:
		c.restoreWindow(processed, dropped)
		return true, fmt.Errorf("crowdsec usage metrics: status %d", resp.StatusCode)
	}
	return true, nil
}

func (c *CrowdSec) metricsLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(usageMetricsInterval)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			supported, err := c.pushUsageMetrics(ctx, now.Sub(last))
			last = now
			c.mu.RLock()
			logger := c.logger
			c.mu.RUnlock()
			if !supported {
				if logger != nil {
					logger.Info("crowdsec lapi does not accept usage metrics; reporting disabled")
				}
				return
			}
			if err != nil && logger != nil && ctx.Err() == nil {
				logger.Warn("crowdsec usage metrics push failed", "error", err)
			}
		}
	}
}

func hostOS() *usageMetricsOS {
	if runtime.GOOS != "linux" {
		return &usageMetricsOS{Name: runtime.GOOS, Version: "?"}
	}
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return &usageMetricsOS{Name: runtime.GOOS, Version: "?"}
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	name := values["ID"]
	if name == "" {
		name = runtime.GOOS
	}
	version := values["VERSION_ID"]
	if version == "" {
		version = "?"
	}
	return &usageMetricsOS{Name: name, Version: version}
}

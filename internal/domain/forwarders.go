package domain

import (
	"fmt"
	"time"
)

type ForwarderFinding struct {
	Host     string  `json:"host"`
	Prefix   string  `json:"prefix"`
	Header   string  `json:"header"`
	Requests int64   `json:"requests"`
	Total    int64   `json:"total"`
	Percent  float64 `json:"percent"`
}

type ForwarderReport struct {
	CheckedAt time.Time          `json:"checked_at"`
	Window    string             `json:"window"`
	Findings  []ForwarderFinding `json:"findings"`
}

func (f ForwarderFinding) Message() string {
	return fmt.Sprintf("%.0f%% of requests to %s come from %s which sends %s but is not in TRUSTED_PROXY_CIDRS; client IPs, geo rules and reputation decisions apply to the proxy, not the visitor",
		f.Percent, f.Host, f.Prefix, f.Header)
}

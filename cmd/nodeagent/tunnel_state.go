package main

import (
	"os"
	"strings"
	"time"
)

type tunnelState struct {
	configPath string
}

func newTunnelState(configPath string) *tunnelState {
	return &tunnelState{configPath: strings.TrimSpace(configPath)}
}

func (t *tunnelState) enabled() bool {
	if t == nil || t.configPath == "" {
		return false
	}
	if _, err := os.Stat(t.configPath); err != nil {
		return false
	}
	return true
}

func (t *tunnelState) snapshot() (*time.Time, int64, int64, string) {
	if !t.enabled() {
		return nil, 0, 0, "inactive"
	}
	info, err := os.Stat(t.configPath)
	if err != nil {
		return nil, 0, 0, "inactive"
	}
	mtime := info.ModTime().UTC()
	return &mtime, 0, 0, "provisioned"
}

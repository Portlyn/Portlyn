package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type agentState struct {
	NodeID          uint     `json:"node_id"`
	HeartbeatToken  string   `json:"heartbeat_token"`
	WGPrivateKey    string   `json:"wg_private_key"`
	WGPublicKey     string   `json:"wg_public_key"`
	TunnelIP        string   `json:"tunnel_ip"`
	ServerPublicKey string   `json:"server_public_key"`
	ServerEndpoint  string   `json:"server_endpoint"`
	PresharedKey    string   `json:"preshared_key"`
	AllowedIPs      []string `json:"allowed_ips"`
	Subnets         []string `json:"subnets"`
	Keepalive       int      `json:"keepalive"`
}

func (s *agentState) provisioned() bool {
	return s != nil && s.NodeID > 0 && s.HeartbeatToken != "" && s.WGPrivateKey != "" && s.TunnelIP != "" && s.ServerPublicKey != "" && s.ServerEndpoint != ""
}

func defaultStatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "portlyn-nodeagent", "state.json"), nil
}

func loadState(path string) (*agentState, error) {
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, 0o600)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state agentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(path string, state *agentState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"portlyn/internal/tunnel"
)

const (
	provisionRetryStart = 5 * time.Second
	provisionRetryMax   = 5 * time.Minute
)

type statusError struct {
	step string
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s failed: %d %s: %s", e.step, e.code, http.StatusText(e.code), e.body)
}

func retryableProvisionError(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		switch se.code {
		case http.StatusConflict, http.StatusPreconditionFailed, http.StatusTooManyRequests:
			return true
		}
		return se.code >= 500
	}
	return true
}

type provisioner struct {
	client          *http.Client
	api             string
	name            string
	description     string
	version         string
	enrollmentToken func() (string, error)
	save            func(*agentState) error
	retryStart      time.Duration
}

func (p *provisioner) run(ctx context.Context, state *agentState) (*agentState, error) {
	delay := p.retryStart
	if delay <= 0 {
		delay = provisionRetryStart
	}
	for {
		next, err := p.step(state)
		state = next
		if err == nil {
			return state, nil
		}
		if !retryableProvisionError(err) {
			var se *statusError
			if errors.As(err, &se) && se.step == "bootstrap" && (se.code == http.StatusUnauthorized || se.code == http.StatusNotFound) {
				log.Print("the hub no longer knows this node; clearing the saved enrollment so a new token can be used")
				if saveErr := p.save(&agentState{}); saveErr != nil {
					log.Printf("save state: %v", saveErr)
				}
			}
			if errors.As(err, &se) && se.step == "enroll" && se.code == http.StatusUnauthorized {
				return state, fmt.Errorf("%w (the enrollment token is invalid, expired or already used; create a new one)", err)
			}
			return state, err
		}
		log.Printf("provision: %v; retrying in %s", err, delay)
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, provisionRetryMax)
	}
}

func (p *provisioner) step(state *agentState) (*agentState, error) {
	if state == nil || state.NodeID == 0 || state.HeartbeatToken == "" {
		token, err := p.enrollmentToken()
		if err != nil {
			return state, fmt.Errorf("read enrollment token: %w", err)
		}
		if token == "" {
			return state, errors.New("no saved state found: provide an enrollment token via --token-file, systemd credentials or --token for the first run")
		}
		id, _, heartbeatToken, err := enrollNode(p.client, p.api, token, p.name, p.description, p.version)
		if err != nil {
			return state, err
		}
		state = &agentState{NodeID: id, HeartbeatToken: heartbeatToken}
		if err := p.save(state); err != nil {
			return state, fmt.Errorf("save state: %w", err)
		}
	}
	if state.WGPrivateKey == "" || state.WGPublicKey == "" {
		keys, err := tunnel.GenerateKeyPair()
		if err != nil {
			return state, fmt.Errorf("generate keypair: %w", err)
		}
		state.WGPrivateKey = keys.PrivateKey
		state.WGPublicKey = keys.PublicKey
		if err := p.save(state); err != nil {
			return state, fmt.Errorf("save state: %w", err)
		}
	}
	boot, err := selfBootstrap(p.client, p.api, state.HeartbeatToken, state.NodeID, state.WGPublicKey)
	if err != nil {
		return state, err
	}
	keepalive := boot.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}
	state.TunnelIP = boot.TunnelIP
	state.ServerPublicKey = boot.ServerPublicKey
	state.ServerEndpoint = boot.ServerEndpoint
	state.ServerTunnelIP = strings.TrimSpace(boot.ServerTunnelIP)
	state.PresharedKey = boot.PresharedKey
	state.AllowedIPs = boot.AllowedIPs
	state.Subnets = boot.AdvertisedSubnets
	state.Keepalive = keepalive
	if err := p.save(state); err != nil {
		return state, fmt.Errorf("save state: %w", err)
	}
	return state, nil
}

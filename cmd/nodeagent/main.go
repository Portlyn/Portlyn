package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"portlyn/internal/tunnel"
)

type heartbeatPayload struct {
	Version          string     `json:"version,omitempty"`
	Status           string     `json:"status,omitempty"`
	Load             float64    `json:"load,omitempty"`
	BandwidthInKbps  float64    `json:"bandwidth_in_kbps,omitempty"`
	BandwidthOutKbps float64    `json:"bandwidth_out_kbps,omitempty"`
	WGLastHandshake  *time.Time `json:"wg_last_handshake,omitempty"`
	WGRxBytes        *int64     `json:"wg_rx_bytes,omitempty"`
	WGTxBytes        *int64     `json:"wg_tx_bytes,omitempty"`
	TunnelStatus     string     `json:"tunnel_status,omitempty"`
}

type enrollRequest struct {
	Token       string `json:"token"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
}

type enrollResponse struct {
	Node struct {
		ID uint `json:"id"`
	} `json:"node"`
	HeartbeatToken string `json:"heartbeat_token"`
	HeartbeatURL   string `json:"heartbeat_url"`
}

type selfBootstrapResponse struct {
	NodeID            uint     `json:"node_id"`
	TunnelIP          string   `json:"tunnel_ip"`
	ServerPublicKey   string   `json:"server_public_key"`
	ServerEndpoint    string   `json:"server_endpoint"`
	PresharedKey      string   `json:"preshared_key"`
	AllowedIPs        []string `json:"allowed_ips"`
	Keepalive         int      `json:"keepalive"`
	AdvertisedSubnets []string `json:"advertised_subnets"`
}

type tunnelTargetsResponse struct {
	Targets           []targetSpec `json:"targets"`
	AdvertisedSubnets []string     `json:"advertised_subnets"`
}

var version = "dev-agent"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "update":
			if err := runUpdate(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "update:", err)
				os.Exit(1)
			}
			return
		case "verify-release":
			if err := runVerifyRelease(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "verify-release:", err)
				os.Exit(1)
			}
			return
		case "version", "--version", "-v":
			fmt.Println("portlyn-nodeagent", version)
			return
		}
	}
	apiBase := flag.String("api", "https://localhost", "api base url")
	token := flag.String("token", "", "enrollment token (only needed on first run)")
	name := flag.String("name", "node-agent", "node name used during enrollment")
	description := flag.String("description", "", "node description used during enrollment")
	versionFlag := flag.String("version", version, "node version")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	targetInterval := flag.Duration("target-interval", 60*time.Second, "tunnel target refresh interval")
	statePath := flag.String("state", "", "path to the agent state file")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "skip tls verification (development only)")
	flag.Parse()

	if *insecureSkipVerify && strings.TrimSpace(os.Getenv("PORTLYN_AGENT_ALLOW_INSECURE")) != "1" {
		log.Fatal("--insecure-skip-verify requires PORTLYN_AGENT_ALLOW_INSECURE=1; refusing to disable TLS verification")
	}

	resolvedStatePath := strings.TrimSpace(*statePath)
	if resolvedStatePath == "" {
		def, err := defaultStatePath()
		if err != nil {
			log.Fatalf("resolve state path: %v", err)
		}
		resolvedStatePath = def
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureSkipVerify},
		},
	}
	api := strings.TrimRight(*apiBase, "/")

	state, err := loadState(resolvedStatePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	if !state.provisioned() {
		if strings.TrimSpace(*token) == "" {
			log.Fatal("no saved state found: provide an enrollment --token for the first run")
		}
		state, err = provision(client, api, *token, *name, *description, *versionFlag)
		if err != nil {
			log.Fatalf("provision: %v", err)
		}
		if err := saveState(resolvedStatePath, state); err != nil {
			log.Fatalf("save state: %v", err)
		}
		log.Printf("node enrolled and tunnel provisioned: node_id=%d tunnel_ip=%s", state.NodeID, state.TunnelIP)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	tunnelIP, err := netip.ParseAddr(state.TunnelIP)
	if err != nil {
		log.Fatalf("parse tunnel ip: %v", err)
	}
	wgClient := tunnel.NewClient(tunnel.ClientOptions{
		PrivateKey:      state.WGPrivateKey,
		ServerPublicKey: state.ServerPublicKey,
		ServerEndpoint:  state.ServerEndpoint,
		PresharedKey:    state.PresharedKey,
		TunnelIP:        tunnelIP,
		AllowedIPs:      state.AllowedIPs,
		Keepalive:       state.Keepalive,
	})
	if err := wgClient.Start(ctx); err != nil {
		log.Fatalf("start tunnel client: %v", err)
	}
	defer wgClient.Stop()
	log.Printf("tunnel client up on %s, dialing %s", state.TunnelIP, state.ServerEndpoint)

	if subnets := parseCIDRs(state.Subnets); len(subnets) > 0 {
		if err := wgClient.EnableSubnetProxy(subnets); err != nil {
			log.Printf("enable subnet proxy: %v", err)
		} else {
			log.Printf("subnet proxy active for %v", state.Subnets)
		}
	}

	fwd := newForwarder(wgClient)
	defer fwd.stop()

	refreshTargets := func() {
		targets, err := fetchTargets(client, api, state.NodeID, state.HeartbeatToken)
		if err != nil {
			log.Printf("fetch tunnel targets: %v", err)
			return
		}
		fwd.reconcile(targets)
	}
	refreshTargets()

	heartbeatEndpoint := fmt.Sprintf("%s/api/v1/nodes/%d/heartbeat", api, state.NodeID)
	heartbeatTicker := time.NewTicker(*interval)
	defer heartbeatTicker.Stop()
	targetTicker := time.NewTicker(*targetInterval)
	defer targetTicker.Stop()

	sendHeartbeat(client, heartbeatEndpoint, state.HeartbeatToken, *versionFlag, wgClient)

	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return
		case <-heartbeatTicker.C:
			sendHeartbeat(client, heartbeatEndpoint, state.HeartbeatToken, *versionFlag, wgClient)
		case <-targetTicker.C:
			refreshTargets()
		}
	}
}

func provision(client *http.Client, api, token, name, description, version string) (*agentState, error) {
	id, _, heartbeatToken, err := enrollNode(client, api, token, name, description, version)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	keys, err := tunnel.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	boot, err := selfBootstrap(client, api, heartbeatToken, id, keys.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	keepalive := boot.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}
	return &agentState{
		NodeID:          id,
		HeartbeatToken:  heartbeatToken,
		WGPrivateKey:    keys.PrivateKey,
		WGPublicKey:     keys.PublicKey,
		TunnelIP:        boot.TunnelIP,
		ServerPublicKey: boot.ServerPublicKey,
		ServerEndpoint:  boot.ServerEndpoint,
		PresharedKey:    boot.PresharedKey,
		AllowedIPs:      boot.AllowedIPs,
		Subnets:         boot.AdvertisedSubnets,
		Keepalive:       keepalive,
	}, nil
}

func enrollNode(client *http.Client, api, token, name, description, version string) (uint, string, string, error) {
	payload := enrollRequest{Token: token, Name: name, Description: description, Version: version}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, api+"/api/v1/nodes/enroll", bytes.NewReader(body))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := readBody(resp)
		return 0, "", "", fmt.Errorf("enroll failed: %s: %s", resp.Status, string(buf))
	}
	var result enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", "", err
	}
	return result.Node.ID, api + result.HeartbeatURL, result.HeartbeatToken, nil
}

func selfBootstrap(client *http.Client, api, heartbeatToken string, nodeID uint, publicKey string) (*selfBootstrapResponse, error) {
	payload := map[string]any{"public_key": publicKey}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/nodes/%d/wg-bootstrap", api, nodeID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+heartbeatToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := readBody(resp)
		return nil, fmt.Errorf("bootstrap failed: %s: %s", resp.Status, string(buf))
	}
	var result selfBootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func fetchTargets(client *http.Client, api string, nodeID uint, heartbeatToken string) ([]targetSpec, error) {
	url := fmt.Sprintf("%s/api/v1/nodes/%d/tunnel-targets", api, nodeID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+heartbeatToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := readBody(resp)
		return nil, fmt.Errorf("targets failed: %s: %s", resp.Status, string(buf))
	}
	var result tunnelTargetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Targets, nil
}

func sendHeartbeat(client *http.Client, endpoint, heartbeatToken, version string, wgClient *tunnel.Client) {
	payload := heartbeatPayload{
		Version: version,
		Status:  "online",
	}
	if wgClient.Started() {
		rx, tx := wgClient.Stats()
		payload.WGRxBytes = &rx
		payload.WGTxBytes = &tx
		if handshake, ok := wgClient.HandshakeAge(); ok {
			payload.WGLastHandshake = &handshake
			payload.TunnelStatus = "connected"
		} else {
			payload.TunnelStatus = "provisioned"
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal heartbeat: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("build heartbeat request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+heartbeatToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("heartbeat failed: %v", err)
		return
	}
	_ = resp.Body.Close()
	log.Printf("heartbeat status=%s", resp.Status)
}

func readBody(resp *http.Response) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

func parseCIDRs(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			log.Printf("skip invalid subnet %q: %v", value, err)
			continue
		}
		out = append(out, prefix)
	}
	return out
}

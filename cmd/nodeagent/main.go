package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
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

type bootstrapResponse struct {
	NodeID          uint     `json:"node_id"`
	PublicKey       string   `json:"public_key"`
	PrivateKey      string   `json:"private_key"`
	Address         string   `json:"address"`
	ServerPublicKey string   `json:"server_public_key"`
	ServerEndpoint  string   `json:"server_endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	PersistentKeep  int      `json:"persistent_keepalive"`
	ConfigText      string   `json:"config_text"`
}

func main() {
	apiBase := flag.String("api", "https://localhost", "api base url")
	endpoint := flag.String("endpoint", "", "heartbeat endpoint, auto-derived after enrollment if omitted")
	token := flag.String("token", "", "enrollment token or existing node bearer token")
	nodeID := flag.Uint("node-id", 0, "existing node id when using a pre-issued heartbeat token")
	name := flag.String("name", "node-agent", "node name used during enrollment")
	description := flag.String("description", "", "node description used during enrollment")
	version := flag.String("version", "dev-agent", "node version")
	interval := flag.Duration("interval", 30*time.Second, "heartbeat interval")
	wgConfigPath := flag.String("wg-config", "", "path to write the wireguard client config (enables tunnel bootstrap)")
	wgBootstrap := flag.Bool("wg-bootstrap", false, "request a wireguard client config from the server after enrollment")
	wgForce := flag.Bool("wg-force-reissue", false, "force reissue of wg keypair even if node already has one")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "skip tls verification (development only)")
	flag.Parse()

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureSkipVerify},
		},
	}
	heartbeatToken := *token
	heartbeatEndpoint := strings.TrimSpace(*endpoint)
	resolvedNodeID := *nodeID

	if heartbeatEndpoint == "" {
		if resolvedNodeID > 0 {
			heartbeatEndpoint = strings.TrimRight(*apiBase, "/") + "/api/v1/nodes/" + fmt.Sprintf("%d", resolvedNodeID) + "/heartbeat"
		} else if *token != "" {
			id, enrolledEndpoint, enrolledToken, err := enrollNode(client, strings.TrimRight(*apiBase, "/"), *token, *name, *description, *version)
			if err != nil {
				log.Fatalf("enroll node: %v", err)
			}
			heartbeatEndpoint = enrolledEndpoint
			heartbeatToken = enrolledToken
			resolvedNodeID = id
		}
	}
	if heartbeatEndpoint == "" || heartbeatToken == "" {
		log.Fatal("provide either --endpoint and --token, or --api and an enrollment --token")
	}

	if *wgBootstrap && *wgConfigPath != "" && resolvedNodeID > 0 {
		if err := bootstrapWireguard(client, strings.TrimRight(*apiBase, "/"), heartbeatToken, resolvedNodeID, *wgConfigPath, *wgForce); err != nil {
			log.Printf("wg bootstrap failed: %v", err)
		} else {
			log.Printf("wireguard config written to %s", *wgConfigPath)
		}
	}

	tunnelState := newTunnelState(*wgConfigPath)

	for {
		payload := heartbeatPayload{
			Version:          *version,
			Status:           "online",
			Load:             0.1,
			BandwidthInKbps:  128,
			BandwidthOutKbps: 64,
		}
		if tunnelState.enabled() {
			handshake, rx, tx, status := tunnelState.snapshot()
			if handshake != nil {
				payload.WGLastHandshake = handshake
			}
			payload.WGRxBytes = &rx
			payload.WGTxBytes = &tx
			payload.TunnelStatus = status
		}

		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("marshal heartbeat: %v", err)
			time.Sleep(*interval)
			continue
		}

		req, err := http.NewRequest(http.MethodPost, heartbeatEndpoint, bytes.NewReader(body))
		if err != nil {
			log.Printf("build request: %v", err)
			time.Sleep(*interval)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+heartbeatToken)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("heartbeat failed: %v", err)
			time.Sleep(*interval)
			continue
		}
		_ = resp.Body.Close()
		log.Printf("heartbeat status=%s", resp.Status)
		time.Sleep(*interval)
	}
}

func enrollNode(client *http.Client, apiBase, token, name, description, version string) (uint, string, string, error) {
	payload := enrollRequest{
		Token:       token,
		Name:        name,
		Description: description,
		Version:     version,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/v1/nodes/enroll", bytes.NewReader(body))
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
		return 0, "", "", fmt.Errorf("enroll failed: %s", resp.Status)
	}
	var result enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", "", err
	}
	return result.Node.ID, strings.TrimRight(apiBase, "/") + result.HeartbeatURL, result.HeartbeatToken, nil
}

func bootstrapWireguard(client *http.Client, apiBase, heartbeatToken string, nodeID uint, configPath string, forceReissue bool) error {
	payload := map[string]any{"force_reissue": forceReissue}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/v1/nodes/%d/wg-bootstrap", apiBase, nodeID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+heartbeatToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := readBody(resp)
		return fmt.Errorf("bootstrap failed: %s: %s", resp.Status, string(buf))
	}
	var result bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(result.ConfigText), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, configPath)
}

func readBody(resp *http.Response) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"portlyn/internal/domain"
)

func TestServerStartStop(t *testing.T) {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	settings := &domain.AppSettings{
		TunnelEnabled:          true,
		TunnelServerPrivateKey: keys.PrivateKey,
		TunnelServerPublicKey:  keys.PublicKey,
		TunnelServerEndpoint:   "127.0.0.1:0",
		TunnelListenPort:       0,
		TunnelCIDR:             "10.99.0.0/24",
		TunnelServerTunnelIP:   "10.99.0.1",
	}
	srv := NewServer(ServerOptions{MTU: 1420, LogLevel: device.LogLevelSilent})
	if err := srv.Start(context.Background(), settings); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !srv.Started() {
		t.Fatal("expected started")
	}
	if !srv.ContainsTunnelIP("10.99.0.5") {
		t.Fatal("expected tunnel cidr to contain 10.99.0.5")
	}
	if srv.ContainsTunnelIP("10.42.0.1") {
		t.Fatal("expected 10.42.0.1 outside cidr")
	}
	srv.Stop()
	if srv.Started() {
		t.Fatal("expected stopped")
	}
}

func TestServerRoundTrip(t *testing.T) {
	serverKeys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	clientKeys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}

	settings := &domain.AppSettings{
		TunnelEnabled:          true,
		TunnelServerPrivateKey: serverKeys.PrivateKey,
		TunnelServerPublicKey:  serverKeys.PublicKey,
		TunnelServerEndpoint:   "127.0.0.1:51899",
		TunnelListenPort:       51899,
		TunnelCIDR:             "10.99.0.0/24",
		TunnelServerTunnelIP:   "10.99.0.1",
	}
	srv := NewServer(ServerOptions{MTU: 1420, LogLevel: device.LogLevelSilent})
	if err := srv.Start(context.Background(), settings); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(srv.Stop)

	clientIP := netip.MustParseAddr("10.99.0.2")
	if err := srv.ApplyPeers([]domain.Node{{
		ID:           1,
		Name:         "test",
		WGPublicKey:  clientKeys.PublicKey,
		WGTunnelIP:   clientIP.String(),
		WGAllowedIPs: clientIP.String() + "/32",
	}}); err != nil {
		t.Fatalf("apply peers: %v", err)
	}

	tun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client tun: %v", err)
	}
	clientLogger := device.NewLogger(device.LogLevelSilent, "client: ")
	clientDevice := device.NewDevice(tun, conn.NewDefaultBind(), clientLogger)
	t.Cleanup(clientDevice.Close)

	clientPriv, err := keyToHex(clientKeys.PrivateKey)
	if err != nil {
		t.Fatalf("client priv hex: %v", err)
	}
	serverPubHex, err := keyToHex(serverKeys.PublicKey)
	if err != nil {
		t.Fatalf("server pub hex: %v", err)
	}
	clientCfg := strings.Join([]string{
		fmt.Sprintf("private_key=%s", clientPriv),
		fmt.Sprintf("public_key=%s", serverPubHex),
		fmt.Sprintf("endpoint=127.0.0.1:%d", settings.TunnelListenPort),
		"allowed_ip=10.99.0.1/32",
		"persistent_keepalive_interval=5",
		"",
	}, "\n")
	if err := clientDevice.IpcSet(clientCfg); err != nil {
		t.Fatalf("client ipc: %v", err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}

	listener, err := clientNet.ListenTCPAddrPort(netip.AddrPortFrom(clientIP, 18080))
	if err != nil {
		t.Fatalf("listen on peer tun: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello-tunnel")
	})
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Close() })

	transport := &http.Transport{DialContext: srv.DialContext}
	httpClient := &http.Client{Timeout: 8 * time.Second, Transport: transport}

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://" + clientIP.String() + ":18080/echo")
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "hello-tunnel" {
			lastErr = fmt.Errorf("unexpected response: %d %s", resp.StatusCode, body)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatalf("tunnel round trip never succeeded: %v", lastErr)
}

func TestKeyConversionRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	hexKey, err := keyToHex(kp.PublicKey)
	if err != nil {
		t.Fatalf("to hex: %v", err)
	}
	if _, err := hex.DecodeString(hexKey); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
	back, err := hexToKey(hexKey)
	if err != nil {
		t.Fatalf("from hex: %v", err)
	}
	if back != kp.PublicKey {
		decoded, _ := base64.StdEncoding.DecodeString(back)
		t.Fatalf("roundtrip mismatch: got=%s len=%d", back, len(decoded))
	}
}

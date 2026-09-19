package tunnel

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"portlyn/internal/domain"
)

type fakeClientRepo struct{ clients []domain.Client }

func (f *fakeClientRepo) List(ctx context.Context) ([]domain.Client, error) { return f.clients, nil }
func (f *fakeClientRepo) Create(ctx context.Context, c *domain.Client) error {
	f.clients = append(f.clients, *c)
	return nil
}
func (f *fakeClientRepo) GetByID(ctx context.Context, id uint) (*domain.Client, error) {
	for i := range f.clients {
		if f.clients[i].ID == id {
			return &f.clients[i], nil
		}
	}
	return nil, ErrPoolExhausted
}
func (f *fakeClientRepo) Update(ctx context.Context, c *domain.Client) error { return nil }
func (f *fakeClientRepo) Delete(ctx context.Context, id uint) error          { return nil }

func TestBuildPeerSpecs(t *testing.T) {
	nodes := newStubNodeRepo(
		&domain.Node{ID: 1, WGPublicKey: "nodepub1", WGTunnelIP: "10.42.0.2", AdvertisedSubnets: "192.168.1.0/24,10.5.0.0/16"},
		&domain.Node{ID: 2, WGPublicKey: "", WGTunnelIP: "10.42.0.3"},
	)
	clients := &fakeClientRepo{clients: []domain.Client{
		{ID: 1, WGPublicKey: "clientpub1", WGTunnelIP: "10.42.1.2", Enabled: true},
		{ID: 2, WGPublicKey: "clientpub2", WGTunnelIP: "10.42.1.3", Enabled: false},
	}}
	m := NewManager(nodes, clients, &stubSettingsRepo{settings: &domain.AppSettings{}})

	specs, err := m.BuildPeerSpecs(context.Background())
	if err != nil {
		t.Fatalf("build peer specs: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs (1 node with key + 1 enabled client), got %d", len(specs))
	}
	var nodeSpec, clientSpec *PeerSpec
	for i := range specs {
		switch specs[i].PublicKey {
		case "nodepub1":
			nodeSpec = &specs[i]
		case "clientpub1":
			clientSpec = &specs[i]
		}
	}
	if nodeSpec == nil || clientSpec == nil {
		t.Fatalf("missing expected specs: %+v", specs)
	}
	want := []string{"10.42.0.2/32", "192.168.1.0/24", "10.5.0.0/16"}
	if len(nodeSpec.AllowedIPs) != len(want) {
		t.Fatalf("node allowed ips = %v, want %v", nodeSpec.AllowedIPs, want)
	}
	for i, v := range want {
		if nodeSpec.AllowedIPs[i] != v {
			t.Fatalf("node allowed ip[%d] = %s, want %s", i, nodeSpec.AllowedIPs[i], v)
		}
	}
	if len(clientSpec.AllowedIPs) != 1 || clientSpec.AllowedIPs[0] != "10.42.1.2/32" {
		t.Fatalf("client allowed ips = %v", clientSpec.AllowedIPs)
	}
}

func TestSubnetProxyRoundTrip(t *testing.T) {
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
		TunnelServerEndpoint:   "127.0.0.1:51897",
		TunnelListenPort:       51897,
		TunnelCIDR:             "10.99.0.0/24",
		TunnelServerTunnelIP:   "10.99.0.1",
	}
	srv := NewServer(ServerOptions{MTU: 1420, LogLevel: device.LogLevelSilent})
	if err := srv.Start(context.Background(), settings); err != nil {
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(srv.Stop)

	clientIP := netip.MustParseAddr("10.99.0.2")
	const lanSubnet = "10.123.0.0/24"
	if err := srv.ApplyPeerSpecs([]PeerSpec{{
		PublicKey:  clientKeys.PublicKey,
		AllowedIPs: []string{clientIP.String() + "/32", lanSubnet},
	}}); err != nil {
		t.Fatalf("apply peer specs: %v", err)
	}

	// Stand-in for a real LAN host: the subnet proxy dial target is rewritten to this echo server.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, readErr := c.Read(buf)
				if readErr == nil {
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()
	echoAddr := echo.Addr().String()

	// Build the client device manually so we can inject a dialer that reaches the
	// in-process echo server instead of an unreachable LAN IP.
	dial := func(network, _ string) (net.Conn, error) { return net.Dial(network, echoAddr) }
	clientTun, _, err := CreateNetStackWithProxy([]netip.Addr{clientIP}, 1420, &SubnetProxy{
		Subnets: []netip.Prefix{netip.MustParsePrefix(lanSubnet)},
		Dial:    dial,
	})
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	clientDevice := device.NewDevice(clientTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "client: "))
	t.Cleanup(clientDevice.Close)
	clientPrivHex, _ := keyToHex(clientKeys.PrivateKey)
	serverPubHex, _ := keyToHex(serverKeys.PublicKey)
	clientCfg := strings.Join([]string{
		"private_key=" + clientPrivHex,
		"public_key=" + serverPubHex,
		"endpoint=127.0.0.1:51897",
		"allowed_ip=10.99.0.0/24",
		"persistent_keepalive_interval=5",
		"",
	}, "\n")
	if err := clientDevice.IpcSet(clientCfg); err != nil {
		t.Fatalf("client ipc: %v", err)
	}
	if err := clientDevice.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}

	clientCtx := context.Background()
	target := "10.123.0.5:80"
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		dialCtx, dialCancel := context.WithTimeout(clientCtx, 2*time.Second)
		conn, err := srv.DialContext(dialCtx, "tcp", target)
		dialCancel()
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("ping-mesh")); err != nil {
			lastErr = err
			conn.Close()
			time.Sleep(250 * time.Millisecond)
			continue
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if string(buf[:n]) == "ping-mesh" {
			return
		}
		lastErr = nil
	}
	t.Fatalf("subnet proxy round trip never succeeded: %v", lastErr)
}

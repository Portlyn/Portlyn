package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"portlyn/internal/domain"
)

func TestBuildForwardRulesScopesClientsToAllowedNodes(t *testing.T) {
	nodes := newStubNodeRepo(
		&domain.Node{ID: 1, WGPublicKey: "nodepub1", WGTunnelIP: "10.42.0.2", AdvertisedSubnets: "192.168.1.0/24"},
		&domain.Node{ID: 2, WGPublicKey: "nodepub2", WGTunnelIP: "10.42.0.3", AdvertisedSubnets: "192.168.2.0/24"},
	)
	clients := &fakeClientRepo{clients: []domain.Client{
		{ID: 1, WGPublicKey: "clientpub1", WGTunnelIP: "10.42.1.2", AllowedNodeIDs: "1", Enabled: true},
		{ID: 2, WGPublicKey: "clientpub2", WGTunnelIP: "10.42.1.3", AllowedNodeIDs: "1,2", Enabled: false},
		{ID: 3, WGPublicKey: "clientpub3", WGTunnelIP: "10.42.1.4", AllowedNodeIDs: "", Enabled: true},
	}}
	m := NewManager(nodes, clients, &stubSettingsRepo{settings: &domain.AppSettings{}})
	rules, err := m.BuildForwardRules(context.Background())
	if err != nil {
		t.Fatalf("build forward rules: %v", err)
	}
	srv := NewServer(ServerOptions{})
	srv.SetForwardRules(rules)

	cases := []struct {
		src, dst string
		want     bool
	}{
		{"10.42.1.2", "192.168.1.10", true},
		{"10.42.1.2", "10.42.0.2", true},
		{"192.168.1.10", "10.42.1.2", true},
		{"10.42.0.2", "10.42.1.2", true},
		{"10.42.1.2", "192.168.2.10", false},
		{"10.42.1.2", "10.42.0.3", false},
		{"10.42.1.2", "10.42.1.4", false},
		{"10.42.1.3", "192.168.1.10", false},
		{"10.42.1.4", "192.168.1.10", false},
		{"10.42.0.2", "10.42.0.3", false},
		{"10.42.0.2", "192.168.2.10", false},
		{"192.168.1.10", "10.42.1.4", false},
	}
	for _, tc := range cases {
		got := srv.forwardAllowed(netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst))
		if got != tc.want {
			t.Errorf("forwardAllowed(%s -> %s) = %v, want %v", tc.src, tc.dst, got, tc.want)
		}
	}

	sources, err := m.ClientSourcesForNode(context.Background(), 1)
	if err != nil {
		t.Fatalf("client sources: %v", err)
	}
	if len(sources) != 1 || sources[0] != "10.42.1.2" {
		t.Fatalf("client sources for node 1 = %v, want [10.42.1.2]", sources)
	}
}

func TestForwardAllowedDeniesWithoutRules(t *testing.T) {
	srv := NewServer(ServerOptions{})
	if srv.forwardAllowed(netip.MustParseAddr("10.42.1.2"), netip.MustParseAddr("10.42.0.2")) {
		t.Fatal("expected forwarding to be denied before any rules are set")
	}
}

func TestNetStackInboundFilterDropsPackets(t *testing.T) {
	_, ns, err := CreateNetStack([]netip.Addr{netip.MustParseAddr("10.42.0.1")}, 1420)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	t.Cleanup(func() { _ = ns.Close() })

	packet := make([]byte, header.IPv4MinimumSize)
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 42, 1, 2}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 42, 0, 3}),
	})
	if !ns.allowInbound(packet) {
		t.Fatal("expected packets to pass without a filter")
	}
	var seenSrc, seenDst netip.Addr
	ns.SetInboundFilter(func(src, dst netip.Addr) bool {
		seenSrc, seenDst = src, dst
		return false
	})
	if ns.allowInbound(packet) {
		t.Fatal("expected filter to drop the packet")
	}
	if seenSrc != netip.MustParseAddr("10.42.1.2") || seenDst != netip.MustParseAddr("10.42.0.3") {
		t.Fatalf("filter saw %s -> %s", seenSrc, seenDst)
	}
	if ns.allowInbound(packet[:10]) {
		t.Fatal("expected truncated packets to be dropped")
	}
}

func upPeerDevice(t *testing.T, dev *device.Device, privateKey, serverPublicKey string, port int, allowed []string) {
	t.Helper()
	privHex, err := keyToHex(privateKey)
	if err != nil {
		t.Fatalf("priv hex: %v", err)
	}
	pubHex, err := keyToHex(serverPublicKey)
	if err != nil {
		t.Fatalf("pub hex: %v", err)
	}
	lines := []string{
		"private_key=" + privHex,
		"public_key=" + pubHex,
		fmt.Sprintf("endpoint=127.0.0.1:%d", port),
	}
	for _, cidr := range allowed {
		lines = append(lines, "allowed_ip="+cidr)
	}
	lines = append(lines, "persistent_keepalive_interval=5", "")
	if err := dev.IpcSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("device up: %v", err)
	}
}

func echoOnce(conn net.Conn, payload string) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != payload {
		return fmt.Errorf("unexpected echo %q", buf[:n])
	}
	return nil
}

func serveEcho(t *testing.T, ln net.Listener) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, err := c.Read(buf)
				if err == nil {
					_, _ = c.Write(buf[:n])
				}
			}(c)
		}
	}()
}

func TestServerForwardingEnforcesClientNodeScope(t *testing.T) {
	const port = 51893
	serverKeys, _ := GenerateKeyPair()
	nodeKeys, _ := GenerateKeyPair()
	allowedKeys, _ := GenerateKeyPair()
	deniedKeys, _ := GenerateKeyPair()

	settings := &domain.AppSettings{
		TunnelEnabled:          true,
		TunnelServerPrivateKey: serverKeys.PrivateKey,
		TunnelServerPublicKey:  serverKeys.PublicKey,
		TunnelServerEndpoint:   fmt.Sprintf("127.0.0.1:%d", port),
		TunnelListenPort:       port,
		TunnelCIDR:             "10.98.0.0/24",
		TunnelServerTunnelIP:   "10.98.0.1",
	}
	srv := NewServer(ServerOptions{MTU: 1420, LogLevel: device.LogLevelSilent})
	if err := srv.Start(context.Background(), settings); err != nil {
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(srv.Stop)

	const lanSubnet = "10.124.0.0/24"
	nodes := newStubNodeRepo(&domain.Node{ID: 1, WGPublicKey: nodeKeys.PublicKey, WGTunnelIP: "10.98.0.2", AdvertisedSubnets: lanSubnet})
	clients := &fakeClientRepo{clients: []domain.Client{
		{ID: 1, WGPublicKey: allowedKeys.PublicKey, WGTunnelIP: "10.98.0.3", AllowedNodeIDs: "1", Enabled: true},
		{ID: 2, WGPublicKey: deniedKeys.PublicKey, WGTunnelIP: "10.98.0.4", AllowedNodeIDs: "", Enabled: true},
	}}
	m := NewManager(nodes, clients, &stubSettingsRepo{settings: settings})
	m.AttachServer(srv)
	if err := m.ApplyPeers(context.Background()); err != nil {
		t.Fatalf("apply peers: %v", err)
	}

	hubListener, err := srv.net.ListenTCP(7000)
	if err != nil {
		t.Fatalf("hub listen: %v", err)
	}
	serveEcho(t, hubListener)

	lanEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	serveEcho(t, lanEcho)
	lanAddr := lanEcho.Addr().String()

	nodeTun, _, err := CreateNetStackWithProxy([]netip.Addr{netip.MustParseAddr("10.98.0.2")}, 1420, &SubnetProxy{
		Subnets: []netip.Prefix{netip.MustParsePrefix(lanSubnet)},
		Dial:    func(network, _ string) (net.Conn, error) { return net.Dial(network, lanAddr) },
	})
	if err != nil {
		t.Fatalf("node netstack: %v", err)
	}
	nodeDevice := device.NewDevice(nodeTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "node: "))
	t.Cleanup(nodeDevice.Close)
	upPeerDevice(t, nodeDevice, nodeKeys.PrivateKey, serverKeys.PublicKey, port, []string{"10.98.0.0/24"})

	newClient := func(ip string, keys KeyPair) *netstack.Net {
		tunDev, clientNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, 1420)
		if err != nil {
			t.Fatalf("client tun: %v", err)
		}
		dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "client: "))
		t.Cleanup(dev.Close)
		upPeerDevice(t, dev, keys.PrivateKey, serverKeys.PublicKey, port, []string{"10.98.0.0/24", lanSubnet})
		return clientNet
	}
	allowedNet := newClient("10.98.0.3", allowedKeys)
	deniedNet := newClient("10.98.0.4", deniedKeys)

	dialUntil := func(clientNet *netstack.Net, target string) error {
		deadline := time.Now().Add(20 * time.Second)
		var lastErr error
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c, err := clientNet.DialContext(ctx, "tcp", target)
			cancel()
			if err != nil {
				lastErr = err
				time.Sleep(250 * time.Millisecond)
				continue
			}
			err = echoOnce(c, "ping-scope")
			c.Close()
			if err == nil {
				return nil
			}
			lastErr = err
			time.Sleep(250 * time.Millisecond)
		}
		return lastErr
	}

	if err := dialUntil(allowedNet, "10.124.0.5:80"); err != nil {
		t.Fatalf("allowed client could not reach its node subnet: %v", err)
	}
	if err := dialUntil(deniedNet, "10.98.0.1:7000"); err != nil {
		t.Fatalf("denied client could not reach the hub: %v", err)
	}

	for _, target := range []string{"10.124.0.5:80", "10.98.0.2:80"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := deniedNet.DialContext(ctx, "tcp", target)
		cancel()
		if err == nil {
			echoErr := echoOnce(c, "ping-scope")
			c.Close()
			if echoErr == nil {
				t.Fatalf("expected client without node access to be blocked from %s", target)
			}
		}
	}
}

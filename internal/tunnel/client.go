package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func resolveEndpoint(endpoint string) (string, error) {
	udp, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return "", err
	}
	return udp.String(), nil
}

type ClientOptions struct {
	PrivateKey      string
	ServerPublicKey string
	ServerEndpoint  string
	PresharedKey    string
	TunnelIP        netip.Addr
	AllowedIPs      []string
	MTU             int
	Keepalive       int
	LogLevel        int
}

type Client struct {
	mu       sync.Mutex
	options  ClientOptions
	device   *device.Device
	net      *NetStack
	tunnelIP netip.Addr
	started  bool
}

func NewClient(opts ClientOptions) *Client {
	if opts.MTU <= 0 {
		opts.MTU = 1420
	}
	if opts.Keepalive <= 0 {
		opts.Keepalive = 25
	}
	if opts.LogLevel == 0 {
		opts.LogLevel = device.LogLevelError
	}
	return &Client{options: opts, tunnelIP: opts.TunnelIP}
}

func (c *Client) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if !c.tunnelIP.IsValid() {
		return fmt.Errorf("tunnel client: invalid tunnel ip")
	}
	if strings.TrimSpace(c.options.PrivateKey) == "" {
		return fmt.Errorf("tunnel client: private key missing")
	}
	if strings.TrimSpace(c.options.ServerPublicKey) == "" {
		return fmt.Errorf("tunnel client: server public key missing")
	}
	endpoint := strings.TrimSpace(c.options.ServerEndpoint)
	if endpoint == "" {
		return fmt.Errorf("tunnel client: server endpoint missing")
	}
	resolved, err := resolveEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("tunnel client: resolve endpoint %q: %w", endpoint, err)
	}

	tunDevice, netStack, err := CreateNetStack([]netip.Addr{c.tunnelIP}, c.options.MTU)
	if err != nil {
		return fmt.Errorf("tunnel client: create tun: %w", err)
	}

	logger := device.NewLogger(c.options.LogLevel, "portlyn-wg-client: ")
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	privHex, err := keyToHex(c.options.PrivateKey)
	if err != nil {
		dev.Close()
		return err
	}
	pubHex, err := keyToHex(c.options.ServerPublicKey)
	if err != nil {
		dev.Close()
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	if psk := strings.TrimSpace(c.options.PresharedKey); psk != "" {
		pskHex, err := keyToHex(psk)
		if err != nil {
			dev.Close()
			return err
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", resolved)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.options.Keepalive)
	allowed := c.options.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	for _, cidr := range allowed {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}

	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return fmt.Errorf("tunnel client: ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("tunnel client: bring up: %w", err)
	}

	c.device = dev
	c.net = netStack
	c.started = true

	go func() {
		<-ctx.Done()
		c.Stop()
	}()
	return nil
}

func (c *Client) ListenTCP(port int) (net.Listener, error) {
	c.mu.Lock()
	ns := c.net
	started := c.started
	c.mu.Unlock()
	if !started || ns == nil {
		return nil, fmt.Errorf("tunnel client: not running")
	}
	return ns.ListenTCP(port)
}

func (c *Client) EnableSubnetProxy(subnets []netip.Prefix) error {
	c.mu.Lock()
	ns := c.net
	started := c.started
	c.mu.Unlock()
	if !started || ns == nil {
		return fmt.Errorf("tunnel client: not running")
	}
	return ns.EnableSubnetProxy(subnets, net.Dial)
}

func (c *Client) HandshakeAge() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.device == nil {
		return time.Time{}, false
	}
	value, err := c.device.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(value, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "last_handshake_time_sec" {
			secs := parseInt64(parts[1])
			if secs > 0 {
				return time.Unix(secs, 0).UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func (c *Client) Stats() (rx int64, tx int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.device == nil {
		return 0, 0
	}
	value, err := c.device.IpcGet()
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(value, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "rx_bytes":
			rx = parseInt64(parts[1])
		case "tx_bytes":
			tx = parseInt64(parts[1])
		}
	}
	return rx, tx
}

func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return
	}
	if c.device != nil {
		c.device.Close()
	}
	c.device = nil
	c.net = nil
	c.started = false
}

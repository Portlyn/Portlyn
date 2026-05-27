package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"portlyn/internal/domain"
)

type ServerOptions struct {
	MTU       int
	LogLevel  int
	DNSServer []netip.Addr
}

type Server struct {
	mu         sync.Mutex
	options    ServerOptions
	device     *device.Device
	net        *netstack.Net
	started    bool
	listenPort int
	cidr       netip.Prefix
	tunnelIP   netip.Addr
	settings   *domain.AppSettings
}

func NewServer(opts ServerOptions) *Server {
	if opts.MTU <= 0 {
		opts.MTU = 1420
	}
	if opts.LogLevel == 0 {
		opts.LogLevel = device.LogLevelError
	}
	return &Server{options: opts}
}

func (s *Server) Started() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

func (s *Server) Start(ctx context.Context, settings *domain.AppSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	if !settings.TunnelEnabled {
		return nil
	}
	if strings.TrimSpace(settings.TunnelServerPrivateKey) == "" {
		return fmt.Errorf("tunnel: server private key missing")
	}
	tunnelIP, err := netip.ParseAddr(strings.TrimSpace(settings.TunnelServerTunnelIP))
	if err != nil {
		return fmt.Errorf("tunnel: parse server tunnel ip: %w", err)
	}
	cidr, err := netip.ParsePrefix(strings.TrimSpace(settings.TunnelCIDR))
	if err != nil {
		return fmt.Errorf("tunnel: parse cidr: %w", err)
	}
	listenPort := settings.TunnelListenPort
	if listenPort <= 0 {
		listenPort = 51820
	}

	tunDevice, netStack, err := netstack.CreateNetTUN([]netip.Addr{tunnelIP}, s.options.DNSServer, s.options.MTU)
	if err != nil {
		return fmt.Errorf("tunnel: create tun: %w", err)
	}

	logger := device.NewLogger(s.options.LogLevel, "portlyn-wg: ")
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	uapi, err := keyToHex(settings.TunnelServerPrivateKey)
	if err != nil {
		dev.Close()
		return err
	}
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", uapi, listenPort)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return fmt.Errorf("tunnel: ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("tunnel: bring up: %w", err)
	}

	s.device = dev
	s.net = netStack
	s.listenPort = listenPort
	s.cidr = cidr
	s.tunnelIP = tunnelIP
	s.settings = settings
	s.started = true

	go func() {
		<-ctx.Done()
		s.Stop()
	}()
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return
	}
	if s.device != nil {
		s.device.Close()
	}
	s.device = nil
	s.net = nil
	s.started = false
}

func (s *Server) ApplyPeers(peers []domain.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.device == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	for _, peer := range peers {
		pub := strings.TrimSpace(peer.WGPublicKey)
		ip := strings.TrimSpace(peer.WGTunnelIP)
		if pub == "" || ip == "" {
			continue
		}
		hexKey, err := keyToHex(pub)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "public_key=%s\n", hexKey)
		fmt.Fprintf(&b, "replace_allowed_ips=true\n")
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", ip)
		fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	}
	return s.device.IpcSet(b.String())
}

func (s *Server) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.mu.Lock()
	stack := s.net
	started := s.started
	s.mu.Unlock()
	if !started || stack == nil {
		return nil, fmt.Errorf("tunnel: server not running")
	}
	return stack.DialContext(ctx, network, address)
}

func (s *Server) ContainsTunnelIP(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return false
	}
	parsed, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return s.cidr.Contains(parsed)
}

func (s *Server) PeerHandshakes() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]time.Time)
	if !s.started || s.device == nil {
		return out
	}
	value, err := s.device.IpcGet()
	if err != nil {
		return out
	}
	var currentKey string
	for _, line := range strings.Split(value, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "public_key":
			currentKey = parts[1]
		case "last_handshake_time_sec":
			secs := parseInt64(parts[1])
			if secs > 0 && currentKey != "" {
				if pub, err := hexToKey(currentKey); err == nil {
					out[pub] = time.Unix(secs, 0).UTC()
				}
			}
		}
	}
	return out
}

func keyToHex(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid key length: %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

func hexToKey(value string) (string, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid hex key length: %d", len(decoded))
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func parseInt64(value string) int64 {
	var out int64
	for _, c := range strings.TrimSpace(value) {
		if c < '0' || c > '9' {
			return 0
		}
		out = out*10 + int64(c-'0')
	}
	return out
}

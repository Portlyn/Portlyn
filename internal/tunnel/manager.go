package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"portlyn/internal/domain"
)

var (
	ErrNodeAlreadyProvisioned = errors.New("node already has a tunnel assignment")
	ErrInvalidServerSettings  = errors.New("tunnel server settings are invalid")
)

type NodeRepo interface {
	List(ctx context.Context) ([]domain.Node, error)
	GetByID(ctx context.Context, id uint) (*domain.Node, error)
	Update(ctx context.Context, node *domain.Node) error
}

type SettingsRepo interface {
	Get(ctx context.Context) (*domain.AppSettings, error)
	Upsert(ctx context.Context, settings *domain.AppSettings) error
}

type Manager struct {
	mu       sync.Mutex
	nodes    NodeRepo
	settings SettingsRepo
	server   *Server
}

func NewManager(nodes NodeRepo, settings SettingsRepo) *Manager {
	return &Manager{nodes: nodes, settings: settings}
}

func (m *Manager) AttachServer(server *Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.server = server
}

func (m *Manager) Server() *Server {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.server
}

func (m *Manager) EnsureServerKey(ctx context.Context) (*domain.AppSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(current.TunnelServerPrivateKey) != "" && strings.TrimSpace(current.TunnelServerPublicKey) != "" {
		return current, nil
	}

	keys, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	current.TunnelServerPrivateKey = keys.PrivateKey
	current.TunnelServerPublicKey = keys.PublicKey
	if current.TunnelListenPort <= 0 {
		current.TunnelListenPort = 51820
	}
	if strings.TrimSpace(current.TunnelCIDR) == "" {
		current.TunnelCIDR = "10.42.0.0/16"
	}
	if strings.TrimSpace(current.TunnelServerTunnelIP) == "" {
		current.TunnelServerTunnelIP = "10.42.0.1"
	}
	if err := m.settings.Upsert(ctx, current); err != nil {
		return nil, err
	}
	return current, nil
}

func (m *Manager) loadPool(ctx context.Context, settings *domain.AppSettings) (*IPPool, error) {
	serverAddr, err := netip.ParseAddr(strings.TrimSpace(settings.TunnelServerTunnelIP))
	if err != nil {
		return nil, fmt.Errorf("parse server tunnel ip: %w", err)
	}
	pool, err := NewIPPool(strings.TrimSpace(settings.TunnelCIDR), serverAddr)
	if err != nil {
		return nil, err
	}
	nodes, err := m.nodes.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		raw := strings.TrimSpace(node.WGTunnelIP)
		if raw == "" {
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		_ = pool.MarkAllocated(addr)
	}
	return pool, nil
}

type BootstrapResult struct {
	Node            *domain.Node
	ClientConfig    string
	ClientBundle    ClientBundle
	ServerPublicKey string
}

func (m *Manager) BootstrapNode(ctx context.Context, nodeID uint, opts BootstrapOptions) (*BootstrapResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, err := m.settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(settings.TunnelServerPublicKey) == "" {
		return nil, ErrInvalidServerSettings
	}
	if strings.TrimSpace(settings.TunnelServerEndpoint) == "" {
		return nil, fmt.Errorf("%w: server endpoint not configured", ErrInvalidServerSettings)
	}

	node, err := m.nodes.GetByID(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	pool, err := m.loadPool(ctx, settings)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(node.WGTunnelIP) != "" && !opts.ForceReissue {
		return nil, ErrNodeAlreadyProvisioned
	}

	clientKeys, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(node.WGTunnelIP) != "" {
		if addr, parseErr := netip.ParseAddr(strings.TrimSpace(node.WGTunnelIP)); parseErr == nil {
			pool.Release(addr)
		}
	}

	assignedIP, err := pool.Allocate()
	if err != nil {
		return nil, err
	}

	allowedIPs := []string{strings.TrimSpace(settings.TunnelCIDR)}
	if len(opts.ClientAllowedIPs) > 0 {
		allowedIPs = append([]string{}, opts.ClientAllowedIPs...)
	}

	bundle := ClientBundle{
		PrivateKey:      clientKeys.PrivateKey,
		PublicKey:       clientKeys.PublicKey,
		Address:         assignedIP.String() + "/32",
		ServerPublicKey: settings.TunnelServerPublicKey,
		ServerEndpoint:  settings.TunnelServerEndpoint,
		AllowedIPs:      allowedIPs,
		Keepalive:       25,
	}

	node.WGPublicKey = clientKeys.PublicKey
	node.WGTunnelIP = assignedIP.String()
	node.WGAllowedIPs = assignedIP.String() + "/32"
	node.WGEndpoint = settings.TunnelServerEndpoint
	node.TunnelStatus = domain.TunnelStatusProvisioned

	if err := m.nodes.Update(ctx, node); err != nil {
		pool.Release(assignedIP)
		return nil, err
	}

	if err := m.writeServerConfigLocked(ctx, settings); err != nil {
		return nil, err
	}
	if m.server != nil && m.server.Started() {
		if nodes, err := m.nodes.List(ctx); err == nil {
			_ = m.server.ApplyPeers(nodes)
		}
	}

	return &BootstrapResult{
		Node:            node,
		ClientConfig:    RenderClientConfig(bundle),
		ClientBundle:    bundle,
		ServerPublicKey: settings.TunnelServerPublicKey,
	}, nil
}

type BootstrapOptions struct {
	ForceReissue     bool
	ClientAllowedIPs []string
}

func (m *Manager) WriteServerConfig(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	settings, err := m.settings.Get(ctx)
	if err != nil {
		return err
	}
	return m.writeServerConfigLocked(ctx, settings)
}

func (m *Manager) writeServerConfigLocked(ctx context.Context, settings *domain.AppSettings) error {
	path := strings.TrimSpace(settings.TunnelConfigPath)
	if path == "" {
		return nil
	}
	nodes, err := m.nodes.List(ctx)
	if err != nil {
		return err
	}
	peers := make([]PeerConfig, 0, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.WGPublicKey) == "" || strings.TrimSpace(node.WGTunnelIP) == "" {
			continue
		}
		peers = append(peers, PeerConfig{
			Name:       fmt.Sprintf("node-%d-%s", node.ID, node.Name),
			PublicKey:  node.WGPublicKey,
			AllowedIPs: []string{node.WGTunnelIP + "/32"},
			Keepalive:  25,
		})
	}
	cfg := ServerConfig{
		PrivateKey: settings.TunnelServerPrivateKey,
		Address:    settings.TunnelServerTunnelIP + cidrMask(settings.TunnelCIDR),
		ListenPort: settings.TunnelListenPort,
		MTU:        1420,
		Peers:      peers,
	}
	rendered := RenderServerConfig(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(rendered), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func cidrMask(cidr string) string {
	idx := strings.Index(cidr, "/")
	if idx < 0 {
		return "/32"
	}
	return cidr[idx:]
}

func (m *Manager) RevokeNode(ctx context.Context, nodeID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, err := m.settings.Get(ctx)
	if err != nil {
		return err
	}
	node, err := m.nodes.GetByID(ctx, nodeID)
	if err != nil {
		return err
	}
	node.WGPublicKey = ""
	node.WGTunnelIP = ""
	node.WGAllowedIPs = ""
	node.WGEndpoint = ""
	node.WGLastHandshake = nil
	node.TunnelStatus = domain.TunnelStatusInactive
	if err := m.nodes.Update(ctx, node); err != nil {
		return err
	}
	if err := m.writeServerConfigLocked(ctx, settings); err != nil {
		return err
	}
	if m.server != nil && m.server.Started() {
		if nodes, err := m.nodes.List(ctx); err == nil {
			_ = m.server.ApplyPeers(nodes)
		}
	}
	return nil
}

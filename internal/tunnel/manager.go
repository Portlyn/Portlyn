package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	ErrPeerKeyDuplicate       = errors.New("wireguard public key already in use")
	ErrAllowedIPsNotPermitted = errors.New("requested allowed_ips fall outside the tunnel CIDR")
)

func validateClientAllowedIPs(requested []string, tunnelCIDR string, advertised []string) ([]string, error) {
	tunnelPrefix, err := netip.ParsePrefix(strings.TrimSpace(tunnelCIDR))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tunnel CIDR", ErrInvalidServerSettings)
	}
	allowedRanges := []netip.Prefix{tunnelPrefix.Masked()}
	for _, adv := range advertised {
		if prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(adv)); parseErr == nil {
			allowedRanges = append(allowedRanges, prefix.Masked())
		}
	}
	out := make([]string, 0, len(requested))
	for _, raw := range requested {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return nil, fmt.Errorf("%w: %q", ErrAllowedIPsNotPermitted, entry)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefix = prefix.Masked()
		permitted := false
		for _, allowed := range allowedRanges {
			if allowed.Bits() <= prefix.Bits() && allowed.Contains(prefix.Addr()) {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, fmt.Errorf("%w: %q", ErrAllowedIPsNotPermitted, entry)
		}
		out = append(out, prefix.String())
	}
	if len(out) == 0 {
		return []string{tunnelPrefix.Masked().String()}, nil
	}
	return out, nil
}

func (m *Manager) ensureUniquePeerKey(ctx context.Context, key string, excludeNodeID, excludeClientID uint) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	nodes, err := m.nodes.List(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.ID == excludeNodeID {
			continue
		}
		if strings.TrimSpace(n.WGPublicKey) == key {
			return ErrPeerKeyDuplicate
		}
	}
	if m.clients != nil {
		clients, err := m.clients.List(ctx)
		if err != nil {
			return err
		}
		for _, c := range clients {
			if c.ID == excludeClientID {
				continue
			}
			if strings.TrimSpace(c.WGPublicKey) == key {
				return ErrPeerKeyDuplicate
			}
		}
	}
	return nil
}

func composeServerEndpoint(endpoint string, listenPort int) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	port := listenPort
	if port <= 0 {
		port = 51820
	}
	return fmt.Sprintf("%s:%d", endpoint, port)
}

type NodeRepo interface {
	List(ctx context.Context) ([]domain.Node, error)
	GetByID(ctx context.Context, id uint) (*domain.Node, error)
	Update(ctx context.Context, node *domain.Node) error
}

type SettingsRepo interface {
	Get(ctx context.Context) (*domain.AppSettings, error)
	Upsert(ctx context.Context, settings *domain.AppSettings) error
}

type ClientRepo interface {
	List(ctx context.Context) ([]domain.Client, error)
	Create(ctx context.Context, client *domain.Client) error
	GetByID(ctx context.Context, id uint) (*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	Delete(ctx context.Context, id uint) error
}

type Manager struct {
	mu       sync.Mutex
	nodes    NodeRepo
	clients  ClientRepo
	settings SettingsRepo
	server   *Server
}

func NewManager(nodes NodeRepo, clients ClientRepo, settings SettingsRepo) *Manager {
	return &Manager{nodes: nodes, clients: clients, settings: settings}
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
	if m.clients != nil {
		clients, err := m.clients.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			raw := strings.TrimSpace(client.WGTunnelIP)
			if raw == "" {
				continue
			}
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			_ = pool.MarkAllocated(addr)
		}
	}
	return pool, nil
}

type BootstrapResult struct {
	Node              *domain.Node
	ClientConfig      string
	ClientBundle      ClientBundle
	ServerPublicKey   string
	AdvertisedSubnets []string
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

	var clientKeys KeyPair
	if strings.TrimSpace(opts.ClientPublicKey) != "" {
		if err := ValidatePublicKey(strings.TrimSpace(opts.ClientPublicKey)); err != nil {
			return nil, fmt.Errorf("invalid client public key: %w", err)
		}
		clientKeys = KeyPair{PublicKey: strings.TrimSpace(opts.ClientPublicKey)}
	} else {
		generated, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		clientKeys = generated
	}

	if err := m.ensureUniquePeerKey(ctx, clientKeys.PublicKey, node.ID, 0); err != nil {
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
		validated, err := validateClientAllowedIPs(opts.ClientAllowedIPs, settings.TunnelCIDR, splitCSV(node.AdvertisedSubnets))
		if err != nil {
			return nil, err
		}
		allowedIPs = validated
	}

	presharedKey, err := GeneratePresharedKey()
	if err != nil {
		return nil, err
	}

	serverEndpoint := composeServerEndpoint(settings.TunnelServerEndpoint, settings.TunnelListenPort)
	bundle := ClientBundle{
		PrivateKey:      clientKeys.PrivateKey,
		PublicKey:       clientKeys.PublicKey,
		Address:         assignedIP.String() + "/32",
		ServerPublicKey: settings.TunnelServerPublicKey,
		ServerEndpoint:  serverEndpoint,
		PresharedKey:    presharedKey,
		AllowedIPs:      allowedIPs,
		Keepalive:       25,
	}

	node.WGPublicKey = clientKeys.PublicKey
	node.WGPresharedKey = presharedKey
	node.WGTunnelIP = assignedIP.String()
	node.WGAllowedIPs = assignedIP.String() + "/32"
	node.WGEndpoint = serverEndpoint
	node.TunnelStatus = domain.TunnelStatusProvisioned

	if err := m.nodes.Update(ctx, node); err != nil {
		pool.Release(assignedIP)
		return nil, err
	}

	if err := m.writeServerConfigLocked(ctx, settings); err != nil {
		return nil, err
	}
	m.applyPeersLocked(ctx)

	return &BootstrapResult{
		Node:              node,
		ClientConfig:      RenderClientConfig(bundle),
		ClientBundle:      bundle,
		ServerPublicKey:   settings.TunnelServerPublicKey,
		AdvertisedSubnets: splitCSV(node.AdvertisedSubnets),
	}, nil
}

type BootstrapOptions struct {
	ForceReissue     bool
	ClientAllowedIPs []string
	ClientPublicKey  string
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
			Name:         fmt.Sprintf("node-%d-%s", node.ID, node.Name),
			PublicKey:    node.WGPublicKey,
			PresharedKey: strings.TrimSpace(node.WGPresharedKey),
			AllowedIPs:   []string{node.WGTunnelIP + "/32"},
			Keepalive:    25,
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
	node.WGPresharedKey = ""
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
	m.applyPeersLocked(ctx)
	return nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (m *Manager) BuildPeerSpecs(ctx context.Context) ([]PeerSpec, error) {
	nodes, err := m.nodes.List(ctx)
	if err != nil {
		return nil, err
	}
	specs := make([]PeerSpec, 0, len(nodes))
	for _, node := range nodes {
		pub := strings.TrimSpace(node.WGPublicKey)
		ip := strings.TrimSpace(node.WGTunnelIP)
		if pub == "" || ip == "" {
			continue
		}
		allowed := []string{ip + "/32"}
		allowed = append(allowed, splitCSV(node.AdvertisedSubnets)...)
		specs = append(specs, PeerSpec{PublicKey: pub, PresharedKey: strings.TrimSpace(node.WGPresharedKey), AllowedIPs: allowed})
	}
	if m.clients != nil {
		clients, err := m.clients.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			pub := strings.TrimSpace(client.WGPublicKey)
			ip := strings.TrimSpace(client.WGTunnelIP)
			if pub == "" || ip == "" || !client.Enabled {
				continue
			}
			specs = append(specs, PeerSpec{PublicKey: pub, AllowedIPs: []string{ip + "/32"}})
		}
	}
	return specs, nil
}

func (m *Manager) applyPeersLocked(ctx context.Context) {
	if m.server == nil || !m.server.Started() {
		return
	}
	specs, err := m.BuildPeerSpecs(ctx)
	if err != nil {
		return
	}
	_ = m.server.ApplyPeerSpecs(specs)
}

func (m *Manager) ApplyPeers(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	specs, err := m.BuildPeerSpecs(ctx)
	if err != nil {
		return err
	}
	if m.server == nil || !m.server.Started() {
		return nil
	}
	return m.server.ApplyPeerSpecs(specs)
}

func (m *Manager) ProvisionClient(ctx context.Context, name, description string, allowedNodeIDs []uint) (*ClientBundle, *domain.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, err := m.settings.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(settings.TunnelServerPublicKey) == "" || strings.TrimSpace(settings.TunnelServerEndpoint) == "" {
		return nil, nil, ErrInvalidServerSettings
	}

	pool, err := m.loadPool(ctx, settings)
	if err != nil {
		return nil, nil, err
	}
	assignedIP, err := pool.Allocate()
	if err != nil {
		return nil, nil, err
	}

	allowedSubnets, err := m.subnetsForNodes(ctx, allowedNodeIDs)
	if err != nil {
		return nil, nil, err
	}

	keys, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	bundle := ClientBundle{
		PrivateKey:      keys.PrivateKey,
		PublicKey:       keys.PublicKey,
		Address:         assignedIP.String() + "/32",
		ServerPublicKey: settings.TunnelServerPublicKey,
		ServerEndpoint:  composeServerEndpoint(settings.TunnelServerEndpoint, settings.TunnelListenPort),
		AllowedIPs:      allowedSubnets,
		Keepalive:       25,
	}

	client := &domain.Client{
		Name:           strings.TrimSpace(name),
		Description:    strings.TrimSpace(description),
		WGPublicKey:    keys.PublicKey,
		WGTunnelIP:     assignedIP.String(),
		WGAllowedIPs:   strings.Join(allowedSubnets, ","),
		AllowedNodeIDs: joinUintCSV(allowedNodeIDs),
		Enabled:        true,
		TunnelStatus:   domain.TunnelStatusProvisioned,
	}
	if err := m.clients.Create(ctx, client); err != nil {
		pool.Release(assignedIP)
		return nil, nil, err
	}

	m.applyPeersLocked(ctx)
	return &bundle, client, nil
}

func (m *Manager) RotateClient(ctx context.Context, clientID uint) (*ClientBundle, *domain.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, err := m.settings.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	client, err := m.clients.GetByID(ctx, clientID)
	if err != nil {
		return nil, nil, err
	}
	keys, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	allowedSubnets := splitCSV(client.WGAllowedIPs)
	client.WGPublicKey = keys.PublicKey
	client.TunnelStatus = domain.TunnelStatusProvisioned
	if err := m.clients.Update(ctx, client); err != nil {
		return nil, nil, err
	}
	bundle := ClientBundle{
		PrivateKey:      keys.PrivateKey,
		PublicKey:       keys.PublicKey,
		Address:         client.WGTunnelIP + "/32",
		ServerPublicKey: settings.TunnelServerPublicKey,
		ServerEndpoint:  composeServerEndpoint(settings.TunnelServerEndpoint, settings.TunnelListenPort),
		AllowedIPs:      allowedSubnets,
		Keepalive:       25,
	}
	m.applyPeersLocked(ctx)
	return &bundle, client, nil
}

func (m *Manager) RevokeClient(ctx context.Context, clientID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.clients.Delete(ctx, clientID); err != nil {
		return err
	}
	m.applyPeersLocked(ctx)
	return nil
}

func (m *Manager) subnetsForNodes(ctx context.Context, nodeIDs []uint) ([]string, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	wanted := make(map[uint]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		wanted[id] = struct{}{}
	}
	nodes, err := m.nodes.List(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, node := range nodes {
		if _, ok := wanted[node.ID]; !ok {
			continue
		}
		for _, subnet := range splitCSV(node.AdvertisedSubnets) {
			if _, dup := seen[subnet]; dup {
				continue
			}
			seen[subnet] = struct{}{}
			out = append(out, subnet)
		}
	}
	return out, nil
}

func joinUintCSV(values []uint) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ",")
}

package tunnel

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"portlyn/internal/domain"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if kp.PrivateKey == "" || kp.PublicKey == "" {
		t.Fatal("empty keys returned")
	}
	priv, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("invalid priv key: len=%d err=%v", len(priv), err)
	}
	if err := ValidatePublicKey(kp.PublicKey); err != nil {
		t.Fatalf("validate pub: %v", err)
	}
}

func TestIPPoolAllocateSkipsReservedAndNetworkAddresses(t *testing.T) {
	server, _ := netip.ParseAddr("10.42.0.1")
	pool, err := NewIPPool("10.42.0.0/29", server)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	got := map[string]bool{}
	for {
		addr, err := pool.Allocate()
		if err != nil {
			break
		}
		got[addr.String()] = true
	}
	if got["10.42.0.0"] || got["10.42.0.7"] || got["10.42.0.1"] {
		t.Fatalf("pool returned reserved or boundary address: %v", got)
	}
	if len(got) == 0 {
		t.Fatal("pool returned no addresses")
	}
}

type stubNodeRepo struct {
	mu    sync.Mutex
	items map[uint]*domain.Node
}

func newStubNodeRepo(initial ...*domain.Node) *stubNodeRepo {
	r := &stubNodeRepo{items: map[uint]*domain.Node{}}
	for _, n := range initial {
		copy := *n
		r.items[n.ID] = &copy
	}
	return r
}

func (r *stubNodeRepo) List(ctx context.Context) ([]domain.Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.Node, 0, len(r.items))
	for _, n := range r.items {
		out = append(out, *n)
	}
	return out, nil
}

func (r *stubNodeRepo) GetByID(ctx context.Context, id uint) (*domain.Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.items[id]
	if !ok {
		return nil, errNotFound
	}
	copy := *n
	return &copy, nil
}

func (r *stubNodeRepo) Update(ctx context.Context, node *domain.Node) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := *node
	r.items[node.ID] = &copy
	return nil
}

type stubSettingsRepo struct {
	settings *domain.AppSettings
}

func (r *stubSettingsRepo) Get(ctx context.Context) (*domain.AppSettings, error) {
	copy := *r.settings
	return &copy, nil
}

func (r *stubSettingsRepo) Upsert(ctx context.Context, settings *domain.AppSettings) error {
	copy := *settings
	r.settings = &copy
	return nil
}

var errNotFound = &stubErr{"not found"}

type stubErr struct{ msg string }

func (e *stubErr) Error() string { return e.msg }

func TestManagerEnsureServerKeyGeneratesOnce(t *testing.T) {
	settings := &stubSettingsRepo{settings: &domain.AppSettings{}}
	mgr := NewManager(newStubNodeRepo(), settings)
	first, err := mgr.EnsureServerKey(context.Background())
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if first.TunnelServerPublicKey == "" {
		t.Fatal("expected key generated")
	}
	prev := first.TunnelServerPrivateKey
	second, err := mgr.EnsureServerKey(context.Background())
	if err != nil {
		t.Fatalf("ensure 2: %v", err)
	}
	if second.TunnelServerPrivateKey != prev {
		t.Fatal("expected stable key on second call")
	}
}

func TestManagerBootstrapNodeAssignsIPAndBuildsConfig(t *testing.T) {
	settings := &stubSettingsRepo{settings: &domain.AppSettings{
		TunnelEnabled:        true,
		TunnelServerEndpoint: "vpn.example.com:51820",
		TunnelListenPort:     51820,
		TunnelCIDR:           "10.42.0.0/24",
		TunnelServerTunnelIP: "10.42.0.1",
	}}
	nodes := newStubNodeRepo(&domain.Node{ID: 7, Name: "edge"})
	mgr := NewManager(nodes, settings)
	if _, err := mgr.EnsureServerKey(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	result, err := mgr.BootstrapNode(context.Background(), 7, BootstrapOptions{})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if result.Node.WGTunnelIP == "" {
		t.Fatal("expected tunnel ip assigned")
	}
	if !strings.Contains(result.ClientConfig, "[Peer]") {
		t.Fatalf("client config missing peer section: %s", result.ClientConfig)
	}
	if !strings.Contains(result.ClientConfig, "vpn.example.com:51820") {
		t.Fatalf("client config missing endpoint: %s", result.ClientConfig)
	}
	if !strings.Contains(result.ClientConfig, result.ClientBundle.PrivateKey) {
		t.Fatalf("client config missing private key: %s", result.ClientConfig)
	}
	if _, err := mgr.BootstrapNode(context.Background(), 7, BootstrapOptions{}); err != ErrNodeAlreadyProvisioned {
		t.Fatalf("expected ErrNodeAlreadyProvisioned, got %v", err)
	}
	if _, err := mgr.BootstrapNode(context.Background(), 7, BootstrapOptions{ForceReissue: true}); err != nil {
		t.Fatalf("force reissue: %v", err)
	}
}

func TestManagerRevokeNodeFreesIP(t *testing.T) {
	settings := &stubSettingsRepo{settings: &domain.AppSettings{
		TunnelEnabled:        true,
		TunnelServerEndpoint: "vpn.example.com:51820",
		TunnelListenPort:     51820,
		TunnelCIDR:           "10.42.0.0/30",
		TunnelServerTunnelIP: "10.42.0.1",
	}}
	nodes := newStubNodeRepo(&domain.Node{ID: 1, Name: "n1"})
	mgr := NewManager(nodes, settings)
	if _, err := mgr.EnsureServerKey(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := mgr.BootstrapNode(context.Background(), 1, BootstrapOptions{}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := mgr.RevokeNode(context.Background(), 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := mgr.BootstrapNode(context.Background(), 1, BootstrapOptions{}); err != nil {
		t.Fatalf("rebootstrap after revoke: %v", err)
	}
}

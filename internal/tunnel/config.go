package tunnel

import (
	"fmt"
	"sort"
	"strings"
)

type ServerConfig struct {
	PrivateKey string
	Address    string
	ListenPort int
	MTU        int
	Peers      []PeerConfig
}

type PeerConfig struct {
	Name         string
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string
	Keepalive    int
}

type ClientBundle struct {
	PrivateKey      string
	PublicKey       string
	Address         string
	DNS             string
	ServerPublicKey string
	ServerEndpoint  string
	PresharedKey    string
	AllowedIPs      []string
	Keepalive       int
}

func RenderServerConfig(cfg ServerConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if strings.TrimSpace(cfg.PrivateKey) != "" {
		fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	}
	if strings.TrimSpace(cfg.Address) != "" {
		fmt.Fprintf(&b, "Address = %s\n", cfg.Address)
	}
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	}
	if cfg.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", cfg.MTU)
	}
	peers := append([]PeerConfig(nil), cfg.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})
	for _, peer := range peers {
		b.WriteString("\n[Peer]\n")
		if peer.Name != "" {
			fmt.Fprintf(&b, "# %s\n", peer.Name)
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		if strings.TrimSpace(peer.PresharedKey) != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
		}
		if len(peer.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
		}
		if strings.TrimSpace(peer.Endpoint) != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", peer.Endpoint)
		}
		if peer.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.Keepalive)
		}
	}
	return b.String()
}

func RenderClientConfig(bundle ClientBundle) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", bundle.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", bundle.Address)
	if strings.TrimSpace(bundle.DNS) != "" {
		fmt.Fprintf(&b, "DNS = %s\n", bundle.DNS)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", bundle.ServerPublicKey)
	if strings.TrimSpace(bundle.PresharedKey) != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", bundle.PresharedKey)
	}
	if len(bundle.AllowedIPs) > 0 {
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(bundle.AllowedIPs, ", "))
	}
	if strings.TrimSpace(bundle.ServerEndpoint) != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", bundle.ServerEndpoint)
	}
	keepalive := bundle.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	return b.String()
}

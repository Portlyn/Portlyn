package config

import "testing"

func TestEmptyProxyHTTPSAddrDisablesHTTPS(t *testing.T) {
	setStrongSecrets(t)
	t.Setenv("PROXY_HTTPS_ADDR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ProxyHTTPSAddr != "" {
		t.Fatalf("expected an explicitly empty PROXY_HTTPS_ADDR to stay empty, got %q", cfg.ProxyHTTPSAddr)
	}
}

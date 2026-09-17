package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const initBanner = `
Portlyn — initial setup
=======================
This wizard generates a complete .env so the server can boot in dev or prod.
You can re-run it at any time; existing .env files are preserved unless --force is set.
`

type initAnswers struct {
	Domain            string
	AdminEmail        string
	AdminPassword     string
	ACMEEmail         string
	DataDir           string
	HTTPSEnabled      bool
	DNSProvider       string
	DNSToken          string
	PasswordGenerated bool
	BreakGlassEnabled bool
	BreakGlassToken   string
}

func runInitWizard(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	output := flags.String("output", ".env", "where to write the generated .env file")
	dataDir := flags.String("data-dir", "./data", "directory for the sqlite database and certificates")
	domainFlag := flags.String("domain", envDefault("PORTLYN_DOMAIN", ""), "primary admin domain")
	adminEmailFlag := flags.String("admin-email", envDefault("PORTLYN_ADMIN_EMAIL", ""), "admin email")
	adminPasswordFlag := flags.String("admin-password", os.Getenv("PORTLYN_ADMIN_PASSWORD"), "admin password (min 16 chars; auto-generated if empty in --non-interactive)")
	acmeEmailFlag := flags.String("acme-email", envDefault("PORTLYN_ACME_EMAIL", ""), "letsencrypt email")
	dnsProviderFlag := flags.String("dns-provider", envDefault("PORTLYN_DNS_PROVIDER", ""), "seed a DNS-01 provider: cloudflare, hetzner, or digitalocean")
	dnsTokenFlag := flags.String("dns-token", os.Getenv("PORTLYN_DNS_TOKEN"), "API token for the selected --dns-provider")
	nonInteractive := flags.Bool("non-interactive", envBoolDefault("PORTLYN_NONINTERACTIVE", false), "never prompt; fail if required values are missing")
	acmeEnabled := flags.Bool("acme", true, "enable ACME/Letsencrypt HTTPS")
	breakGlass := flags.Bool("break-glass", true, "seed a loopback-only break-glass recovery login (recommended, prevents SSO-only lockout)")
	force := flags.Bool("force", false, "overwrite existing output file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*output); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", *output)
	}

	answers := initAnswers{
		Domain:            strings.TrimSpace(*domainFlag),
		AdminEmail:        strings.TrimSpace(*adminEmailFlag),
		AdminPassword:     *adminPasswordFlag,
		ACMEEmail:         strings.TrimSpace(*acmeEmailFlag),
		DataDir:           strings.TrimSpace(*dataDir),
		DNSProvider:       strings.ToLower(strings.TrimSpace(*dnsProviderFlag)),
		DNSToken:          strings.TrimSpace(*dnsTokenFlag),
		HTTPSEnabled:      *acmeEnabled,
		BreakGlassEnabled: *breakGlass,
	}
	if answers.BreakGlassEnabled {
		token, err := randomURLSafe(32)
		if err != nil {
			return err
		}
		answers.BreakGlassToken = token
	}

	if *nonInteractive {
		if answers.ACMEEmail == "" {
			answers.ACMEEmail = answers.AdminEmail
		}
		if answers.AdminPassword == "" {
			generated, err := randomURLSafe(24)
			if err != nil {
				return err
			}
			answers.AdminPassword = generated
			answers.PasswordGenerated = true
		}
	} else if answers.Domain == "" || answers.AdminEmail == "" || answers.AdminPassword == "" || answers.ACMEEmail == "" {
		fmt.Print(initBanner)
		reader := bufio.NewReader(os.Stdin)
		if answers.Domain == "" {
			answers.Domain = prompt(reader, "Admin domain (e.g. portlyn.example.com)", "")
		}
		if answers.AdminEmail == "" {
			answers.AdminEmail = prompt(reader, "Admin email", "")
		}
		if answers.AdminPassword == "" {
			generated, err := randomURLSafe(24)
			if err != nil {
				return err
			}
			suggested := prompt(reader, fmt.Sprintf("Admin password (press enter to use generated: %s)", generated), generated)
			answers.AdminPassword = suggested
		}
		if answers.ACMEEmail == "" {
			answers.ACMEEmail = prompt(reader, "ACME / Letsencrypt email", answers.AdminEmail)
		}
		answers.HTTPSEnabled = yesNo(reader, "Enable ACME (HTTPS via Letsencrypt)?", true)
	}

	if isLocalInitDomain(answers.Domain) && answers.AdminEmail == "" {
		answers.AdminEmail = "admin@localhost"
	}

	if err := validateInitAnswers(answers); err != nil {
		return err
	}

	if err := os.MkdirAll(answers.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	envText, err := buildEnvFile(answers)
	if err != nil {
		return err
	}

	if err := os.WriteFile(*output, []byte(envText), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *output, err)
	}

	fmt.Printf("\nGenerated %s\n", *output)
	fmt.Printf("Database path: %s\n", filepath.Join(answers.DataDir, "portlyn.db"))
	fmt.Printf("Certificate dir: %s\n", filepath.Join(answers.DataDir, "certificates"))
	if answers.PasswordGenerated {
		fmt.Printf("\nA random admin password was written to %s (ADMIN_PASSWORD).\n", *output)
		fmt.Printf("Read it with: grep '^ADMIN_PASSWORD=' %s\n", *output)
	}
	if answers.BreakGlassEnabled {
		fmt.Printf("\nBreak-glass recovery is enabled, reachable only from the server itself (loopback).\n")
		fmt.Printf("If you ever lock yourself out (e.g. SSO-only plus a lost authenticator), use the token in BREAK_GLASS_TOKEN.\n")
	}
	printStartHint()
	return nil
}

const systemdUnitPath = "/etc/systemd/system/portlyn.service"

func printStartHint() {
	_, err := os.Stat(systemdUnitPath)
	fmt.Print(startHint(err == nil))
}

func startHint(managedBySystemd bool) string {
	if managedBySystemd {
		return "\nStart the server with:\n  sudo systemctl start portlyn\n" +
			"It may already be running, in which case restart it so it picks up this file:\n  sudo systemctl restart portlyn\n"
	}
	return "\nStart the server with:\n  portlyn\n"
}

func isLocalInitDomain(domain string) bool {
	host := strings.ToLower(strings.TrimSpace(domain))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBoolDefault(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func validateInitAnswers(a initAnswers) error {
	if a.Domain == "" {
		return fmt.Errorf("domain is required (--domain or PORTLYN_DOMAIN)")
	}
	if a.AdminEmail == "" {
		return fmt.Errorf("admin email is required (--admin-email or PORTLYN_ADMIN_EMAIL)")
	}
	if len(a.AdminPassword) < 16 {
		return fmt.Errorf("admin password must be at least 16 characters")
	}
	if a.DNSProvider != "" {
		switch a.DNSProvider {
		case "cloudflare", "hetzner", "digitalocean":
			if a.DNSToken == "" {
				return fmt.Errorf("--dns-token (or PORTLYN_DNS_TOKEN) is required for --dns-provider %s", a.DNSProvider)
			}
		default:
			return fmt.Errorf("unsupported --dns-provider %q (expected cloudflare, hetzner, or digitalocean)", a.DNSProvider)
		}
	}
	return nil
}

const optionalEnvReference = `
# ---------------------------------------------------------------------------
# Everything below is optional. The value shown is the built-in default, so
# uncommenting a line without changing it does nothing. Delete what you do not
# need. Reference: https://portlyn.dev/reference/configuration/
# ---------------------------------------------------------------------------

# Sessions and tokens
#TOKEN_TTL=30m
#REFRESH_TOKEN_TTL=720h
#ROUTE_AUTH_TTL=12h
#CSRF_TOKEN_TTL=12h
#AUTH_CACHE_TTL=1m
#JWT_ISSUER=portlyn

# Sign-in
#REQUIRE_MFA_FOR_ADMINS=true
#AUTH_RATE_LIMIT_ATTEMPTS=10
#AUTH_RATE_LIMIT_WINDOW=10m
#BOOTSTRAP_ADMIN_ALLOW_REMOTE=false

# One-time codes by email. Needs SMTP, which is configured in the dashboard.
#OTP_ENABLED=true
#OTP_TOKEN_TTL=10m
#OTP_REQUEST_LIMIT=5
#OTP_REQUEST_WINDOW=15m

# OIDC. Issuer, client id and secret are set in the dashboard.
#OIDC_ENABLED=false
#OIDC_REQUIRE_VERIFIED_EMAIL=true
#OIDC_ALLOW_EMAIL_LINKING=false
#OIDC_ALLOWED_EMAIL_DOMAINS=
#OIDC_MANAGE_ROLES=true
#OIDC_ADMIN_ROLE_CLAIM_PATH=realm_access.roles
#OIDC_PROVIDER_LABEL=SSO
#OIDC_ALLOW_PRIVATE_ISSUER=false

# Proxy and client addresses
#TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
#CORS_ALLOWED_ORIGINS=http://localhost,http://127.0.0.1
#PROXY_ALLOW_PRIVATE_UPSTREAMS=true
#REQUEST_CLIENT_CERT=false
#ROUTE_CACHE_TTL=30s
#ROUTE_LOCAL_CACHE_TTL=5s
#ROUTE_LOCAL_CACHE_SIZE=2048

# Certificates
#ACME_RENEW_WITHIN=720h
#ACME_POLL_INTERVAL=1m

# Nodes and tunnel
#NODE_OFFLINE_AFTER=2m
#NODE_TRUST_FORWARDED_PROTO=true
#NODE_ALLOW_MTLS_HEADER_FALLBACK=false
#NODE_ENROLL_RATE_LIMIT=20
#NODE_ENROLL_RATE_WINDOW=10m
#NODE_HEARTBEAT_AUTH_FAIL_RATE_LIMIT=20
#NODE_HEARTBEAT_AUTH_FAIL_RATE_WINDOW=1m

# Audit log
#AUDIT_BUFFER_SIZE=1024
#AUDIT_BATCH_SIZE=128
#AUDIT_FLUSH_INTERVAL=250ms
#AUDIT_DROP_POLICY=sync_fallback
#AUDIT_WEBHOOK_ALLOW_PRIVATE_TARGETS=false

# Alerting thresholds, counted within ALERT_WINDOW
#ALERT_WINDOW=15m
#ALERT_LOGIN_FAIL_SPIKE_THRESHOLD=20
#ALERT_NODE_HEARTBEAT_FAIL_THRESHOLD=20
#ALERT_AUDIT_ANOMALY_THRESHOLD=10

# Break-glass recovery, reachable from the listed networks only
#BREAK_GLASS_ENABLED=false
#BREAK_GLASS_TTL=15m
#BREAK_GLASS_ALLOW_CIDRS=127.0.0.1/32,::1/128

# GeoIP and CrowdSec decide what happens when the lookup itself fails
#GEOIP_FAIL_OPEN=false
#CROWDSEC_FAIL_OPEN=true

# Diagnostics. Leave these off in production.
#LOG_LEVEL=info
#DB_LOG_LEVEL=warn
#METRICS_PUBLIC=false
#HEALTH_EXPOSE_VERSION=false
#EXPOSE_AUTH_TOKENS=false
#ALLOW_INSECURE_DEV_MODE=false
#OTP_RESPONSE_INCLUDES_CODE=false

# Key rotation. Old secrets stay here until everything is re-encrypted.
#DATA_ENCRYPTION_LEGACY_SECRETS=
`

var generatedSecretKeys = []string{
	"JWT_SECRET",
	"JWT_SIGNING_SECRET",
	"SESSION_BRIDGE_SECRET",
	"OIDC_STATE_SECRET",
	"MFA_ENCRYPTION_SECRET",
	"CSRF_SECRET",
	"DATA_ENCRYPTION_SECRET",
	"AUDIT_HMAC_SECRET",
}

func buildEnvFile(a initAnswers) (string, error) {
	secrets := map[string]string{}
	for _, key := range generatedSecretKeys {
		s, err := randomURLSafe(48)
		if err != nil {
			return "", err
		}
		secrets[key] = s
	}

	local := isLocalInitDomain(a.Domain)

	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by `portlyn init` on %s\n", strings.TrimSpace(a.Domain))
	if local {
		fmt.Fprintln(&b, "FRONTEND_BASE_URL=http://localhost:8000")
		fmt.Fprintln(&b, "HTTP_ADDR=:8080")
		fmt.Fprintln(&b, "PROXY_HTTP_ADDR=:8000")
		fmt.Fprintln(&b, "PROXY_HTTPS_ADDR=")
	} else {
		fmt.Fprintf(&b, "FRONTEND_BASE_URL=https://%s\n", a.Domain)
		fmt.Fprintln(&b, "HTTP_ADDR=:8080")
		fmt.Fprintln(&b, "PROXY_HTTP_ADDR=:80")
		fmt.Fprintln(&b, "PROXY_HTTPS_ADDR=:443")
	}
	fmt.Fprintln(&b, "DATABASE_DRIVER=sqlite")
	fmt.Fprintf(&b, "DATABASE_PATH=%s\n", filepath.Join(a.DataDir, "portlyn.db"))
	fmt.Fprintf(&b, "CERTIFICATE_STORAGE_DIR=%s\n", filepath.Join(a.DataDir, "certificates"))
	fmt.Fprintf(&b, "ADMIN_EMAIL=%s\n", a.AdminEmail)
	fmt.Fprintf(&b, "ADMIN_PASSWORD=%s\n", a.AdminPassword)
	fmt.Fprintf(&b, "ACME_EMAIL=%s\n", a.ACMEEmail)
	if a.HTTPSEnabled && !local {
		fmt.Fprintln(&b, "ACME_ENABLED=true")
		fmt.Fprintln(&b, "ACME_LEADER=true")
		fmt.Fprintln(&b, "REDIRECT_HTTP_TO_HTTPS=true")
	} else {
		fmt.Fprintln(&b, "ACME_ENABLED=false")
	}
	if a.DNSProvider != "" {
		fmt.Fprintf(&b, "ACME_DNS_PROVIDER=%s\n", a.DNSProvider)
		switch a.DNSProvider {
		case "cloudflare":
			fmt.Fprintf(&b, "ACME_DNS_CLOUDFLARE_API_TOKEN=%s\n", a.DNSToken)
		case "hetzner":
			fmt.Fprintf(&b, "ACME_DNS_HETZNER_API_TOKEN=%s\n", a.DNSToken)
		case "digitalocean":
			fmt.Fprintf(&b, "ACME_DNS_DIGITALOCEAN_API_TOKEN=%s\n", a.DNSToken)
		}
	}
	fmt.Fprintln(&b, "NODE_REQUIRE_HTTPS=true")
	fmt.Fprintln(&b, "BOOTSTRAP_ADMIN_ENABLED=true")
	if a.BreakGlassEnabled && strings.TrimSpace(a.BreakGlassToken) != "" {
		fmt.Fprintln(&b, "BREAK_GLASS_ENABLED=true")
		fmt.Fprintf(&b, "BREAK_GLASS_TOKEN=%s\n", a.BreakGlassToken)
	}
	fmt.Fprintln(&b, "LOG_LEVEL=info")
	fmt.Fprintln(&b)
	for _, key := range generatedSecretKeys {
		fmt.Fprintf(&b, "%s=%s\n", key, secrets[key])
	}
	fmt.Fprint(&b, optionalEnvReference)
	return b.String(), nil
}

func prompt(reader *bufio.Reader, label, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", label, defaultValue)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue
	}
	return line
}

func yesNo(reader *bufio.Reader, label string, defaultYes bool) bool {
	suffix := "[Y/n]"
	if !defaultYes {
		suffix = "[y/N]"
	}
	fmt.Printf("%s %s: ", label, suffix)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes
	}
	return line == "y" || line == "yes"
}

func randomURLSafe(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

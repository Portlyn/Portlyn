package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
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
	force := flags.Bool("force", false, "overwrite existing output file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*output); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", *output)
	}

	answers := initAnswers{
		Domain:        strings.TrimSpace(*domainFlag),
		AdminEmail:    strings.TrimSpace(*adminEmailFlag),
		AdminPassword: *adminPasswordFlag,
		ACMEEmail:     strings.TrimSpace(*acmeEmailFlag),
		DataDir:       strings.TrimSpace(*dataDir),
		DNSProvider:   strings.ToLower(strings.TrimSpace(*dnsProviderFlag)),
		DNSToken:      strings.TrimSpace(*dnsTokenFlag),
		HTTPSEnabled:  *acmeEnabled,
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
		fmt.Printf("\nGenerated admin password: %s\n", answers.AdminPassword)
		fmt.Printf("Store it now; it is only shown once.\n")
	}
	fmt.Printf("\nStart the server with:\n  portlyn\n")
	return nil
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

func buildEnvFile(a initAnswers) (string, error) {
	secrets := map[string]string{}
	for _, key := range []string{
		"JWT_SECRET",
		"JWT_SIGNING_SECRET",
		"SESSION_BRIDGE_SECRET",
		"OIDC_STATE_SECRET",
		"MFA_ENCRYPTION_SECRET",
		"CSRF_SECRET",
		"DATA_ENCRYPTION_SECRET",
		"AUDIT_HMAC_SECRET",
	} {
		s, err := randomURLSafe(48)
		if err != nil {
			return "", err
		}
		secrets[key] = s
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by `portlyn init` on %s\n", strings.TrimSpace(a.Domain))
	fmt.Fprintf(&b, "FRONTEND_BASE_URL=https://%s\n", a.Domain)
	fmt.Fprintln(&b, "HTTP_ADDR=:8080")
	fmt.Fprintln(&b, "PROXY_HTTP_ADDR=:80")
	fmt.Fprintln(&b, "PROXY_HTTPS_ADDR=:443")
	fmt.Fprintln(&b, "DATABASE_DRIVER=sqlite")
	fmt.Fprintf(&b, "DATABASE_PATH=%s\n", filepath.Join(a.DataDir, "portlyn.db"))
	fmt.Fprintf(&b, "CERTIFICATE_STORAGE_DIR=%s\n", filepath.Join(a.DataDir, "certificates"))
	fmt.Fprintf(&b, "ADMIN_EMAIL=%s\n", a.AdminEmail)
	fmt.Fprintf(&b, "ADMIN_PASSWORD=%s\n", a.AdminPassword)
	fmt.Fprintf(&b, "ACME_EMAIL=%s\n", a.ACMEEmail)
	if a.HTTPSEnabled {
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
	fmt.Fprintln(&b, "LOG_LEVEL=info")
	fmt.Fprintln(&b)
	for key, value := range secrets {
		fmt.Fprintf(&b, "%s=%s\n", key, value)
	}
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

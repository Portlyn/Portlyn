# Installation and configuration

Portlyn ships as two binaries: a hub (`portlyn`) and an optional node agent (`portlyn-nodeagent`). The hub can run from a single binary on a Linux host or via Docker Compose. The node agent runs on machines behind NAT or CGNAT and dials out to the hub over WireGuard.

## Try it locally (no domain, no TLS, no root)

To kick the tyres before any real deployment:

```bash
PORTLYN_DOMAIN=localhost ./portlyn init --non-interactive
./portlyn
```

The `localhost` domain makes `init` write a local profile: plain HTTP, ACME disabled, the dashboard on `http://localhost:8000` (an unprivileged port, so no `sudo`). The admin account is `admin@localhost`; read its generated password with `grep '^ADMIN_PASSWORD=' .env`.

Portlyn's config validation is strict on purpose (no non-localhost URL without TLS, unique 32+ char secrets, and so on). If a start-up ever fails, run `./portlyn doctor` to see **every** problem at once with a fix hint instead of one at a time.

## Verify a release

Every tagged release is signed with Cosign keyless via Sigstore. Verify before running anything in production.

```bash
curl -L https://github.com/portlyn/Portlyn/releases/latest/download/portlyn-linux-amd64 -o portlyn
curl -L https://github.com/portlyn/Portlyn/releases/latest/download/checksums.txt     -o checksums.txt
curl -L https://github.com/portlyn/Portlyn/releases/latest/download/checksums.txt.sig -o checksums.txt.sig
curl -L https://github.com/portlyn/Portlyn/releases/latest/download/checksums.txt.pem -o checksums.txt.pem

sha256sum -c checksums.txt --ignore-missing

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/[Pp]ortlyn/[Pp]ortlyn' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  checksums.txt
```

## One line install (recommended)

The hub ships an install script that downloads the binary, verifies its SHA-256 checksum and Cosign signature, creates a `portlyn` system user, installs the systemd unit, and (when domain/email are provided) runs `portlyn init` non-interactively:

```bash
curl -fsSL https://raw.githubusercontent.com/portlyn/Portlyn/main/scripts/install-hub.sh \
  | sudo PORTLYN_DOMAIN=portlyn.example.com PORTLYN_ADMIN_EMAIL=admin@example.com sh
```

Run without the environment variables to install the binary and unit only, then configure interactively. Signature verification needs no external tools: if `cosign` is present it is used, otherwise the freshly downloaded (and checksum-verified) binary verifies the release signature itself via the embedded Sigstore trust root (`portlyn verify-release`). Pass `ALLOW_UNSIGNED=1` to skip signature verification (checksum only).

## Single binary (manual)

```bash
chmod +x portlyn
sudo mv portlyn /usr/local/bin/portlyn
sudo portlyn init
sudo portlyn
```

`portlyn init` generates secrets, writes a `.env` file, prepares the data directory, and creates the admin account. Existing `.env` files are preserved unless you pass `--force`.

The systemd unit is shipped at [`scripts/portlyn.service`](../scripts/portlyn.service). It expects the binary at `/usr/local/bin/portlyn` and the `.env` at `/var/lib/portlyn/.env`.

### Non-interactive setup (CI / config management)

`portlyn init --non-interactive` never prompts. Every value comes from a flag or environment variable, and the admin password is auto-generated (and printed once) if not supplied:

```bash
portlyn init --non-interactive \
  --domain portlyn.example.com \
  --admin-email admin@example.com \
  --admin-password "$(openssl rand -base64 24)" \
  --acme-email ops@example.com \
  --dns-provider cloudflare --dns-token "$CF_TOKEN"
```

Equivalent environment variables: `PORTLYN_DOMAIN`, `PORTLYN_ADMIN_EMAIL`, `PORTLYN_ADMIN_PASSWORD`, `PORTLYN_ACME_EMAIL`, `PORTLYN_DNS_PROVIDER`, `PORTLYN_DNS_TOKEN`, and `PORTLYN_NONINTERACTIVE=true`.

### Validate the configuration

`portlyn doctor` (alias `portlyn config check`) validates the full environment and lists **every** problem at once with a fix hint, instead of failing on the first one. It exits non-zero if any blocking error remains, so it works as a pre-start gate in CI:

```bash
portlyn doctor
```

## Docker Compose

```bash
git clone https://github.com/portlyn/Portlyn.git
cd Portlyn
cp .env.docker.example .env.docker
# edit secrets and admin credentials in .env.docker
docker compose --env-file .env.docker up -d
```

The default `docker-compose.yml` pulls `ghcr.io/portlyn/portlyn:latest`. Pin a specific tag with `PORTLYN_IMAGE_TAG=v1.2.3`.

If the pull fails with `denied` / `unauthorized`, the GHCR packages are private for that build. Either authenticate (`docker login ghcr.io`) or build the images locally with the dev overlay instead of pulling them:

```bash
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

The bundled PostgreSQL connects over the private Compose network with `sslmode=disable`. Portlyn treats a plaintext link to a private or container-local database host as acceptable (it emits a warning, not an error). For an external database, use `sslmode=require` or stronger. The config validator rejects `sslmode=disable` to a public host.

## First boot and TLS onboarding

Portlyn is reachable immediately after start, before any real certificate exists:

1. **Install and start.** The hub generates a short-lived self-signed bootstrap certificate on demand for whichever hostname (or server IP) it is asked for.
2. **Open the dashboard** at `https://<your-domain>` and accept the temporary certificate warning. Log in with the admin account from `init`.
3. **Configure a DNS-01 provider** under **Certificates → DNS providers** (or seed it from the environment, below).
4. **Request a certificate.** Once issued, the hub serves the real certificate automatically and the warning disappears.

### Reaching the dashboard by IP (no DNS yet)

For a Proxmox/Portainer-style flow where you first reach the UI at `https://<server-ip>` and configure the domain from there, set `BOOTSTRAP_ADMIN_ENABLED=true` (the default from `portlyn init`) **and** `BOOTSTRAP_ADMIN_ALLOW_REMOTE=true`. The hub then serves the admin UI on the raw server IP with a matching self-signed certificate, so you can log in, add your domain and DNS token, and let Portlyn fetch the real certificate.

This exposes the admin login on the server IP to any client that can reach it, so turn it back off (`BOOTSTRAP_ADMIN_ALLOW_REMOTE=false`) once the domain and real certificate are active. Left at its default (`false`), the bootstrap admin UI is only reachable from the local host (loopback/SSH tunnel).

The bootstrap certificate is also served when a client connects without SNI. When testing with a spoofed `Host` header, pass SNI explicitly so the right certificate is selected:

```bash
curl --resolve portlyn.example.com:443:<hub-ip> https://portlyn.example.com/
```

### Seed a DNS provider from the environment

For a fully automated install that obtains a real certificate on first boot, seed the DNS-01 provider via the environment. The provider is created only if none exists yet (the database wins afterwards):

```env
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
```

Supported providers and their credential variables:

- Cloudflare: `ACME_DNS_CLOUDFLARE_API_TOKEN`
- Hetzner: `ACME_DNS_HETZNER_API_TOKEN`
- DigitalOcean: `ACME_DNS_DIGITALOCEAN_API_TOKEN`
- Route53: `ACME_DNS_ROUTE53_ACCESS_KEY_ID` and `ACME_DNS_ROUTE53_SECRET_ACCESS_KEY`, plus optional `ACME_DNS_ROUTE53_SESSION_TOKEN`, `ACME_DNS_ROUTE53_REGION`, `ACME_DNS_ROUTE53_HOSTED_ZONE_ID`, `ACME_DNS_ROUTE53_PROFILE`

`portlyn init` writes these lines for you when you pass `--dns-provider` and `--dns-token`.

## Node agent

The node agent runs on the machine behind NAT or CGNAT. The hub exposes a one line install script that downloads the binary, verifies it, and installs a systemd unit.

```bash
curl -fsSL https://<your-hub-host>/install.sh | sudo sh -s -- --token <ENROLL_TOKEN>
```

Generate enrollment tokens in the admin UI under **Nodes**. Tokens are single use.

## Update

```bash
sudo portlyn update              # download latest, verify SHA-256 and cosign, atomic swap, restart
sudo portlyn update --check      # only check whether a newer release exists
sudo portlyn update --version v1.2.3
sudo portlyn update --no-restart # swap the binary but leave the service alone
```

The same command exists for the node agent: `sudo portlyn-nodeagent update`. Backups are written next to the binary as `<path>.bak`. There are no automatic update checks. The CLI only contacts GitHub when you run the command.

## Deployment topologies

Which ACME challenge and which proxy settings you need depends on how traffic reaches the hub.

### A) Direct on a public IP

The hub has a public IP and inbound `:80`/`:443` are reachable. Point an `A`/`AAAA` record at it.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
REDIRECT_HTTP_TO_HTTPS=true
```

HTTP-01 works out of the box (Let's Encrypt reaches `:80`). No `TRUSTED_PROXY_CIDRS` needed, since the hub sees real client IPs directly. DNS-01 is optional (useful for wildcards).

### B) Behind the Cloudflare proxy (orange cloud)

Cloudflare terminates TLS and forwards to the hub, so the client IP arrives in a forwarded header and HTTP-01 is intercepted by Cloudflare.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
TRUSTED_PROXY_CIDRS=173.245.48.0/20,103.21.244.0/22,...   # Cloudflare ranges
NODE_TRUST_FORWARDED_PROTO=true
```

Use **DNS-01** (Cloudflare provider) so issuance does not depend on inbound `:80`. Set `TRUSTED_PROXY_CIDRS` to Cloudflare's published ranges so the hub trusts `X-Forwarded-For`/`-Proto` from Cloudflare only. Set the Cloudflare SSL mode to *Full (strict)*.

### C) Behind NAT/CGNAT or another load balancer (no inbound)

No inbound port reaches the hub (home lab, CGNAT), so HTTP-01 is impossible. This is the node-agent scenario: the machine dials out over WireGuard.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
```

**DNS-01 only.** With a DNS provider configured, the hub also enqueues the admin/dashboard certificate over DNS-01 automatically, so the first certificate succeeds without any inbound connectivity.

## Configuration

All runtime settings are environment driven. `portlyn init` writes a complete `.env` with strong random secrets.

Minimum production set:

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=use a long random value
ACME_ENABLED=true
ACME_EMAIL=ops@example.com
NODE_REQUIRE_HTTPS=true
REQUIRE_MFA_FOR_ADMINS=true

JWT_SECRET=...
JWT_SIGNING_SECRET=...
SESSION_BRIDGE_SECRET=...
OIDC_STATE_SECRET=...
MFA_ENCRYPTION_SECRET=...
CSRF_SECRET=...
DATA_ENCRYPTION_SECRET=...
AUDIT_HMAC_SECRET=...
```

### Database backends

PostgreSQL (default for Docker Compose):

```env
DATABASE_DRIVER=postgres
DATABASE_URL=postgres://user:password@db-host:5432/portlyn?sslmode=require
```

SQLite (default for the standalone binary):

```env
DATABASE_DRIVER=sqlite
DATABASE_PATH=/data/portlyn.db
DATABASE_URL=
```

### Production checklist

- `ALLOW_INSECURE_DEV_MODE=false`
- `OTP_RESPONSE_INCLUDES_CODE=false`
- `REDIRECT_HTTP_TO_HTTPS=true` once TLS is active
- `REQUIRE_MFA_FOR_ADMINS=true` and enroll every admin
- Distinct random secrets for each secret variable
- `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` point at the real public hostname
- `TRUSTED_PROXY_CIDRS` configured if Portlyn sits behind another L7 proxy
- External PostgreSQL connection verified from inside the Portlyn container

See [PRODUCTION-HARDENING.md](PRODUCTION-HARDENING.md) for the full hardening guide.

## API tokens (CI and automation)

Human logins use a session cookie plus CSRF and MFA. For scripts and CI, create an **API token** under **Access → API Tokens** (admin only). A token is shown once, carries a role (`viewer` = read-only, `admin` = full access), and can be given an expiry. Send it as a bearer token; it is exempt from CSRF and MFA and can be revoked at any time:

```bash
curl -H "Authorization: Bearer plyn_..." https://portlyn.example.com/api/v1/services
```

Tokens are stored only as a SHA-256 hash. Revoking one takes effect immediately.

## Observability

- Structured logs cover API and proxy requests with request id, method, path, host, latency, status, user context, matched service, access mode and method, and outcome.
- Metrics at `GET /metrics` (admin authenticated unless `METRICS_PUBLIC=true`).
- Health endpoints: `GET /livez`, `GET /readyz`, `GET /healthz`.
- Bundled Grafana dashboards in [`deploy/grafana/dashboards/`](../deploy/grafana/dashboards/).

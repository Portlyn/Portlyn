<p align="center">
  <img src="assets/logo.png" alt="Portlyn logo" width="120" />
</p>

<h1 align="center">Portlyn</h1>

<p align="center">
  An identity aware reverse proxy with a built in WireGuard tunnel.
  One Go binary that fronts your services with TLS, per route auth, and a tunnel to machines behind NAT or CGNAT.
</p>

<p align="center">
  <a href="https://github.com/invaliduser231/Portlyn/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/invaliduser231/Portlyn/ci.yml?branch=main&label=ci"></a>
  <a href="https://github.com/invaliduser231/Portlyn/releases"><img alt="Release" src="https://img.shields.io/github/v/release/invaliduser231/Portlyn?include_prereleases&sort=semver"></a>
  <img alt="Go version" src="https://img.shields.io/badge/go-1.26-00ADD8">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <a href="#what-portlyn-does">What it does</a> ·
  <a href="#install">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#security-model">Security model</a> ·
  <a href="#develop">Develop</a> ·
  <a href="docs/">Docs</a>
</p>

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="Portlyn admin dashboard" width="420" />
  <img src="assets/screenshots/route-login.png" alt="What your users see at a protected route" width="420" />
  <br />
  <em>Admin dashboard (left) and what end users see at a protected route (right).</em>
</p>

<p align="center">
  <img src="assets/gif/hero.gif" alt="Add a service in Portlyn and reach it on your own domain" width="820" />
  <br />
  <em>Add a service in the admin UI and reach it on your own domain.</em>
</p>

## What Portlyn does

Three things, well.

**1. Expose a service from a machine behind NAT or CGNAT** over HTTPS on your own domain. The node dials out to the hub over WireGuard, so no inbound port at the home end.

**2. Put auth in front of any route**. Full SSO session, OIDC, a shared PIN, a one off email code, or none. Per route, set in the UI, no config file edits.

<p align="center">
  <img src="assets/gif/auth-pin.gif" alt="Per route PIN auth in front of a service" width="820" />
</p>

**3. Manage TLS certificates** without touching Let's Encrypt directly. ACME with HTTP-01 and DNS-01 (Cloudflare, Hetzner, Route 53, DigitalOcean), wildcards, multi SAN, auto renew.

Also in the box: TOTP and passkey MFA, OIDC SSO with role claim mapping, hash chained audit log, rate limits, GeoIP allow and block, CrowdSec integration, signed audit webhooks, Prometheus metrics, Grafana dashboards.

## What it is not

So you know before you install:

* **Not horizontally scaled.** Single hub for now. HA is on the roadmap; it is a homelab and small team tool first.
* **Not a node mesh.** Hub and spoke only. Nodes do not talk to each other directly.
* **Not a Cloudflare Tunnel drop in.** The node dials out to your hub, not to Cloudflare. You still need a public IP or a VPS for the hub.
* **Not at kernel WireGuard throughput.** Userspace tunnel reaches roughly 80 percent of kernel WG. Use kernel WG yourself if you saturate links above 1 Gbps.
* **No native WAF rules bundled.** CrowdSec integration is pull based against LAPI. Geo and IP rules are first class; deep request inspection is not.
* **Young ecosystem.** Fewer third party plugins than the Traefik or Caddy world.

## Install

Prebuilt, signed binaries are published on every tagged release. Verify before you run anything.

### Single binary

```bash
# Download
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/portlyn-linux-amd64 -o portlyn
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt     -o checksums.txt
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt.sig -o checksums.txt.sig
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt.pem -o checksums.txt.pem

# Verify checksum
sha256sum -c checksums.txt --ignore-missing

# Verify the release was built by this repository's GitHub Actions workflow
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/invaliduser231/Portlyn' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  checksums.txt

# Run the interactive setup wizard
chmod +x portlyn
./portlyn init
./portlyn
```

The wizard generates secrets, writes a `.env` file, prepares the data directory, and creates the admin account. Re run it any time; existing `.env` files are preserved unless `--force` is set.

### Docker (published image)

```bash
git clone https://github.com/invaliduser231/Portlyn.git
cd Portlyn
cp .env.docker.example .env.docker
# edit secrets and admin credentials
docker compose --env-file .env.docker up -d
```

The default `docker-compose.yml` pulls the published image from `ghcr.io/invaliduser231/portlyn`. No local build needed. Pin a specific tag with `PORTLYN_IMAGE_TAG=v1.2.3`.

### Update

```bash
sudo portlyn update              # download latest, verify SHA-256 and cosign, atomic swap, restart
sudo portlyn update --check      # only check whether a newer release exists
sudo portlyn update --version v1.2.3
sudo portlyn update --no-restart # swap the binary but leave the service alone
```

Same command exists for the node agent: `sudo portlyn-nodeagent update`. Backups land next to the binary as `<path>.bak`. No automatic update checks happen anywhere; the CLI only reaches GitHub when you invoke it.

## How it works

```mermaid
flowchart LR
    U[User browser]:::ext
    N[Remote node behind CGNAT]:::ext

    subgraph Hub [Portlyn hub. single Go binary]
        direction TB
        P[Reverse proxy and policy engine]
        A[Auth: session, OIDC, PIN, email code, MFA]
        G[GeoIP and CrowdSec]
        W[Userspace WireGuard via gVisor]
        L[Hash chained audit log]
        AC[ACME and certmagic]
    end

    subgraph Local [Local upstreams]
        B1[Gitea]
    end
    subgraph Remote [Upstreams on the node]
        B2[Home Assistant]
        B3[Jellyfin]
    end

    H[(Webhooks: Slack, Discord, ntfy, JSON)]:::ext

    U -->|HTTPS| P
    P --> A
    P --> G
    P -->|loopback| B1
    P -->|tunnel| W
    W <-->|WireGuard UDP| N
    N --> B2
    N --> B3
    P --> L
    L --> H
    AC --> P

    classDef ext fill:#1f2329,stroke:#3b424d,color:#d9dde3
```

* The hub is a single Go binary. SQLite by default, PostgreSQL optional.
* The node agent is a second small Go binary. It dials the hub over WireGuard, never listens for inbound. Userspace WG via `wireguard-go` plus gVisor netstack means no kernel module and no root on the node.
* The admin UI is a Next.js app embedded into the same binary via `go:embed`. One process to deploy.
* Per service routes match by domain and path, run policy checks (auth, GeoIP, CrowdSec, IP lists, access windows), then proxy to a local upstream or to the node over the tunnel.

<p align="center">
  <img src="assets/screenshots/service-detail.png" alt="Service detail page for a local service with PIN auth" width="420" />
  <img src="assets/screenshots/node-detail.png" alt="Node detail page with WireGuard handshake age" width="420" />
  <br />
  <em>Service detail (left): a local service routed without a tunnel, gated by PIN. Node detail (right): tunnel state with live WireGuard handshake age.</em>
</p>

## Security model

What Portlyn protects and what it does not, stated plainly.

### What it protects

* **Origin services from direct internet exposure.** Inbound traffic terminates at the hub. The node never opens a listener.
* **Unauthenticated access to a route.** Each route has an access mode (`public`, `authenticated`, `restricted`) and an access method (session, OIDC, PIN, email code). Mode `restricted` requires both authentication and policy (groups, IP, GeoIP, access windows).
* **Credential theft via weak factors.** Passkeys, TOTP, OIDC SSO, account lockout, rate limited login and OTP endpoints, optional admin MFA enforcement.
* **Audit trail tampering.** Hash chained audit log with previous hash verification.

<p align="center">
  <img src="assets/screenshots/audit-log.png" alt="Hash chained audit log with granted and denied events" width="720" />
</p>

* **Supply chain.** Releases are reproducible from GitHub Actions, signed with Cosign keyless, and verified by the binary on self update via sigstore-go with the embedded TUF trust root.

### What it does not protect

* **The application behind it.** A vulnerable upstream is still vulnerable. Portlyn is not a WAF and does not inspect request bodies.
* **Multi tenant isolation.** Single tenant model. All admins see all services.
* **Side channels at the node.** A node compromise lets the attacker reach what that node is authorized to forward to. Use per node scoping.
* **DDoS at L3 or L4.** The hub absorbs L7 abuse with rate limits and CrowdSec lists, but you still want a CDN or a beefier upstream for volumetric attacks.

### Threat model boundary

| Asset                | In scope                                            | Out of scope                                        |
| -------------------- | --------------------------------------------------- | --------------------------------------------------- |
| Admin session        | CSRF, replay, MFA bypass, session fixation          | Local malware on the admin's machine                |
| Route auth (PIN etc) | Brute force, replay, cross host cookie smuggling    | Phishing the PIN out of a legitimate user           |
| Tunnel               | Tunnel auth, peer key collision, replay, key reuse  | A compromised node's outbound destinations          |
| Certificates         | ACME validation hijack via the proxy, key at rest   | DNS account takeover at your registrar              |
| Supply chain         | Release artifact integrity                          | Compromise of GitHub itself or your local toolchain |

### Defaults you should know

* `ALLOW_INSECURE_DEV_MODE=false` (rejected outright in production)
* `REQUIRE_MFA_FOR_ADMINS=true` recommended; once set, admins cannot dismiss the bootstrap wizard
* `NODE_REQUIRE_HTTPS=true`, `NODE_TRUST_FORWARDED_PROTO=true`
* `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128` (extend it if you sit behind another L7 proxy)
* HttpOnly cookies, `Secure` outside dev mode, `SameSite=Lax` for sessions, `SameSite=Strict` for refresh tokens
* AES-256-GCM at rest for DNS provider creds and MFA secrets, Argon2id key derivation
* Self update verifies SHA-256 plus full Sigstore certificate chain via sigstore-go, not just the signature

Report a vulnerability via [SECURITY.md](SECURITY.md).

## Comparison

Closest projects, honest pros and cons.

|                              | Portlyn                      | Pangolin              | Traefik + Authelia       |
| ---------------------------- | ---------------------------- | --------------------- | ------------------------ |
| Deploy surface               | 1 hub binary + 1 node agent  | 1 hub binary + Newt   | 3 or more services       |
| Built in tunnel              | Userspace WireGuard          | Userspace WireGuard   | None (use Tailscale etc) |
| Auth model                   | Per route, in process        | Per route, in process | Sidecar (Authelia)       |
| Passkeys                     | Yes                          | Yes                   | Via Authelia             |
| ACME wildcard DNS-01         | Yes                          | Yes                   | Yes                      |
| Hash chained audit log       | Yes                          | No                    | No                       |
| Released, signed binaries    | Yes (Cosign keyless)         | Yes                   | Yes                      |
| Ecosystem maturity           | Young                        | Growing               | Mature, big community    |
| License                      | MIT                          | AGPL-3.0              | MIT / Apache 2 mix       |

Portlyn's bet: one binary, one admin UI, one config story. The cost is a smaller ecosystem and fewer plugins than the Traefik world.

## Configuration

All runtime settings are environment driven. `portlyn init` writes a complete `.env` with strong random secrets. Minimum production set:

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=use a long random value
ACME_ENABLED=true
ACME_EMAIL=ops@example.com
NODE_REQUIRE_HTTPS=true
REQUIRE_MFA_FOR_ADMINS=true

# Generated by portlyn init or out of band
JWT_SECRET=...
JWT_SIGNING_SECRET=...
SESSION_BRIDGE_SECRET=...
OIDC_STATE_SECRET=...
MFA_ENCRYPTION_SECRET=...
CSRF_SECRET=...
DATA_ENCRYPTION_SECRET=...
```

<details>
<summary><strong>Database backends</strong></summary>

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

</details>

<details>
<summary><strong>Production checklist</strong></summary>

* `ALLOW_INSECURE_DEV_MODE=false`
* `OTP_RESPONSE_INCLUDES_CODE=false`
* `REDIRECT_HTTP_TO_HTTPS=true` once TLS is active
* `REQUIRE_MFA_FOR_ADMINS=true` and enroll every admin
* Distinct random secrets for each secret variable
* `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` point at the real public hostname
* `TRUSTED_PROXY_CIDRS` configured if you sit behind another L7 proxy
* External PostgreSQL connection verified from inside the Portlyn container

</details>

## Develop

The default `docker-compose.yml` pulls published images so a fresh clone runs without a build step. To hack on the code:

```bash
# Backend
go run ./cmd/server

# Frontend dev server (proxies /api to the Go server on :8080)
cd frontend
npm install
npm run dev
```

To build images locally from source (instead of pulling):

```bash
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Source build of the single binary with the frontend embedded:

```bash
cd frontend
npm ci
PORTLYN_STATIC_EXPORT=1 npm run build
rm -rf ../cmd/server/frontend_dist
mv out ../cmd/server/frontend_dist
cd ..
go build -trimpath -ldflags="-s -w" -o portlyn ./cmd/server
```

## Testing

Backend:

```bash
go vet ./...
go test -race ./...
gofmt -l $(find . -type f -name '*.go' -not -path './.gomodcache/*' -not -path './cmd/server/frontend_dist/*')
govulncheck ./...
```

Frontend:

```bash
cd frontend
npm ci
npx tsc --noEmit
npm test
PORTLYN_STATIC_EXPORT=1 npm run build
```

End to end (Playwright, scaffold):

```bash
cd frontend
npx playwright install --with-deps chromium
PLAYWRIGHT_BASE_URL=http://localhost:3000 npm run e2e
```

## Observability

Structured logs cover API and proxy requests with request id, method, path, host, latency, status, user context, matched service, access mode, access method, and outcome.

Metrics at `GET /metrics` (admin authenticated unless `METRICS_PUBLIC=true`): API and proxy latency histograms, request totals by outcome, auth attempts and rate limit hits, ACME results, cert expiry gauges, tunnel peer counts and handshake ages, DB ping latency.

Health: `GET /livez`, `GET /readyz`, `GET /healthz`. Admin overview at `GET /api/v1/system/overview`.

Bundled Grafana assets:

* [`deploy/grafana/dashboards/portlyn-overview.json`](deploy/grafana/dashboards/portlyn-overview.json)
* [`deploy/grafana/provisioning/dashboards/portlyn.yml`](deploy/grafana/provisioning/dashboards/portlyn.yml)
* [`deploy/grafana/provisioning/datasources/loki.yml`](deploy/grafana/provisioning/datasources/loki.yml)

## Roadmap

Honest list of what's not in 1.0 yet, in rough priority order. No dates promised.

1. Country picker UI fed by the actual GeoLite2 catalog (today the country code is a free text field)
2. Pluggable secret stores so JWT and data encryption keys can live in Vault or AWS KMS instead of `.env`
3. Kernel WireGuard mode for hubs that need to saturate 1 Gbps+ links
4. HA hub deployment (shared cert storage in PostgreSQL exists; leader election and session storage are missing)

If you want to influence what's next, open a Discussion on the repo. Track the work on the [issues page](https://github.com/invaliduser231/Portlyn/issues).

## Documentation

* [Security Policy](SECURITY.md)
* [Licensing](LICENSING.md)
* [Contributing](CONTRIBUTING.md)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Production Hardening](docs/PRODUCTION-HARDENING.md)
* [Release Process](docs/RELEASE.md)
* [Backup and Restore](docs/BACKUP-RESTORE.md)
* [HA Deployment](docs/HA-DEPLOYMENT.md)
* [Secret Rotation](docs/SECRET-ROTATION.md)
* [Break Glass Recovery](docs/RECOVERY-BREAKGLASS.md)
* [OpenAPI specification](openapi.yaml)
* [Changelog](CHANGELOG.md)

## Privacy

No telemetry. No analytics SDK, no phone home, no automatic update check. The only outbound traffic comes from features you explicitly configure (ACME, webhooks, OIDC, DNS provider APIs, CrowdSec LAPI).

## License

Portlyn is released under the [MIT License](LICENSE). See [LICENSING.md](LICENSING.md) for a short summary.

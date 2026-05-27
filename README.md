<p align="center">
  <img src="assets/logo.png" alt="Portlyn logo" width="120" />
</p>

<h1 align="center">Portlyn</h1>

<p align="center">
  A self-hosted reverse proxy and zero trust control plane for homelabs and small teams.
  One binary covers routing, identity, certificates, audit, and a built-in WireGuard tunnel.
</p>

<p align="center">
  <a href="https://github.com/invaliduser231/Portlyn/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/invaliduser231/Portlyn/ci.yml?branch=main&label=ci"></a>
  <a href="https://github.com/invaliduser231/Portlyn/releases"><img alt="Release" src="https://img.shields.io/github/v/release/invaliduser231/Portlyn?include_prereleases&sort=semver"></a>
  <img alt="Go version" src="https://img.shields.io/badge/go-1.26-00ADD8">
  <img alt="Node version" src="https://img.shields.io/badge/node-24-339933">
  <a href="LICENSING.md"><img alt="License" src="https://img.shields.io/badge/license-see%20LICENSING.md-lightgrey"></a>
  <img alt="Self hosted" src="https://img.shields.io/badge/self--hosted-yes-success">
</p>

<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#security">Security</a> ·
  <a href="#development">Development</a> ·
  <a href="docs/">Docs</a>
</p>

## Overview

Portlyn fronts your self hosted services with a single admin plane.
It terminates TLS, applies access policy, performs identity checks, optionally tunnels traffic to a remote node over WireGuard, then proxies to the upstream.
The backend is a Go binary; the admin UI is a Next.js single page app.
Both ship as one binary in static export mode, or as a Docker stack with PostgreSQL, Loki, and Grafana.

Portlyn is built to replace a Traefik plus Authentik plus Crowdsec plus WireGuard stack with one process and one admin surface.

## Table of Contents

1. [Highlights](#highlights)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Certificates](#certificates)
7. [Security](#security)
8. [Observability](#observability)
9. [Development](#development)
10. [Testing](#testing)
11. [Roadmap](#roadmap)
12. [Documentation](#documentation)
13. [Repository layout](#repository-layout)
14. [License](#license)

## Highlights

* Userspace WireGuard tunnel in the same process. No kernel module, no root, no `wg-quick` glue. Backed by `wireguard-go` and gVisor netstack.
* Passkeys (WebAuthn) and TOTP in parallel. Touch ID, Windows Hello, hardware keys.
* Magic link sharing for single use, time bound access without an account.
* Exposure scanner that grades each service from 0 to 100 across DNS, TLS, HSTS, CSP, X-Frame-Options, redirect, and auth enforcement.
* GeoIP allow and block lists per service. CrowdSec LAPI client built in.
* Audit log with a SHA-256 hash chain. Webhooks for Slack, Discord, ntfy, or any HTTP endpoint, signed with HMAC-SHA256.
* ACME with `http-01` and `dns-01`. Wildcards and multi SAN. Cloudflare, Hetzner DNS, Route 53, and DigitalOcean.
* Single binary deploy with embedded frontend via `go:embed`, or full Docker Compose stack with observability included.

## Features

### Routing and access control

* Per service routes by domain and path
* Access modes: `public`, `authenticated`, `restricted`
* Access methods: session, OIDC only, PIN, email code
* User groups and service groups for reusable policy
* Access windows with timezone aware weekday and time ranges
* IP allow and block lists per service
* GeoIP allow and block lists per service
* Risk assessment before save with confirm by type for high risk changes

### Identity

* Local password login with bcrypt
* OIDC single sign on with role claim mapping
* TOTP MFA with recovery codes
* WebAuthn (passkeys) parallel to TOTP
* Magic link for temporary access
* Email code based one time passwords for routes that do not need accounts

### Certificates

* ACME `http-01` and `dns-01`
* Wildcard certificates through `dns-01`
* Multi SAN
* Let's Encrypt production and staging
* Auto renew, manual renew, retry, sync status, PEM import
* DNS provider credentials encrypted at rest

### Tunnel

* Userspace WireGuard server inside the same process
* Per node keypair, dynamic peer add and revoke
* Direct dial from the proxy into the tunnel via gVisor netstack
* Node agent fetches its config and writes it to disk
* Heartbeat reports handshake age and byte counters

### Audit and operations

* Hash chained audit log, tamper evident
* Webhook fan out to Slack, Discord, ntfy, generic JSON, signed with HMAC
* Exposure scanner with score and findings per service
* Diagnostics endpoint that explains a simulated request step by step
* Access tester page for what if analysis
* Health endpoints, Prometheus metrics, Grafana dashboards

<details>
<summary><strong>Supported DNS providers</strong></summary>

* Cloudflare
* Hetzner DNS
* AWS Route 53
* DigitalOcean DNS

</details>

<details>
<summary><strong>Admin UI sections</strong></summary>

* Services
* Domains
* Nodes
* Tunnel
* Certificates
* DNS providers
* Groups
* Service groups
* Users
* Audit logs
* Audit webhooks
* Access tester
* Passkeys
* System overview
* Settings

</details>

## Architecture

```mermaid
flowchart LR
    U[User browser]:::ext
    C[Remote node behind CGNAT]:::ext

    subgraph Portlyn [Portlyn single binary]
        direction TB
        P[Reverse proxy and policy engine]
        A[Auth: OIDC, TOTP, passkeys, magic link]
        G[GeoIP and CrowdSec]
        W[Userspace WireGuard via gVisor]
        S[Exposure scanner]
        L[Hash chained audit log]
        AC[ACME and cert magic]
    end

    subgraph Backends [Upstream services]
        B1[Gitea]
        B2[Home Assistant]
        B3[Jellyfin]
    end

    H[(Slack, Discord, ntfy, generic webhook)]:::ext

    U -->|HTTPS| P
    P --> A
    P --> G
    P -->|local| B1
    P -->|WG tunnel| W
    W -->|encrypted UDP| C
    C --> B2
    C --> B3
    P --> L
    L --> H
    AC --> P
    S -.->|periodic| P

    classDef ext fill:#1f2329,stroke:#3b424d,color:#d9dde3
```

The default Docker Compose stack adds PostgreSQL, Loki, Alloy, and Grafana.
SQLite works for single node deployments and is the default for the standalone binary built by `portlyn init`.

## Installation

### Single binary

```bash
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/portlyn-linux-amd64 -o portlyn
chmod +x portlyn

# Interactive setup wizard. Generates secrets, creates an admin account,
# writes a .env file, and prepares the data directory.
./portlyn init

# Start the server
./portlyn
```

The admin UI is served from the root of the configured `FRONTEND_BASE_URL`.

### Docker Compose

```bash
git clone https://github.com/invaliduser231/Portlyn.git
cd Portlyn
cp .env.docker.example .env.docker
# fill in secrets and admin credentials
docker compose --env-file .env.docker up -d --build
```

<details>
<summary><strong>Published images (no local build)</strong></summary>

```bash
docker compose --env-file .env.docker \
  -f docker-compose.yml \
  -f docker-compose.public.yml \
  pull

docker compose --env-file .env.docker \
  -f docker-compose.yml \
  -f docker-compose.public.yml \
  up -d
```

Pin a tag:

```bash
PORTLYN_IMAGE_TAG=v1.2.3 docker compose \
  --env-file .env.docker \
  -f docker-compose.yml \
  -f docker-compose.public.yml \
  up -d
```

After the first push to GHCR, set package visibility to `Public` for:

* `ghcr.io/invaliduser231/portlyn`
* `ghcr.io/invaliduser231/portlyn-frontend`

</details>

### Source build

```bash
# Backend
go build -trimpath -ldflags="-s -w" -o portlyn ./cmd/server

# Frontend embedded build
cd frontend
npm ci
PORTLYN_STATIC_EXPORT=1 npm run build
rm -rf ../cmd/server/frontend_dist
mv out ../cmd/server/frontend_dist
cd ..
go build -trimpath -ldflags="-s -w" -o portlyn ./cmd/server
```

The resulting binary serves the admin UI from `go:embed`d static files.

## Configuration

All runtime settings are environment driven.
`portlyn init` writes a complete `.env` file with strong random secrets.

Minimum production set:

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

* Keep `ALLOW_INSECURE_DEV_MODE=false`
* Keep `OTP_RESPONSE_INCLUDES_CODE=false`
* Set `REDIRECT_HTTP_TO_HTTPS=true` once TLS is active
* Set `REQUIRE_MFA_FOR_ADMINS=true` and enroll every admin
* Use distinct random secrets for each secret variable
* Point `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` at the real public hostname
* Configure trusted proxy CIDRs if you sit behind another L7 proxy
* If you use external PostgreSQL, confirm the connection works from inside the Portlyn container

</details>

## Certificates

Certificate workflows are first class admin features.

* ACME `http-01` and `dns-01`
* Wildcards through `dns-01`
* Multi SAN issuance
* Let's Encrypt production and staging
* Automatic renewals with configurable windows
* Actions: create, update, delete, retry, renew, sync status, PEM import

DNS provider credentials are encrypted at rest using Argon2id derived keys with AES-256-GCM and never returned in clear text by the API.

<details>
<summary><strong>Operational rules</strong></summary>

* Wildcard names require `dns-01`
* `http-01` is rejected for wildcard certificates
* Duplicate or invalid SANs are rejected
* `dns-01` requires an active DNS provider resource
* Let's Encrypt staging is available for safe dry runs
* DNS provider tests validate stored configuration, not a full ACME dry run

</details>

## Security

Portlyn ships with conservative defaults and visible enforcement.

* Hash chained audit log with prev hash verification
* CSRF double submit with HMAC, strict JSON parsing, request size limits
* HSTS, CSP, X-Frame-Options, X-Content-Type-Options on the admin and proxy planes
* HttpOnly cookies, `Secure` outside dev mode, `SameSite=Lax` for sessions, `SameSite=Strict` for refresh tokens
* AES-256-GCM secret storage with Argon2id key derivation. v1 (SHA-256) values remain decryptable for migration
* JWT with explicit `alg` allow list
* Node enrollment with single use tokens, optional mTLS client cert pinning
* Rate limits on login, OTP, and node heartbeats

<details>
<summary><strong>Identity factors</strong></summary>

* Local bcrypt password
* OIDC with role claim mapping
* TOTP with recovery codes, in clear separation from passkeys
* WebAuthn passkeys, parallel to TOTP, with optional `user_verified` requirement
* Magic link, single use, scoped to a service, with TTL and label for audit attribution
* PIN and email code methods for low friction service access without accounts

</details>

<details>
<summary><strong>Known boundaries</strong></summary>

* The userspace tunnel reaches roughly 80 percent of kernel WireGuard throughput. Use kernel WG if you saturate links above 1 Gbps.
* The exposure scanner is best effort. A high score is not a substitute for a pentest.
* CrowdSec integration is pull based against LAPI. Web Application Firewall rules are not bundled.

</details>

## Observability

Structured logs and audit records cover:

* API requests with request id, method, path, host, latency, status code, user context
* Proxy requests with the same fields plus the matched service, access mode, access method, and outcome
* Identity events (login, MFA, OIDC) and admin actions

Metrics at `GET /metrics` (admin authenticated unless `METRICS_PUBLIC=true`):

* API and proxy latency histograms
* Request totals by outcome
* Auth attempts and rate limit hits
* Cache hits and config propagation timings
* ACME results and certificate expiry gauges
* DB ping latency
* Tunnel peer counts and handshake ages
* Typed health state gauges

Health surfaces:

* `GET /livez` for process liveness
* `GET /readyz` for required dependency readiness
* `GET /healthz` for combined operational health
* `GET /api/v1/system/overview` for the admin UI summary

Bundled Grafana assets:

* [`deploy/grafana/dashboards/portlyn-overview.json`](deploy/grafana/dashboards/portlyn-overview.json)
* [`deploy/grafana/provisioning/dashboards/portlyn.yml`](deploy/grafana/provisioning/dashboards/portlyn.yml)
* [`deploy/grafana/provisioning/datasources/loki.yml`](deploy/grafana/provisioning/datasources/loki.yml)

## Development

Backend hot reload friendly run:

```bash
go mod tidy
go run ./cmd/server
```

Frontend dev server (proxies `/api` to the Go server on `8080`):

```bash
cd frontend
npm install
npm run dev
```

Useful files:

* [`docker-compose.yml`](docker-compose.yml)
* [`Dockerfile`](Dockerfile)
* [`Dockerfile.single`](Dockerfile.single)
* [`.env.docker.example`](.env.docker.example)
* [`frontend/next.config.mjs`](frontend/next.config.mjs)
* [`deploy.sh`](deploy.sh)

## Testing

Backend:

```bash
go vet ./...
go test -race ./...
gofmt -l $(find . -type f -name '*.go' -not -path './.gomodcache/*' -not -path './cmd/server/frontend_dist/*')
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

Frontend:

```bash
cd frontend
npm ci
npx tsc --noEmit
npm test
npm run build
PORTLYN_STATIC_EXPORT=1 npm run build
```

End to end (Playwright, scaffold only):

```bash
cd frontend
npm install
npx playwright install --with-deps chromium
PLAYWRIGHT_BASE_URL=http://localhost:3000 npm run e2e
# Live mode against a running backend
PORTLYN_E2E_LIVE=1 \
PORTLYN_TEST_ADMIN_EMAIL=admin@example.test \
PORTLYN_TEST_ADMIN_PASSWORD='your password' \
npm run e2e
```

Existing automated coverage includes:

* Auth flows: OTP, OIDC helpers, MFA verification, WebAuthn registration smoke
* Routing and proxy behavior, including upstream degradation
* TLS certificate loading and metadata sync
* Node enrollment, heartbeat tokens, mTLS pinning
* Access policy checks for roles, groups, and restricted policies
* Tunnel keypair generation, IP pool allocation, end to end userspace WireGuard round trip
* Exposure scanner against a real TLS test server
* CrowdSec stream decoder and IP and CIDR blocking
* GeoIP country allow and block resolution
* Audit webhook delivery with HMAC signature
* Secret encryption v1 to v2 round trip and auto detection

## Roadmap

The next milestones, in order:

1. Live integration E2E tests in CI with a real backend
2. WebAuthn login flow (registration ships first; login flow is next)
3. Country picker UI fed by the actual GeoLite2 database catalog
4. CrowdSec settings UI
5. Pluggable secret stores (Vault, AWS KMS)
6. Wireguard kernel mode option for high throughput deployments
7. Multi node ACME with shared cert storage in Postgres
8. Public release of single binary builds for Linux, macOS, Windows on amd64 and arm64

## Documentation

* [Licensing](LICENSING.md)
* [Contributing](CONTRIBUTING.md)
* [Security Policy](SECURITY.md)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Production Hardening](docs/PRODUCTION-HARDENING.md)
* [Release Process](docs/RELEASE.md)
* [Backup and Restore](docs/BACKUP-RESTORE.md)
* [HA Deployment](docs/HA-DEPLOYMENT.md)
* [Secret Rotation](docs/SECRET-ROTATION.md)
* [Break Glass Recovery](docs/RECOVERY-BREAKGLASS.md)
* [OpenAPI specification](openapi.yaml)
* [Changelog](CHANGELOG.md)

## Repository layout

```text
.
├── cmd/                  entrypoints (server, nodeagent, configcheck)
├── deploy/               Loki, Alloy, and Grafana provisioning
├── docs/                 long form documentation
├── frontend/             Next.js admin UI
├── internal/             backend packages
│   ├── acme/             certificate issuance
│   ├── audit/            hash chained audit log and webhook dispatch
│   ├── auth/             local auth, OIDC, TOTP, WebAuthn, magic link
│   ├── geoip/            MaxMind GeoLite2 lookup
│   ├── http/             admin HTTP handlers
│   ├── proxy/            reverse proxy and policy engine
│   ├── scanner/          exposure scanner
│   ├── security/         CrowdSec LAPI client
│   ├── store/            GORM stores
│   └── tunnel/           userspace WireGuard server and IP pool
├── scripts/              helper scripts
├── .env.docker.example   environment template
├── deploy.sh             interactive deployment helper
├── docker-compose.yml    default stack
├── Dockerfile            backend image
├── Dockerfile.single     single binary image with embedded frontend
└── openapi.yaml          API specification
```

## License

See [LICENSING.md](LICENSING.md).
The core platform is intended to ship under a permissive OSS license.
Some hardening modules (exposure scanner, CrowdSec, GeoIP, WebAuthn) may be released as a separately licensed module in the future; until that split lands, all code in this repository is governed by the file in `LICENSING.md`.

# Portlyn

<p align="center">
  <img src="assets/logo.png" alt="Portlyn logo" width="120" />
</p>

Portlyn is a self-hosted reverse proxy and zero-trust control plane built with Go and Next.js.
It combines routing, access control, authentication, certificate management, and observability in one stack.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Certificates and DNS](#certificates-and-dns)
- [Security](#security)
- [Observability and Health](#observability-and-health)
- [Development](#development)
- [Validation and Testing](#validation-and-testing)
- [Project Docs](#project-docs)
- [Repository Layout](#repository-layout)

## Overview

Portlyn is designed for Linux-first Docker deployments and ships with a default stack that brings up:

- Portlyn API and reverse proxy
- Portlyn web UI
- PostgreSQL
- Loki
- Grafana Alloy
- Grafana

Default endpoints:

- Frontend and proxy entrypoint: `http://localhost` or `https://localhost`
- API: `http://localhost:8080`
- Loki: `http://localhost:3100`
- Grafana: `http://localhost:3001`

## Features

### Core Platform

- Self-hosted reverse proxy and control plane
- Go backend with Next.js frontend
- Linux-first Docker Compose deployment
- PostgreSQL by default, SQLite also supported
- Persistent volumes for app data, database, logs, and dashboards

### Access Control

- Service-level access policies: `public`, `authenticated`, `restricted`
- Access methods: session, OIDC-only, route PIN, email code
- User groups and service groups for reusable access rules
- Route login and forbidden flows for protected upstreams
- Session management and revoke-all controls

### Identity and Auth

- Local auth with secure cookies
- OIDC / SSO support
- TOTP MFA with recovery codes
- Optional admin MFA enforcement
- OTP-based login support

### Certificate Management

- ACME `http-01`
- ACME `dns-01`
- Wildcard certificates via `dns-01`
- Multi-SAN certificates
- Auto-renew, retry, renew, and sync-status actions
- DNS provider resources managed from the admin UI

### Operations

- Audit logs for auth, admin actions, and proxy access
- Structured JSON logging
- Prometheus-style metrics on `GET /metrics` (admin-authenticated by default)
- Health endpoints: `GET /livez`, `GET /readyz`, `GET /healthz`
- UI system overview on `GET /api/v1/system/overview`
- Bundled Grafana + Loki stack

<details>
<summary><strong>Supported DNS providers</strong></summary>

- Cloudflare
- Hetzner DNS
- AWS Route53
- DigitalOcean DNS

</details>

<details>
<summary><strong>Admin UI coverage</strong></summary>

- Services
- Domains
- Nodes
- Certificates
- DNS providers
- System overview
- Groups
- Service groups
- Users
- Audit logs
- Settings

</details>

## Architecture

The default deployment model uses Docker Compose.

- `portlyn`: API, proxy, auth, routing, certificate handling
- `frontend`: Next.js admin UI
- `postgres`: default primary database
- `loki`: log storage
- `alloy`: Docker log collection and forwarding
- `grafana`: dashboards and log exploration

If needed, Portlyn can also run against an external PostgreSQL instance through `DATABASE_URL`.

## Quick Start

1. Run the interactive deployment helper:

```bash
./deploy.sh
```

It creates `.env.docker` from `.env.docker.example` when needed, asks for the required values,
updates the file, and starts the stack. The default bootstrap flow keeps the admin UI reachable on
`http://localhost` and direct IP hosts first, so you can log in, add a domain, request a
certificate, and later move the admin UI to a managed public hostname.

2. Manual path if you want to edit the env file yourself:

```bash
cp .env.docker.example .env.docker
```

Then set at least:

- `JWT_SECRET`
- `JWT_SIGNING_SECRET`
- `SESSION_BRIDGE_SECRET`
- `OIDC_STATE_SECRET`
- `MFA_ENCRYPTION_SECRET`
- `CSRF_SECRET`
- `DATA_ENCRYPTION_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `POSTGRES_PASSWORD`
- `GRAFANA_ADMIN_PASSWORD`
- `FRONTEND_BASE_URL`
- `CORS_ALLOWED_ORIGINS`
- `BOOTSTRAP_ADMIN_ENABLED`

3. Start the stack manually:

```bash
docker compose --env-file .env.docker up -d --build
```

Alternative helper:

```bash
./deploy.sh
```

If a required secret is missing, `docker compose` fails early instead of starting with blank values.

## Configuration

Main runtime settings are driven by environment variables.

Important groups:

- HTTP and proxy ports
- Database driver and connection settings
- JWT and session TTLs
- CSRF and request size limits
- Admin bootstrap credentials
- OIDC settings
- OTP and MFA settings
- ACME / TLS settings
- Logging and Grafana settings
- Audit buffer sizing

### Database Modes

Default Docker deployment uses PostgreSQL.

For external PostgreSQL:

```env
DATABASE_DRIVER=postgres
DATABASE_URL=postgres://user:password@db-host:5432/portlyn?sslmode=require
```

For SQLite:

```env
DATABASE_DRIVER=sqlite
DATABASE_PATH=/data/portlyn.db
DATABASE_URL=
```

<details>
<summary><strong>Production notes</strong></summary>

- Keep `ALLOW_INSECURE_DEV_MODE=false`
- Keep `OTP_RESPONSE_INCLUDES_CODE=false`
- Keep `REQUIRE_MFA_FOR_ADMINS=true` (default) and ensure every admin has enrolled TOTP MFA
- Use strong, distinct secrets for JWT signing, session bridge, OIDC state, MFA encryption, CSRF, data encryption, PostgreSQL, and Grafana
- Set `ACME_ENABLED=true` and `ACME_EMAIL=...` for public HTTPS on the shared admin/proxy entrypoint
- Set `REDIRECT_HTTP_TO_HTTPS=true` when TLS is active
- Point `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` to the real external URL
- If you use external PostgreSQL, ensure it is reachable from the `portlyn` container

</details>

## Certificates and DNS

Portlyn exposes certificate management as a first-class admin feature.

Supported flows:

- ACME `http-01`
- ACME `dns-01`
- Wildcard certificates through `dns-01`
- Multi-SAN certificates
- Let's Encrypt production and staging issuers
- Automatic renewals with configurable renewal windows

Available certificate actions:

- Create
- Update
- Delete
- Retry failed issuance
- Renew
- Sync status

DNS provider credentials are encrypted at rest and never returned in clear text by the API.

<details>
<summary><strong>Operational rules and current limits</strong></summary>

- Wildcard names require `dns-01`
- `http-01` is rejected for wildcard certificates
- Duplicate or invalid SANs are rejected
- `dns-01` requires an active DNS provider resource
- Let's Encrypt staging is available for safe dry-runs
- Manual PEM / KEY import is supported through `POST /api/v1/certificates/{id}/import-pem`
- DNS provider testing validates stored configuration and provider readiness, not a full end-to-end ACME dry-run

</details>

## Security

Portlyn includes baseline hardening for browser and proxy traffic.

- HttpOnly cookies with `Secure` enabled outside insecure dev mode
- `SameSite=Lax` session cookies
- `SameSite=Strict` refresh cookies scoped to `/api/v1/auth`
- Double-submit CSRF protection for mutating browser API requests
- Global security headers including HSTS and CSP
- Strict JSON parsing with unknown-field rejection and request-size limits
- Dedicated node heartbeat tokens stored hashed server-side
- Audited heartbeat attempts and admin actions

<details>
<summary><strong>MFA details</strong></summary>

- TOTP MFA with recovery codes
- Current-user MFA endpoints:
  - `POST /api/v1/me/mfa/setup`
  - `POST /api/v1/me/mfa/enable`
  - `POST /api/v1/me/mfa/disable`
  - `POST /api/v1/me/mfa/recovery-codes`
- Login flows can return an MFA challenge that must be completed with `POST /api/v1/auth/verify-mfa`
- Admin MFA enforcement is configurable through settings and environment defaults

</details>

<details>
<summary><strong>Current security boundaries</strong></summary>

- Node heartbeat auth currently uses dedicated tokens
- Node heartbeats can run in `mtls` mode by pinning a client certificate SHA-256 fingerprint per node
- MFA is currently TOTP-first
- WebAuthn / passkeys are not implemented yet

</details>

## Observability and Health

Portlyn emits structured logs and audit records for:

- API access
- Proxy access
- Request IDs
- Method, path, host, latency, and status code
- User context when available

Metrics on `GET /metrics` (admin-authenticated unless `METRICS_PUBLIC=true`) include:

- API and proxy latency / request totals
- Auth attempts and rate-limit hits
- Config propagation and cache-hit counters
- ACME operation results
- Certificate expiry gauges
- DB ping latency
- Typed health-state gauges

Health surfaces:

- `GET /livez`: process liveness
- `GET /readyz`: required dependency readiness
- `GET /healthz`: combined operational health
- `GET /api/v1/system/overview`: UI-facing runtime, warning, and health summary

Bundled observability assets:

- [`deploy/grafana/dashboards/portlyn-overview.json`](deploy/grafana/dashboards/portlyn-overview.json)
- [`deploy/grafana/provisioning/dashboards/portlyn.yml`](deploy/grafana/provisioning/dashboards/portlyn.yml)
- [`deploy/grafana/provisioning/datasources/loki.yml`](deploy/grafana/provisioning/datasources/loki.yml)

## Development

Run the backend locally:

```bash
go mod tidy
go run ./cmd/server
```

Run the frontend separately from `frontend/`:

```bash
npm install
npm run dev
```

Useful project files:

- [`docker-compose.yml`](docker-compose.yml)
- [`Dockerfile`](Dockerfile)
- [`.env.docker.example`](.env.docker.example)
- [`frontend/Dockerfile`](frontend/Dockerfile)
- [`deploy.sh`](deploy.sh)

## Validation and Testing

Validate configuration:

```bash
go run ./cmd/configcheck
```

Validate Compose interpolation and service wiring:

```bash
docker compose --env-file .env.docker config
```

Run backend tests:

```bash
go test ./...
```

Run backend vet:

```bash
go vet ./...
```

Build backend packages:

```bash
go build ./...
```

Run the frontend build check from `frontend/`:

```bash
npm ci
npm test
npm run build
```

Current test coverage in the repository includes:

- OTP login flow
- Proxy pass-through and upstream-down degradation
- Static TLS certificate loading and certificate metadata sync
- OIDC helper validation and role-claim extraction
- Node enrollment and heartbeat token lifecycle
- Access-policy checks for viewer access and restricted role/group matching

## Project Docs

- [Licensing](LICENSING.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Production Hardening Guide](docs/PRODUCTION-HARDENING.md)
- [Release Process](docs/RELEASE.md)
- [Backup and Restore Guide](docs/BACKUP-RESTORE.md)
- [HA Deployment Guide](docs/HA-DEPLOYMENT.md)
- [Secret Rotation Guide](docs/SECRET-ROTATION.md)
- [Recovery Break-glass Guide](docs/RECOVERY-BREAKGLASS.md)
- [OpenAPI Spec](docs/openapi.yaml)
- [Changelog](CHANGELOG.md)

## Repository Layout

```text
.
├── cmd/                  entrypoints
├── deploy/               Loki, Alloy, and Grafana provisioning
├── frontend/             Next.js admin UI
├── internal/             backend packages
├── scripts/              helper scripts
├── .env.docker.example   deployment env template
├── deploy.sh             deployment helper
├── docker-compose.yml    default stack
└── Dockerfile            backend image
```

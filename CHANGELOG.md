# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and the project intends to use Semantic Versioning for
tagged releases.

## [Unreleased]

## [0.2.0] - 2026-05-27

### Added

- Userspace WireGuard tunnel server inside the Portlyn process, backed by `wireguard-go` and gVisor netstack. No kernel module, no root, no external `wg-quick` glue.
- Service routing through a tunneled node via optional `node_id` on each service. The proxy transparently dials the upstream over the WireGuard tunnel when set.
- Per-node WireGuard bootstrap endpoint (`POST /api/v1/nodes/{id}/wg-bootstrap`) and revoke endpoint. Issues a `wg-quick` compatible config bundle.
- Tunnel settings API (`GET` and `PATCH /api/v1/tunnel/settings`) with admin UI for endpoint, listen port, CIDR, server tunnel IP, and config file output.
- Node agent (`cmd/nodeagent`) gains `--wg-bootstrap` and `--wg-config` flags, writes the config to disk and reports tunnel handshake state in the heartbeat.
- WebAuthn passkey support parallel to TOTP. Endpoints under `/api/v1/me/passkeys` for list, registration begin and finish, and credential deletion. Optional Redis backed session store for cross-process WebAuthn challenges.
- Magic link sharing per service. Admin issues a single use link via `POST /api/v1/services/{id}/magic-link`. The proxy consumes the token at `/_portlyn/magic/{token}` and sets a route access cookie on the service host.
- Route access bridge at `/_portlyn/route-access` that fixes the PIN and email code loop where the cookie used to land on the admin host and the browser would not send it back to the service host.
- Exposure scanner running every 6 hours. Scores each service from 0 to 100 across DNS, TLS, HSTS, CSP, X-Frame-Options, HTTP to HTTPS redirect, and auth enforcement. Endpoints under `/api/v1/exposure-reports` and `/api/v1/services/{id}/exposure-scan`.
- GeoIP based country allow and block lists per service. Uses MaxMind GeoLite2.
- CrowdSec LAPI client with periodic decisions stream pull. Both IP and CIDR scopes supported.
- Audit webhooks with HMAC-SHA256 signed payloads. Generic JSON, Slack, Discord, and ntfy formats. CRUD under `/api/v1/audit-webhooks`.
- Service creation wizard with 15 built in templates (Gitea, Grafana, Immich, Jellyfin, Home Assistant, n8n, Vaultwarden, Portainer, Nextcloud, Uptime Kuma, Excalidraw, Plex, PhotoPrism, Vikunja, AdGuard) plus a Custom option.
- Audit log surfaces structured outcome, reason, latency, target host, access mode and method. UI shows status badges and a detail drawer per row.
- Why denied debugger and access tester. `POST /api/v1/services/{id}/explain` simulates a request and returns the per step decision trace. `GET /api/v1/services/{id}/last-denials` lists recent denial events. Standalone Access Tester page in the admin UI.
- Risk assessment and confirm by type when a service policy change increases exposure (for example flipping from `restricted` to `public`).
- `portlyn init` interactive CLI wizard that generates a complete `.env` with 7 random secrets, the SQLite path, the certificate directory, and the admin account.
- Single binary deployment via `Dockerfile.single` with a static export of the Next.js frontend embedded through `go:embed`.
- OpenAPI 3 specification at `openapi.yaml` covering the admin API.
- Playwright end to end test scaffold at `frontend/e2e/` with a CI safe smoke and a live integration mode behind `PORTLYN_E2E_LIVE=1`.

### Changed

- Secret encryption uses Argon2id derived keys with a per value salt and AES-256-GCM. The `enc:v2:` format is used for new writes. The legacy `enc:v1:` SHA-256 format remains decryptable for safe migration.
- Audit logger now dispatches events to configured webhooks alongside persistence.
- Proxy network rule enforcement runs the IP allow and block lists first, then the CrowdSec reputation check, then the GeoIP rules.
- Dashboard layout is client side and delegates the auth check to the existing `AuthGuard` in `DashboardShell`, preserving the `next=` query parameter for the login redirect.
- Detail pages (`/users`, `/groups`, `/service-groups`, `/services`) moved from `[id]` dynamic routes to query string routes (`/users/detail?id=42` and so on) so the Next.js static export builds cleanly.
- README rewritten with a concise overview, mermaid architecture diagram, installation paths for single binary, Docker Compose, and source builds.
- CI extended with gofmt check, race detector, `govulncheck`, frontend typecheck, both dev and static export builds, and a single binary artifact upload.
- Node version bumped to 24 LTS across the Dockerfile, GitHub Actions workflows, and the README badge. `engines` field added to `frontend/package.json`.

### Security

- Service request validation rejects targets pointing at private or link local address space.
- WebAuthn challenges no longer rely on in-memory state when Redis is available, enabling cross-process replay protection in clustered deployments.
- Route access bridge tokens are HMAC signed JWTs with a 2 minute TTL and bound to the target host. Open redirects are blocked by host comparison in the bridge handler.
- Audit log retains the SHA-256 hash chain. Webhook payloads carry an `X-Portlyn-Signature` header.

### Fixed

- PIN and email code route auth no longer trapped the user in a loop when the admin host differs from the service host. The new bridge transfers the route access cookie to the right origin.
- Static export builds no longer reject dynamic detail routes. The detail pages live at fixed paths and read the resource id from a query parameter.

## [0.1.0] - prior baseline

### Added

- GitHub Actions CI for backend tests, frontend build checks, and container build verification.
- Security workflow for `govulncheck` and frontend dependency auditing.
- Dependabot configuration for GitHub Actions, Go modules, and frontend npm dependencies.
- Production hardening and release-process documentation.
- Backend tests for OIDC helpers, node enrollment/heartbeat lifecycle, and access-policy gating.

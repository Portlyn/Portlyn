# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and the project uses Semantic Versioning for tagged releases.

## [Unreleased]

### Fixed

- Login redirects no longer write to the audit log, and other denials are
  capped per minute. Run `portlyn audit compact` once to drop the old rows.

## [1.5.0] - 2026-09-23

This release is almost entirely security fixes from a review of the whole
codebase. Please read the upgrade notes before updating.

### Upgrade notes

- Update the hub first, then the nodes. A new node agent learns the hub's
  tunnel address from the hub. Against an older hub it falls back to the first
  address of the tunnel network, which is right unless you changed the hub's
  tunnel IP in the tunnel settings.
- Anyone logged in to a service through the route login has to log in once
  more. Old service-host cookies are no longer accepted.
- The `route` label on the API metrics is now the route pattern
  (`/api/v1/services/{id}`) and `unmatched` for everything else. The bundled
  Grafana dashboard does not use it, but check your own queries.
- No config changes and no database migration.

### Security

- The session bridge put the dashboard access token into the link it sent to a
  service host, and it would mint that link for any host the request named.
  Together with a tab character slipping through the `returnTo` check on the
  route login page, one link was enough to send an admin's token to a foreign
  domain. Bridge tokens are now only issued for enabled services the user can
  reach, and they carry a separate token that only works on that host and is
  refused by the API. The `returnTo`, login `next` and OIDC `next` checks reject
  control characters and backslashes and compare the parsed origin.
- The proxy now strips Portlyn's own cookies and bearer tokens before
  forwarding to an upstream. Upstream apps used to receive a token that worked
  against the admin API.
- API tokens were treated as the admin who created them on the `/me` routes,
  so a viewer token could change that admin's email, password or MFA. Tokens
  are now refused on `/me/*`, sessions, MFA, passkeys and the session bridge.
- `/me/account-setup` changed email and password without the current password
  at any time. It now only works while a password change is pending, which is
  the only place the UI uses it.
- Paths with `.` or `..` segments are rejected by the proxy, and the path that
  was checked against the access policy is the one forwarded upstream. Before,
  `..` could pick a looser route while the backend resolved it to a stricter
  one.
- Hosts longer than 253 bytes or with empty labels are rejected before the
  route lookup. A very long `Host` header could run the process out of memory.
- `X-Portlyn-*` headers are removed in every spelling, including underscores,
  and on the admin host as well. The client certificate fingerprint the proxy
  passes to the API is now signed, so it can no longer be set by the client.
- Tunnel clients can only reach the nodes they are assigned to. The hub used to
  forward traffic between any two peers. Nodes only accept relay connections
  from the hub, and the subnet proxy stays inside the advertised subnets.
- Deleting a node removes its peer from the running tunnel right away instead
  of at the next restart.
- Release signatures are pinned to `release.yml` on a version tag in
  `Portlyn/Portlyn`. Any workflow in the repo used to be accepted, including
  ones that other repositories can call. `portlyn update` also checks the tag,
  and the install scripts and docs use the stricter check. Installs on 1.4.0
  and older still use the old check for this one update.
- Several store updates wrote back the whole row from an earlier read, which
  could undo a session revocation, a role change or a node deletion. They now
  only write the columns they own.
- The break-glass source check looked at the internal proxy hop, which is
  always loopback, so it never restricted anything. It now uses the real client
  address.
- API metrics used the raw request path as a label, which allowed injecting
  lines into `/metrics` and growing memory without limit.
- Password login now takes the same time whether the email exists or not.
- Viewers no longer see the upstream address in service health errors.
- Health probes no longer leave an idle connection behind on every
  `/healthz` call.

### Changed

- CI workflows default to a read-only token.
- `verify-release` takes an optional `--tag`.

## [1.4.0] - 2026-09-19

### Added

- Services can be switched off from the overview without deleting them. A
  disabled service stops being routed and its host answers 404, the same as one
  that was never configured. The filter sits in the routing query rather than in
  the UI, so turning something off really takes it off the proxy. Useful for a
  maintenance window, and less drastic than deleting a service to take it
  offline for an hour. Existing services default to enabled, so an upgrade
  changes nothing.
- The domain in the service overview links to the public URL, and the target
  URL links to the upstream. The upstream is usually a private address, so that
  link only resolves from inside your network.

### Fixed

- The tunnel registered its transport handlers on a stack that was already
  carrying traffic, which the race detector flagged as a data race in the
  nodeagent startup path. A first attempt moved registration ahead of
  `dev.Up()`, which was not enough: wireguard also starts the receiver from
  `IpcSet` when the device is already up, so "before Up" is not a reliable
  point in time. Registration now happens before the NIC exists at all, and
  the method that allowed attaching handlers later is gone.

## [1.3.2] - 2026-09-17

### Fixed

- Upgrading an existing sqlite installation died in `0001_baseline_schema` with
  `FOREIGN KEY constraint failed (787)` on `DROP TABLE dns_providers`, which
  left the server refusing to start until you rolled back. Sqlite changes a
  column by copying the table, dropping the original and renaming the copy,
  which is what gorm does under AutoMigrate, and it refuses that drop while
  another table holds a foreign key on it. `certificates.dns_provider_id` is
  exactly such a key. Foreign keys are now suspended around the migration run
  and switched back on afterwards, with a `foreign_key_check` to confirm
  nothing was left dangling in between. The pragma is a no-op inside a
  transaction, so wrapping the individual migration would not have worked.
  Fresh installs never hit this, only databases with data in them, which is
  why it survived until someone upgraded. Postgres is unaffected.
- `portlyn init` always closed with "Start the server with: portlyn". On any
  machine the installer touched that is wrong twice over: the unit file is in
  place, so you start it through systemd, and the service may already be
  running, in which case it needs a restart to read the file init just wrote.
  It now looks for the unit and says so.

### Changed

- The `.env` that `init` generates now also lists the roughly 60 settings it
  does not set, commented out and with their real defaults, grouped by topic.
  They were previously invisible unless you went through the docs.
- Secrets in that file were written by iterating a map, so they landed in a
  different order on every run. Fixed order now, which keeps diffs readable.

## [1.3.1] - 2026-09-17

### Fixed

- Signed in users bounced between the route login page and `/login` instead of
  reaching the service. The page only read `isAuthenticated`, which is false
  while the auth provider is still loading, so it offered the Continue button
  to someone who was already signed in. That button leads to `/login`, which
  sends them straight back, and round it goes. Whether it settled at all
  depended on whether the bridging effect won the race against the click. The
  page now waits for the auth state, and the button only appears when the user
  really is signed out or when bridging failed and they need a way forward.
- Password managers overwrote the email field with the TOTP code. The login
  fields carried no autocomplete metadata, and the MFA input only mounts after
  the first step, so nothing on the page was marked `one-time-code` when the
  manager went looking for somewhere to put it. It fell back to the first text
  field, which was the email it had just filled. Email is now `username`,
  password is `current-password`, and the recovery code and route PIN opt out.

## [1.3.0] - 2026-09-17

### Security

- gRPC to 1.83.2 for CVE-2026-84445, CVE-2026-84304 and CVE-2026-84303. Worth
  knowing if you pin it yourself: 84445 is only fixed in 1.83.2, so 1.83.1
  still trips a Trivy scan.
- The Alpine images now run `apk upgrade` during build. `libcrypto3` ships
  inside the base layer, and `apk add` only installs what is missing, so it sat
  on 3.5.7-r0 with CVE-2026-14456 no matter how often the image was rebuilt.
  It lands on 3.5.8-r0 now.
- Next.js to 16.3.3 for two critical unauthenticated RCEs,
  GHSA-p293-qw3h-jr36 and GHSA-2xp9-vwfh-vxw4. `sharp` to 0.35.4 for
  GHSA-rgj7-g3m4-5g8c. `sharp` hangs off Next as a transitive dependency and a
  Next bump alone does not move it, the caret range stays resolved where it
  was.
- `golang.org/x/crypto` to 0.57.0 for the two ssh channel denial of service
  fixes, GO-2026-6354 and GO-2026-6355.
- The route email code endpoint used OR where the rest of the code uses AND, so
  `OTP_RESPONSE_INCLUDES_CODE=true` on its own put route codes in the API
  response without dev mode being on. It now needs both, matching how the login
  OTP path has always behaved.

### Added

- Hitting the server by IP while remote bootstrap access is off returns a short
  page explaining the SSH tunnel and the env var, instead of a bare 404. Unknown
  domains still get a plain 404 that does not mention Portlyn.
- Compose passes the `ACME_DNS_*` variables through, and the example env file
  lists them. Setting them previously did nothing there, the variables never
  reached the container, so DNS-01 by env could not work on the Docker path at
  all.

### Changed

- `BOOTSTRAP_ADMIN_ENABLED` now defaults to `true` in Compose, which is what
  `init` and `deploy.sh` already did. With the API bound to loopback and the
  proxy answering 404 on the IP, a fresh Compose install had no way in. It
  still only answers local requests until you also set
  `BOOTSTRAP_ADMIN_ALLOW_REMOTE=true`, and production setups should turn it off
  once a domain is live.
- The OIDC setting is now labelled "Require verified email from provider" and
  says what it does. It checks the `email_verified` claim from your provider and
  needs no SMTP, but the old wording read like Portlyn sends verification mail
  itself, which it never has.

### Fixed

- Viewers saw Security in the sidebar but every click bounced them back to
  `/services`. The guard allowed exactly one path while the API has always
  served `/me/mfa` and `/me/passkeys` to any signed in user, so a non-admin
  could not enrol a passkey or set up TOTP at all.
- Typing into the service wizard threw `Cannot read properties of null` and
  killed the form. The handlers read `event.currentTarget` inside the setState
  updater, and React nulls it after dispatch and runs the updater afterwards.
  It looked intermittent because React sometimes evaluates the updater eagerly.
  Twelve fields had it, across the wizard, the access window editor and the
  service group access methods.

## [1.2.0] - 2026-08-18

### Breaking

- The `ghcr.io/portlyn/portlyn-frontend` image is gone, and so is the separate
  frontend container in Compose. The admin UI ships inside the main image and
  the binary, which is what the proxy already preferred. If you pull the
  frontend image or run that service, drop it: nothing replaces it, the UI is
  served by `portlyn` itself. `NEXT_PUBLIC_API_BASE_URL` is no longer part of
  the Compose environment.

### Security

- A route path of `//evil.example` survived normalization and went straight
  into the Location header on the magic link route. Paths are now rebuilt from
  their segments, so a protocol-relative result cannot be produced, and the
  redirect checks the path independently on top of that. Setting such a path
  needs admin rights, so exposure was limited.
- The bundled UI is the only production path now, which means the hardened CSP
  with script hashes applies everywhere. The weaker `unsafe-inline` policy only
  remains in the dev server.
- The node installer no longer writes the enrollment token into `ExecStart`,
  where it sat in the unit file and in every process listing. It goes into a
  0600 file that systemd passes in with `LoadCredential`. The unit also gained
  `NoNewPrivileges` and the protect settings the hub unit already had.
- wireguard-go and gvisor updated from December 2023 to current, which clears a
  data race the race detector hit during shutdown.
- `golang.org/x/mod` to 0.40.0 for GO-2026-6179 and GO-2026-6180. Neither was
  reachable from Portlyn, but both showed up in scans of the release binary.

### Added

- Migration tests against a real PostgreSQL in CI: migrating from empty, five
  concurrent `Migrate` calls that have to end with exactly one row per
  migration, and data written before an upgrade that has to still be there
  afterwards. The advisory lock exists only on the postgres path and was never
  covered before.
- Biome as a linter, running as a required CI step. `next lint` was configured
  but eslint was never installed, so the frontend had no linting at all.
- `--token-file` on the node agent, and systemd credentials are picked up
  automatically.
- A workflow that regenerates `package-lock.json` on linux. npm on Windows drops
  the optional platform packages that linux needs, which breaks `npm ci` on the
  runner.

### Changed

- Go modules, npm packages, base images, service images and pinned actions moved
  to current versions. Three deliberate exceptions: postgres stays on 17.x (a
  major bump needs `pg_upgrade`), node stays on 24.x (26 is Current, not LTS),
  and gvisor stays on the May snapshot (the newest one does not build).
- All seventeen actions are pinned by commit sha. The github-owned ones still
  rode moving tags in workflows that sign and publish releases.
- The e2e job gained timeouts. `playwright install --with-deps` shells out to
  apt-get, which can wait on a prompt forever; three runs sat stuck for hours
  and blocked the runners. Workflows now also cancel a superseded run on pull
  requests.
- `main` requires pull requests and green checks, with no administrator bypass.

## [1.1.0] - 2026-08-18

### Security

- The installers no longer let the freshly downloaded binary verify its own release signature. `install-hub.sh` and `install-node.sh` use `cosign` if it is present, otherwise they fetch a pinned cosign build and check it against a SHA-256 digest hard-coded in the script. Without a trustworthy verifier the install aborts.
- Alloy talks to a filtered Docker socket proxy instead of a bind-mounted `/var/run/docker.sock`. A read-only mount does not stop API calls.
- The bundled admin UI is served with a `script-src` built from the SHA-256 hashes of its inline scripts, so the single binary no longer needs `unsafe-inline`.
- Node enrolment claims the single-use token and creates the node in one transaction. A failure no longer burns the token or leaves a half-created node.
- Dependency updates: Go 1.26.6, gRPC 1.83.0, `golang.org/x/net` 0.58.0, plus overrides for nanoid, postcss and undici. `npm audit` and `govulncheck` are clean.

### Added

- Playwright suite covering login, wrong credentials, session persistence, TOTP enrolment and login, passkey registration and login through a virtual authenticator, and domain policy edits. It runs in CI against a throwaway hub started by `scripts/e2e-hub.sh`.
- Frontend unit tests for the API client, the auth flows, the WebAuthn encoding and the open redirect guard.
- `portlyn migrate` with `status` and `down`.
- `Dockerfile.dev` that builds the backend image from source inline (no prebuilt binary in `dist/` required).
- `docker-compose.dev.yml` overlay that switches the stack to local builds via `pull_policy: build`.

### Changed

- Database schema changes run as versioned migrations recorded in `schema_migrations`, with a Postgres advisory lock so several hubs can start at once.
- Tags no longer build a release on their own. `release.yml` now requires CI, the security workflow, CodeQL and the container scan to pass on the tagged commit first, and ships a source SBOM.
- Trivy fails the run on fixable CRITICAL or HIGH findings instead of only reporting them.
- Compose files pin the Portlyn image tag instead of defaulting to `latest`.
- `openapi.yaml` documents every endpoint the router registers, up from 48 of them. A test walks the router and compares both directions, so an undocumented endpoint fails the build and so does a documented one that no longer exists. The stale `docs/openapi.yaml` was removed and the docs site builds from the live spec.
- The README and the HA guide now say the same thing about multi-instance mode: it is implemented, but not covered by failover tests.
- `internal/proxy/manager.go`, `internal/http/resources.go` and `internal/auth/service.go` split into smaller files along their existing seams. No behaviour change.
- README rewritten with an honest scope statement, threat model summary, and explicit Cosign verify instructions. The phrase "zero trust" was replaced with "identity aware reverse proxy".
- `SECURITY.md` expanded with a detailed threat model (in scope, out of scope, trust boundaries) and supply chain section.

## [1.0.17] - 2026-05-30

Post launch hotfix series. v1.0.1 through v1.0.17 were all cut on the same day during the public demo setup, covering install, tunnel, ACME, embed handler, and auth flow issues that surfaced under real traffic.

### Fixed

- Route auth (`getRouteAuthService`, `verifyRoutePIN`, `requestRouteEmailCode`, `verifyRouteEmailCode`) no longer redirects to the admin login on a 401. A wrong PIN shows an inline error and stays on the route login page.
- `cmd/server/embed.go` rewritten to bypass `http.FileServer` and serve embedded files directly via `io.Copy`. Eliminates the 301 redirect loop on `/services/` that came from `http.FileServer` canonicalising index paths under `embed.FS`.
- `RequireWritable` no longer probes the running binary file. Atomic rename handles updates fine; the previous probe failed on Linux with `ETXTBSY`.
- Tunnel start now runs against `context.Background()` instead of the request context, so saving tunnel settings no longer cancels the tunnel mid restart.
- `auth-public` route matching tolerates a trailing slash introduced by the static export.
- `version`, `update`, `settings`, and `help` flags are handled before config load, so they work even when the environment is missing required secrets.
- Route login: optional chaining on `service.access_method_config?.hint` so a service without configured hint text does not crash the page.
- Bootstrap wizard's passkey register button is disabled while a registration is in flight, preventing double submits.
- Logout request failures are surfaced through `console.warn` instead of being silently swallowed.

### Added

- Self update CLI (`portlyn update`, `portlyn-nodeagent update`) with subcommands for `--check`, `--version`, `--no-restart`. Verifies SHA-256 against signed `checksums.txt`, then performs full Sigstore chain verification via `sigstore-go` against the embedded TUF trust root, then atomic swap.
- Auth cache janitor (`StartCacheJanitor`) that periodically evicts expired entries and caps the cache at 10000 entries.
- `RevokeOtherUserSessions` so self service password change, account setup, and MFA enrollment no longer kill the caller's own session. Other sessions for the same user are still revoked.
- Bootstrap admin certificate flow: hub auto enrolls its own admin hostname on first start and serves a per host self signed certificate as a fallback until ACME completes, so the admin UI is reachable over HTTPS immediately.
- Bootstrap wizard with account setup, MFA enrollment, recovery codes, and a Skip path. Skip is blocked when `REQUIRE_MFA_FOR_ADMINS=true` and the admin has not yet enrolled.
- Multi architecture release pipeline: parallel container jobs split into three, GHA cache, binary artifact sharing across jobs, `-X main.version` injection for the node agent.
- Cosign release signing uses the new bundle format and pins `cosign v2.5.0` (later v3.7.0) so verification works against the current Sigstore bundle schema.

### Changed

- ACME certificates explicitly disable the TLS-ALPN-01 challenge. The self signed bootstrap fallback was breaking TLS-ALPN-01 by intercepting the challenge cert, so issuance now sticks to HTTP-01 or DNS-01.
- Trusted proxy defaults: `NODE_TRUST_FORWARDED_PROTO=true` and `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128`. `ALLOW_INSECURE_DEV_MODE` is rejected outright in production.
- `composeServerEndpoint(endpoint, listenPort)` builds the tunnel endpoint with the correct UDP port.
- Self signed bootstrap certificate validity reduced from 7 days to 24 hours.
- TOTP validation window narrowed to `{-30, 0}` (no future slot accepted).

### Security

- Open redirect protection on the route access bridge: `returnTo` is validated to share the apex domain with the route host (`sanitizeReturnToForOrigin`).
- Login `next` parameter sanitised to same origin only.
- Webhook URLs go through `validateServiceTargetURL` to prevent SSRF against private or link local addresses.
- Public `publicAccessMethodConfig` strips admin only fields (`allowed_email_domain`, `allowed_emails`) from the route login response.
- Login token `MarkUsed` uses an atomic `WHERE used_at IS NULL` clause to prevent replay.
- MFA enforcement when `REQUIRE_MFA_FOR_ADMINS=true`: bootstrap dismissal is denied until MFA is enrolled.
- Auth mailer: themed HTML plus ASCII box text fallback, signed with a footer.

## [1.0.0] - 2026-05-30

First MIT licensed release.

### Changed

- License switched from Business Source License to **MIT**. Sponsorship metadata updated.
- Multi platform release workflow: `linux/amd64` and `linux/arm64` for both `portlyn` and `portlyn-nodeagent`. Docker images built via `BUILDPLATFORM` trick to avoid emulation on the cross arch path.
- Dashboard shell uses Mantine `AppShell` with the `alt` layout. Sidebar restructured; redundant `PageHeader` descriptions removed for a cleaner UI.
- Text color standardised to `dimmed` across components for consistent contrast.

### Added

- Service detail page shows tunnel node information, last handshake age, and route status alongside the service config.
- Service wizard supports selecting a tunnel node so a single click maps a hostname to a service that lives on a remote node.
- `ServiceStore` preloads the related `Node` in `List`, `GetByID`, and `Delete` to avoid n+1 queries on the service list.
- Tunnel UDP port (default 51820) exposed in `docker-compose.yml`.
- Client endpoint resolution helper used by the service wizard.

## [0.3.0] - 2026-05-28

Install ergonomics and UX polish.

### Added

- One line install script: `curl -fsSL https://<your-host>/install.sh | sudo sh -s -- --token <TOKEN>` downloads a checksum verified binary and registers a systemd service. Hub serves `/install.sh` from the admin host.
- Client management surface: list, create, revoke node clients from the admin UI, integrated with the tunnel server.
- Exposure overview page with one click rescan, per service score, and findings.
- MFA and network security settings cards in the admin UI (TOTP and passkey enrollment, CrowdSec configuration, GeoIP toggles).
- Login screen: wider layout, status badge tooltips.

### Changed

- Netstack tunnel server gains graceful shutdown via a close channel and sync, so reloads stop cleanly without leaking goroutines.
- Sidebar labels and security related component organisation refactored.
- Brand accent switched to the logo purple; previous backgrounds restored. Alert and button colors aligned for accessibility contrast.

### Fixed

- Several missing fields surfaced on the service detail and audit log views.

## [0.2.0] - 2026-05-27

### Added

- Userspace WireGuard tunnel server inside the Portlyn process, backed by `wireguard-go` and gVisor netstack. No kernel module, no root, no external `wg-quick` glue.
- Service routing through a tunneled node via optional `node_id` on each service. The proxy transparently dials the upstream over the WireGuard tunnel when set.
- Per node WireGuard bootstrap endpoint (`POST /api/v1/nodes/{id}/wg-bootstrap`) and revoke endpoint. Issues a `wg-quick` compatible config bundle.
- Tunnel settings API (`GET` and `PATCH /api/v1/tunnel/settings`) with admin UI for endpoint, listen port, CIDR, server tunnel IP, and config file output.
- Node agent (`cmd/nodeagent`) gains `--wg-bootstrap` and `--wg-config` flags, writes the config to disk and reports tunnel handshake state in the heartbeat.
- WebAuthn passkey support parallel to TOTP. Endpoints under `/api/v1/me/passkeys` for list, registration begin and finish, and credential deletion. Optional Redis backed session store for cross process WebAuthn challenges.
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
- Detail pages (`/users`, `/groups`, `/service-groups`, `/services`) moved from `[id]` dynamic routes to query string routes so the Next.js static export builds cleanly.
- README rewritten with a concise overview, mermaid architecture diagram, installation paths for single binary, Docker Compose, and source builds.
- CI extended with gofmt check, race detector, `govulncheck`, frontend typecheck, both dev and static export builds, and a single binary artifact upload.
- Node version bumped to 24 LTS across the Dockerfile, GitHub Actions workflows, and the README badge. `engines` field added to `frontend/package.json`.

### Security

- Service request validation rejects targets pointing at private or link local address space.
- WebAuthn challenges no longer rely on in memory state when Redis is available, enabling cross process replay protection in clustered deployments.
- Route access bridge tokens are HMAC signed JWTs with a 2 minute TTL and bound to the target host. Open redirects are blocked by host comparison in the bridge handler.
- Audit log retains the SHA-256 hash chain. Webhook payloads carry an `X-Portlyn-Signature` header.

### Fixed

- PIN and email code route auth no longer trapped the user in a loop when the admin host differs from the service host. The new bridge transfers the route access cookie to the right origin.
- Static export builds no longer reject dynamic detail routes. The detail pages live at fixed paths and read the resource id from a query parameter.

## [0.1.0] - 2026-05-19

### Added

- GitHub Actions CI for backend tests, frontend build checks, and container build verification.
- Security workflow for `govulncheck` and frontend dependency auditing.
- Dependabot configuration for GitHub Actions, Go modules, and frontend npm dependencies.
- Production hardening and release process documentation.
- Backend tests for OIDC helpers, node enrollment and heartbeat lifecycle, and access policy gating.

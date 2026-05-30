# Installation and configuration

Portlyn ships as two binaries: a hub (`portlyn`) and an optional node agent (`portlyn-nodeagent`). The hub can run from a single binary on a Linux host or via Docker Compose. The node agent runs on machines behind NAT or CGNAT and dials out to the hub over WireGuard.

## Verify a release

Every tagged release is signed with Cosign keyless via Sigstore. Verify before running anything in production.

```bash
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/portlyn-linux-amd64 -o portlyn
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt     -o checksums.txt
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt.sig -o checksums.txt.sig
curl -L https://github.com/invaliduser231/Portlyn/releases/latest/download/checksums.txt.pem -o checksums.txt.pem

sha256sum -c checksums.txt --ignore-missing

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/invaliduser231/Portlyn' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  checksums.txt
```

## Single binary

```bash
chmod +x portlyn
sudo mv portlyn /usr/local/bin/portlyn
sudo portlyn init
sudo portlyn
```

`portlyn init` is an interactive wizard. It generates secrets, writes a `.env` file, prepares the data directory, and creates the admin account. Existing `.env` files are preserved unless you pass `--force`.

A systemd unit example is available at [`scripts/portlyn.service`](../scripts/portlyn.service) (create one if not present).

## Docker Compose

```bash
git clone https://github.com/invaliduser231/Portlyn.git
cd Portlyn
cp .env.docker.example .env.docker
# edit secrets and admin credentials in .env.docker
docker compose --env-file .env.docker up -d
```

The default `docker-compose.yml` pulls `ghcr.io/invaliduser231/portlyn:latest`. Pin a specific tag with `PORTLYN_IMAGE_TAG=v1.2.3`. To build the images locally instead of pulling them, add the dev overlay:

```bash
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

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

## Observability

- Structured logs cover API and proxy requests with request id, method, path, host, latency, status, user context, matched service, access mode and method, and outcome.
- Metrics at `GET /metrics` (admin authenticated unless `METRICS_PUBLIC=true`).
- Health endpoints: `GET /livez`, `GET /readyz`, `GET /healthz`.
- Bundled Grafana dashboards in [`deploy/grafana/dashboards/`](../deploy/grafana/dashboards/).

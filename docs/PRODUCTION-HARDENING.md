# Production Hardening Guide

This project ships with a developer-friendly default Docker Compose stack. That default is not a
production security posture by itself.

## Required before internet exposure

- Set `ALLOW_INSECURE_DEV_MODE=false`.
- Set strong, distinct values for `JWT_SECRET`, `JWT_SIGNING_SECRET`, `SESSION_BRIDGE_SECRET`, `OIDC_STATE_SECRET`, `MFA_ENCRYPTION_SECRET`, `CSRF_SECRET`, `DATA_ENCRYPTION_SECRET`, `AUDIT_HMAC_SECRET`, `POSTGRES_PASSWORD`, and `GRAFANA_ADMIN_PASSWORD`.
- Keep bootstrap login disabled by default (`BOOTSTRAP_ADMIN_ENABLED=false`) and only enable it briefly for controlled first-time setup.
- Keep admin MFA enforcement enabled (`REQUIRE_MFA_FOR_ADMINS=true`) and enroll TOTP for every admin.
- Set `FRONTEND_BASE_URL`, `CORS_ALLOWED_ORIGINS`, and OIDC redirect settings to the final public URL.
- Enable TLS for the shared admin/proxy entrypoint before exposing it publicly.
- Keep `EXPOSE_AUTH_TOKENS=false` so browser auth uses HttpOnly cookies instead of JSON-exposed bearer tokens.
- Keep `METRICS_PUBLIC=false` unless `/metrics` is protected by a dedicated network/auth layer.
- Keep internal admin and observability binds local by default (`PORTLYN_API_BIND_ADDR=127.0.0.1`, `LOKI_BIND_ADDR=127.0.0.1`, `GRAFANA_BIND_ADDR=127.0.0.1`).
- Set `TRUSTED_PROXY_CIDRS` only to the exact CIDR ranges of your TLS-terminating load balancers. Leave it empty when Portlyn receives traffic directly.
- Keep node transport hardening enabled:
  - `NODE_REQUIRE_HTTPS=true`
  - `NODE_TRUST_FORWARDED_PROTO=false` unless behind a trusted TLS-terminating proxy listed in `TRUSTED_PROXY_CIDRS`
  - `NODE_ALLOW_MTLS_HEADER_FALLBACK=false` unless explicitly required behind trusted infrastructure
  - keep enrollment and heartbeat auth-fail rate limits enabled (`NODE_ENROLL_RATE_*`, `NODE_HEARTBEAT_AUTH_FAIL_RATE_*`)

## Exposure model

- Treat the admin UI and API as privileged surfaces.
- Do not expose Grafana, Loki, or `/metrics` publicly without an explicit access layer.
- Prefer a private network, VPN, or upstream access control in front of observability endpoints.
- Require TLS for PostgreSQL transport (`sslmode=require` or stronger verification where available).
- If you publish the main proxy entrypoint, separate public service routes from operator-only endpoints.

## Authentication and secrets

- Keep `OTP_RESPONSE_INCLUDES_CODE=false` outside local development.
- Use a dedicated SMTP account for OTP and route email flows.
- Keep signing and encryption secrets separated to reduce blast radius if one key is exposed.
- Rotate credentials when operators change.
- For encryption-key rotation use a dual-key window (`DATA_ENCRYPTION_SECRET` + `DATA_ENCRYPTION_LEGACY_SECRETS`) and re-encrypt stored DNS provider secrets.
- Back up secrets separately from the application host.

## Emergency access

- Keep break-glass disabled by default (`BREAK_GLASS_ENABLED=false`).
- If enabled for an incident, constrain with short TTL and CIDR allowlist, then disable again after recovery.

## Storage and recovery

- Back up PostgreSQL on a schedule and test restore regularly.
- Back up `/data` when using local certificate storage.
- Record the exact application version used for each backup.

## Release and upgrade discipline

- Run `go test ./...`, `go vet ./...`, and the frontend build before every release.
- Review the security workflow results before tagging a release.
- Keep a rollback path for database and config changes.

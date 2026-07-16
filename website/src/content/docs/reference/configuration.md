---
title: Configuration
description: The environment variables that matter, and what init sets for you.
sidebar:
  order: 1
---

Everything is driven by environment variables, usually through the `.env` that `init` writes. Run `portlyn doctor` any time to check the whole set at once.

## The minimum for production

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD=a long random value
ACME_ENABLED=true
ACME_EMAIL=ops@example.com
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

Each secret has to be unique and at least 32 characters. `init` generates them; don't reuse one across two variables.

## Database

Postgres, which the Docker stack uses:

```env
DATABASE_DRIVER=postgres
DATABASE_URL=postgres://user:pass@host:5432/portlyn?sslmode=require
```

SQLite, the default for the standalone binary:

```env
DATABASE_DRIVER=sqlite
DATABASE_PATH=/var/lib/portlyn/portlyn.db
```

`sslmode=disable` is rejected for a public database host. It's allowed (with a warning) for a private or container-local one, since that link isn't crossing an untrusted network.

## Reaching the dashboard early

- `BOOTSTRAP_ADMIN_ENABLED` serves the dashboard on the raw IP or loopback before a domain exists. `init` sets it to `true`.
- `BOOTSTRAP_ADMIN_ALLOW_REMOTE` drops the local-only guard so a remote browser can reach that bootstrap dashboard. Off by default. See [First boot and TLS](/guides/tls/).

## Behind a proxy

- `TRUSTED_PROXY_CIDRS` lists the CIDRs of a fronting proxy you trust for `X-Forwarded-*`. Required if you set `NODE_TRUST_FORWARDED_PROTO=true`.

## Reaching internal services

Portlyn blocks its own outbound requests from reaching private addresses, which stops an SSRF from hitting your LAN or a cloud metadata endpoint. If your OIDC provider or audit webhook receiver genuinely lives on an internal address, two opt-ins relax that, one client at a time:

- `OIDC_ALLOW_PRIVATE_ISSUER` lets the OIDC issuer resolve to an RFC1918 address. Off by default.
- `AUDIT_WEBHOOK_ALLOW_PRIVATE_TARGETS` lets audit webhooks post to an RFC1918 address. Off by default.

Both keep loopback and the cloud metadata address (`169.254.169.254`) blocked, and both cover the save-time validation and the actual connection, so a DNS rebind can't slip past. `doctor` warns while either is on.

## Before you go live

- `ALLOW_INSECURE_DEV_MODE=false`
- `OTP_RESPONSE_INCLUDES_CODE=false`
- `REDIRECT_HTTP_TO_HTTPS=true` once TLS works
- `REQUIRE_MFA_FOR_ADMINS=true`, and actually enroll every admin
- `FRONTEND_BASE_URL` and `CORS_ALLOWED_ORIGINS` on the real hostname

The [production hardening](/operations/production-hardening/) page goes deeper.

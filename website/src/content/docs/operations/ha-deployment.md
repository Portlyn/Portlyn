---
title: High availability
description: Running more than one hub.
---

This guide defines the currently supported high-availability mode for Portlyn.

## Supported cluster mode

- Multiple Portlyn instances behind a load balancer
- Shared PostgreSQL database
- Shared Redis instance (required for distributed auth cache, rate limits, and route cache invalidation bus)
- ACME worker leader enabled on exactly one instance at a time (`ACME_LEADER=true`)

## Required settings

- `DATABASE_DRIVER=postgres`
- `DATABASE_URL=...` pointing at shared PostgreSQL
- `REDIS_URL=...` pointing at shared Redis
- `ACME_ENABLED=true` on all nodes
- `ACME_LEADER=true` on one node and `false` on all others

## Deployment notes

- Keep auth and crypto secrets identical across all instances: `JWT_SIGNING_SECRET`, `SESSION_BRIDGE_SECRET`, `OIDC_STATE_SECRET`, `MFA_ENCRYPTION_SECRET`, `CSRF_SECRET`, `DATA_ENCRYPTION_SECRET`, and `AUDIT_HMAC_SECRET` (a differing `AUDIT_HMAC_SECRET` breaks audit hash-chain verification across instances).
- Use the same app version across the cluster during rollout.
- Configure health checks against `/readyz` and `/healthz`.
- If Redis is unavailable, Portlyn falls back to local mode; this is not a supported HA steady state.

## Rollout pattern

1. Drain one instance from the load balancer.
2. Upgrade it and verify `/readyz`.
3. Re-add it and continue with next instance.
4. Upgrade ACME leader last and reassign `ACME_LEADER=true` intentionally.

## Failure handling

- If ACME leader fails, promote one standby instance by setting `ACME_LEADER=true`.
- If Redis fails, expect degraded cluster behavior and restore Redis first.
- If PostgreSQL fails, all nodes become unready; restore DB before rotating app nodes.

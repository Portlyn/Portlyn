---
title: Break-glass recovery
description: Getting back in when you have locked yourself out.
---

Break-glass is a one-time emergency login path for local admin accounts when normal auth paths are blocked (for example OIDC outage + admin MFA lockout).

## Enable

Set:

- `BREAK_GLASS_ENABLED=true`
- `BREAK_GLASS_TOKEN=<strong one-time token>`
- `BREAK_GLASS_TTL=15m` (or shorter)
- `BREAK_GLASS_ALLOW_CIDRS=127.0.0.1/32,::1/128` (or your secure jump-host CIDRs)

## Use

Call:

- `POST /api/v1/auth/break-glass/login`

Body:

```json
{
  "email": "admin@example.com",
  "password": "your-local-admin-password",
  "token": "BREAK_GLASS_TOKEN"
}
```

Constraints:

- Allowed only from `BREAK_GLASS_ALLOW_CIDRS`.
- One-time token (consumed after successful login).
- Expired after `BREAK_GLASS_TTL`.
- Restricted to **active local admin accounts**.

## After recovery

1. Fix root cause (OIDC/MFA/DB/etc.).
2. Rotate `BREAK_GLASS_TOKEN`.
3. Disable break-glass (`BREAK_GLASS_ENABLED=false`) unless currently needed.
4. Review audit log entries:
   - `break_glass_login_failed`
   - `break_glass_login_succeeded`


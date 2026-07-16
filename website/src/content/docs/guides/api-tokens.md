---
title: API tokens
description: Bearer tokens for CI and automation, without CSRF or MFA getting in the way.
sidebar:
  order: 4
---

People log in with a session cookie, CSRF, and MFA. Scripts shouldn't have to. An API token is a long-lived bearer token you create once, hand to CI, and revoke when you're done.

Create one under Access → API Tokens (admin only). The token is shown once. It carries a role (`viewer` is read-only, `admin` can change anything) and an optional expiry. Send it as a bearer header:

```bash
curl -H "Authorization: Bearer plyn_..." https://portlyn.example.com/api/v1/services
```

Token requests skip CSRF and the MFA bootstrap, since neither applies to something that isn't a browser. Roles and audit logging work the same as a normal session.

The server never stores the token itself, only a SHA-256 hash of it. Revoking one takes effect on the next request. Give admin tokens sparingly and set an expiry on anything that doesn't need to live forever.

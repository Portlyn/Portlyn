---
title: Using the API
description: Base URL, authentication, and error format for the Portlyn control plane.
sidebar:
  order: 5
---

Everything the dashboard does goes through a JSON API under `/api/v1`. The full endpoint list is in the [API reference](/api/); this page covers the parts you need before you start poking at it.

## Auth

Two ways in, both as `Authorization: Bearer <token>`:

- A **session JWT** from `/auth/login` or the OTP flow. This is what the browser uses. It's short-lived and paired with a CSRF token and, for admins, MFA.
- An **API token** you create under Access → API Tokens. Long-lived, revocable, and exempt from CSRF and MFA, since none of that makes sense for a script. See [API tokens](/guides/api-tokens/).

For anything automated, use an API token:

```bash
curl -H "Authorization: Bearer plyn_..." https://portlyn.example.com/api/v1/services
```

Browser clients get an `HttpOnly` session cookie instead of a token in the response body. The login response only includes the raw token if `EXPOSE_AUTH_TOKENS=true`, which you shouldn't set in production.

## Conventions

- Base URL is `/api/v1`.
- Request and response bodies are JSON.
- Writes need the CSRF header when you're on a cookie session. Bearer-token requests skip it.
- Errors come back as `{ "error": { "code": "...", "message": "..." } }` with the matching HTTP status.

## Reference

The [API reference](/api/) is generated from [`docs/openapi.yaml`](https://github.com/portlyn/Portlyn/blob/main/docs/openapi.yaml). It's not complete yet, it covers auth, nodes, certificates, DNS providers, and API tokens so far. The rest of the endpoints exist in the code under `internal/http` and get added to the spec over time.

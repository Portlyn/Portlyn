---
title: Quickstart
description: Run Portlyn on your own machine in one command, no domain and no TLS.
sidebar:
  order: 1
---

Grab a binary from the [releases page](https://github.com/portlyn/Portlyn/releases/latest) (or build with `go build ./cmd/server`), then:

```bash
PORTLYN_DOMAIN=localhost ./portlyn init --non-interactive
./portlyn
```

That's it. The `localhost` domain tells `init` to write a local profile: plain HTTP, no ACME, dashboard on `http://localhost:8000`. Port 8000 is unprivileged, so you don't need root.

Log in as `admin@localhost`. The password was generated and written to the `.env`:

```bash
grep '^ADMIN_PASSWORD=' .env
```

## When something won't start

Portlyn is strict about config. It won't run a non-localhost URL without TLS, it wants unique 32-character secrets, and so on. That's deliberate, but the first time you hit it it's annoying.

`doctor` prints every problem at once with a fix for each, instead of failing on the first one and making you guess:

```bash
./portlyn doctor
```

Once local poking around gets boring, [install it properly](/start/install/) on a server.

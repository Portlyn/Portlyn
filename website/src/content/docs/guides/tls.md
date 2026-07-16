---
title: First boot and TLS
description: How Portlyn is reachable before it has a real certificate, and how to reach it by IP.
sidebar:
  order: 2
---

The hub answers on HTTPS the moment it starts, before any real certificate exists. It generates a short-lived self-signed cert on demand for whatever hostname (or IP) a client asks for.

So the onboarding path is:

1. Install and start.
2. Open `https://your-domain`, accept the certificate warning, log in with the admin account from `init`.
3. Add a DNS-01 provider under **Certificates → DNS providers**, or [seed one from the environment](/guides/dns-providers/).
4. Request a certificate. Once it's issued the hub serves it automatically and the warning goes away.

## Reaching it by IP, before you have DNS

Sometimes you want the Proxmox/Portainer flow: hit `https://<server-ip>`, log in, sort out the domain from there. Easiest way is to set the IP as the domain during `init`:

```bash
sudo portlyn init --non-interactive --domain 192.168.1.50 --admin-email you@example.com
```

Now the IP is the admin host, the self-signed cert matches it, and it's reachable from your LAN. Later, add the real domain (the [setup wizard](/guides/dns-providers/#from-the-dashboard) does it in the UI), point `FRONTEND_BASE_URL` at it, and restart.

If you'd rather keep `FRONTEND_BASE_URL` on the domain but still reach the box by IP while DNS isn't ready yet, set `BOOTSTRAP_ADMIN_ENABLED=true` (the default from `init`) together with `BOOTSTRAP_ADMIN_ALLOW_REMOTE=true`. That drops the "local requests only" guard on the bootstrap dashboard.

Turn `BOOTSTRAP_ADMIN_ALLOW_REMOTE` back off once the real domain and certificate work. Left at its default it only serves the bootstrap dashboard to the local host, so you'd reach it through an SSH tunnel. `doctor` warns while it's on.

## The empty-SNI case

The bootstrap cert is also served when a client connects without SNI. Testing with a spoofed `Host` header trips this, so pass SNI explicitly and the right cert gets picked:

```bash
curl --resolve portlyn.example.com:443:<hub-ip> https://portlyn.example.com/
```

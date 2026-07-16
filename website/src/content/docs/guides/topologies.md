---
title: Where does it sit?
description: How to configure TLS and the ACME challenge for the three common network setups.
sidebar:
  order: 1
---

The right ACME challenge and proxy settings depend on how traffic reaches the hub. Three cases cover almost everyone.

## Public IP

The hub has a public address and ports 80 and 443 are open. Point an `A`/`AAAA` record at it.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
REDIRECT_HTTP_TO_HTTPS=true
```

HTTP-01 works with no extra config, since Let's Encrypt can reach port 80. You don't need `TRUSTED_PROXY_CIDRS` here, because the hub sees real client IPs. DNS-01 is optional and handy for wildcards.

## Behind Cloudflare's proxy

Cloudflare terminates TLS and forwards to you, so the client IP arrives in a header and Cloudflare eats the HTTP-01 challenge.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
TRUSTED_PROXY_CIDRS=173.245.48.0/20,103.21.244.0/22,...
NODE_TRUST_FORWARDED_PROTO=true
```

Use DNS-01 so issuance doesn't depend on inbound port 80. Set `TRUSTED_PROXY_CIDRS` to Cloudflare's published ranges. That's what tells the hub to believe `X-Forwarded-For` and `-Proto`, and only from Cloudflare. Set Cloudflare's SSL mode to Full (strict).

## Behind NAT or another load balancer

Nothing inbound reaches the hub. Home lab, CGNAT, that sort of thing. HTTP-01 is out.

```env
FRONTEND_BASE_URL=https://portlyn.example.com
ACME_ENABLED=true
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
```

DNS-01 only. With a provider configured, the hub also enqueues the dashboard certificate over DNS-01, so the first cert lands without any inbound connectivity. This is the case the node agent exists for: run it on the machine behind the firewall and it dials the hub over WireGuard.

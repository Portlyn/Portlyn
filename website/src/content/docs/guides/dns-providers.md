---
title: DNS providers
description: Seed a DNS-01 provider from the environment or from the dashboard.
sidebar:
  order: 3
---

DNS-01 lets Portlyn get a certificate without any inbound ports, which is the whole point for anything behind NAT. You give it an API token that can edit DNS records for your zone.

## From the environment

For a hands-off install that gets a real cert on first boot, set the provider in the environment. It's only created if none exists yet. After that the database wins:

```env
ACME_DNS_PROVIDER=cloudflare
ACME_DNS_CLOUDFLARE_API_TOKEN=...
```

Supported providers and their variables:

- Cloudflare: `ACME_DNS_CLOUDFLARE_API_TOKEN`
- Hetzner: `ACME_DNS_HETZNER_API_TOKEN`
- DigitalOcean: `ACME_DNS_DIGITALOCEAN_API_TOKEN`
- Route53: `ACME_DNS_ROUTE53_ACCESS_KEY_ID` and `ACME_DNS_ROUTE53_SECRET_ACCESS_KEY`, plus optional `ACME_DNS_ROUTE53_SESSION_TOKEN`, `ACME_DNS_ROUTE53_REGION`, `ACME_DNS_ROUTE53_HOSTED_ZONE_ID`, `ACME_DNS_ROUTE53_PROFILE`

`init` writes these for you when you pass `--dns-provider` and `--dns-token`.

## From the dashboard

If you'd rather not touch env files, the first-run wizard asks for your domain, DNS provider, and token after you log in. It creates the provider, registers the domain, and requests a DNS-01 certificate for you. `FRONTEND_BASE_URL` is a start-up value, so switching the dashboard onto the new domain needs a restart. The wizard tells you when.

You can also do it any time under **Certificates → DNS providers**.

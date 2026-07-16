---
title: Install on a server
description: One-line install, manual binary, or Docker Compose, plus how to verify a release.
sidebar:
  order: 2
---

## One line

The install script pulls the binary, checks its signature, makes a `portlyn` system user, drops a systemd unit, and runs `init` if you hand it a domain and email:

```bash
curl -fsSL https://get.portlyn.dev \
  | sudo PORTLYN_DOMAIN=portlyn.example.com PORTLYN_ADMIN_EMAIL=you@example.com sh
```

Leave the env vars off to install the binary and unit only, then configure it yourself.

On a stripped-down box without `curl` or `sudo` (a minimal LXC, say), install the prerequisites first (`apt-get install -y curl ca-certificates`), or fetch the script with `wget` and run it as root:

```bash
wget -qO- https://get.portlyn.dev | sh
```

Signature checking needs no extra tools. If `cosign` is on the box it uses that; otherwise the downloaded binary (already checksum-verified) checks its own release signature against a Sigstore trust root baked into it. Set `ALLOW_UNSIGNED=1` to skip the signature and settle for the checksum.

## Manual binary

```bash
curl -L https://github.com/portlyn/Portlyn/releases/latest/download/portlyn-linux-amd64 -o portlyn
chmod +x portlyn
sudo mv portlyn /usr/local/bin/portlyn
sudo portlyn init
sudo portlyn
```

The systemd unit lives at [`scripts/portlyn.service`](https://github.com/portlyn/Portlyn/blob/main/scripts/portlyn.service). It expects the binary at `/usr/local/bin/portlyn` and the `.env` at `/var/lib/portlyn/.env`.

## Verify a release

Every tag is signed with keyless Cosign through Sigstore. For a production box, check it before you run anything. Either point the binary at the release files:

```bash
portlyn verify-release --checksums checksums.txt --bundle checksums.txt.bundle.json
```

or do it by hand with `cosign`:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/[Pp]ortlyn/[Pp]ortlyn' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  checksums.txt
```

## Non-interactive setup

`init --non-interactive` never prompts. Every value comes from a flag or an env var, and the admin password is generated (and written to the `.env`) if you don't supply one:

```bash
portlyn init --non-interactive \
  --domain portlyn.example.com \
  --admin-email you@example.com \
  --admin-password "$(openssl rand -base64 24)" \
  --dns-provider cloudflare --dns-token "$CF_TOKEN"
```

Env equivalents: `PORTLYN_DOMAIN`, `PORTLYN_ADMIN_EMAIL`, `PORTLYN_ADMIN_PASSWORD`, `PORTLYN_ACME_EMAIL`, `PORTLYN_DNS_PROVIDER`, `PORTLYN_DNS_TOKEN`, `PORTLYN_NONINTERACTIVE=true`.

## Docker Compose

```bash
git clone https://github.com/portlyn/Portlyn.git
cd Portlyn
cp .env.docker.example .env.docker
# fill in secrets and admin credentials
docker compose --env-file .env.docker up -d
```

The stack pulls `ghcr.io/portlyn/portlyn:latest`. Pin a tag with `PORTLYN_IMAGE_TAG=v1.2.3`. If the pull is denied the packages are private for that build, so either `docker login ghcr.io` or build locally:

```bash
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

The bundled Postgres talks to the hub over the private compose network with `sslmode=disable`. Portlyn treats a plaintext link to a private or container-local database as fine (it warns, doesn't refuse). For an external database use `sslmode=require` or stronger.

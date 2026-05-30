# Security Policy

## Supported versions

Security fixes are applied to the latest tagged release on the default branch.
Older tags are not patched.

## Reporting a vulnerability

Please do not open public GitHub issues for suspected vulnerabilities.

Report security issues privately through either:

- Email: `security@portlyn.dev`
- GitHub Private Vulnerability Reporting: use the **Security** tab of this repository

Include:

- a clear description of the issue
- affected version, tag, or commit
- reproduction steps or proof of concept
- impact assessment if known

You will get an acknowledgement within a few business days.
Please allow time for investigation and remediation before public disclosure.

## Threat model

What Portlyn protects against and what it does not, so you can decide whether it fits your deployment.

### In scope

- **Origin exposure.** Inbound traffic terminates at the hub. Nodes never listen for inbound from the public internet.
- **Route authentication.** Per route access mode (`public`, `authenticated`, `restricted`) plus access method (session, OIDC, PIN, email code). Brute force protection on PIN and email code.
- **Admin authentication.** Passkeys, TOTP, OIDC SSO, bcrypt for local password. Account lockout on repeated failed attempts. Optional mandatory MFA for admins.
- **Session integrity.** HttpOnly cookies, `Secure` outside dev mode, `SameSite=Lax` for sessions, `SameSite=Strict` for refresh tokens. CSRF double submit with HMAC. JWT with explicit `alg` allow list.
- **Audit integrity.** Hash chained audit log with previous hash verification. Webhook payloads carry an HMAC-SHA256 signature.
- **Cross host auth bridging.** Route access cookies are bound to the service host through a signed JWT bridge token with a short TTL.
- **Secrets at rest.** AES-256-GCM with Argon2id derived keys for DNS provider credentials, MFA secrets, and similar sensitive material.
- **Supply chain.** Releases are built from GitHub Actions and signed with Cosign keyless. Self update verifies the SHA-256 checksum and the full Sigstore certificate chain via sigstore-go using the embedded TUF trust root.
- **Tunnel.** Single use enrollment tokens. Per node WireGuard keypairs that never leave the node. Heartbeat tokens scoped per node. Node enrollment rate limit.

### Out of scope

- **Application layer vulnerabilities behind Portlyn.** Portlyn is not a Web Application Firewall. It rate limits and matches IP, country, and CrowdSec decisions, but it does not inspect request bodies for SQLi, XSS, RCE patterns. A vulnerable upstream remains vulnerable.
- **Multi tenant isolation.** Portlyn is single tenant. All admins see all services. Do not deploy a single hub to host workloads for parties that do not trust each other.
- **Compromise of an enrolled node.** If a node is compromised the attacker can reach whatever that node is configured to forward to. Limit per node scope.
- **DNS account takeover.** If your DNS registrar account is compromised, DNS-01 validation can be hijacked. This is outside Portlyn's control.
- **Volumetric L3 or L4 DDoS.** Portlyn rate limits at L7. For volumetric attacks, use a CDN or a larger upstream.
- **Local malware on an admin's machine.** Session theft from a compromised admin browser cannot be prevented by the server.
- **Compromise of GitHub itself or your local build toolchain.** Reproducible builds and Cosign signatures detect tampering of released artifacts; they do not defend against an attacker with commit rights or a compromised laptop.

### Trust boundaries

```
[ User browser ] -- HTTPS --> [ Hub ] -- WireGuard --> [ Node ] -- TCP/UDP --> [ Upstream ]
                                 |
                                 +--> ACME provider, OIDC IdP, DNS API, webhook sinks
```

Each arrow is a separate trust boundary:

- **Browser to hub.** TLS, CSRF, session, MFA. Hostile browser is out of scope.
- **Hub to node.** WireGuard authentication (keypair plus enrollment token at first boot). A rogue node cannot impersonate another node without its private key.
- **Node to upstream.** Standard TCP or UDP. Portlyn does not add encryption between the node and the upstream; deploy the upstream on the same trust boundary as the node.
- **Hub to external services** (ACME, OIDC, DNS, webhooks). Standard TLS verification. Credentials encrypted at rest in the hub database.

## Supply chain

- **Build.** Every release is built by `.github/workflows/release.yml` on a GitHub hosted runner. The workflow is the only entity that holds the keyless signing identity.
- **Sign.** Cosign keyless via Sigstore Fulcio. The certificate identity is bound to the workflow URL.
- **Verify.** Consumers can verify any release artifact with:

  ```bash
  cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-identity-regexp 'https://github.com/invaliduser231/Portlyn' \
    --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
    checksums.txt
  ```

- **Self update.** `portlyn update` performs the same verification automatically using the embedded TUF trust root, then verifies the per binary SHA-256 against the signed checksum file before atomic swap.

## Defaults that should not be weakened

- `ALLOW_INSECURE_DEV_MODE=false`. Rejected at startup in production builds.
- `REQUIRE_MFA_FOR_ADMINS=true`.
- `NODE_REQUIRE_HTTPS=true`.
- `REDIRECT_HTTP_TO_HTTPS=true` once TLS is active.
- `OTP_RESPONSE_INCLUDES_CODE=false`.
- `TRUSTED_PROXY_CIDRS` left at loopback unless Portlyn actually sits behind another L7 proxy.

## Telemetry

Portlyn collects no telemetry. No analytics SDK. No automatic update checks. The only outbound traffic comes from features you explicitly configure (ACME, webhooks, OIDC, DNS provider APIs, CrowdSec LAPI).

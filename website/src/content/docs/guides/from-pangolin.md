---
title: Coming from Pangolin
description: How Pangolin's concepts map onto Portlyn, and the steps to move a setup across.
sidebar:
  order: 6
---

Pangolin and Portlyn solve the same problem in a similar way: a hub on a VPS, an agent on a box behind NAT, a login in front of your services. If you're already running Pangolin, the mental model carries over almost directly. There's no automatic importer, and after reading how the pieces actually move you'll see why one wouldn't save much. The manual path is short.

## How the concepts line up

| Pangolin | Portlyn |
| --- | --- |
| Organization | The whole instance. Portlyn isn't multi-tenant; every admin sees everything. |
| Site (Newt connector) | [Node](/guides/expose-a-service/#steps) running `portlyn-nodeagent` |
| Resource | Service (a host, a target URL, an access policy) |
| Resource domain / subdomain | Service **Root domain** + **Subdomain** |
| Resource target | Service **Target URL**, with **Route via tunnel node** set to the node |
| Password / PIN on a resource | **Authentication flow** → Route-PIN |
| Email whitelist | Allowed email addresses or domain on the service |
| SSO / IdP | [OIDC](/reference/configuration/) plus Portlyn users |
| Gerbil + Traefik internals | Built in. Nothing to move. |

## What doesn't transfer

Two things stay behind, and they're the reason a one-click button wouldn't help much:

- **The tunnels.** Pangolin's Newt agents have their own keys. You re-enroll each machine as a Portlyn node, which takes one command. The old Newt tunnel keeps running until you're done, so nothing breaks mid-move.
- **Secrets.** Resource passwords are hashed and SSO client secrets are encrypted on Pangolin's side. You set PINs again and re-add the OIDC client. There's no way around that, and no importer could do it either.

## Moving a setup across

You can do this one resource at a time, with both systems live, and only cut DNS over when you're happy.

1. Stand up the Portlyn hub. Follow [Install](/start/install/), or the full [expose-a-service walkthrough](/guides/expose-a-service/) if you want the whole path in one page.
2. For each Pangolin **site**, enroll the same machine as a Portlyn **node**: Nodes → Install node, then run the one-liner on the box. New keys, outbound only, same as Newt.
3. For each Pangolin **resource**, create a Portlyn **service** with the same domain, the same internal target as the **Target URL**, and **Route via tunnel node** pointing at the node from step 2.
4. Set the access policy to match what the resource used: a Route-PIN, an emailed code, an email allowlist, or OIDC.
5. When a service checks out, repoint that subdomain's DNS from the Pangolin VPS to the Portlyn hub. Per-subdomain records let you migrate gradually instead of all at once.
6. Use the access tester to confirm the rules do what you expect, then retire the Pangolin resource.

Once every resource is across and DNS is cut over, the Pangolin VPS and its Newt agents can go.

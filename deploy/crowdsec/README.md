# CrowdSec integration

Portlyn has a built-in CrowdSec bouncer (the `portlyn-crowdsec` local API client), so it can act on decisions without a separate bouncer process. What it can't do on its own is *detect* attacks. That's what this collection does: it teaches a CrowdSec engine to read Portlyn's logs, spot scanning, and hand decisions back.

## What's here

- `acquis.yaml` — tells CrowdSec where Portlyn's logs are (journald by default).
- `parsers/s01-parse/portlyn-logs.yaml` — strips the syslog prefix the journalctl datasource adds, then pulls `source_ip`, `status`, `path`, `outcome` out of the JSON.
- `scenarios/portlyn-http-404-scan.yaml` — bans an IP that walks a lot of distinct 404s. Ignores blocked requests so a ban can't feed itself.

## Install

```bash
sudo cp acquis.yaml /etc/crowdsec/acquis.d/portlyn.yaml
sudo cp parsers/s01-parse/portlyn-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo cp scenarios/portlyn-http-404-scan.yaml /etc/crowdsec/scenarios/
sudo systemctl restart crowdsec
```

Check it sees the logs and the scenario loads:

```bash
sudo cscli metrics          # acquisition + parser + scenario counts
sudo cscli scenarios list | grep portlyn
```

Verify parsing against a **live** feed, not `cscli explain`. The journalctl
datasource prepends a syslog prefix that `cscli explain --file` never sees, so
explain can pass while the live parser extracts nothing. Generate a 404 against a
service and watch the parser bucket fill:

```bash
curl -s -o /dev/null https://yourservice.example.com/this-does-not-exist
sudo cscli metrics | grep -A2 portlyn/proxy-logs   # parsed count should climb
```

If parsed stays at zero but acquisition is reading lines, the prefix strip is the
first thing to check.

## Real client IPs

The scenario is only as good as the IP in the log. If Portlyn sits behind Cloudflare (or any proxy), set `TRUSTED_PROXY_CIDRS` to the proxy's ranges. Portlyn then logs the real client IP as `remote_addr` instead of the edge, so CrowdSec bans the attacker, not Cloudflare. Without it you'd be banning your own CDN.

## Getting unbanned

Decisions propagate to the built-in bouncer within one poll interval (`crowdsec_poll_interval_secs`, default 60). If you ban yourself:

```bash
sudo cscli decisions delete --ip <your-ip>
```

You're back in within a poll cycle. No Portlyn restart needed.

## Status

First cut. The parser and 404 scenario are here; an auth-brute-force scenario, an IP allowlist, and a Grafana dashboard are the obvious next additions.

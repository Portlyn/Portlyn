---
title: CLI
description: The portlyn subcommands.
sidebar:
  order: 2
---

```
portlyn                start the server (needs a .env)
portlyn init           set up .env and the admin account; --non-interactive for CI
portlyn doctor         check the whole environment and list every problem with a fix
portlyn config check   same as doctor
portlyn settings sync  push env-controlled settings into the database
portlyn update         download, verify, and swap in the latest release
portlyn verify-release  check a release signature in-process, no cosign needed
portlyn version        print the version
```

## init

Writes a complete `.env` with fresh secrets, makes the data directory, and creates the admin. Existing `.env` files are left alone unless you pass `--force`. A `localhost` domain gets you a local HTTP profile with no ACME. See [Quickstart](/start/quickstart/) and [Install](/start/install/#non-interactive-setup).

## doctor

Loads the environment, runs the full validation, and prints every error and warning together, each with a suggested fix. Exits non-zero if anything is broken, so it works as a pre-start check in CI.

## update

Pulls the latest release, verifies the SHA-256 and the Sigstore signature against a trust root embedded in the binary, swaps atomically, and restarts the service. Flags: `--check` (just look), `--version v1.2.3`, `--no-restart`, `--unit`. The node agent has the same command. It only talks to GitHub when you run it, so there are no background update checks.

## verify-release

Checks that `checksums.txt` is really signed by the release workflow, using the same in-process Sigstore verification as `update`. Point it at the downloaded release files:

```bash
portlyn verify-release --checksums checksums.txt --bundle checksums.txt.bundle.json --asset portlyn-linux-amd64
```

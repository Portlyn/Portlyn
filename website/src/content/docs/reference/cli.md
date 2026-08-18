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
portlyn migrate        apply pending schema migrations (status, down)
portlyn update         download, verify, and swap in the latest release
portlyn verify-release  check a release signature with an already trusted binary
portlyn version        print the version
```

## init

Writes a complete `.env` with fresh secrets, makes the data directory, and creates the admin. Existing `.env` files are left alone unless you pass `--force`. A `localhost` domain gets you a local HTTP profile with no ACME. See [Quickstart](/start/quickstart/) and [Install](/start/install/#non-interactive-setup).

## doctor

Loads the environment, runs the full validation, and prints every error and warning together, each with a suggested fix. Exits non-zero if anything is broken, so it works as a pre-start check in CI.

## migrate

The schema is versioned. Every change is a numbered migration that runs once, in
order, and is recorded in the `schema_migrations` table together with the time it
ran. The server applies pending migrations on start, so you rarely need this
command, but before an upgrade it tells you what is about to happen.

```bash
portlyn migrate status        # what has run, what is pending
portlyn migrate up            # apply everything pending
portlyn migrate down <id>     # roll one migration back, if it has a down step
```

Each migration commits together with its bookkeeping row, so a crash mid-upgrade
never leaves a half-recorded migration. On Postgres the run takes an advisory
lock, so several hub instances starting at once cannot migrate over each other.
The first one migrates, the rest wait and then find nothing to do.

Not every migration can be undone. Ones that drop data have no down step and
`migrate down` refuses them; restore from a backup instead.

## update

Pulls the latest release, verifies the SHA-256 and the Sigstore signature against a trust root embedded in the binary, swaps atomically, and restarts the service. Flags: `--check` (just look), `--version v1.2.3`, `--no-restart`, `--unit`. The node agent has the same command. It only talks to GitHub when you run it, so there are no background update checks.

## verify-release

Checks that `checksums.txt` is really signed by the release workflow, using the same in-process Sigstore verification as `update`. Point it at the downloaded release files:

This only means something when the `portlyn` doing the checking is one you already trust, meaning an installed binary checking a *new* download. Never use a freshly downloaded binary to verify itself; for a first install use `cosign` (the installer does).

```bash
portlyn verify-release --checksums checksums.txt --bundle checksums.txt.bundle.json --asset portlyn-linux-amd64
```

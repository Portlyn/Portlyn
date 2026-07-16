---
title: Backup and restore
description: What to back up and how to bring it back.
---

Portlyn now includes built-in backup/restore helper scripts for self-hosted operations.

## Scripts

- `scripts/backup.sh [output-dir]`
- `scripts/restore.sh <backup-file>`

Both scripts read `.env.docker` automatically when present.

## PostgreSQL mode

When `DATABASE_DRIVER=postgres`:

- backup uses `pg_dump`
- restore uses `psql`

Required tools:

- `pg_dump`
- `psql`

## SQLite mode

When `DATABASE_DRIVER=sqlite`:

- backup copies `DATABASE_PATH` to timestamped file
- restore copies selected backup file back to `DATABASE_PATH`

## Operational guidance

- Keep application version metadata with each backup.
- Keep database backups and `/data` artifacts in separate storage.
- Test restore regularly in a disposable environment.
- Run backup before upgrades and retain at least one known-good restore point.

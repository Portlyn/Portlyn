---
title: Secret rotation
description: Rotating the data-encryption key without downtime.
---

This guide covers rotation of `DATA_ENCRYPTION_SECRET` used for encrypted DNS provider config.

## Dual-key window model

- `DATA_ENCRYPTION_SECRET` is the active encryption key.
- `DATA_ENCRYPTION_LEGACY_SECRETS` is a comma-separated list of previous keys used only for decryption fallback.
- New writes always use the active key.

## Rotation steps

1. Generate a new strong active key.
2. Move the old active key into `DATA_ENCRYPTION_LEGACY_SECRETS`.
3. Deploy config with both keys present.
4. Run status:
   - `GET /api/v1/security/rotation/status`
5. Run re-encrypt:
   - dry run: `POST /api/v1/security/rotation/data-key/reencrypt?dry_run=true`
   - execute: `POST /api/v1/security/rotation/data-key/reencrypt`
6. Verify `reencrypt_candidates` is zero.
7. Remove legacy keys and redeploy.

## Notes

- All rotation actions are audit-logged.
- If `decrypt_failures` is non-zero, resolve those providers before removing legacy keys.


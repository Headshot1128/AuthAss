License freeze
==============

The licenses table has a Freeze / Unfreeze action. Freezing pauses the key's
remaining lifetime and blocks activation. If assigned, it also pauses the
account subscription and blocks protected resources, including access through
existing sessions. Authentication itself remains available.

Unfreezing shifts the key expiry forward by the paused duration. The account
subscription resumes once its last frozen key is unfrozen or revoked. An
already expired key stays expired after unfreezing.

The Python backend applies migration 005 at startup. For the Cloudflare
backend, apply D1 migration 0005_classy_meltdown.sql before deploying the new
server and assets. Both licenses and users receive a nullable frozen_at column.

Regression coverage: tests/test_license_freeze.py.

# Deployment and operations

## HTTPS and network boundaries

Use a dedicated unprivileged service account, Python 3.13+, and a patched TLS stack. Install dependencies in an isolated environment. Resolve, lock, scan, and archive all transitive dependencies for your deployment platform; `requirements.txt` pins tested direct dependencies, not a complete supply-chain lock. C++ dependencies come from your OS package manager or vcpkg; pin a reviewed vcpkg baseline in your release process.

The simplest secure topology runs uvicorn with a full certificate chain and private key, directly on TLS, bound to a private interface behind a TCP load balancer or firewall. Do not expose an HTTP uvicorn port publicly. The application rejects HTTP and does not itself trust arbitrary forwarded headers. If a reverse proxy terminates TLS, either reencrypt its backend connection or configure uvicorn's `--proxy-headers --forwarded-allow-ips=<exact proxy IP>` and firewall the backend to that proxy only. Never use `*` on an exposed service. Test that forged `X-Forwarded-Proto` from an untrusted connection cannot bypass HTTPS enforcement. Trust the same exact proxy for real client IPs or peer throttles will group all clients together.

Example direct-TLS Linux systemd service (adjust installed paths and certificate ACLs):

```ini
[Unit]
Description=Secure authorization API
After=network.target

[Service]
User=secureauth
Group=secureauth
WorkingDirectory=/opt/secureauth
EnvironmentFile=/etc/secureauth/environment
UMask=0077
ExecStart=/opt/secureauth/.venv/bin/python -m uvicorn backend.app:create_app --factory --host 0.0.0.0 --port 8443 --ssl-certfile /etc/secureauth/tls/fullchain.pem --ssl-keyfile /etc/secureauth/tls/privkey.pem --no-access-log --limit-concurrency 64 --timeout-keep-alive 5
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/secureauth

[Install]
WantedBy=multi-user.target
```

Environment file:

```ini
AUTH_DATABASE=/var/lib/secureauth/auth.db
AUTH_STORAGE=/var/lib/secureauth/private
AUTH_REGISTRATION=false
```

Initialize the schema and provision an administrator offline under that same environment before starting the service. Use a persistent local disk; SQLite WAL must not reside on a network filesystem. Run one worker initially. Multiple workers on the same local DB serialize writes but do not improve DB throughput. Do not share this database between machines. Add connection limits, bounded headers/body sizes, handshake and request-body timeouts, and external rate limiting at the edge. The application's 32 KiB body cap alone does not prevent slow-client denial of service. Keep management routes behind a VPN or restricted management network where possible.

On Windows use a dedicated restricted service identity and a service manager that can run the same uvicorn command, with absolute paths. Grant that identity access to its database directory, read access to payloads and TLS key, and deny ordinary users. Do not run the service as Administrator. The API does not launch a GUI or require interactive access.

## Storage and database

SQLite has no network password: anyone who can read the database can read its data and password hashes. Anyone who can write it can grant permissions. Protect its directory, WAL/SHM files, backups, and the TLS private key with restrictive OS ACLs. On Linux use directory mode 0700 and a 0077 service umask. Use encrypted disks/backups for data-at-rest protection. A future move to PostgreSQL must preserve refresh atomicity, transactions, foreign keys, and every request's authorization checks; simply swapping connection strings is unsupported.

The private file directory must not be a web root and must never be mounted by a static server. Operator uploads should use a separate trusted provisioning channel. Write new immutable versioned files and atomically replace metadata after successful transfer; verify business-specific integrity requirements before enabling them. Keep the running service's payload directory read-only when feasible. The metadata API restricts filenames and rejects resolved paths outside this directory. It does not scan files for malware or provide a general upload service. Never make metadata permission decisions from a client-supplied user ID.

Schema migration 001 is in `backend/migrations`. `python -m backend.cli init` applies it once. Take an online backup before future migrations, test migration/restore on staging, and deploy migrations before starting new workers. Current tables include users, sessions, access/refresh token hashes, licenses, permissions, variables, file metadata, audit records, rate counters, and schema versions.

## Backups and retention

New NOVYX license keys have an encrypted display copy in addition to the lookup hash.
Protect and separately back up the server-only encryption file (`AUTH_LICENSE_KEY_FILE`,
default database path plus `.license-key`). Restrict it to the service identity. Never
copy it into the client, public assets, or a source archive. Restore the matching encryption
file when restoring a database. Do not delete or replace it to rotate credentials: rotation
requires reencrypting every display copy with the replacement key while the service is
offline. Historical hash-only keys are not recoverable. The application refuses display
or new key creation if an existing display key file is lost.

Use SQLite's online backup API while the service is running; copying only the live `.db` file can omit WAL changes. Example under the service identity (with your real absolute paths):

```python
import sqlite3
with sqlite3.connect('/var/lib/secureauth/auth.db') as source:
    with sqlite3.connect('/secure-backups/auth-snapshot.db') as target:
        source.backup(target)
```

Back up immutable private files and matching metadata, encrypt backup media, and periodically restore into an isolated environment. After restoring a database snapshot, revoke all restored sessions **before** accepting traffic (`UPDATE sessions SET revoked=1` in an offline maintenance transaction). Otherwise old backup tokens could become valid again. Verify checksums and `PRAGMA integrity_check`, then test login, denied resources, permitted resources, and replay detection.

Audit and token tables grow. Schedule maintenance under an exclusive maintenance window or a trusted job: remove sessions only after their absolute deadline and delete their access/refresh rows first; retain refresh replay markers for the whole live session. Do not delete live used-refresh markers. Export audit events to your secured log system, then prune according to retention policy. Rate counters older than one day are cleaned on rate-limit checks. Do not disable auditing to reduce database load; size storage and monitor capacity. A database write failure denies the request instead of bypassing policy.

## Rotation and incident response

There are no token signing keys, database passwords, storage API credentials, or admin master API keys in this design. TLS private keys and administrator passwords are server-side operational credentials. Rotate TLS certificates through your CA, restrict key permissions, and reload/restart uvicorn to load the new pair. Maintain CA trust continuity for clients; never disable certificate verification to work around rotation. Custom enterprise CAs require an updated bundle passed to `CurlTransport`.

Rotate account passwords offline using `python -m backend.cli reset-password --username NAME`; it prompts securely and revokes every session for that account. Suspend/revoke accounts and licenses via the admin API; session checks use current records immediately. For a token or server compromise, stop public traffic, revoke all sessions in a trusted maintenance transaction, rotate affected passwords and TLS keys, inspect exported audit records, restore trusted software and data, then reopen. A short access lifetime is not a substitute for revocation.

Keep clocks synchronized. Monitor login denials, refresh replays, rate limits, unusual download volume, failed backups, DB contention, and disk usage. Do not enable access logging that records Authorization headers, request bodies, refresh tokens, or license keys. Admin passwords are not protected by MFA in this implementation; a restricted management network and strong unique passwords are essential deployment controls.

## Release gate

Run backend regressions, compile the SDK on each supported platform, execute CTest, and run `SDK_E2E_BINARY` TLS integration against the actual release dependencies. Exercise production TLS, proxy forwarding, backup restoration, ACLs, disk exhaustion, and revocation during downloads in staging. A passing unit suite does not validate your firewall, CA renewal, filesystem configuration, or production deployment. Obtain independent review before relying on this system for sensitive assets.

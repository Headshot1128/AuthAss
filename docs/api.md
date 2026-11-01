# API reference

Requests use JSON. All bodies reject unknown fields. Usernames are case-insensitive ASCII letters, digits, `_`, `.`, or `-`, length 3–64. Passwords are 12–128 characters. Optional `hardware_id` is 16–256 characters; use a stable ASCII pseudonymous value and send the identical value as `X-Hardware-ID` on protected requests. Hardware IDs should never contain personal identifiers.

Protected endpoints require `Authorization: Bearer <access_token>`. Admin routes require tokens from admin login. Refresh accepts either audience's refresh token and preserves that audience. Responses are uncached.

| Method | Route | Body / behavior |
|---|---|---|
| POST | `/v1/register` | `username,password[,hardware_id]`; 201 success, no session |
| POST | `/v1/login` | `username,password[,hardware_id]`; client token pair |
| POST | `/v1/admin/login` | Same credentials; admin role required, separate audience |
| POST | `/v1/refresh` | `refresh_token[,hardware_id]`; rotates token pair |
| GET | `/v1/session` | Validates current client session; returns user ID and subscription deadline |
| POST | `/v1/logout` | Revokes current client session and all its tokens |
| POST | `/v1/admin/logout` | Revokes current admin session |
| POST | `/v1/licenses/activate` | `key`; binds valid license to authenticated account |
| GET | `/v1/variables/{name}` | Returns authorized personal value, otherwise application value |
| GET | `/v1/files/{file_id}/content` | Authenticated binary stream |
| GET | `/v1/admin/users?offset=0` | Lists up to 100 users; excludes password hashes |
| GET | `/v1/admin/session` | Current website username, user ID, and is_owner flag |
| GET | `/v1/admin/overview` | Live user, subscription, license, file counts and eight recent audit events |
| GET | `/v1/admin/licenses?offset=0` | Up to 100 license records with recoverable key text for administrators; excludes hashes and ciphertext |
| GET | `/v1/admin/variables?offset=0` | Up to 100 variable records and values, administrator access only |
| GET | `/v1/admin/files?offset=0` | Up to 100 private-file metadata records |
| GET | `/v1/admin/users/{id}/permissions` | Lists direct permissions for a user |
| POST | `/v1/admin/users` | `username,password`; creates a website-only user pending owner approval, 201 with `id` |
| DELETE | `/v1/admin/users/{id}` | Permanently deletes another account, sessions, permissions and personal variables; revokes its licenses; retains audit history; own account deletion returns 409 |
| PUT | `/v1/admin/users/{id}` | `status,subscription_until[,password_until,web_access]`; status active/suspended/revoked; owner-approved website access blocks SDK login; only owner may change it |
| POST | `/v1/admin/users/{id}/revoke-sessions` | Revokes every session for account |
| PUT | `/v1/admin/users/{id}/permissions` | `permission,allowed`; assigns/removes direct permission |
| POST | `/v1/admin/licenses` | `days` (integer 1–999, default 30), optional `hardware_bound` and `permission` (default `premium`); 201 with `id,key` (key also visible in the admin list) |
| DELETE | `/v1/admin/licenses/{id}` | Revokes license; keeps audit/history |
| POST | `/v1/admin/licenses/{id}/reset-hwid` | Clears hardware binding, keeps ownership, and revokes the owner’s client sessions; next activation binds the new device |
| POST | `/v1/admin/licenses/{id}/extend` | `days` (integer 1–999); extends from expiry, or from server time if expired; extends the assigned account subscription as needed |
| PUT | `/v1/admin/variables/{id}` | `name,value,permission[,user_id]`; creates/replaces variable, NULL scope is application-wide |
| DELETE | `/v1/admin/variables/{id}` | Removes variable |
| PUT | `/v1/admin/files/{id}` | `storage_name,permission,max_bytes[,enabled]`; registers or updates private file, disabled to revoke |
| GET | `/v1/admin/audit?after=0` | Up to 100 audit events in increasing ID order |

For the browser console, `/v1/admin/audit?recent=true&offset=0` lists the newest 100 events
in descending ID order. The default `after` behavior remains unchanged for exporters.
`/` and `/admin` serve the public console shell, while `/assets` serves only packaged
frontend assets. None of these routes exposes the database or private download storage.

Times are Unix seconds in UTC. Subscription and license expiry must exceed server time. `password_until: null` removes password expiry; omitting it in a user replacement also clears it. Suspension/revocation permanently revokes existing sessions, so reactivation requires a fresh login. Revocation is a soft account operation preserving history. Administrator roles may be granted by an authenticated administrator using web_access, or by the offline CLI. Public registration cannot grant website access. Removing website access revokes sessions and keeps the account blocked from SDK login.

Token response: `{"success":true,"access_token":"...","refresh_token":"...","expires_at":1234567890}`. Variable response: `{"success":true,"value":"enabled"}`. Binary responses use `application/octet-stream` and Content-Length. Most management writes return `{"success":true}`. No successful response implies permission for subsequent requests.

Errors use `{"success":false,"error":"code"}`:

| Status | Codes |
|---|---|
| 400 | `https_required` |
| 401 | `authentication_required`, `invalid_credentials`, `invalid_token`, `expired`, `revoked` |
| 403 | `permission_denied`, `subscription_expired`, `hardware_mismatch`, `invalid_license`, `registration_disabled` |
| 404 | `not_found`, `file_unavailable` |
| 409 | `registration_failed`, `user_exists`, `variable_exists`, `file_exists` |
| 413 | `request_too_large` |
| 422 | `invalid_request`, `invalid_storage_file` |
| 429 | `rate_limited` |
| 500 | `server_error` |

Unknown routes/methods use framework 404/405 codes inside the same error envelope. SDK errors distinguish authentication failure, expiration, revocation, permission denial, rate limiting, network failure, malformed response, invalid input, and server failure. Permission errors preserve the current session but expose no resource. Network failures clear local tokens. Remote revocation cannot be guaranteed during an outage; use server-side expiry and admin session revocation.

All /v1/admin/users routes require the configured owner, not just an approved website session. New website accounts cannot log in until web_access is granted by the owner. Correct credentials without approval return 403 website_approval_required. Removing approval invalidates existing tokens and refresh; non-owner user-management requests return 403 owner_required.

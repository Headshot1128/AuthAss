# NOVYX cloud hosting

Live site: https://novyx-authorization.epicmaple8.chatgpt.site

NOVYX runs on Sites cloud infrastructure and stays available when the original PC is off. Sign in as `gerry2.0` with the existing password. The public URL displays the login page; account data and management endpoints require NOVYX authentication. The owner grants website access to other accounts.

## Migration completed

- Imported 2 accounts, 2 licenses, and 152 audit records from the local database. Password hashes were preserved; existing sessions were deliberately not transferred.
- License display values were re-encrypted for the hosted runtime. No private files existed to transfer.
- Hosted data uses D1; private uploads use R2. Local backups remain in `data/backups`.
- The original local server was stopped to avoid writing to two separate databases. Use the hosted URL for ongoing changes.
- Source checkout: `sites/novyx`; published source commit: `c565660d165e440ce4b766ca3136cf58c939a6757`.
- Production deployment succeeded with environment revision 2. The temporary migration credential has been removed.

Validation: production login page returned HTTP 200; unauthenticated users/licenses requests and invalid login returned 401; disabled import returned 403. The integration suite and local browser workflow passed. A local preview restart required a second explicit sign-in during browser testing. A successful owner login on production has not been tested because the owner's password was not requested.

## Connect novyx.online

The domain is active. Sites confirmed active domain verification and TLS on 2026-10-23 (Asia/Taipei); an HTTPS check returned 200 with the NOVYX page, and unauthenticated user access returned 401. In the DNS service authoritative for `novyx.online`, add these records. For Hostinger's relative Name/Host fields, use the names below:

| Type | Name / Host | Value |
| --- | --- | --- |
| A | @ | 162.159.143.30 |
| A | @ | 172.66.3.26 |
| TXT | _openai-site-verification | openai-site-verification=BPM2RCBs1Zu1WOoQoY1yPvappTqYdnM-5wOijIpRy6k |
| TXT | _cf-custom-hostname | 0d341e0b-b11d-478f-8ed0-f51358ed92a4 |

Replace conflicting apex (`@`) A, AAAA, or CNAME records that route the website elsewhere. Preserve unrelated records, especially email MX and TXT records. If another provider controls the domain's nameservers, edit DNS there instead. Do not include the domain suffix twice when entering TXT names.

https://novyx.online is ready with HTTPS. The Sites URL above remains usable. The user entered the Hostinger DNS records and activation was verified. Keep the records listed above.

## C++ clients

Use `https://novyx-authorization.epicmaple8.chatgpt.site` as the SDK API base URL now; switch to `https://novyx.online` after domain activation. Keep TLS certificate verification enabled. Application accounts and license entitlement checks remain separate from website approval.

## Future updates

Follow the Sites skill from `sites/novyx`: check the existing project and public audience, run relevant checks, use the source helper to commit/push and package the exact source, then save and deploy that version. Preserve `.openai/hosting.json` and the existing project ID. Never put database exports, runtime secrets, or repository credentials in source control.



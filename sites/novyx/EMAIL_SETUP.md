# Website password recovery

Owner and approved website users add a recovery address under **My account**. They must enter their current password and confirm the email link. Application/SDK accounts cannot use this flow. Email addresses are private to the signed-in account and are not included in customer listings.

Delivery remains disabled until these production runtime settings are configured through Sites:

- `RESEND_API_KEY`: secret, use a Resend sending-only key for the verified domain.
- `EMAIL_FROM`: a sender on the verified domain, for example `NOVYX <accounts@auth.novyx.online>`.
- `PUBLIC_SITE_URL`: `https://novyx.online` (fixed HTTPS origin; never taken from a request header).

Create a Resend account at https://resend.com, add a sending domain, and add the DNS records Resend supplies through your domain's DNS provider. Verify the domain before enabling delivery. Disable click/open tracking for these security messages. Keep API keys in runtime secret settings, never source files or browser code. Redeploy the saved Site version after updating runtime settings.

Official setup: https://resend.com/docs/dashboard/domains/introduction
Sending API: https://resend.com/docs/api-reference/emails/send-email

Verification links expire after 30 minutes. Reset links expire after 15 minutes. Tokens are random, single-use, and stored only as hashes. Links use fragments to keep tokens out of request URLs and the page clears the fragment immediately. The user explicitly confirms a verification link so email scanners cannot consume it via GET. A reset revokes all sessions and recovery tokens for the target account. Unknown, unverified, disabled, and unapproved accounts receive the same reset-request response. Limits apply to request IPs and email addresses. New requests supersede older links of the same type.

The additive `0002` migration preserves accounts and adds nullable email columns and the token table. Existing accounts must enroll an email before email recovery works. No existing owner email is guessed or silently assigned.

Local QA uses a mocked Resend endpoint in the API tests; it never sends external email. Real inbox delivery cannot be verified until an authorized provider account, secret key and verified DNS records are available.

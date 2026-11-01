# Traffic protection

The Worker checks traffic before API/database access: 300 requests per minute per
Cloudflare client IP, with a shared 30 per minute budget for authentication,
recovery and maintenance routes. Rejections return HTTP 429 and Retry-After: 60.
Existing account/session limits remain in place. JSON requests with oversized
Content-Length are rejected early; existing streamed body limits still apply.
File upload routes keep their existing upload size limits.

The Vite Cloudflare configuration includes TRAFFIC_LIMITER (namespace 1001) and
AUTH_LIMITER (namespace 1002). Verify these bindings survive your deployment
pipeline in the final Worker configuration. Namespace IDs must be reserved for
this application in your account. Native counters are approximate and local to
each Cloudflare location. Without bindings, a bounded per-isolate fallback runs;
it does not provide a distributed quota. Requests outside local development must
arrive through Cloudflare with CF-Connecting-IP. Shared networks share IP budgets.

## Production configuration

Deploy the updated Worker to activate these application controls. In the
Cloudflare account managing novyx.online, verify the hostname is proxied and
review DDoS protection and WAF events. Configure an edge rate limiting rule for
the API to reject floods before Worker execution, using limits suitable for
actual SDK traffic and your plan. Apply browser challenges only to browser
pages; challenges on /v1/ break native SDK clients. Use temporary Under Attack
mode only after assessing its effect on SDK access.

Application limits reduce database and password-hashing load. They do not stop
all distributed attacks or prevent Worker request charges. Account-level DDoS,
WAF and edge rate limiting settings must be managed separately; this code change
does not enable or verify them in the live account.

Reference: https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/

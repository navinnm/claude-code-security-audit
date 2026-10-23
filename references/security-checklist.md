# 19-control evidence playbook

This is the canonical definition of the controls. Each control lists what to inspect, the evidence a PASS requires, the failures most often found in SaaS codebases, and the regression test that proves the fix.

Scanner IDs (`SECxxx`) are leads that map to the control. They are never proof in either direction.

**Universal PASS bar.** A control is `PASS` only when all four hold:
1. **Located:** the enforcement point is found (file and function), not inferred from a package name or comment.
2. **Complete:** every entry point is covered (all routes, jobs, webhooks, GraphQL resolvers, server actions, RPCs). Check the full route inventory, not a sample.
3. **Server-side:** enforcement runs on the server or at the data layer, not only in the UI.
4. **Tested:** a test exercises the *negative* case (wrong user, wrong tenant, bad input), or equivalent evidence is recorded and labelled.

Otherwise use `PARTIAL` (some enforcement exists but there are gaps), `NOT VERIFIED` (could not establish the facts), or `FAIL` (a concrete exploit path is confirmed).

---

## 1. Row-level security and tenant isolation
- **Inspect:** the tenant model (org/workspace/account), how the tenant ID reaches queries (session-derived or client-supplied), RLS policies, ORM default scopes and middleware, background jobs, caches keyed without the tenant, search indexes, exports, and analytics queries.
- **PASS needs:** every tenant-owned table or collection is scoped by a server-derived tenant ID, or by RLS policies tied to `auth.uid()` or a session claim. Service-role, admin, and `SECURITY DEFINER` paths re-check tenancy themselves.
- **Common failures:** a table added without RLS (SEC030); `USING (true)` policies (SEC022); tenant ID taken from the request body or header; the service-role client used in request handlers; cache keys missing the tenant; raw SQL that skips the ORM scope.
- **Regression test:** with two tenants A and B, a user of A lists, reads, updates, and deletes B's records through each API, and every attempt gets 403/404 with no data in the body.

## 2. Authentication and authorization on every API route
- **Inspect:** build a route inventory from the framework router, file-based routes (`app/api/**`, `pages/api/**`), server actions, GraphQL, RPC, and WebSocket handlers. For each route, note the auth middleware that applies and any explicit public allowlist.
- **PASS needs:** deny-by-default (global middleware with an explicit public list), or a per-route check proven for 100% of the inventory. Tokens are verified for signature, algorithm, expiry, issuer, and audience (SEC017). Password hashing uses Argon2id, scrypt, or bcrypt (SEC024).
- **Common failures:** a new route missing the decorator; a middleware matcher that excludes `/api/*`; `jwt.decode` used without verifying; `Math.random` reset tokens (SEC021); session not rotated on login.
- **Regression test:** a parametrized test hits every non-public route without credentials and expects 401, then with an expired or forged token and expects 401.

## 3. Server-side enforcement of permissions and business rules
- **Inspect:** role and plan checks, pricing and limit logic, state transitions (draft → paid), fields the client can set, and CSRF configuration (SEC018).
- **PASS needs:** permissions, quotas, prices, and state rules are enforced in server code or the database. Writes use explicit field allowlists (SEC019).
- **Common failures:** a hidden button treated as access control; `create(req.body)` letting the client set `role`, `tenant_id`, `plan`, or `price`; client-computed totals; CSRF disabled on cookie-auth routes.
- **Regression test:** call the API directly as a low-privilege user with privileged fields or a forbidden transition, and assert rejection with the stored record unchanged.

## 4. Rate limiting and abuse prevention
- **Inspect:** login, signup, password reset, OTP/MFA, invite, search, export, AI/LLM, and email/SMS-sending endpoints. Check where the limiter state lives (in memory or shared), and the key (IP, user, or tenant).
- **PASS needs:** limits on authentication and cost-bearing endpoints, keyed per account and per IP, with shared state across instances, plus lockout or backoff on credential endpoints.
- **Common failures:** an in-memory limiter behind several instances; limiting by IP only where `X-Forwarded-For` is spoofable (see C8); limits on login but not on OTP verification.
- **Regression test:** N+1 rapid requests to the limited endpoint return 429. Assert the counter is per account, not just per process.

## 5. Input validation, output encoding, and safe deserialization
- **Inspect:** schema validation at the API boundary, HTML rendering sinks (SEC015), deserialization (SEC014), shell execution (SEC013), outbound fetches (SEC020), redirects (SEC027), templating, and Markdown rendering.
- **PASS needs:** typed schema validation on every external input. Output is escaped by default, and raw-HTML sinks are sanitized with a vetted library. No unsafe deserializers or shells reach untrusted data. Outbound URLs and redirects are allowlisted.
- **Common failures:** `dangerouslySetInnerHTML` on user content; `yaml.load` or `pickle` on uploads; fetching a user-supplied URL (SSRF to cloud metadata); `?next=` open redirects.
- **Regression test:** submit `<img src=x onerror=alert(1)>`, `http://169.254.169.254/`, `//evil.com`, and wrongly typed JSON (objects where strings are expected), and assert they are rejected or neutralized.

## 6. Parameterized database queries
- **Inspect:** raw SQL calls, query-builder `raw` and `unsafe` APIs, dynamic `ORDER BY` and column names, and NoSQL filters built from request objects (SEC029).
- **PASS needs:** all values go through bound parameters or tagged templates. Identifiers come from allowlists. NoSQL filters are built from typed fields.
- **Common failures:** f-strings, `+` concatenation, or `${}` in `query()` (SEC003); `$queryRawUnsafe`; `sort=` passed straight into SQL; `{"$ne": null}` login bypass.
- **Regression test:** inject `' OR 1=1--`, `1; DROP TABLE`, and `{"$gt": ""}` into each dynamic parameter, and assert no extra rows and no errors that leak SQL.

## 7. CORS allowlist and credential policy
- **Inspect:** CORS middleware configuration, per-route overrides, and the edge/CDN configuration.
- **PASS needs:** an explicit origin allowlist. The request origin is never reflected wholesale. `credentials: true` appears only with exact origins.
- **Common failures:** `origin: true` or `*` with credentials (SEC005); regex allowlists like `/example\.com/` that also match `example.com.evil.io`; a `null` origin allowed.
- **Regression test:** a request with `Origin: https://evil.example` gets no `Access-Control-Allow-Origin` and no `Allow-Credentials` in the response.

## 8. HTTPS, secure cookies, and trusted proxy configuration
- **Inspect:** cookie options, HSTS, HTTPS redirects, the proxy trust setting (`trust proxy`, `ProxyFix`, `SECURE_PROXY_SSL_HEADER`), and outbound TLS (SEC016).
- **PASS needs:** session cookies are `Secure`, `HttpOnly`, with a deliberate `SameSite`. HTTPS is enforced with HSTS. The proxy trust is pinned to the actual hop count. TLS verification is never disabled.
- **Common failures:** `secure: false` copied from development (SEC007); `trust proxy: true` letting clients spoof their IP and defeat rate limits; `verify=False` on internal calls.
- **Regression test:** assert the `Set-Cookie` attributes on login, and that a spoofed `X-Forwarded-For` does not change the client IP seen by the rate limiter.
- **Note:** deployed TLS and HSTS need runtime verification. Source code alone gives `PARTIAL` at most.

## 9. IDOR/BOLA and object-level authorization
- **Inspect:** every lookup by ID from the request (the scanner's C9 signals list these). Check whether each lookup also constrains by owner or tenant, including nested resources (`/orgs/:org/projects/:id`) and file and export IDs.
- **PASS needs:** each object fetch is scoped by owner or tenant in the query itself (`where id = ? and org_id = session.org`) or by a policy check before data is returned. Also scope `update` and `delete`, not just `read`.
- **Common failures:** `findById(req.params.id)` with no ownership check; the parent ID is checked but the child ID is not; sequential IDs that make enumeration trivial; GraphQL nodes resolved by global ID.
- **Regression test:** user A requests user B's object ID on every verb (GET, PATCH, DELETE, and sub-resources), and every request gets 404/403.

## 10. Production debug mode and safe error handling
- **Inspect:** environment-specific config, error middleware, and framework debug flags (SEC004), and error responses (SEC025).
- **PASS needs:** debug mode is off in production configuration, a global error handler returns generic messages plus a correlation ID, and details are logged server-side only.
- **Common failures:** `DEBUG = True` defaults when an environment variable is missing; `res.json({ error: err.stack })`; ORM errors that reveal the schema.
- **Regression test:** force an exception in production mode and assert the response has no stack trace, file paths, SQL, or framework banners.

## 11. CAPTCHA or proportionate anti-automation controls
- **Inspect:** public unauthenticated forms (signup, contact, password reset, free trial, invite) and how the CAPTCHA token is verified server-side.
- **PASS needs:** high-abuse public flows have a server-verified challenge or an equivalent control (risk scoring, email verification before costly actions). The CAPTCHA token is verified on the server, not just rendered.
- **Common failures:** a widget shown but its token never checked; a CAPTCHA on the web form but not on the equivalent API route.
- **`NOT APPLICABLE`** only when no public, unauthenticated, abusable flows exist. Say which flows were checked.
- **Regression test:** submit the form via the API with no token or an invalid one, and assert rejection.

## 12. Admin and security audit logging
- **Inspect:** logging for login success and failure, MFA changes, role and permission changes, admin actions, data exports, API key creation, and billing changes. Also check what gets logged (SEC011).
- **PASS needs:** security events record actor, tenant, action, target, timestamp, and IP. The logs are append-only or tamper-evident and contain no secrets or tokens.
- **Common failures:** no log of role changes; logging the full request including the `Authorization` header; admin impersonation not logged.
- **Regression test:** perform a role change and assert an audit record exists with the expected fields and no credential values.

## 13. Private storage and authorized file access
- **Inspect:** bucket ACLs and policies (SEC026), signed URL lifetimes, the download routes, and path handling (SEC028).
- **PASS needs:** buckets are private, files are served after an authorization check via short-lived signed URLs or a proxy route, and object keys are scoped by tenant.
- **Common failures:** `public-read` buckets; signed URLs valid for days; download endpoints that take a raw path; tenant files sharing one predictable prefix.
- **Regression test:** user B requests user A's file key and gets 403, and the unauthenticated public object URL also gets 403.

## 14. Admin interface and privileged-operation protection
- **Inspect:** admin routes and UI, impersonation, feature-flag toggles, support tools, internal APIs, and the use of admin SDKs that bypass row rules (`firebase-admin`, the Supabase service role).
- **PASS needs:** admin access is checked server-side on every privileged handler, requires MFA, and is separated from tenant roles. Impersonation is time-bound and logged. Admin SDKs are confined to trusted server code.
- **Common failures:** `/admin` protected only by a hidden link; `isAdmin` read from a client-editable profile field; an internal API reachable from the internet.
- **Regression test:** a normal user calls each admin endpoint directly and gets 403, and a user setting `is_admin` on their own profile is rejected.

## 15. Dependency vulnerability management and secret exposure
- **Inspect:** manifests and lockfiles (SEC033), the scanner's recommended tools, CI audit steps, committed secrets (SEC001, SEC012, SEC023), and `.gitignore` coverage of env files (SEC032).
- **PASS needs:** a dependency audit was actually run with its output recorded, with no unresolved Critical/High findings on reachable code. Lockfiles are committed. A secret scan was run. No live secrets are in the tree or the history.
- **Common failures:** a service-role key in a `NEXT_PUBLIC_` variable; `.env.production` committed; no lockfile; audits never run in CI.
- **Note:** dependency databases need network access. Ask before running. If not run, the status is `NOT VERIFIED`, never `PASS`.

## 16. File upload security
- **Inspect:** upload handlers (C16 signals), size limits, content-type and magic-byte checks, filename handling, the storage location, image processing libraries, and how files are served back.
- **PASS needs:** a server-side size cap, type checking by content (not extension alone), generated storage names, storage outside the web root or in a private bucket, an authorization check on download, and `Content-Disposition`/`nosniff` headers on serving.
- **Common failures:** the user's filename used as the path (traversal); SVG or HTML served inline from the app origin (stored XSS); no size cap; ImageMagick or PDF processing of untrusted files without limits.
- **Regression test:** upload `../../x`, an oversized file, an HTML file renamed `.png`, and an SVG containing a script, and assert each is rejected or served safely.

## 17. Independent AI-assisted review
- **Inspect:** dispatch the `security-reviewer` agent separately for each high-risk area (auth, tenancy, billing, uploads, webhooks, admin), with only its scope as input, so its conclusions are independent of the main audit.
- **PASS needs:** reviews done and recorded per area, with disagreements between the reviewer and the main audit resolved with evidence.
- **Note:** this control records the process. It never upgrades another control to PASS by itself.

## 18. Security headers
- **Inspect:** helmet or equivalent middleware, framework header config (`next.config.js` `headers()`, Django `SecurityMiddleware`), and CDN/edge config.
- **PASS needs:** a CSP appropriate to the app (no `unsafe-inline` scripts where avoidable), `X-Content-Type-Options: nosniff`, frame protection (`frame-ancestors` or `X-Frame-Options`), `Referrer-Policy`, and HSTS (C8).
- **Note:** headers are often set at the edge. Without the runtime response, source evidence gives `PARTIAL` at most.
- **Regression test:** an integration test asserts the headers on an HTML response and on an API response.

## 19. Webhook authenticity, replay protection, and idempotency
- **Inspect:** each inbound webhook route (SEC031, SEC034), whether the raw body is preserved for signature checks, timestamp tolerance, and event-ID storage.
- **PASS needs:** the provider signature is verified over the raw body with a constant-time comparison before any side effect; old timestamps are rejected; processed event IDs are stored under a unique constraint; and handlers are safe to retry.
- **Common failures:** a JSON body parser running before verification; `==` used for signature comparison; the handler trusting `event.data` instead of re-fetching the object; double fulfilment on retries.
- **Regression test:** the same event with an invalid signature is rejected; a stale timestamp is rejected; the same valid event sent twice has its side effect applied only once.

# Claude Code Security Audit — SaaS & Supabase Security Scanner

**A Claude Code plugin that audits SaaS codebases for the security bugs that actually leak customer data:** cross-tenant access, IDOR/BOLA, missing Supabase row-level security (RLS), leaked secrets, SQL injection, permissive CORS, and unsigned webhooks. It maps every finding to 19 OWASP-aligned controls, then helps you fix each one with a regression test. It runs locally and read-only, with zero dependencies.

Install inside Claude Code:

```
/plugin marketplace add navinnm/claude-code-security-audit
/plugin install saas-security-audit@claude-code-security-audit
```

Then open your app repository and run `/saas-security-audit:audit`.

## Why this exists

The bugs that hurt SaaS companies most are **authorization bugs at trust boundaries**: one tenant reading another's invoices, a user calling an admin API, or a Stripe webhook accepted without a signature. Generic linters miss these because they need tracing, not pattern matching. This plugin combines a fast heuristic scanner, which finds leads and shows where enforcement should live, with Claude's code reasoning. Claude follows each request from route to database query and proves enforcement with a negative test.

A control is marked PASS only on evidence (enforcement located, every entry point covered, server-side, and tested), never because the scanner found nothing.

## Example findings

| Finding | Control |
|---|---|
| Supabase `service_role` key exposed through a `NEXT_PUBLIC_` env variable | Secrets |
| `create table public.invoices` with no `ENABLE ROW LEVEL SECURITY` | Tenant isolation / RLS |
| RLS policy `USING (true)`: every user can read every row | Tenant isolation / RLS |
| `findById(req.params.id)` with no owner or tenant check | IDOR / BOLA |
| `User.create(req.body)`: client can set `role` or `tenant_id` | Mass assignment |
| Stripe webhook route with no signature verification | Webhook security |
| `cors({ origin: true, credentials: true })` | CORS misconfiguration |
| `` db.query(`SELECT … ${id}`) `` and `"SELECT …" + id` | SQL injection |
| Live `sk_live_` / AWS keys committed in `.env.production` | Secret scanning |
| `rejectUnauthorized: false`, `Math.random()` reset tokens, `jwt.decode` without verify | Transport / auth |

## Works with

Next.js, Express, NestJS, Fastify, Hono, Django, Flask, FastAPI, Rails, Laravel, Go, and more. Data-layer checks cover Supabase/Postgres RLS policies, Firebase security rules, MongoDB/Mongoose query injection, and S3 bucket ACLs.

**Limitations:** This is a security-assessment aid, not a penetration-testing suite or certification. Static heuristics produce false positives and miss vulnerabilities. Human review and application-specific tests remain necessary.

## Commands

- `/saas-security-audit:audit`: map routes and the tenant model, run the scanner, dispatch independent reviewers, assess all controls, and write `security-reports/security-audit.md`.
- `/saas-security-audit:fix`: write a regression test, then make a root-cause fix for confirmed findings.
- `/saas-security-audit:verify`: re-run tests, diff the scan against the baseline, and update statuses.

## Layout
- `skills/security-audit/SKILL.md`: methodology, statuses, and readiness rules.
- `references/security-checklist.md`: the canonical 19-control playbook (inspect / PASS needs / common failures / regression test).
- `references/report-template.md`: severity rubric and report structure.
- `agents/security-reviewer.md`: read-only reviewer, dispatched once per high-risk area.
- `scripts/scan.py`: dependency-free scanner (Python 3.9+).

## Run the scanner directly
```bash
python3 scripts/scan.py --root /path/to/project                        # Markdown report
python3 scripts/scan.py --root . --format json --output security-reports/scan-baseline.json
python3 scripts/scan.py --root . --baseline security-reports/scan-baseline.json   # new / resolved / persisting
python3 scripts/scan.py --root . --min-severity medium --fail-on high  # CI gate: exit 1 on High+
```

What it reports:
- **Line leads (SEC001–SEC029):** secrets (provider formats, Supabase `service_role` JWTs, connection-URL passwords, `.env*` files), SQL/NoSQL injection, command execution, unsafe deserialization, XSS sinks, SSRF, open redirect, path traversal, mass assignment, permissive CORS, disabled TLS verification, weak JWT verification, CSRF disabled, weak password hashing, insecure randomness, permissive RLS/Firebase rules, public buckets, debug mode, and stack traces in responses.
- **Repo leads (SEC030–SEC034):** tables without RLS in RLS-based apps, webhook handlers without signature verification or idempotency, env files not gitignored, manifests without lockfiles.
- **Control signals:** for each control, where enforcement probably lives (auth middleware, tenant scoping, ID lookups to check for IDOR, rate limiters, headers, and so on), with source/test hit counts. Zero signals for a control is a strong hint of a gap.
- **Inventory:** manifests, security-relevant packages, test and CI files, and the dependency/secret tools to run (marked installed or not, and network-dependent or offline).

Context: findings in test paths are marked `test`, and findings in gitignored local env files are marked `ignored-local-env`. Neither trips `--fail-on`, except a known-format secret in a test file, which does.

Suppression: add `security-audit: ignore[SEC002] -- reason` on the line or the line above. Suppressed leads remain listed in the report with their reason, for a reviewer to accept or reject.

IDs SEC008–SEC010 (v0.1 upload/webhook/admin keyword matches) are retired. Those areas are now covered by control signals and SEC031/SEC034.

## Requirements
- Claude Code with plugin support.
- Python 3.9+.
- Optional tools: Semgrep, Gitleaks, OSV-Scanner, Trivy, ecosystem audit commands (`npm audit`, `pip-audit`, …), and the project's test suite.

## Load locally
From your application repository:
```bash
claude --plugin-dir /absolute/path/to/saas-security-audit
```
Check current Claude Code docs if your installed version uses different CLI syntax.

## Tests
```bash
python3 -m unittest discover -s tests
```

The scanner is read-only, does not execute target code, and makes no network requests. It never marks a control PASS.

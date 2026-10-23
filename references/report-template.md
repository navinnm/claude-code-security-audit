# Report template and severity rubric

Write the report to `security-reports/security-audit.md`. When JSON is requested, put it in `security-reports/security-audit.json` with the same fields. Save the scanner's JSON as `security-reports/scan-baseline.json` so `/saas-security-audit:verify` can diff against it.

## Severity rubric
Rate each confirmed finding by realistic impact × reachability in *this* app. Do not invent CVSS scores.

| Severity | Use when |
|---|---|
| Critical | Unauthenticated or any-tenant access to other tenants' data, account takeover, RCE, or a live production secret exposed. Exploitable now with no special preconditions. |
| High | An authenticated user can reach another tenant's or user's data or a privileged action; stored XSS in a shared view; SSRF to internal services; a missing webhook signature on a money-moving flow. |
| Medium | Exploitation needs specific preconditions or user interaction, or impact is limited (reflected XSS, missing rate limit on login, verbose errors, CSRF on low-impact actions). |
| Low | Defence-in-depth gaps with no direct exploit path (missing headers, a missing lockfile, weak cookie `SameSite` where other controls hold). |
| Informational | Observations that need no fix but help the reader. |

Confidence is separate from severity: `confirmed` (exploit path traced end to end, ideally with a test), `likely` (code path traced but one assumption unverified), or `suspected` (pattern only).

## Report structure

```markdown
# Security Audit — <repo> (<date>)

## Scope and method
- Commit / branch, directories in scope, excluded areas
- Stack detected (framework, data store, auth, hosting)
- Tenant model: <how tenants are identified and where the ID comes from>
- Tools run (exact command, version, exit code) and tools skipped (with reason)

## Executive summary
- Readiness: READY | READY WITH CONDITIONS | NOT READY
- Counts by severity (confirmed only)
- Top 3 risks in plain language

## Control matrix
| # | Control | Status | Evidence (file:line / test) | Gaps | Findings |
|---|---|---|---|---|---|

## Findings
### F-001 <title>
- Severity / confidence: High / confirmed
- Controls: C9, C1
- Location: `path/to/file.ts:42` — `GET /api/projects/:id`
- Evidence (redacted): <minimal snippet>
- Attack: preconditions → steps → result
- Impact: <data or actions exposed, blast radius>
- Remediation: <root-cause fix, where it belongs>
- Regression test: <test name/file, or the test to write>
- Status: OPEN | FIXED (verified) | PARTIALLY FIXED | NOT VERIFIED

## Standards & vibe-code review
Copy the scanner's `standards` and `vibe_review` JSON into tables: OWASP Top 10 / API Top 10 / LLM Top 10 with confirmed (not just heuristic) counts, CWE IDs per finding, and related ASVS, PCI DSS, SOC 2, ISO 27001 and NIST SSDF requirements. State that the mapping does not demonstrate compliance.

## Scanner leads dismissed
| Lead | Location | Why dismissed |
|---|---|---|

## Limitations and residual risk
## Remediation order
```

## Rules
- Every `PASS` cites its enforcement location **and** its test (or labelled equivalent evidence).
- Every dismissed scanner lead gets a one-line reason, so the next audit doesn't re-investigate it.
- Never include secret values, customer data, or full tokens. Redact to a prefix such as `sk_live_…`.

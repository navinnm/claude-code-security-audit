---
description: Audit the current local repository against 19 SaaS security controls and produce an evidence-based report.
argument-hint: "[optional scope]"
---

Perform a read-only-first security audit of the current repository by following the `security-audit` skill.

Scope: $ARGUMENTS

1. Read `${CLAUDE_PLUGIN_ROOT}/skills/security-audit/SKILL.md`, `${CLAUDE_PLUGIN_ROOT}/references/security-checklist.md`, and `${CLAUDE_PLUGIN_ROOT}/references/report-template.md`.
2. Do not modify application source files during the audit. Write only under `security-reports/`.
3. Map the stack, then build the **route inventory** and **tenant model** before judging any control.
4. Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" --root . --format json --output security-reports/scan-baseline.json`, and read the Markdown form (`--format markdown`). If it can't run, explain why and continue.
5. Treat scanner output as leads, not proof. Start tracing each control from the "Look first" locations. "None found" for a control usually means a gap or a custom implementation.
6. Run installed optional tools from the scanner's inventory. Ask first for anything that needs network access. Record commands, versions, and exit codes, and list skipped tools.
7. Dispatch the `security-reviewer` agent in parallel, once per high-risk area that exists in this repo (auth/session, tenancy/IDOR, billing and webhooks, uploads/storage, admin). Reconcile its results with your own.
8. Assess all 19 controls against the checklist's PASS bar, with exactly one status each.
9. Write `security-reports/security-audit.md` per the template, including the dismissed-leads table. Redact secrets and exclude customer data.
10. Do not run destructive commands, access production, deploy, or install packages.
11. Finish in chat with: the readiness decision, confirmed counts by severity, the top fixes in remediation order, and coverage limitations. No heuristic findings does not mean the project is secure.

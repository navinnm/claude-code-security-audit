---
description: Remediate approved, confirmed security findings with targeted tests.
argument-hint: "[finding IDs or scope]"
---

Scope: $ARGUMENTS

1. Read `security-reports/security-audit.md`. If it is missing, run `/saas-security-audit:audit` first. Read the relevant sections of `${CLAUDE_PLUGIN_ROOT}/references/security-checklist.md`.
2. Re-confirm each in-scope finding in the current code. Don't blindly trust AI or scanner output.
3. Summarize the proposed changes and tests per finding. Ask before destructive operations, broad dependency upgrades, migrations, external requests, or infrastructure changes.
4. Write the checklist's regression test for the finding (a negative authorization/tenant test where relevant). Run it to show it fails against the vulnerable code whenever that can be done safely.
5. Make the smallest root-cause fix at the right layer: enforce authorization server-side and scope data access by tenant or owner in the query or policy, not only at one call site.
6. Run the new test, then the narrow suite, then the broader suite, then the scanner with `--baseline security-reports/scan-baseline.json`.
7. Update the report with changed files, commands and results, residual risks, and status. Never mark a finding fixed without verification.
8. Do not deploy, touch production data, expose secrets, weaken tests, add `security-audit: ignore` markers to hide findings, or silently change business behavior.

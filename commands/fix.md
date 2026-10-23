---
description: Remediate approved, confirmed security findings with targeted tests.
argument-hint: "[finding IDs or scope]"
---

Scope: $ARGUMENTS

1. Read `security-reports/security-audit.md`; if absent, run `/saas-security-audit:audit` first.
2. Confirm findings in code; do not blindly trust AI/scanner output.
3. Summarize proposed changes and tests. Ask before destructive operations, broad dependency upgrades, migrations, external requests, or infrastructure changes.
4. Make the smallest safe root-cause fix; enforce authorization server-side and at the appropriate data boundary.
5. Add regression tests, including negative authorization tests where relevant.
6. Run narrow tests, then applicable broader tests and scanner checks.
7. Update the report with changed files, commands/results, residual risks, and status. Never mark fixed without verification.
8. Do not deploy, touch production data, expose secrets, weaken tests, or silently change business behavior.

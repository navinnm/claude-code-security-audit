---
description: Verify security remediation using tests, scans, and repository evidence.
argument-hint: "[finding IDs or all]"
---

Scope: $ARGUMENTS

1. Read `security-reports/security-audit.md` and select the findings in scope.
2. Inspect the current diff and confirm the fix addresses the root cause.
3. Run relevant regression tests and `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" --root . --format markdown`.
4. Run existing safe project tests and available static/dependency checks.
5. Record exact commands, exit codes, failures, and skipped checks. Never imply skipped checks passed.
6. Update findings as fixed, partially fixed, unresolved, or not verified, with evidence.
7. Reassess the 19 controls and list limitations.
8. Do not run destructive tests or access production. Local success does not verify production runtime/configuration.

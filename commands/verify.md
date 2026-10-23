---
description: Verify security remediation using tests, scans, and repository evidence.
argument-hint: "[finding IDs or all]"
---

Scope: $ARGUMENTS

1. Read `security-reports/security-audit.md` and select the findings in scope.
2. Inspect the current diff and confirm that each fix addresses the root cause at the right layer, not just the reported line.
3. Run the findings' regression tests, then `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" --root . --format markdown --baseline security-reports/scan-baseline.json`.
4. Treat scanner "resolved" leads as hints: a pattern that disappeared may only have been reworded. Treat "new" leads as possible regressions introduced by the fix.
5. Run existing safe project tests and installed static/dependency checks. Ask before network-dependent tools.
6. Record exact commands, exit codes, failures, and skipped checks. Never imply skipped checks passed.
7. Update findings to FIXED (verified), PARTIALLY FIXED, OPEN, or NOT VERIFIED, with evidence.
8. Reassess the affected controls against the checklist's PASS bar, update the readiness decision, and list limitations.
9. Do not run destructive tests or access production. Local success does not verify production runtime or configuration.

---
description: Audit the current local repository against 19 SaaS security controls and produce an evidence-based report.
argument-hint: "[optional scope]"
---

Perform a read-only-first security audit of the current repository.

Scope: $ARGUMENTS

1. Discover actual architecture, framework, routes, authentication/authorization, tenant model, database access, storage, webhooks, dependency files, deployment configuration, and tests.
2. Do not modify application source files during the initial audit.
3. Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan.py" --root . --format markdown`. If unavailable, explain why and continue.
4. Assess all 19 controls in `skills/security-audit/SKILL.md` by inspecting actual enforcement paths and tests. Treat scanner output as leads, not proof.
5. Use statuses PASS, FAIL, PARTIAL, NOT APPLICABLE, or NOT VERIFIED.
6. Write `security-reports/security-audit.md`, optionally JSON. Redact secrets and exclude customer data.
7. Include evidence, realistic attack scenarios, impact, remediation, regression tests, and confidence for findings.
8. Do not run destructive commands, access production, deploy, install packages, or make external requests without approval.
9. Finish with an executive summary, coverage limitations, top fixes, and remediation order. No heuristic findings does not mean the project is secure.

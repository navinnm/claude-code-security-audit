# SaaS Security Audit — Claude Code Plugin

A local-first Claude Code plugin for reviewing SaaS repositories against 19 security controls. It combines a read-only heuristic scanner with Claude's codebase reasoning and test-driven verification.

**Limitations:** This is a starter security-assessment aid, not a penetration-testing suite or certification. Static heuristics produce false positives and miss vulnerabilities. Human review and application-specific tests remain necessary.

## Commands

- `/saas-security-audit:audit` — inspect architecture, run the scanner, assess all controls, and write a report.
- `/saas-security-audit:fix` — plan and implement approved fixes for confirmed findings.
- `/saas-security-audit:verify` — re-run relevant tests/scans and update remediation statuses.

## Requirements
- Claude Code with plugin support.
- Python 3.9+.
- Optional tools: Semgrep, Gitleaks, OSV-Scanner, framework tests, and package-manager audit commands.

## Run the scanner directly
```bash
python3 scripts/scan.py --root /path/to/project --format markdown
python3 scripts/scan.py --root /path/to/project --format json --output /tmp/security-scan.json
```

## Load locally
From your application repository:
```bash
claude --plugin-dir /absolute/path/to/saas-security-audit
```
Then use `/saas-security-audit:audit`, `/saas-security-audit:fix`, or `/saas-security-audit:verify`. Check current Claude Code docs if your installed version uses different CLI syntax.

The scanner is read-only, does not execute target code, and makes no network requests. It never marks a control PASS based only on the absence of matches.

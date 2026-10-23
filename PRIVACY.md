# Privacy Policy — Claude Code Security Audit plugin

_Last updated: 2026-10-23_

This policy covers the `saas-security-audit` Claude Code plugin published by Fulgid Software Solutions Pvt Ltd ("we") at https://github.com/navinnm/claude-code-security-audit.

## Summary
The plugin runs entirely on your machine. We operate no server or backend for it, and we do not receive, collect, store, sell, or share any of your data.

## What the plugin accesses
- **Repository files:** the plugin's scanner and audit instructions read files in the repository you choose to audit. Those files may incidentally contain personal data, such as names or emails in seed data, test fixtures, or author fields. The plugin does not look for personal data and does not process it beyond reading files for security analysis.
- **No credentials or environment variables:** the scanner (`scripts/scan.py`) does not read environment variables or credentials, and makes no network requests.

## Where results go
Findings are printed to your terminal or written to a local `security-reports/` folder in your repository. Secret values (API keys, tokens, passwords) are redacted, and the audit instructions tell Claude to keep customer data out of reports. These files stay on your machine unless you choose to share or commit them.

## Claude
The plugin runs inside Claude Code. Content Claude reads during an audit is handled under your agreement with Anthropic and Anthropic's privacy policy, not by us.

## Optional third-party tools
During an audit, Claude may suggest running security tools you have installed, such as `npm audit`, `pip-audit`, `osv-scanner`, or semgrep with a registry ruleset. Some of these contact their vendor's service, typically sending dependency names and versions, or downloading rules and advisory databases. Claude asks for your approval before running any of them, and their vendors' privacy policies apply. The README's "Data and privacy" section lists each tool and what it sends.

## Data retention
None. We receive no data, so we retain none.

## Children
The plugin is a developer tool and is not intended for people under 18.

## Changes and contact
Changes to this policy are published in this file, with the date above updated. For questions, open an issue at https://github.com/navinnm/claude-code-security-audit/issues.

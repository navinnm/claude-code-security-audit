#!/usr/bin/env python3
"""Read-only heuristic scanner. No target-code execution or network requests."""
import argparse
import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
             "dist", "build", "coverage", ".next", ".nuxt", "__pycache__",
             ".idea", ".vscode", "target", "bin", "obj", "security-reports"}
EXTS = {".py", ".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java",
        ".go", ".rb", ".rs", ".cs", ".sql", ".sh", ".bash", ".yml", ".yaml",
        ".json", ".toml", ".ini", ".conf", ".config", ".env", ".xml", ".html",
        ".htm", ".vue", ".svelte", ".tf", ".md"}
MAX_BYTES = 1_500_000
CONTROLS = [
"Row-level security and tenant isolation",
"Authentication and authorization on every API route",
"Server-side enforcement of permissions and business rules",
"Rate limiting and abuse prevention",
"Input validation, output encoding, and safe deserialization",
"Parameterized database queries", "CORS configuration",
"HTTPS and secure transport/cookies", "IDOR/BOLA and object-level authorization",
"Production debug mode and safe error handling",
"CAPTCHA or proportionate anti-automation controls", "Admin/security audit logging",
"Private storage and authorized file access",
"Admin interface and privileged-operation protection",
"Dependency vulnerability management", "File upload security",
"Independent AI-assisted review", "Security headers",
"Webhook signature, replay protection, and idempotency"
]
RULES = [
("SEC001", "Possible hardcoded credential", "High",
 re.compile(r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret[_-]?key)\b\s*[:=]\s*["'][^"'$\s]{8,}["']"""),
 "Inspect securely; rotate real credentials and move them to an approved secret store."),
("SEC002", "Dynamic code execution primitive", "High",
 re.compile(r"\b(?:eval|exec)\s*\("),
 "Avoid evaluating untrusted strings; use explicit parsers and allowlisted operations."),
("SEC003", "Potential SQL string interpolation", "High",
 re.compile(r"""(?i)(?:execute|executemany|raw|query)\s*\(\s*(?:f["']|["'][^"']*(?:%s|\+))"""),
 "Use parameterized queries or safe query-builder APIs; inspect the complete data flow."),
("SEC004", "Debug mode may be enabled", "Medium",
 re.compile(r"""(?i)(?:DEBUG|APP_DEBUG|debug)\s*[:=]\s*(?:true|1|['"]true['"])"""),
 "Confirm environment context; disable verbose debug output in production."),
("SEC005", "Wildcard CORS origin", "High",
 re.compile(r"""(?i)(?:Access-Control-Allow-Origin|allow_origins|cors_origin)\s*[:=]\s*(?:\*|[\["']\*[\]"'])"""),
 "Use an explicit origin allowlist and review credential/preflight behavior."),
("SEC006", "Potential insecure HTTP URL", "Low",
 re.compile(r"""http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)[A-Za-z0-9.-]+"""),
 "Check whether this is a production endpoint carrying sensitive traffic; prefer HTTPS."),
("SEC007", "Cookie security option may be disabled", "Medium",
 re.compile(r"(?i)(?:secure\s*[:=]\s*false|httponly\s*[:=]\s*false|http_only\s*[:=]\s*false)"),
 "For session cookies, enable Secure and HttpOnly where appropriate and choose SameSite."),
("SEC008", "Potential file upload handling", "Informational",
 re.compile(r"(?i)(?:move_uploaded_file|multipart/form-data|multer\s*\(|upload\.single|request\.files)"),
 "Trace upload flow: size/type/signature checks, generated names, authorization, private storage."),
("SEC009", "Potential webhook endpoint", "Informational",
 re.compile(r"(?i)webhook"),
 "For inbound webhooks, verify signatures over the raw body, timestamps/replay protection, idempotency."),
("SEC010", "Potential admin/privileged code path", "Informational",
 re.compile(r"(?i)\b(?:admin|is_admin|superuser|role)\b"),
 "Verify server-side authorization at each privileged operation; UI guards are insufficient."),
("SEC011", "Potential sensitive logging", "Medium",
 re.compile(r"(?i)(?:log(?:ger)?\.(?:info|debug|warning|error)|console\.log)\s*\([^)]{0,200}(?:password|token|secret|authorization|cookie)"),
 "Avoid logging credentials, access tokens, session identifiers, or sensitive personal data.")
]

def redact(line):
    line = re.sub(r"""(?i)(\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret[_-]?key)\b\s*[:=]\s*)["'][^"']*["']""",
                  r'\1"[REDACTED]"', line)
    line = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,})\b", "[REDACTED_TOKEN]", line)
    return line.strip()[:260]

def scan(root):
    findings = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink()]
        for name in names:
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in EXTS and name not in {
                "Dockerfile", "Makefile", "Gemfile", "Pipfile", "Procfile",
                ".env", "composer.lock", "package-lock.json", "pnpm-lock.yaml",
                "yarn.lock", "poetry.lock", "requirements.txt", "go.sum", "Cargo.lock"
            }:
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                for rid, title, severity, pattern, guidance in RULES:
                    if pattern.search(line):
                        findings.append({
                            "id": rid, "title": title, "severity": severity,
                            "confidence": "low-to-medium heuristic",
                            "status": "NEEDS_REVIEW",
                            "file": path.relative_to(root).as_posix(),
                            "line": number, "evidence": redact(line), "guidance": guidance
                        })
    return findings

def markdown(root, findings):
    out = ["# Local SaaS Security Heuristic Scan", "",
           "- **Mode:** Read-only, local heuristics; no network requests.",
           "- **Interpretation:** Matches are leads requiring manual validation, not confirmed vulnerabilities.",
           "- **Coverage:** No control is automatically marked PASS.", "",
           "## Summary", "", f"- Heuristic matches: **{len(findings)}**", ""]
    if not findings:
        out += ["No heuristic matches detected. This does **not** mean the project is secure.", ""]
    for f in findings:
        evidence = f["evidence"].replace("`", "'")
        out += [f"### {f['id']} — {f['title']}",
                f"- Severity: {f['severity']} (heuristic; validate in context)",
                f"- Confidence: {f['confidence']}",
                f"- Location: `{f['file']}:{f['line']}`",
                f"- Evidence: `{evidence}`", f"- Guidance: {f['guidance']}", ""]
    out += ["## 19-control coverage", ""]
    out += [f"{i}. **NOT VERIFIED** — {name}" for i, name in enumerate(CONTROLS, 1)]
    out += ["", "## Limitations", "",
            "Regex triage only: false positives and false negatives are expected. Use source tracing, framework-aware tests, dependency tools, and human review."]
    return "\n".join(out) + "\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Optional output path; otherwise stdout")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print("ERROR: --root must be an existing directory", file=sys.stderr)
        return 2
    findings = scan(root)
    if args.format == "json":
        result = {"scanner": "saas-security-audit-heuristics", "version": "0.1.0",
                  "root": str(root), "mode": "read-only-local-heuristics",
                  "findings": findings,
                  "controls": [{"id": i, "name": name, "status": "NOT VERIFIED"}
                               for i, name in enumerate(CONTROLS, 1)],
                  "limitations": ["Regex heuristics only; false positives and false negatives expected.",
                                  "No control is automatically marked PASS.",
                                  "No network access or target-code execution."]}
        output = json.dumps(result, indent=2)
    else:
        output = markdown(root, findings)
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

"""Shared constants, redaction, and the finding model used by every module."""
import base64
import hashlib
import json
import re

VERSION = "0.3.0"
SCHEMA_VERSION = 3
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}

CONTROLS = [
    "Row-level security and tenant isolation",
    "Authentication and authorization on every API route",
    "Server-side enforcement of permissions and business rules",
    "Rate limiting and abuse prevention",
    "Input validation, output encoding, and safe deserialization",
    "Parameterized database queries",
    "CORS allowlist and credential policy",
    "HTTPS, secure cookies, and trusted proxy configuration",
    "IDOR/BOLA and object-level authorization",
    "Production debug mode and safe error handling",
    "CAPTCHA or proportionate anti-automation controls",
    "Admin and security audit logging",
    "Private storage and authorized file access",
    "Admin interface and privileged-operation protection",
    "Dependency vulnerability management and secret exposure",
    "File upload security",
    "Independent AI-assisted review",
    "Security headers",
    "Webhook authenticity, replay protection, and idempotency",
    "SSRF and outbound egress control",
    "JWT and session lifecycle security",
    "AI/LLM security and prompt injection",
]

SECRET_FORMATS = [
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "Critical"),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "Critical"),
    ("Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), "Critical"),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"), "High"),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "High"),
    ("LLM provider API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}"), "High"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "High"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Medium"),
    ("Stripe test secret key", re.compile(r"\b(?:sk|rk)_test_[0-9A-Za-z]{16,}\b"), "Low"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(?P<payload>eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}"), "Medium"),
    ("Credentials in connection URL", re.compile(
        r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@'\"`]+:(?P<v>[^\s@/'\"`]{3,})@(?P<host>[^\s/:'\"`]+)"), "High"),
]
CRED_KEY = (r"[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"refresh[_-]?token|password|passwd|pwd|secret[_-]?key|private[_-]?key|secret|signing[_-]?key|encryption[_-]?key)")
QUOTED_CRED_RE = re.compile(r"(?i)(?P<k>\b" + CRED_KEY + r")[\"']?\s*(?:[:=]|=>|:=)\s*(?P<q>[\"'`])(?P<v>[^\"'`\s$]{8,})(?P=q)")
ENV_CRED_RE = re.compile(r"(?i)^\s*(?:export\s+)?(?P<k>[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_?KEY|PRIVATE_KEY|"
                         r"ACCESS_KEY|CREDENTIALS?|DSN)[A-Z0-9_]*)\s*=\s*[\"']?(?P<v>[^\s\"'#]{8,})")
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}=*")
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|0+|changeme|change_?me|changeit|password\d*|secret|none|null|undefined|todo|tbd|redacted|"
    r"(?:example|sample|dummy|placeholder|your|replace|test|fake|mock|insert|enter|my)[\w.-]*|<[^>]*>|\{\{.*\}\}|\$\{.*\}|%\(.*\)s|.*xxxx.*)$")
LOCAL_HOST_RE = re.compile(r"(?i)^(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|db|postgres|mysql|redis|mongo|database|host\.docker\.internal)$")


def is_placeholder(value):
    return bool(PLACEHOLDER_RE.match(value)) or value.startswith(("process.env", "os.environ", "env(", "ENV["))


def jwt_role(payload):
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data.get("role") if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


def redact(line):
    for _, rx, _ in SECRET_FORMATS:
        if "v" in rx.groupindex:
            line = rx.sub(lambda m: m.group(0)[:m.start("v") - m.start()] + "[REDACTED]" + m.group(0)[m.end("v") - m.start():], line)
        else:
            line = rx.sub("[REDACTED_TOKEN]", line)
    line = QUOTED_CRED_RE.sub(lambda m: m.group(0)[:m.start("v") - m.start()] + "[REDACTED]" + m.group(0)[m.end("v") - m.start():], line)
    line = ENV_CRED_RE.sub(lambda m: m.group(0)[:m.start("v") - m.start()] + "[REDACTED]", line)
    line = BEARER_RE.sub("Bearer [REDACTED]", line)
    return line.strip()[:240]


def redact_cookie(header_value):
    """Keep cookie names and attributes, drop values."""
    parts = [p.strip() for p in header_value.split(";")]
    if parts and "=" in parts[0]:
        parts[0] = parts[0].split("=", 1)[0] + "=[REDACTED]"
    return "; ".join(parts)[:240]


def fingerprint(f):
    basis = "|".join([f["id"], f["file"], re.sub(r"\s+", " ", f["evidence"])])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def make_finding(rid, title, severity, confidence, controls, rel, line, evidence, guidance, context):
    f = {"id": rid, "title": title, "severity": severity, "confidence": confidence,
         "controls": list(controls), "status": "NEEDS_REVIEW", "file": rel, "line": line,
         "evidence": evidence, "guidance": guidance, "context": context}
    f["fingerprint"] = fingerprint(f)
    return f


def gate_counts(f):
    return f["context"] in ("source", "runtime") or (f["context"] == "test" and f["id"] == "SEC012")


def md_escape(text):
    return str(text).replace("`", "'").replace("|", "\\|")

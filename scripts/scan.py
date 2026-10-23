#!/usr/bin/env python3
"""Read-only heuristic SaaS security scanner.

Never executes target code and makes no network requests. Output is a set of
leads mapped to the 19 controls plus per-control "where to look" signals.
No control is ever marked PASS: absence of matches is not evidence of safety.
"""
import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

VERSION = "0.3.1"
SCHEMA_VERSION = 3

SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "vendor",
             "dist", "build", "coverage", ".next", ".nuxt", ".output", ".svelte-kit",
             ".turbo", ".vercel", ".serverless", ".terraform", "__pycache__", ".tox",
             ".pytest_cache", ".mypy_cache", ".idea", ".vscode", "target", "bin", "obj",
             "bower_components", ".yarn", "Pods", "security-reports"}
CODE_EXTS = {".py", ".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt",
             ".scala", ".go", ".rb", ".rs", ".cs", ".swift", ".sh", ".bash", ".vue",
             ".svelte", ".html", ".htm", ".erb", ".ejs", ".hbs", ".njk", ".jinja",
             ".jinja2", ".j2", ".twig"}
CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config",
               ".xml", ".tf", ".tfvars", ".properties", ".rules", ".env", ".prisma"}
SQL_EXTS = {".sql"}
DOC_EXTS = {".md", ".txt", ".rst"}
CONFIG_NAMES = {"Dockerfile", "Procfile", "Makefile", "Caddyfile", ".htaccess",
                "nginx.conf", "Gemfile", "Pipfile"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "bun.lockb", "bun.lock", "poetry.lock", "Pipfile.lock", "uv.lock",
             "Gemfile.lock", "composer.lock", "go.sum", "Cargo.lock"}
MANIFESTS = {"package.json": "npm", "requirements.txt": "PyPI", "pyproject.toml": "PyPI",
             "Pipfile": "PyPI", "Gemfile": "RubyGems", "composer.json": "Packagist",
             "go.mod": "Go", "Cargo.toml": "crates.io", "pom.xml": "Maven",
             "build.gradle": "Gradle", "build.gradle.kts": "Gradle"}
LOCK_FOR = {"package.json": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                             "pnpm-lock.yaml", "bun.lockb", "bun.lock"},
            "Gemfile": {"Gemfile.lock"}, "composer.json": {"composer.lock"}}
DEP_TOOLS = {
    "npm": [("npm audit --omit=dev", "npm", True), ("osv-scanner scan -r .", "osv-scanner", True)],
    "PyPI": [("pip-audit", "pip-audit", True), ("osv-scanner scan -r .", "osv-scanner", True)],
    "RubyGems": [("bundle-audit check --update", "bundle-audit", True)],
    "Packagist": [("composer audit", "composer", True)],
    "Go": [("govulncheck ./...", "govulncheck", True)],
    "crates.io": [("cargo audit", "cargo-audit", True)],
    "Maven": [("osv-scanner scan -r .", "osv-scanner", True)],
    "Gradle": [("osv-scanner scan -r .", "osv-scanner", True)],
}
GENERAL_TOOLS = [("gitleaks dir . --redact", "gitleaks", False),
                 ("semgrep scan --config p/owasp-top-ten", "semgrep", True),
                 ("trivy fs --scanners vuln,secret,misconfig .", "trivy", True)]
MAX_BYTES = 1_500_000
MAX_LINE = 4000
MAX_SIGNAL_LOCATIONS = 8
REPORT_MARKDOWN_HEADER = "# Local SaaS Security Heuristic Scan"
REPORT_JSON_MARKER = '"scanner": "saas-security-audit-heuristics"'
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

JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
PY = {".py"}
CODE = {"code"}
CODE_CFG = {"code", "config", "env"}
ANY_TEXT = {"code", "config", "env", "sql", "doc"}
REQ_SRC = r"(?:req|request|ctx\.request|event|input)\.(?:body|query|params|args|GET|POST|form|json|data|values)\b"
SQL_KW = r"\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b"
SQL_CALL = (r"(?i)\b(?:execute|executemany|executescript|query|raw|exec_query|find_by_sql|"
            r"whereRaw|selectRaw|orderByRaw|havingRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*")
RAND_KW = r"(?:token|secret|password|passwd|otp|nonce|salt|session|api_?key|reset|invite|verification|csrf)"


class Rule:
    def __init__(self, rid, title, severity, confidence, controls, scope, patterns, guidance,
                 skip_comments=True):
        self.rid, self.title, self.severity, self.confidence = rid, title, severity, confidence
        self.controls, self.scope, self.guidance = tuple(controls), set(scope), guidance
        self.skip_comments = skip_comments
        self.patterns = []
        for p in patterns:
            regex, exts = (p if isinstance(p, tuple) else (p, None))
            self.patterns.append((re.compile(regex), exts))

    def match(self, line, ext):
        return any((exts is None or ext in exts) and rx.search(line) for rx, exts in self.patterns)


RULES = [
    Rule("SEC002", "Dynamic code evaluation", "High", "medium", (5,), CODE,
         [r"(?<![\w.$])eval\s*\(", (r"(?<![\w.$])exec\s*\(", PY), (r"\bnew\s+Function\s*\(", JS),
          (r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]", JS), (r"\bvm\.run(?:In\w*Context)?\s*\(", JS)],
         "Never evaluate request-influenced strings; use explicit parsers and allowlisted operations."),
    Rule("SEC003", "SQL built with string interpolation or concatenation", "High", "medium", (6, 1), CODE,
         [SQL_CALL + r"f[\"']",
          SQL_CALL + r"`[^`]*\$\{",
          SQL_CALL + r"[\"'][^\"']*[\"']\s*(?:\+|\.\s*\$|\.format\s*\(|%\s*[\w(\[{])",
          SQL_KW + r"[^\"'\n]*[\"']\s*(?:\+\s*[A-Za-z_$]|\.\s*\$|\.format\s*\(|%\s*[\w(\[{])",
          r"\bf[\"'][^\"'\n]*" + SQL_KW + r"[^\"'\n]*\{",
          (r"(?<![\w$.])`[^`\n]*" + SQL_KW + r"[^`\n]*\$\{", JS),
          (r"\"[^\"\n]*" + SQL_KW + r"[^\"\n]*#\{", {".rb"}),
          (r"\"[^\"\n]*" + SQL_KW + r"[^\"\n]*\$\w", {".php"}),
          (r"Sprintf\(\s*\"[^\"]*" + SQL_KW, {".go"})],
         "Use bound parameters or tagged/query-builder APIs. Identifiers (columns, sort order) must come from an allowlist."),
    Rule("SEC004", "Debug mode or verbose errors may be enabled", "Medium", "low", (10,), CODE_CFG,
         [r"(?i)\b(?:DEBUG|APP_DEBUG|FLASK_DEBUG)\s*[:=]\s*[\"']?(?:true|1|on|yes)\b",
          r"\bapp\.run\([^)\n]*debug\s*=\s*True", r"(?i)\bdisplay_errors\s*=\s*(?:on|1)\b",
          r"consider_all_requests_local\s*=\s*true", r"(?i)\bdebug\s*:\s*true\b"],
         "Confirm which environment loads this value; production must not expose debug pages or stack traces."),
    Rule("SEC005", "Permissive CORS policy", "High", "medium", (7,), CODE_CFG,
         [r"(?i)Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*[\"']",
          r"(?i)\ballow_origins\s*=\s*\[\s*[\"']\*[\"']",
          r"(?i)\bCORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True",
          r"\borigin\s*:\s*(?:[\"']\*[\"']|true\b)", r"\bAllowAllOrigins\s*:\s*true",
          r"\.AllowAnyOrigin\s*\(", r"(?<![\w.])cors\(\s*\)", r"\bCORS\(\s*app\s*\)",
          r"(?i)Access-Control-Allow-Origin[\"']?\s*,\s*(?:req|request)\.headers?(?:\.origin|\[[\"']origin)"],
         "Use an explicit origin allowlist. Reflecting any origin with credentials lets any site act as the user."),
    Rule("SEC006", "Plain HTTP URL", "Low", "low", (8,), CODE_CFG,
         [r"http://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|json-schema\.org|example\.|"
          r"host\.docker\.internal|purl\.org|ns\.adobe\.com|xmlns\.|java\.sun\.com|maven\.apache\.org|"
          r"www\.apache\.org|[^/\s\"']*\.(?:local|test|example|internal|localhost)\b)[A-Za-z0-9-]+\.[A-Za-z0-9.-]+"],
         "Check whether this endpoint carries credentials or user data; require HTTPS for anything sensitive."),
    Rule("SEC007", "Cookie security attribute weakened", "Medium", "low", (8,), CODE_CFG,
         [r"(?i)\b(?:secure|httponly|http_only)\s*[:=]\s*false\b",
          r"\b(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_SECURE_COOKIE)\s*=\s*(?:False|false)\b",
          r"(?i)\bsame_?site\s*[:=]\s*[\"']?none\b"],
         "Session/auth cookies need Secure, HttpOnly, and a deliberate SameSite value."),
    Rule("SEC011", "Possible sensitive data in logs", "Medium", "low", (12,), CODE,
         [r"(?i)\b(?:log(?:ger|ging)?|console|winston|pino|logrus|zap|Log)\.(?:info|debug|warn|warning|error|log|trace|fatal|critical|exception)"
          r"\s*\([^)\n]{0,200}\b(?:password|passwd|secret|token|authorization|cookie|api_?key|card_?number|cvv|ssn)\b"],
         "Never log credentials, tokens, session IDs, or sensitive personal data; log identifiers instead."),
    Rule("SEC013", "OS command execution", "High", "medium", (5,), CODE,
         [r"\bos\.(?:system|popen)\s*\(", r"\bsubprocess\.\w+\([^\n]*shell\s*=\s*True",
          (r"(?:\bchild_process\.|(?<![\w$.]))exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*[,)])", JS),
          (r"\b(?:shell_exec|passthru|proc_open|popen|system|exec)\s*\([^)\n]*\$", {".php"}),
          (r"`[^`\n]*#\{|\b(?:system|exec|spawn)\s*\(?[^\n]*#\{", {".rb"}),
          (r"exec\.Command(?:Context)?\([^)]*\"(?:sh|bash|cmd(?:\.exe)?)\"\s*,\s*\"(?:-c|/c)\"", {".go"}),
          (r"Runtime\.getRuntime\(\)\.exec\s*\(", {".java", ".kt"})],
         "Avoid shells; pass argument arrays to a fixed executable and allowlist any user-influenced values."),
    Rule("SEC014", "Unsafe deserialization", "High", "medium", (5,), CODE,
         [r"\b(?:c?[Pp]ickle|dill|shelve|jsonpickle)\.(?:loads?|decode|open)\s*\(",
          r"\byaml\.load\s*\((?![^)\n]*Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader))",
          r"\byaml\.(?:unsafe_load|load_all)\s*\(",
          r"\btorch\.load\s*\((?![^)\n]*weights_only\s*=\s*True)",
          (r"\bunserialize\s*\(", {".php"}), (r"\b(?:Marshal\.load|Oj\.load)\b", {".rb"}),
          (r"\b(?:ObjectInputStream|XMLDecoder)\b", {".java", ".kt", ".scala"}),
          (r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|TypeNameHandling\.(?:All|Auto|Objects))\b", {".cs"}),
          (r"\bnode-serialize\b|\bserialize\.unserialize\s*\(", JS)],
         "Deserialize untrusted data only with data-only formats (JSON) or safe loaders."),
    Rule("SEC015", "Raw HTML sink (possible XSS)", "Medium", "medium", (5,), CODE,
         [(r"dangerouslySetInnerHTML", JS), (r"\.(?:inner|outer)HTML\s*=(?!=)", JS | {".html", ".htm"}),
          (r"\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(", JS | {".html", ".htm"}),
          (r"\bv-html\s*=", {".vue", ".html"}), (r"\{@html\s", {".svelte"}),
          (r"\|\s*safe\b", {".html", ".htm", ".jinja", ".jinja2", ".j2", ".njk", ".twig"}),
          (r"\bmark_safe\s*\(", PY), (r"\{!!", {".php"}), (r"\.html_safe\b|<%==", {".rb", ".erb"}),
          (r"<%-", {".ejs"}), (r"\{\{\{", {".hbs"}), (r"\bbypassSecurityTrust\w+\s*\(", {".ts"})],
         "Confirm the value is sanitized with a vetted HTML sanitizer or never user-controlled; prefer escaped rendering."),
    Rule("SEC016", "TLS certificate verification disabled", "High", "high", (8,), CODE_CFG,
         [r"\bverify\s*=\s*False\b", r"\brejectUnauthorized\s*:\s*false\b",
          r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0\b", r"\bInsecureSkipVerify\s*:\s*true\b",
          r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b", r"\bssl\._create_unverified_context\b",
          r"\bcheck_hostname\s*=\s*False\b", r"\bstrictSSL\s*:\s*false\b", r"\bVERIFY_NONE\b",
          r"ServerCertificateValidationCallback\s*=[^;\n]*=>\s*true"],
         "Keep certificate verification on; trust a private CA explicitly instead of disabling checks."),
    Rule("SEC017", "JWT verification weakened or decoded without verification", "High", "medium", (21, 2), CODE,
         [r"[\"']?verify_signature[\"']?\s*:\s*False", r"[\"']?verify_exp[\"']?\s*:\s*False",
          r"(?i)\balgorithms?\s*[:=]\s*\[?\s*[\"']none[\"']", r"\bjwt\.decode\s*\([^)\n]*verify\s*=\s*False",
          r"\bignoreExpiration\s*:\s*true\b", (r"\bjwt\.decode\s*\(|\bdecodeJwt\s*\(", JS),
          (r"\bjwt\.verify\s*\(\s*[^,()]+,\s*[^,()]+\s*\)", JS),
          r"(?i)\balgorithms?\s*[:=]\s*\[[^\]\n]*HS\d{3}[^\]\n]*(?:RS|ES|PS)\d{3}|\balgorithms?\s*[:=]\s*\[[^\]\n]*(?:RS|ES|PS)\d{3}[^\]\n]*HS\d{3}"],
         "Verify signature, algorithm allowlist, expiry, issuer, and audience before trusting any claim."),
    Rule("SEC018", "CSRF protection disabled", "Medium", "medium", (3,), CODE_CFG,
         [r"@csrf_exempt\b|\bcsrf_exempt\s*\(", r"\bWTF_CSRF_ENABLED\s*=\s*False",
          r"(?i)\bcsrf(?:Protection)?\s*:\s*false\b",
          r"skip_(?:before_action|forgery_protection)\b[^\n]*verify_authenticity_token",
          r"\bprotect_from_forgery\b[^\n]*null_session",
          r"\.csrf\(\s*\)\s*\.disable\(\)|\bcsrf\s*\([^)\n]*disable"],
         "Cookie-authenticated state-changing routes need CSRF tokens or strict SameSite plus origin checks."),
    Rule("SEC019", "Possible mass assignment from request body", "Medium", "low", (3, 9, 1), CODE,
         [(r"\.(?:create|createMany|update|updateMany|updateOne|insert|insertMany|upsert|findOneAndUpdate|"
           r"findByIdAndUpdate|build|set|assign)\s*\(\s*(?:\{\s*(?:data\s*:\s*)?(?:\.\.\.)?\s*)?(?:req|request|ctx\.request)\.body\b", JS),
          (r"\bdata\s*:\s*(?:\.\.\.)?\s*(?:req|request)\.body\b", JS),
          (r"Object\.assign\s*\([^,\n]+,\s*(?:req|request)\.body\b", JS),
          (r"\bnew\s+[A-Z]\w*\s*\(\s*(?:req|request)\.body\b", JS),
          (r"\*\*\s*request\.(?:data|json|POST|form|GET|args|get_json\(\))", PY),
          (r"\b(?:fill|forceFill|create|update)\s*\(\s*\$request->(?:all|input)\(\)", {".php"}),
          (r"\bparams\.permit!", {".rb"})],
         "Bind an explicit field allowlist; tenant_id, owner_id, role, and plan must come from the server-side session."),
    Rule("SEC020", "Outbound request to a request-controlled URL (possible SSRF)", "High", "low", (20, 5), CODE,
         [r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|stream)\s*\(\s*" + REQ_SRC,
          r"\burlopen\s*\(\s*" + REQ_SRC,
          (r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got(?:\.\w+)?|needle|https?\.(?:get|request))\s*\(\s*(?:`\$\{\s*)?" + REQ_SRC, JS),
          (r"\b(?:file_get_contents|curl_init|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)", {".php"}),
          (r"\bhttp\.(?:Get|Post)\s*\(\s*r\.(?:URL\.Query|FormValue)", {".go"})],
         "Allowlist destination hosts/schemes, resolve and block private/metadata IPs, and disable redirects to them."),
    Rule("SEC021", "Insecure randomness for a security value", "Medium", "low", (2,), CODE,
         [(r"(?i)" + RAND_KW + r"[^\n]{0,80}Math\.random\s*\(|Math\.random\s*\([^\n]{0,80}" + RAND_KW, JS),
          (r"(?i)" + RAND_KW + r"[^\n]{0,80}\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\s*\("
           r"|\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\s*\([^\n]{0,80}" + RAND_KW, PY),
          (r"(?i)" + RAND_KW + r"[^\n]{0,80}\b(?:rand|mt_rand|uniqid)\s*\(", {".php"})],
         "Use a CSPRNG (crypto.randomBytes / secrets / random_bytes) for tokens, codes, and identifiers."),
    Rule("SEC022", "Permissive data access rule or RLS bypass", "High", "medium", (1,), {"code", "config", "sql"},
         [r"\ballow\s+[\w,\s]+:\s*if\s+true\b", r"[\"']\.(?:read|write)[\"']\s*:\s*(?:true\b|[\"']true[\"'])",
          r"(?i)\bdisable\s+row\s+level\s+security\b", r"(?i)\b(?:using|with\s+check)\s*\(\s*true\s*\)",
          r"(?i)\bgrant\s+all\b[^;\n]*\bto\s+(?:anon|public)\b", r"(?i)\bsecurity\s+definer\b"],
         "Policies must scope rows to the caller's tenant/user; SECURITY DEFINER functions bypass RLS and need their own checks."),
    Rule("SEC023", "Secret exposed through a public client-side env variable", "High", "high", (15, 3), CODE_CFG,
         [r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|ADMIN_KEY)[A-Z0-9_]*\b"],
         "Public-prefixed variables are bundled into browser code. Move the secret server-side and rotate it."),
    Rule("SEC024", "Weak password hashing", "High", "low", (2,), CODE,
         [r"(?i)\b(?:md5|sha1)\s*\([^)\n]*pass", r"(?i)hashlib\.(?:md5|sha1|sha256)\s*\([^)\n]*pass",
          r"(?i)createHash\s*\(\s*[\"'](?:md5|sha1|sha256)[\"']\s*\)[^\n]*pass",
          r"(?i)\b(?:password|passwd|pwd)\w*\s*=\s*[^\n]*\b(?:md5|sha1|sha256)\s*\("],
         "Use a password hashing function (Argon2id, scrypt, bcrypt) with per-user salts."),
    Rule("SEC025", "Stack trace or raw error returned to client", "Medium", "medium", (10,), CODE,
         [r"(?i)\b(?:res|response|reply|ctx)\.[^\n]{0,40}\b(?:err|error|e|ex)\.stack\b",
          r"(?:return|Response|JsonResponse|jsonify|HttpResponse)[^\n]*traceback\.format_exc"],
         "Return a generic error with a correlation ID; log details server-side."),
    Rule("SEC026", "Public storage bucket or object ACL", "High", "medium", (13,), {"code", "config", "sql"},
         [r"(?i)[\"']?acl[\"']?\s*[:=]\s*[\"']public-read(?:-write)?[\"']", r"\bBlockPublic(?:Acls|Policy)\s*[:=]\s*false\b",
          r"\bblock_public_(?:acls|policy)\s*=\s*false\b", r"[\"']allUsers[\"']|\ballUsers\b|[\"']allAuthenticatedUsers[\"']",
          r"(?i)\bpredefined_acl\s*=\s*[\"']publicRead", r"(?i)createBucket\s*\([^)\n]*public\s*:\s*true",
          r"(?i)insert\s+into\s+storage\.buckets[^;\n]*\btrue\b"],
         "Keep tenant files private; serve them through short-lived signed URLs after an authorization check."),
    Rule("SEC027", "Redirect to a request-controlled URL (possible open redirect)", "Medium", "low", (5,), CODE,
         [r"\b(?:redirect|redirect_to|HttpResponseRedirect|RedirectResponse|Redirect)\s*\(\s*(?:[^,)\n]*,\s*)?" + REQ_SRC,
          (r"\bheader\s*\(\s*[\"']Location:\s*[\"']\s*\.\s*\$_(?:GET|POST|REQUEST)", {".php"})],
         "Allow only relative paths or allowlisted hosts for post-login and return URLs."),
    Rule("SEC028", "File path built from request input (possible path traversal)", "High", "low", (13, 16), CODE,
         [r"\b(?:sendFile|readFile(?:Sync)?|createReadStream|writeFile(?:Sync)?|unlink(?:Sync)?|send_file|send_from_directory|"
          r"file_get_contents|fopen|path\.(?:join|resolve)|os\.path\.join|open)\s*\([^)\n]*" + REQ_SRC],
         "Resolve the path and confirm it stays inside the intended directory, or map IDs to server-generated names."),
    Rule("SEC029", "Query object taken directly from request (possible NoSQL injection)", "High", "low", (6, 5), CODE,
         [(r"\.(?:find|findOne|where|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*(?:req|request)\.(?:body|query)\b", JS),
          r"[\"']\$where[\"']"],
         "Validate types (reject objects where strings are expected) and build query filters from explicit fields."),
    Rule("SEC035", "Untrusted input interpolated into an LLM system prompt", "Medium", "low", (22,), CODE,
         [r"(?i)\b(?:system_?prompt|systemPrompt|system_message|instructions)\s*[:=]\s*(?:f[\"']|`)[^\n]*(?:\{|\$\{)\s*(?:req|request|user|input|body|query|params|doc|document|page|email|content)",
          r"(?i)role\s*[:=]\s*[\"']system[\"'][^\n]*content\s*[:=]\s*(?:f[\"']|`)[^\n]*(?:\{|\$\{)\s*(?:req|request|user|input|body|query|params)"],
         "Keep untrusted text out of the system prompt; pass it as delimited user content and treat model output as untrusted."),
    Rule("SEC036", "LLM output passed to an execution or query sink", "High", "low", (22, 5), CODE,
         [r"(?i)\b(?:eval|exec|execSync|query|execute|raw|system|subprocess\.\w+)\s*\(\s*(?:\w+\.)?(?:completion|response|result|output|answer|message|llm\w*|ai\w*)"
          r"(?:\.(?:content|text|output_text|choices|message))+",
          r"(?i)\b(?:fetch|requests\.get|axios\.get)\s*\(\s*(?:\w+\.)?(?:completion|response|output|llm\w*)(?:\.(?:content|text|output_text))+"],
         "Never execute, query, or fetch model output directly; validate it against a strict schema and an allowlist of actions."),
    Rule("SEC037", "Long-lived token or session lifetime", "Medium", "low", (21,), CODE_CFG,
         [r"(?i)\bexpiresIn\s*:\s*[\"']?(?:\d{3,}d|\d+y|[3-9]\dd|\d{7,}[\"']?\s*[,}])",
          r"(?i)\b(?:ACCESS_TOKEN_EXPIRE\w*|JWT_EXPIRATION\w*|SESSION_COOKIE_AGE)\s*=\s*(?:timedelta\(\s*days\s*=\s*(?:[3-9]\d|\d{3,})|\d{7,})",
          r"(?i)\bmaxAge\s*:\s*(?:\d{10,}|[3-9]\d\s*\*\s*24\s*\*\s*60\s*\*\s*60(?:\s*\*\s*1000)?|\d{3,}\s*\*\s*24\s*\*\s*60\s*\*\s*60)"],
         "Keep access tokens short (minutes), rotate refresh tokens on use, and revoke sessions server-side on password or role change."),
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

COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--", ";")
SUPPRESS_RE = re.compile(r"security-audit:\s*ignore(?:\[(?P<ids>[^\]]*)\])?(?:\s*(?:--|:)\s*(?P<reason>.*))?")
TEST_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|__mocks__|testdata|mocks?)/"
    r"|(?:^|/)(?:test_[^/]*|[^/]*_test\.\w+|[^/]*\.(?:test|spec)\.\w+|conftest\.py)$")
EXAMPLE_ENV_RE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults)$")

# Per-control signals: where enforcement probably lives. Leads for review, never proof.
CONTROL_SIGNALS = {
    1: r"(?i)\b(?:tenant_?id|org(?:anization)?_?id|workspace_?id|team_?id)\b|row\s+level\s+security|auth\.uid\(\)|current_setting\(",
    2: r"(?i)\b(?:authenticate|requireAuth|isAuthenticated|login_required|getServerSession|currentUser|verifyToken|"
       r"get_current_user|authenticate_user!|clerkMiddleware|withAuth|authMiddleware|auth\.getUser)\b|passport\.authenticate|middleware\(\s*[\"']auth",
    3: r"(?i)\b(?:authorize|permission_required|has_?permission|checkPermission|can\?|Gate::|@PreAuthorize|requireRole|hasRole|policy|ability)\b",
    4: r"(?i)rate.?limit|throttl|slowapi|rack.?attack|@upstash/ratelimit|\blimiter\b",
    5: r"(?i)\b(?:zod|z\.object|joi|yup|pydantic|BaseModel|class-validator|marshmallow|ajv|valibot|FormRequest|sanitize|DOMPurify|bleach)\b",
    6: r"(?i)\b(?:prisma|drizzle|sequelize|typeorm|knex|sqlalchemy|psycopg2?|mysql2|pg\.Pool|createPool|\$queryRaw|ActiveRecord|Eloquent|mongoose)\b",
    7: r"(?i)\bcors\b|Access-Control-Allow",
    8: r"(?i)\bsecure\s*:\s*true|SESSION_COOKIE_SECURE|SECURE_SSL_REDIRECT|force_ssl|trust\s*proxy|ProxyFix|SECURE_PROXY_SSL_HEADER|Strict-Transport-Security|\bhsts\b",
    9: r"(?i)(?:findUnique|findFirst|findById|findOne|findByPk|get_object_or_404|objects\.get|find_by|findOrFail|\.eq\(\s*[\"']id[\"'])\s*\(?[^\n]*(?:req\.params|params\[|params\.|request\.|\$request|kwargs|query\.)",
    10: r"(?i)\b(?:errorHandler|exception_handler|handler500|@app\.errorhandler|rescue_from|ErrorBoundary|onError|NODE_ENV)\b|app\.use\(\s*\(?\s*err",
    11: r"(?i)recaptcha|hcaptcha|turnstile|captcha|friendlycaptcha",
    12: r"(?i)audit.?log|audit.?trail|activity.?log|security.?event",
    13: r"(?i)\b(?:S3Client|putObject|getObject|getSignedUrl|presign\w*|createSignedUrl|storage\.from|bucket|GetSignedURL)\b",
    14: r"(?i)\b(?:is_?admin|is_?superuser|is_staff|superuser|admin(?:Only|Required|Guard)|requireAdmin)\b|role\s*={2,3}\s*[\"']admin|[\"']/admin",
    16: r"(?i)\b(?:multer|formidable|busboy|UploadFile|FileField|ImageField|move_uploaded_file|request\.files|upload\.(?:single|array|fields)|multipart/form-data)\b",
    18: r"(?i)\bhelmet\b|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|SecurityMiddleware|secure_headers",
    19: r"(?i)webhook",
    20: r"(?i)\b(?:fetch|axios(?:\.\w+)?|got|requests\.(?:get|post|request)|httpx\.\w+|urlopen|http\.Get|HttpClient|curl_init)\s*\(\s*(?![\"'`]https?://)[\w$`]",
    21: r"(?i)\b(?:expiresIn|maxAge|refresh_?token|ACCESS_TOKEN_EXPIRE\w*|SESSION_COOKIE_AGE|revoke\w*|rotate\w*Token|jwt\.(?:sign|verify)|jwtVerify|SignJWT)\b",
    22: r"(?i)\b(?:openai|anthropic|@ai-sdk|langchain|llamaindex|generateText|streamText|chat\.completions|messages\.create|responses\.create|ChatOpenAI|ChatAnthropic|ollama)\b",
}
CONTROL_SIGNALS = {k: re.compile(v) for k, v in CONTROL_SIGNALS.items()}

WEBHOOK_ROUTE_RE = re.compile(r"(?i)(?:\.(?:post|put|all|route)\s*\(|@\w+\.(?:post|route|api_route)|\b(?:re_)?path\s*\(|"
                              r"Route::(?:post|any|match)|\bpost\s+[\"']|@PostMapping|@RequestMapping|HandleFunc)[^\n]*webhook")
WEBHOOK_VERIFY_RE = re.compile(r"(?i)constructEvent|verifyHeader|validateRequest|verify_?signature|verifySignature|\bhmac\b|createHmac|"
                               r"timingSafeEqual|compare_digest|hash_equals|secure_compare|\bsvix\b|new\s+Webhook\s*\(|webhooks?\.verify|"
                               r"x-hub-signature|stripe-signature|x-slack-signature|x-signature")
WEBHOOK_IDEMPOTENCY_RE = re.compile(r"(?i)idempoten|event\.id\b|event_id|eventId|already[_ ]processed|processed_events|dedup|on\s+conflict")
SECURITY_PACKAGES = {
    "helmet": (18, "security headers"), "express-rate-limit": (4, "rate limiting"), "@upstash/ratelimit": (4, "rate limiting"),
    "rate-limiter-flexible": (4, "rate limiting"), "slowapi": (4, "rate limiting"), "django-ratelimit": (4, "rate limiting"),
    "rack-attack": (4, "rate limiting"), "cors": (7, "CORS"), "django-cors-headers": (7, "CORS"), "zod": (5, "validation"),
    "joi": (5, "validation"), "yup": (5, "validation"), "class-validator": (5, "validation"), "pydantic": (5, "validation"),
    "dompurify": (5, "HTML sanitizing"), "isomorphic-dompurify": (5, "HTML sanitizing"), "bleach": (5, "HTML sanitizing"),
    "next-auth": (2, "authentication"), "@auth/core": (2, "authentication"), "@clerk/nextjs": (2, "authentication"),
    "passport": (2, "authentication"), "lucia": (2, "authentication"), "better-auth": (2, "authentication"),
    "@supabase/supabase-js": (1, "Supabase (RLS-based tenancy)"), "@supabase/ssr": (1, "Supabase (RLS-based tenancy)"),
    "firebase": (1, "Firebase (rules-based access)"), "firebase-admin": (14, "Firebase admin SDK (bypasses rules)"),
    "prisma": (6, "ORM"), "@prisma/client": (6, "ORM"), "drizzle-orm": (6, "ORM"), "sequelize": (6, "ORM"), "typeorm": (6, "ORM"),
    "mongoose": (6, "ODM"), "sqlalchemy": (6, "ORM"), "django": (2, "Django"), "djangorestframework": (2, "DRF"),
    "flask": (2, "Flask"), "fastapi": (2, "FastAPI"), "express": (2, "Express"), "next": (2, "Next.js"),
    "@nestjs/core": (2, "NestJS"), "fastify": (2, "Fastify"), "hono": (2, "Hono"), "laravel/framework": (2, "Laravel"),
    "rails": (2, "Rails"), "multer": (16, "uploads"), "formidable": (16, "uploads"), "busboy": (16, "uploads"),
    "stripe": (19, "Stripe webhooks"), "openai": (22, "LLM SDK"), "@anthropic-ai/sdk": (22, "LLM SDK"), "anthropic": (22, "LLM SDK"),
    "ai": (22, "Vercel AI SDK"), "langchain": (22, "LLM framework"), "ssrf-req-filter": (20, "SSRF filter"), "request-filtering-agent": (20, "SSRF filter"),
    "svix": (19, "webhook verification"), "@aws-sdk/client-s3": (13, "S3 storage"),
    "svix": (19, "webhook verification"), "@aws-sdk/client-s3": (13, "S3 storage"),
    "boto3": (13, "AWS SDK"), "jsonwebtoken": (2, "JWT"), "jose": (2, "JWT"), "pyjwt": (2, "JWT"),
    "react-google-recaptcha": (11, "CAPTCHA"), "@hcaptcha/react-hcaptcha": (11, "CAPTCHA"),
    "@marsidev/react-turnstile": (11, "CAPTCHA"), "csurf": (3, "CSRF"), "django-csp": (18, "CSP"),
}


def classify(name, suffix):
    if name in LOCKFILES or name.endswith((".min.js", ".min.css", ".map")):
        return None
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "env"
    if suffix in CODE_EXTS:
        return "code"
    if suffix in CONFIG_EXTS or name in CONFIG_NAMES or name.startswith("Dockerfile"):
        return "config"
    if suffix in SQL_EXTS:
        return "sql"
    if suffix in DOC_EXTS:
        return "doc"
    return None


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


def secret_hits(line, category):
    hits = []
    for title, rx, severity in SECRET_FORMATS:
        for m in rx.finditer(line):
            sev, label = severity, title
            if "v" in rx.groupindex and is_placeholder(m.group("v")):
                continue
            if "host" in rx.groupindex and LOCAL_HOST_RE.match(m.group("host")):
                sev, label = "Low", title + " (local/dev host)"
            if "payload" in rx.groupindex:
                role = jwt_role(m.group("payload"))
                if role == "anon":
                    continue
                if role == "service_role":
                    sev, label = "Critical", "Supabase service_role JWT"
            hits.append(("SEC012", "Known-format secret: " + label, sev, "high"))
            break
    if hits:
        return hits[:1]
    m = (ENV_CRED_RE if category == "env" else QUOTED_CRED_RE).search(line)
    if m and not is_placeholder(m.group("v")):
        return [("SEC001", "Possible hardcoded credential", "High", "medium")]
    return []


RULE_TITLES = {r.rid: r.title for r in RULES}
RULE_TITLES.update({"SEC001": "Possible hardcoded credential", "SEC012": "Known-format secret",
                    "SEC030": "Table without row-level security", "SEC031": "Webhook handler without visible signature verification",
                    "SEC032": "Environment file not covered by root .gitignore", "SEC033": "Dependency manifest without a lockfile",
                    "SEC034": "Webhook handler without visible idempotency handling",
                    "SEC038": "RLS enabled but no policies defined", "SEC039": "Prisma model without a tenant key in a multi-tenant schema"})
SECRET_GUIDANCE = {
    "SEC001": "Confirm whether the value is real. If so, rotate it, remove it from history, and load it from a secret store.",
    "SEC012": "Treat as exposed: rotate first, then purge from git history and move to a secret store.",
}


def parse_gitignore(root):
    path = root / ".gitignore"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith(("#", "!"))]


def is_ignored(rel, patterns):
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        p = pat.rstrip("/")
        if p.startswith("/") or "/" in p:
            p = p.lstrip("/")
            if fnmatch.fnmatch(rel, p) or rel.startswith(p + "/"):
                return True
        elif fnmatch.fnmatch(name, p) or any(fnmatch.fnmatch(part, p) for part in rel.split("/")[:-1]):
            return True
    return False


TABLE_NAME = r"(?P<name>(?:\"?\w+\"?\.)?\"?\w+\"?)"
CREATE_TABLE_RE = re.compile(r"(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?" + TABLE_NAME)
ENABLE_RLS_RE = re.compile(r"(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + TABLE_NAME + r"\s+enable\s+row\s+level\s+security")
DROP_TABLE_RE = re.compile(r"(?i)\bdrop\s+table\s+(?:if\s+exists\s+)?" + TABLE_NAME)
POLICY_RE = re.compile(r"(?i)\bcreate\s+policy\s+(?:\"[^\"]+\"|\w+)\s+on\s+" + TABLE_NAME)
DRIZZLE_TABLE_RE = re.compile(r"(?:export\s+)?const\s+(?P<var>\w+)\s*=\s*pgTable(?P<rls>\.withRLS)?\s*\(\s*[\"'](?P<name>\w+)[\"']")
DRIZZLE_RLS_RE = re.compile(r"\.enableRLS\s*\(|\bpgPolicy\s*\(")
PRISMA_MODEL_RE = re.compile(r"^\s*model\s+(?P<name>\w+)\s*\{")
TENANT_FIELD_RE = re.compile(r"^\s*(?:tenant|org|organization|workspace|account|team|company)_?[iI]d\b", re.I)
PRISMA_GLOBAL_MODELS = re.compile(r"(?i)^(?:user|users|account|session|verificationtoken|authenticator|tenant|org|organization|"
                                  r"workspace|team|company|plan|price|product|feature|migration|_\w+)$")
SUPABASE_INTERNAL_SCHEMAS = ("auth", "storage", "realtime", "supabase_functions", "extensions", "graphql", "graphql_public",
                             "vault", "pgsodium", "pgsodium_masks", "net", "supabase_migrations", "cron", "pgbouncer")


def norm_table(name):
    parts = [p.strip('"').lower() for p in name.split(".")]
    return (parts[0] if len(parts) == 2 else "public", parts[-1])


def analyze_schema_files(files, rls_app):
    """files: list of (rel, ext, lines, in_test). Returns findings."""
    findings = []
    tables, rls_tables, policies, rls_seen = {}, set(), set(), False
    drizzle_tables, drizzle_rls_used = [], False
    prisma_models = []
    for rel, ext, lines, in_test in files:
        context = "test" if in_test else "source"
        if ext == ".sql":
            for number, line in enumerate(lines, 1):
                if line.lstrip().startswith("--"):
                    continue
                for m in CREATE_TABLE_RE.finditer(line):
                    tables[norm_table(m.group("name"))] = (rel, number, redact(line), context)
                for m in ENABLE_RLS_RE.finditer(line):
                    rls_tables.add(norm_table(m.group("name")))
                    rls_seen = True
                for m in POLICY_RE.finditer(line):
                    policies.add(norm_table(m.group("name")))
                for m in DROP_TABLE_RE.finditer(line):
                    tables.pop(norm_table(m.group("name")), None)
        elif ext == ".prisma":
            prisma_models += parse_prisma(rel, lines, context)
        else:
            text = "\n".join(lines)
            drizzle_rls_used = drizzle_rls_used or bool(DRIZZLE_RLS_RE.search(text)) or ".withRLS" in text
            starts = [(m.start(), m) for m in DRIZZLE_TABLE_RE.finditer(text)]
            for i, (pos, m) in enumerate(starts):
                end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
                body = text[pos:end]
                number = text.count("\n", 0, pos) + 1
                has_rls = bool(m.group("rls")) or bool(DRIZZLE_RLS_RE.search(body))
                drizzle_tables.append((m.group("name"), rel, number, has_rls, redact(lines[number - 1]), context))

    if rls_app or rls_seen:
        for (schema, table), (rel, number, evidence, context) in sorted(tables.items()):
            if schema != "public":
                continue
            if (schema, table) not in rls_tables:
                findings.append(make_finding(
                    "SEC030", f"Table '{table}' created without ENABLE ROW LEVEL SECURITY", "High", "medium", (1,),
                    rel, number, evidence,
                    "In an RLS-based app, any exposed table without RLS is readable/writable across tenants. "
                    "Enable RLS and add tenant-scoped policies, or move the table to a non-exposed schema.", context))
            elif (schema, table) not in policies:
                findings.append(make_finding(
                    "SEC038", f"Table '{table}' has RLS enabled but no policies", "Low", "medium", (1,), rel, number, evidence,
                    "Deny-all is safe, but it often pushes app code to the service-role key, which bypasses RLS entirely. "
                    "Confirm how the app reads this table.", context))
    if rls_app or drizzle_rls_used:
        for name, rel, number, has_rls, evidence, context in drizzle_tables:
            if not has_rls:
                findings.append(make_finding(
                    "SEC030", f"Drizzle table '{name}' defined without RLS", "High", "low", (1,), rel, number, evidence,
                    "Use pgTable.withRLS / .enableRLS() and pgPolicy for tenant-owned tables, or confirm RLS is applied in SQL migrations.",
                    context))
    tenant_models = [m for m in prisma_models if m[3]]
    if len(tenant_models) >= 2:
        for name, rel, number, has_tenant, context in prisma_models:
            if not has_tenant and not PRISMA_GLOBAL_MODELS.match(name):
                findings.append(make_finding(
                    "SEC039", f"Prisma model '{name}' has no tenant key", "Informational", "low", (1, 9), rel, number,
                    f"model {name} lacks a tenant/org field while {len(tenant_models)} models have one",
                    "Confirm this model is global or always reached through a tenant-scoped parent; otherwise add a tenant key "
                    "and scope every query (Prisma has no RLS; consider a client extension that injects the tenant filter).",
                    context))
    return findings


def parse_prisma(rel, lines, context):
    models, current = [], None
    for number, line in enumerate(lines, 1):
        m = PRISMA_MODEL_RE.match(line)
        if m:
            current = [m.group("name"), rel, number, False, context]
        elif current is not None:
            if line.strip() == "}":
                models.append(tuple(current))
                current = None
            elif TENANT_FIELD_RE.match(line):
                current[3] = True
    return models


def fingerprint(f):
    basis = "|".join([f["id"], f["file"], re.sub(r"\s+", " ", f["evidence"])])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def make_finding(rid, title, severity, confidence, controls, rel, line, evidence, guidance, context):
    f = {"id": rid, "title": title, "severity": severity, "confidence": confidence,
         "controls": list(controls), "status": "NEEDS_REVIEW", "file": rel, "line": line,
         "evidence": evidence, "guidance": guidance, "context": context}
    f["fingerprint"] = fingerprint(f)
    return f


def read_lines(path):
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()


def is_own_report(lines):
    """True for a report this scanner wrote (Markdown or JSON); re-scanning it would flag quoted evidence."""
    head = "\n".join(lines[:4])
    return head.startswith(REPORT_MARKDOWN_HEADER) or REPORT_JSON_MARKER in head


def scan(root, collect=None):
    """Return line- and repo-level findings. `collect`, if given, receives signals/inventory."""
    root = Path(root)
    state = collect if collect is not None else {}
    scan_state_defaults(state)
    findings, ignore_pats = [], parse_gitignore(root)
    schema_files = []
    webhook_files = []
    supabase = (root / "supabase").is_dir()

    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if name in MANIFESTS:
                state["manifests"].append(rel)
            if rel.startswith(".github/workflows/") or name in {".gitlab-ci.yml", "Jenkinsfile", "bitbucket-pipelines.yml", ".circleci"}:
                state["ci_files"].append(rel)
            category = classify(name, path.suffix.lower())
            if category is None:
                continue
            lines = read_lines(path)
            if lines is None or is_own_report(lines):
                continue
            state["files_scanned"] += 1
            in_test = bool(TEST_PATH_RE.search(rel))
            if in_test and category == "code":
                state["test_files"] += 1
            context = "test" if in_test else "source"
            if category == "env":
                example = bool(EXAMPLE_ENV_RE.search(name))
                ignored = is_ignored(rel, ignore_pats)
                state["env_files"].append({"file": rel, "gitignored": ignored, "example": example})
                if ignored and not example:
                    context = "ignored-local-env"
            if name in MANIFESTS:
                record_packages(name, lines, state["packages"])
            ext = path.suffix.lower()
            text_hits_webhook = category == "code" and not in_test and "webhook" in rel.lower()
            first_webhook_line = 1 if text_hits_webhook else None

            for number, line in enumerate(lines, 1):
                if len(line) > MAX_LINE:
                    state["skipped_large_lines"] += 1
                    continue
                stripped = line.lstrip()
                is_comment = stripped.startswith(COMMENT_PREFIXES) and category != "env"
                hits = [(rid, title, sev, conf, (15,), SECRET_GUIDANCE[rid]) for rid, title, sev, conf in secret_hits(line, category)]
                for rule in RULES:
                    if category in rule.scope and not (is_comment and rule.skip_comments) and rule.match(line, ext):
                        hits.append((rule.rid, rule.title, rule.severity, rule.confidence, rule.controls, rule.guidance))
                if hits:
                    sup = SUPPRESS_RE.search(line) or (number > 1 and SUPPRESS_RE.search(lines[number - 2]))
                    evidence = redact(line)
                    for rid, title, sev, conf, controls, guidance in hits:
                        f = make_finding(rid, title, sev, conf, controls, rel, number, evidence, guidance, context)
                        ids = sup and [i.strip() for i in (sup.group("ids") or "").split(",") if i.strip()]
                        if sup and (not ids or rid in ids):
                            f["suppressed"] = (sup.group("reason") or "").strip() or "no reason given"
                            state["suppressed"].append(f)
                        else:
                            findings.append(f)
                if category in {"code", "config", "sql"} and not is_comment:
                    for cid, rx in CONTROL_SIGNALS.items():
                        if rx.search(line):
                            sig = state["signals"][cid]
                            if in_test:
                                sig["test_count"] += 1
                            else:
                                sig["source_count"] += 1
                                if len(sig["source"]) < MAX_SIGNAL_LOCATIONS and not any(s.startswith(rel + ":") for s in sig["source"]):
                                    sig["source"].append(f"{rel}:{number}")
                if category == "code" and not in_test and first_webhook_line is None and WEBHOOK_ROUTE_RE.search(line):
                    first_webhook_line = number
            if category == "sql" or ext == ".prisma" or (category == "code" and any("pgTable(" in l for l in lines)):
                schema_files.append((rel, ext, lines, in_test))
            if first_webhook_line is not None:
                text = "\n".join(lines)
                webhook_files.append((rel, first_webhook_line, bool(WEBHOOK_VERIFY_RE.search(text)),
                                      bool(WEBHOOK_IDEMPOTENCY_RE.search(text))))

    rls_app = supabase or any(p.startswith("@supabase/") for p in state["packages"])
    findings += analyze_schema_files(schema_files, rls_app)
    for rel, number, verified, idempotent in webhook_files:
        if not verified:
            findings.append(make_finding(
                "SEC031", "Webhook handler without visible signature verification", "High", "low", (19,),
                rel, number, "No signature/HMAC verification call found in this file",
                "Verify the provider signature over the raw request body with a constant-time comparison before parsing. "
                "Verification may live in shared middleware; confirm before reporting.", "source"))
        elif not idempotent:
            findings.append(make_finding(
                "SEC034", "Webhook handler without visible idempotency handling", "Low", "low", (19,),
                rel, number, "Signature check found; no event-ID deduplication found in this file",
                "Persist processed event IDs (unique constraint) so retries and replays cannot apply side effects twice.", "source"))
    for env in state["env_files"]:
        if not env["gitignored"] and not env["example"]:
            findings.append(make_finding(
                "SEC032", "Environment file not covered by root .gitignore", "High", "medium", (15,),
                env["file"], 1, "File name not matched by any root .gitignore pattern",
                "Add the file to .gitignore, check whether it was ever committed (git log --all -- <file>), and rotate any secrets in it.",
                "source"))
    manifest_dirs = {}
    for m in state["manifests"]:
        d, _, n = m.rpartition("/")
        manifest_dirs.setdefault(d, set()).add(n)
    for d, present in sorted(manifest_dirs.items()):
        for manifest, locks in LOCK_FOR.items():
            if manifest in present and not any((root / d / l).exists() for l in locks):
                rel = f"{d}/{manifest}" if d else manifest
                if TEST_PATH_RE.search(rel):
                    continue
                findings.append(make_finding(
                    "SEC033", "Dependency manifest without a lockfile", "Low", "medium", (15,), rel, 1,
                    "No lockfile next to this manifest",
                    "Commit a lockfile so builds are reproducible and dependency audits reflect what ships.", "source"))
    return findings


def record_packages(name, lines, packages):
    found = set()
    if name in {"package.json", "composer.json"}:
        try:
            data = json.loads("\n".join(lines))
            for key in ("dependencies", "devDependencies", "require", "require-dev"):
                if isinstance(data.get(key), dict):
                    found.update(k.lower() for k in data[key])
        except (ValueError, AttributeError):
            pass
    else:
        for line in lines:
            m = re.match(r"""\s*(?:gem\s+["']|require\s+)?["']?([A-Za-z0-9_.@/-]+)""", line)
            if m:
                found.add(m.group(1).lower())
    for pkg in found:
        if pkg in SECURITY_PACKAGES:
            packages[pkg] = SECURITY_PACKAGES[pkg]


def gate_counts(f):
    return f["context"] == "source" or (f["context"] == "test" and f["id"] == "SEC012")


def tool_inventory(state):
    ecosystems = sorted({MANIFESTS[m.rsplit("/", 1)[-1]] for m in state["manifests"]})
    tools = []
    seen = set()
    for eco in ecosystems:
        for cmd, binary, network in DEP_TOOLS.get(eco, []):
            if cmd not in seen:
                seen.add(cmd)
                tools.append({"command": cmd, "purpose": f"{eco} dependency audit", "installed": bool(shutil.which(binary)),
                              "needs_network": network})
    for cmd, binary, network in GENERAL_TOOLS:
        tools.append({"command": cmd, "purpose": "secrets/static analysis", "installed": bool(shutil.which(binary)),
                      "needs_network": network})
    return ecosystems, tools


def build_result(root, findings, state, baseline=None):
    ecosystems, tools = tool_inventory(state)
    controls = []
    for i, name in enumerate(CONTROLS, 1):
        sig = state["signals"].get(i)
        controls.append({"id": i, "name": name, "status": "NOT VERIFIED",
                         "lead_count": sum(1 for f in findings if f["controls"][0] == i),
                         "signals": None if sig is None else {"source_count": sig["source_count"], "test_count": sig["test_count"],
                                                              "locations": sig["source"]}})
    result = {
        "scanner": "saas-security-audit-heuristics", "version": VERSION, "schema_version": SCHEMA_VERSION,
        "root": str(root), "mode": "read-only-local-heuristics",
        "stats": {"files_scanned": state["files_scanned"], "skipped_large_lines": state["skipped_large_lines"],
                  "findings": len(findings), "suppressed": len(state["suppressed"]),
                  "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_RANK}},
        "findings": findings, "suppressed": state["suppressed"], "controls": controls,
        "inventory": {"manifests": state["manifests"], "ecosystems": ecosystems, "recommended_tools": tools,
                      "security_packages": [{"package": p, "control": c, "role": r} for p, (c, r) in sorted(state["packages"].items())],
                      "env_files": state["env_files"], "test_files": state["test_files"], "ci_files": state["ci_files"]},
        "limitations": [
            "Regex heuristics only; false positives and false negatives are expected.",
            "No control is automatically marked PASS; signals show where to look, not that a control is enforced.",
            "Only the root .gitignore is parsed; git history and tracked-but-ignored files are not inspected.",
            "No network access or target-code execution; dependency CVEs require the recommended tools.",
        ],
    }
    if baseline is not None:
        result["comparison"] = compare(findings, baseline)
    return result


def compare(findings, baseline):
    old = {f["fingerprint"]: f for f in baseline.get("findings", []) if "fingerprint" in f}
    new = {f["fingerprint"]: f for f in findings}
    return {"new": [new[k] for k in new if k not in old],
            "resolved": [{k2: old[k][k2] for k2 in ("id", "title", "file", "line", "fingerprint")} for k in old if k not in new],
            "persisting": sum(1 for k in new if k in old)}


def md_escape(text):
    return text.replace("`", "'").replace("|", "\\|")


def markdown(root, findings, state=None, result=None):
    if state is None:
        state = {}
        scan_state_defaults(state)
    result = result or build_result(root, findings, state)
    stats = result["stats"]
    out = ["# Local SaaS Security Heuristic Scan", "",
           f"- **Scanner:** v{VERSION}, read-only local heuristics; no network requests, no target-code execution.",
           f"- **Files scanned:** {stats['files_scanned']}",
           "- **Interpretation:** Every finding is a lead to validate in code, not a confirmed vulnerability.",
           "- **Coverage:** No control is automatically marked PASS.", "",
           "## Summary", "", "| Severity | Leads |", "|---|---|"]
    out += [f"| {s} | {n} |" for s, n in stats["by_severity"].items()]
    out += ["", f"Suppressed inline: {stats['suppressed']}. Findings in test paths or gitignored local env files are marked by context.", ""]
    if not findings:
        out += ["No heuristic matches detected. This does **not** mean the project is secure.", ""]
    else:
        out += ["## Leads by control", ""]
        for i, name in enumerate(CONTROLS, 1):
            group = [f for f in findings if f["controls"][0] == i]
            if not group:
                continue
            out += [f"### C{i}. {name}", ""]
            for rid in sorted({f["id"] for f in group}):
                items = sorted((f for f in group if f["id"] == rid), key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file"], f["line"]))
                first = items[0]
                also = [f"C{c}" for c in first["controls"][1:]]
                heading = RULE_TITLES.get(rid, first["title"])
                out += [f"**{rid} — {heading}** · confidence {first['confidence']}" + (f" · also {', '.join(also)}" if also else ""), "",
                        f"Guidance: {first['guidance']}", ""]
                for f in items:
                    ctx = "" if f["context"] == "source" else f" _({f['context']})_"
                    label = f" {f['title']}" if f["title"] != heading else ""
                    out.append(f"- {f['severity']}{label} — `{f['file']}:{f['line']}`{ctx} — `{md_escape(f['evidence'])}`")
                out.append("")
    out += ["## Control coverage", "",
            "Status stays NOT VERIFIED until enforcement and tests are confirmed in code. "
            "Signals are places where enforcement probably lives (source hits / test hits).", "",
            "| # | Control | Status | Leads | Signals (src/test) | Look first |", "|---|---|---|---|---|---|"]
    for c in result["controls"]:
        sig = c["signals"]
        sig_text = "—" if sig is None else f"{sig['source_count']}/{sig['test_count']}"
        look = "agent review" if c["id"] == 17 else ("dependency tools" if c["id"] == 15 else
               ("none found — check for a gap" if sig and not sig["locations"] else
                ", ".join(f"`{l}`" for l in (sig["locations"][:3] if sig else []))))
        out.append(f"| {c['id']} | {c['name']} | NOT VERIFIED | {c['lead_count']} | {sig_text} | {look} |")
    inv = result["inventory"]
    out += ["", "## Inventory", "",
            f"- Dependency manifests: {', '.join(f'`{m}`' for m in inv['manifests']) or 'none found'}",
            f"- Test files detected: {inv['test_files']}" + (" — PASS is unattainable for most controls without tests." if not inv["test_files"] else ""),
            f"- CI files: {', '.join(f'`{c}`' for c in inv['ci_files']) or 'none found'}"]
    if inv["security_packages"]:
        out.append("- Security-relevant packages (presence ≠ enforcement): " +
                   ", ".join(f"`{p['package']}` (C{p['control']} {p['role']})" for p in inv["security_packages"]))
    out += ["", "Recommended tools (ask before running anything that needs network access):", ""]
    for t in inv["recommended_tools"]:
        out.append(f"- `{t['command']}` — {t['purpose']}; {'installed' if t['installed'] else 'not installed'}"
                   f"{'; needs network' if t['needs_network'] else '; offline'}")
    if result["suppressed"]:
        out += ["", "## Suppressed leads", "", "Inline `security-audit: ignore` markers. Each still needs a reviewer to agree with the reason.", ""]
        out += [f"- {f['id']} `{f['file']}:{f['line']}` — reason: {md_escape(f['suppressed'])}" for f in result["suppressed"]]
    if "comparison" in result:
        cmp_ = result["comparison"]
        out += ["", "## Baseline comparison", "",
                f"- New: {len(cmp_['new'])} · Resolved: {len(cmp_['resolved'])} · Persisting: {cmp_['persisting']}",
                "- A resolved lead means the pattern no longer matches — confirm the root cause was fixed, not just reworded.", ""]
        out += [f"- NEW {f['id']} `{f['file']}:{f['line']}` — {f['title']}" for f in cmp_["new"]]
        out += [f"- RESOLVED {f['id']} `{f['file']}` — {f['title']}" for f in cmp_["resolved"]]
    out += ["", "## Limitations", ""] + [f"- {l}" for l in result["limitations"]]
    return "\n".join(out) + "\n"


def scan_state_defaults(state):
    state.update({"files_scanned": 0, "skipped_large_lines": 0, "suppressed": [],
                  "signals": {i: {"source": [], "source_count": 0, "test_count": 0} for i in CONTROL_SIGNALS},
                  "manifests": [], "env_files": [], "test_files": 0, "ci_files": [], "packages": {}})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="Optional output path; otherwise stdout")
    parser.add_argument("--min-severity", choices=[s.lower() for s in SEVERITY_RANK], default="informational",
                        help="Hide leads below this severity")
    parser.add_argument("--baseline", help="Previous JSON output; adds new/resolved/persisting comparison")
    parser.add_argument("--fail-on", choices=["none"] + [s.lower() for s in SEVERITY_RANK if s != "Informational"], default="none",
                        help="Exit 1 if any unsuppressed source lead is at or above this severity (CI gate)")
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print("ERROR: --root must be an existing directory", file=sys.stderr)
        return 2
    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot read baseline: {exc}", file=sys.stderr)
            return 2
    state = {}
    findings = scan(root, state)
    floor = SEVERITY_RANK[args.min_severity.capitalize()]
    shown = [f for f in findings if SEVERITY_RANK[f["severity"]] >= floor]
    shown.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file"], f["line"], f["id"]))
    result = build_result(root, shown, state, baseline)
    output = json.dumps(result, indent=2) if args.format == "json" else markdown(root, shown, state, result)
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on.capitalize()]
        if any(gate_counts(f) and SEVERITY_RANK[f["severity"]] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Module B: live header, cookie, CORS, and rate-limit probe (opt-in via --probe-url)."""
import re

from .common import make_finding, redact_cookie
from .net import join_url

EVIL_ORIGIN = "https://evil.example.com"
SESSION_COOKIE_RE = re.compile(r"(?i)sess|sid\b|token|auth|jwt|remember|login|^__host-|^__secure-|^sb-")
VERSION_HEADER_RE = re.compile(r"\d+\.\d+")
MAX_BURST = 100


def new_result(module, target):
    return {"module": module, "target": target, "checks": [], "findings": [], "requests": 0, "error": None}


def add(result, control, check, outcome, detail="", finding=None):
    result["checks"].append({"control": control, "check": check, "result": outcome, "detail": detail})
    if finding is not None:
        result["findings"].append(finding)


def rt(rid, title, severity, confidence, controls, where, evidence, guidance):
    return make_finding(rid, title, severity, confidence, controls, where, 0, evidence, guidance, "runtime")


def probe(client, base_url, paths=("/",), rate_limit_path=None, rate_limit_method="GET", burst=25):
    result = new_result("probe", base_url)
    https = base_url.lower().startswith("https://")
    first = None
    for path in paths or ("/",):
        url = join_url(base_url, path)
        resp = client.request("GET", url)
        if resp.status is None:
            add(result, 18, f"GET {path}", "inconclusive", resp.error)
            continue
        first = first or (path, resp)
        check_cookies(result, path, resp, https)
    if first is None:
        result["error"] = "target unreachable"
        result["requests"] = client.requests_made
        return result
    check_headers(result, first[0], first[1], https)
    check_cors(result, client, base_url, first[0])
    check_rate_limit(result, client, base_url, rate_limit_path or first[0], rate_limit_method, burst)
    result["requests"] = client.requests_made
    return result


def check_headers(result, path, resp, https):
    csp = resp.header("Content-Security-Policy") or ""
    if not csp:
        add(result, 18, "Content-Security-Policy present", "fail", f"GET {path} returned no CSP",
            rt("RT101", "Missing Content-Security-Policy", "Medium", "confirmed", (18,), path, "No Content-Security-Policy header",
               "Add a CSP (start with default-src 'self'; frame-ancestors 'none'; object-src 'none') and tighten script-src."))
    else:
        script_src = re.search(r"(?i)script-src([^;]*)", csp) or re.search(r"(?i)default-src([^;]*)", csp)
        weak = script_src and re.search(r"'unsafe-inline'|'unsafe-eval'|\*(?:\s|$)", script_src.group(1)) and "nonce-" not in script_src.group(1) \
            and "strict-dynamic" not in script_src.group(1)
        add(result, 18, "Content-Security-Policy present", "warn" if weak else "pass",
            "script-src allows unsafe-inline/eval or *" if weak else "CSP present")
    xfo = (resp.header("X-Frame-Options") or "").upper()
    if xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower():
        add(result, 18, "Clickjacking protection", "pass", xfo or "CSP frame-ancestors")
    else:
        add(result, 18, "Clickjacking protection", "fail", "no X-Frame-Options or frame-ancestors",
            rt("RT102", "Missing clickjacking protection", "Medium", "confirmed", (18,), path, "No X-Frame-Options / frame-ancestors",
               "Send CSP frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY."))
    if (resp.header("X-Content-Type-Options") or "").lower() == "nosniff":
        add(result, 18, "X-Content-Type-Options: nosniff", "pass")
    else:
        add(result, 18, "X-Content-Type-Options: nosniff", "fail", "missing",
            rt("RT103", "Missing X-Content-Type-Options", "Low", "confirmed", (18,), path, "No X-Content-Type-Options header",
               "Send X-Content-Type-Options: nosniff on all responses."))
    if not https:
        add(result, 8, "Strict-Transport-Security", "not_applicable", "target is plain HTTP; verify HSTS on the HTTPS deployment")
    elif re.search(r"(?i)max-age=(\d+)", resp.header("Strict-Transport-Security") or "") and \
            int(re.search(r"(?i)max-age=(\d+)", resp.header("Strict-Transport-Security")).group(1)) >= 15552000:
        add(result, 8, "Strict-Transport-Security", "pass", resp.header("Strict-Transport-Security"))
    else:
        add(result, 8, "Strict-Transport-Security", "fail", resp.header("Strict-Transport-Security") or "missing",
            rt("RT104", "Missing or short HSTS", "Medium", "confirmed", (8, 18), path,
               f"Strict-Transport-Security: {resp.header('Strict-Transport-Security') or 'missing'}",
               "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS is enforced everywhere."))
    disclosed = [f"{h}: {resp.header(h)}" for h in ("Server", "X-Powered-By", "X-AspNet-Version")
                 if resp.header(h) and (h != "Server" or VERSION_HEADER_RE.search(resp.header(h)))]
    if disclosed:
        add(result, 10, "No technology/version disclosure", "warn", "; ".join(disclosed),
            rt("RT105", "Technology/version disclosure header", "Low", "confirmed", (10,), path, "; ".join(disclosed)[:240],
               "Remove X-Powered-By and version numbers from Server headers."))
    else:
        add(result, 10, "No technology/version disclosure", "pass")


def check_cookies(result, path, resp, https):
    for raw in resp.header_all("Set-Cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "") for a in raw.split(";")[1:]}
        safe = redact_cookie(raw)
        if not SESSION_COOKIE_RE.search(name):
            continue
        if "httponly" in attrs:
            add(result, 8, f"Cookie {name}: HttpOnly", "pass")
        else:
            add(result, 8, f"Cookie {name}: HttpOnly", "fail", safe,
                rt("RT110", f"Session cookie '{name}' missing HttpOnly", "High", "confirmed", (8,), path, safe,
                   "Set HttpOnly on session/auth cookies so injected scripts cannot read them."))
        if "secure" in attrs:
            add(result, 8, f"Cookie {name}: Secure", "pass")
        elif https:
            add(result, 8, f"Cookie {name}: Secure", "fail", safe,
                rt("RT111", f"Session cookie '{name}' missing Secure", "High", "confirmed", (8,), path, safe,
                   "Set Secure on session/auth cookies so they are never sent over plain HTTP."))
        else:
            add(result, 8, f"Cookie {name}: Secure", "warn", "missing over plain HTTP; confirm production sets Secure")
        samesite = attrs.get("samesite", "").lower()
        if samesite in ("lax", "strict") or (samesite == "none" and "secure" in attrs):
            add(result, 8, f"Cookie {name}: SameSite", "pass", samesite)
        else:
            add(result, 8, f"Cookie {name}: SameSite", "fail", safe or "missing",
                rt("RT112", f"Session cookie '{name}' missing a safe SameSite", "Low", "confirmed", (8, 3), path, safe,
                   "Set SameSite=Lax (or Strict); SameSite=None requires Secure and CSRF protection."))


def check_cors(result, client, base_url, path):
    url = join_url(base_url, path)
    pre = client.request("OPTIONS", url, headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "POST",
                                                  "Access-Control-Request-Headers": "authorization,content-type"})
    simple = client.request("GET", url, headers={"Origin": EVIL_ORIGIN})
    null = client.request("GET", url, headers={"Origin": "null"})
    if pre.status is None and simple.status is None:
        add(result, 7, "CORS rejects untrusted origin", "inconclusive", pre.error or simple.error)
        return
    reflected = [r for r in (pre, simple) if r.header("Access-Control-Allow-Origin") == EVIL_ORIGIN]
    creds = any((r.header("Access-Control-Allow-Credentials") or "").lower() == "true" for r in reflected)
    wildcard_creds = any(r.header("Access-Control-Allow-Origin") == "*" and
                         (r.header("Access-Control-Allow-Credentials") or "").lower() == "true" for r in (pre, simple))
    if reflected and creds:
        add(result, 7, "CORS rejects untrusted origin", "fail", "evil origin reflected with credentials",
            rt("RT120", "CORS reflects an untrusted origin with credentials", "High", "confirmed", (7,), path,
               f"Origin: {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {EVIL_ORIGIN}; Allow-Credentials: true",
               "Any website can make authenticated requests and read responses as the logged-in user. Use an exact origin allowlist."))
    elif reflected:
        add(result, 7, "CORS rejects untrusted origin", "fail", "evil origin reflected without credentials",
            rt("RT121", "CORS reflects an untrusted origin", "Medium", "confirmed", (7,), path,
               f"Origin: {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {EVIL_ORIGIN}",
               "Reflect only allowlisted origins. Risk rises sharply if credentials or bearer tokens are ever allowed."))
    elif wildcard_creds:
        add(result, 7, "CORS rejects untrusted origin", "fail", "wildcard with credentials",
            rt("RT123", "Wildcard CORS combined with Allow-Credentials", "Medium", "confirmed", (7,), path,
               "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
               "Browsers block this combination, but it signals a misconfigured policy; use an exact allowlist."))
    else:
        add(result, 7, "CORS rejects untrusted origin", "pass",
            f"ACAO={pre.header('Access-Control-Allow-Origin') or simple.header('Access-Control-Allow-Origin') or 'absent'}")
    if null.header("Access-Control-Allow-Origin") == "null" and (null.header("Access-Control-Allow-Credentials") or "").lower() == "true":
        add(result, 7, "CORS rejects null origin", "fail", "null origin allowed with credentials",
            rt("RT122", "CORS allows the 'null' origin with credentials", "High", "confirmed", (7,), path,
               "Origin: null -> Access-Control-Allow-Origin: null; Allow-Credentials: true",
               "Sandboxed iframes and local files send Origin: null; never allowlist it."))
    elif null.status is not None:
        add(result, 7, "CORS rejects null origin", "pass")


def check_rate_limit(result, client, base_url, path, method, burst):
    burst = max(1, min(int(burst), MAX_BURST))
    url = join_url(base_url, path)
    statuses, limited_at, limiter_headers = [], None, False
    body = "{}" if method.upper() != "GET" else None
    headers = {"Content-Type": "application/json"} if body else {}
    for i in range(1, burst + 1):
        resp = client.request(method.upper(), url, headers=headers, body=body)
        statuses.append(resp.status)
        if any(resp.header(h) for h in ("RateLimit-Limit", "X-RateLimit-Limit", "RateLimit-Policy", "RateLimit", "Retry-After")):
            limiter_headers = True
        if resp.status == 429:
            limited_at = i
            break
    if all(s is None for s in statuses):
        add(result, 4, f"Rate limit on {method.upper()} {path}", "inconclusive", "no responses")
    elif limited_at:
        add(result, 4, f"Rate limit on {method.upper()} {path}", "pass", f"429 after {limited_at} requests")
    elif limiter_headers:
        add(result, 4, f"Rate limit on {method.upper()} {path}", "pass",
            f"rate-limit headers present; limit not reached within {burst} requests")
    else:
        dist = {}
        for s in statuses:
            dist[str(s)] = dist.get(str(s), 0) + 1
        add(result, 4, f"Rate limit on {method.upper()} {path}", "fail", f"no 429 or rate-limit headers in {burst} requests: {dist}",
            rt("RT130", f"No rate limiting observed on {method.upper()} {path}", "Medium", "medium", (4,), path,
               f"{burst} rapid requests, status counts {dist}, no 429 or RateLimit headers",
               "Add a shared-store limiter keyed by account and IP on auth and cost-bearing endpoints. "
               "A limit above the burst size, or one applied only at the edge/CDN, would not show here."))

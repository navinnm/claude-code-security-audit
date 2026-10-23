"""Shared, guarded HTTP client for opt-in runtime probes (stdlib only).

Safety model:
- Targets must be local, private-network, or staging-like hosts unless --allow-production is set.
- Cloud metadata addresses are always refused.
- Redirects are never followed (a redirect could leave the approved host).
- Response bodies are read with a size cap and never stored in reports.
"""
import ipaddress
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

USER_AGENT = "saas-security-audit-probe/0.3 (+authorized local testing)"
MAX_BODY = 65536
STAGING_LABEL_RE = re.compile(r"(?i)(?:^|[.-])(?:staging|stage|stg|preview|dev|develop|development|test|testing|qa|uat|sandbox|local)(?:[.-]|$)")
LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa")
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}


class TargetBlocked(Exception):
    pass


def classify_host(host):
    """Return 'local', 'private', 'staging', 'metadata', or 'public'."""
    host = (host or "").strip("[]").lower()
    if host in METADATA_HOSTS:
        return "metadata"
    if host in ("localhost", "host.docker.internal") or host.endswith(LOCAL_SUFFIXES):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            return "metadata"
        if ip.is_loopback or ip.is_unspecified:
            return "local"
        if ip.is_private:
            return "private"
        return "public"
    except ValueError:
        pass
    return "staging" if STAGING_LABEL_RE.search(host) else "public"


def check_target(url, allow_hosts=(), allow_production=False):
    """Raise TargetBlocked unless the URL is an approved test target. Returns the host class."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https", "postgres", "postgresql"):
        raise TargetBlocked(f"unsupported scheme '{parts.scheme}'")
    host = (parts.hostname or "").lower()
    if not host:
        raise TargetBlocked("URL has no host")
    kind = classify_host(host)
    if kind == "metadata":
        raise TargetBlocked(f"{host} is a cloud metadata/link-local address; always refused")
    if host in {h.lower() for h in allow_hosts}:
        return "allowlisted"
    if kind == "public" and not allow_production:
        raise TargetBlocked(f"{host} looks like a production/public host. Probe only local or staging targets, "
                            "add it with --allow-host if it is a test environment, or pass --allow-production "
                            "with written authorization.")
    return kind


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, status, headers, body_len, elapsed, error=None, body_sample=b""):
        self.status, self.headers, self.body_len, self.elapsed, self.error = status, headers, body_len, elapsed, error
        self._sample = body_sample

    def header(self, name):
        return self.headers.get(name.lower(), [None])[0]

    def header_all(self, name):
        return self.headers.get(name.lower(), [])

    def body_contains(self, marker):
        return bool(marker) and marker.encode("utf-8") in self._sample


class Client:
    """Minimal guarded client. `opener` is injectable for tests."""

    def __init__(self, allow_hosts=(), allow_production=False, timeout=10.0, opener=None):
        self.allow_hosts, self.allow_production, self.timeout = tuple(allow_hosts), allow_production, timeout
        self.opener = opener or urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self.requests_made = 0

    def request(self, method, url, headers=None, body=None):
        check_target(url, self.allow_hosts, self.allow_production)
        hdrs = {"User-Agent": USER_AGENT}
        hdrs.update(headers or {})
        data = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        start = time.monotonic()
        self.requests_made += 1
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status, raw_headers, sample = resp.status, resp.headers, resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            status, raw_headers = exc.code, exc.headers
            try:
                sample = exc.read(MAX_BODY)
            except Exception:
                sample = b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return Response(None, {}, 0, time.monotonic() - start, error=str(getattr(exc, "reason", exc)))
        headers_map = {}
        for key, value in (raw_headers.items() if raw_headers else []):
            headers_map.setdefault(key.lower(), []).append(value)
        return Response(status, headers_map, len(sample), time.monotonic() - start, body_sample=sample)


def join_url(base, path):
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")

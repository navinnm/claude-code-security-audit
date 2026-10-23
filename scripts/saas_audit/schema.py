"""Module E: tenant-isolation schema analysis.

Static: SQL migrations (Postgres/Supabase RLS), Drizzle pgTable definitions, Prisma models.
Live (opt-in, --db-url): read-only RLS/policy introspection through a local `psql` binary.
"""
import os
import re
import shutil
import subprocess
from urllib.parse import urlsplit, unquote

from .common import make_finding, redact

RULE_TITLES = {"SEC030": "Table without row-level security", "SEC038": "RLS enabled but no policies defined",
               "SEC039": "Prisma model without a tenant key in a multi-tenant schema",
               "DB001": "Live database: exposed table without row-level security",
               "DB002": "Live database: permissive RLS policy"}

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


def analyze_files(files, rls_app):
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


TABLES_SQL = (
    "select n.nspname, c.relname, c.relrowsecurity, "
    "(select count(*) from pg_policies p where p.schemaname = n.nspname and p.tablename = c.relname) "
    "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
    "where c.relkind in ('r','p') and n.nspname not in ('pg_catalog','information_schema') and n.nspname not like 'pg\\_%' "
    "order by 1, 2"
)
POLICIES_SQL = ("select schemaname, tablename, policyname, cmd, array_to_string(roles, ','), coalesce(qual, ''), coalesce(with_check, '') "
                "from pg_policies order by 1, 2, 3")
SUPABASE_SQL = "select exists(select 1 from pg_namespace where nspname = 'auth')"


def db_env(db_url):
    parts = urlsplit(db_url)
    env = dict(os.environ)
    env.update({"PGHOST": parts.hostname or "localhost", "PGPORT": str(parts.port or 5432),
                "PGUSER": unquote(parts.username or ""), "PGDATABASE": (parts.path or "/postgres").lstrip("/") or "postgres",
                "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=15000",
                "PGCONNECT_TIMEOUT": "10", "PGAPPNAME": "saas-security-audit"})
    if parts.password:
        env["PGPASSWORD"] = unquote(parts.password)
    for key, value in [kv.split("=", 1) for kv in (parts.query or "").split("&") if "=" in kv]:
        if key == "sslmode":
            env["PGSSLMODE"] = value
    return env


def safe_db_label(db_url):
    parts = urlsplit(db_url)
    return f"{parts.scheme}://{parts.hostname or 'localhost'}:{parts.port or 5432}{parts.path or ''}"


def run_psql(env, sql, runner=subprocess.run):
    proc = runner(["psql", "-X", "-A", "-t", "-F", "\x1f", "-v", "ON_ERROR_STOP=1", "-c", sql],
                  env=env, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(redact(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"psql exit {proc.returncode}"))
    return [line.split("\x1f") for line in proc.stdout.splitlines() if line.strip()]


def introspect_db(db_url, runner=subprocess.run, which=shutil.which):
    """Returns (findings, checks, error). Never raises for expected failures."""
    label = safe_db_label(db_url)
    if which("psql") is None:
        return [], [], "psql not installed; live RLS introspection skipped"
    env = db_env(db_url)
    try:
        supabase = run_psql(env, SUPABASE_SQL, runner)[0][0] == "t"
        tables = run_psql(env, TABLES_SQL, runner)
        policies = run_psql(env, POLICIES_SQL, runner)
    except (RuntimeError, OSError, subprocess.TimeoutExpired, IndexError) as exc:
        return [], [], f"database introspection failed: {exc}"
    findings, checks = [], []
    exposed = ("public",) if supabase else ("public",)
    for schema, table, rls, policy_count in tables:
        if schema in SUPABASE_INTERNAL_SCHEMAS or schema not in exposed:
            continue
        ok = rls == "t"
        checks.append({"control": 1, "check": f"RLS enabled on {schema}.{table}", "result": "pass" if ok else "fail",
                       "detail": f"policies={policy_count}"})
        if not ok:
            findings.append(make_finding(
                "DB001", f"Live database: {schema}.{table} has row-level security disabled",
                "High" if supabase else "Medium", "confirmed" if supabase else "medium", (1,), label, 0,
                f"relrowsecurity=false on {schema}.{table}",
                "Supabase exposes the public schema through its API with the anon key, so this table is readable by anyone. "
                "Enable RLS and add tenant-scoped policies." if supabase else
                "If tenancy relies on RLS, enable it; if tenancy is enforced in app code, confirm every query is scoped.",
                "runtime"))
    for schema, table, name, cmd, roles, qual, check in policies:
        if schema in SUPABASE_INTERNAL_SCHEMAS:
            continue
        permissive = qual.strip().lower() in ("true", "(true)") or check.strip().lower() in ("true", "(true)")
        if permissive and any(r in roles.split(",") for r in ("anon", "public", "authenticated")):
            findings.append(make_finding(
                "DB002", f"Live database: policy '{name}' on {schema}.{table} allows all rows", "High", "confirmed", (1,),
                label, 0, f"{cmd} to {roles} using ({qual or '-'}) with check ({check or '-'})",
                "Scope the policy to the caller, e.g. tenant_id = (select auth.jwt() ->> 'tenant_id') or owner = auth.uid().",
                "runtime"))
    return findings, checks, None

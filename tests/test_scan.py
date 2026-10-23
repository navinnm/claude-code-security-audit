import base64
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan.py"
spec = importlib.util.spec_from_file_location("scan", SCRIPT)
scan_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_module)


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# Fake credentials are assembled at runtime so no secret-shaped literal ships in the plugin source.
FAKE_API_VALUE = "supersecret" + "value123"
FAKE_STRIPE_LIVE = "sk_" + "live_" + "abcdefghijklmnop1234"
FAKE_AWS_ID = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_DB_PASSWORD = "hunter2" + "pass"


def jwt(payload):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlc2lnbmF0dXJl"


class ScanCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def ids(self, rel, text):
        write(self.root, rel, text)
        return [f["id"] for f in scan_module.scan(self.root) if f["file"] == rel]


class SecretTests(ScanCase):
    def test_detects_debug_and_redacts_secret(self):
        write(self.root, "app.py", f'APP_DEBUG = True\nAPI_KEY = "{FAKE_API_VALUE}"\n')
        findings = scan_module.scan(self.root)
        ids = {f["id"] for f in findings}
        self.assertIn("SEC001", ids)
        self.assertIn("SEC004", ids)
        secret = next(f for f in findings if f["id"] == "SEC001")
        self.assertNotIn(FAKE_API_VALUE, secret["evidence"])
        self.assertIn("[REDACTED]", secret["evidence"])

    def test_scans_suffixed_env_files_and_redacts(self):
        write(self.root, ".env.production", f"STRIPE_SECRET_KEY={FAKE_STRIPE_LIVE}\n"
                                             f"DATABASE_URL=postgres://admin:{FAKE_DB_PASSWORD}@db.prod.example.com/app\n")
        findings = scan_module.scan(self.root)
        live = [f for f in findings if f["id"] == "SEC012"]
        self.assertEqual({f["severity"] for f in live}, {"Critical", "High"})
        for f in findings:
            self.assertNotIn(FAKE_STRIPE_LIVE, f["evidence"])
            self.assertNotIn(FAKE_DB_PASSWORD, f["evidence"])
        self.assertIn("SEC032", {f["id"] for f in findings})

    def test_gitignored_env_is_context_marked_not_gated(self):
        write(self.root, ".gitignore", ".env*\n!.env.example\n")
        write(self.root, ".env.local", f"AWS_KEY={FAKE_AWS_ID}\n")
        findings = scan_module.scan(self.root)
        self.assertNotIn("SEC032", {f["id"] for f in findings})
        hit = next(f for f in findings if f["id"] == "SEC012")
        self.assertEqual(hit["context"], "ignored-local-env")
        self.assertFalse(scan_module.gate_counts(hit))

    def test_placeholders_are_not_secrets(self):
        self.assertEqual(self.ids("config.js", 'const password = "changeme";\nconst apiKey = "your_api_key_here";\n'), [])
        self.assertEqual(self.ids(".env.example", "OPENAI_API_KEY=<your-key>\nDB_PASSWORD=${DB_PASSWORD}\n"), [])

    def test_supabase_jwt_roles(self):
        self.assertEqual(self.ids("a.ts", f'const k = "{jwt({"role": "anon"})}";\n'), [])
        write(self.root, "b.ts", f'const k = "{jwt({"role": "service_role"})}";\n')
        hit = next(f for f in scan_module.scan(self.root) if f["file"] == "b.ts")
        self.assertEqual((hit["id"], hit["severity"]), ("SEC012", "Critical"))

    def test_public_env_secret(self):
        self.assertIn("SEC023", self.ids("lib/supabase.ts", "createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)\n"))
        self.assertNotIn("SEC023", self.ids("lib/map.ts", "const t = process.env.NEXT_PUBLIC_MAPBOX_TOKEN\n"))


class InjectionTests(ScanCase):
    def test_sql_concatenation_and_interpolation(self):
        self.assertIn("SEC003", self.ids("a.js", 'db.query("SELECT * FROM users WHERE id = " + req.params.id);\n'))
        self.assertIn("SEC003", self.ids("b.js", "db.query(`SELECT * FROM users WHERE id = ${id}`);\n"))
        self.assertIn("SEC003", self.ids("c.py", 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n'))
        self.assertIn("SEC003", self.ids("d.py", 'cur.execute("SELECT * FROM t WHERE id = %s" % uid)\n'))

    def test_parameterized_and_tagged_queries_are_clean(self):
        self.assertEqual(self.ids("a.py", 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'), [])
        self.assertEqual(self.ids("b.ts", "await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;\n"), [])
        self.assertEqual(self.ids("c.ts", "const rows = await sql`SELECT * FROM t WHERE id = ${id}`;\n"), [])

    def test_regex_exec_is_not_code_execution(self):
        self.assertEqual(self.ids("a.js", "const m = /abc/.exec(str);\nconst r = db.exec(stmt);\n"), [])
        self.assertIn("SEC013", self.ids("b.js", "exec(`convert ${req.query.file} out.png`);\n"))
        self.assertIn("SEC002", self.ids("c.py", "exec(user_code)\n"))
        self.assertNotIn("SEC002", self.ids("d.py", "ast.literal_eval(value)\n"))

    def test_safe_yaml_loader_not_flagged(self):
        self.assertEqual(self.ids("a.py", "yaml.load(data, Loader=yaml.SafeLoader)\n"), [])
        self.assertIn("SEC014", self.ids("b.py", "yaml.load(data)\n"))

    def test_comment_lines_skip_code_rules_but_not_secrets(self):
        self.assertEqual(self.ids("a.js", "// el.innerHTML = x\n"), [])
        self.assertIn("SEC012", self.ids("b.js", f"// key: {FAKE_AWS_ID}\n"))


class SaasRuleTests(ScanCase):
    def test_rls_missing_on_supabase_table(self):
        write(self.root, "supabase/migrations/001.sql",
              "create table public.invoices (id uuid);\ncreate table orgs (id uuid);\n"
              "alter table public.orgs enable row level security;\ncreate table private.jobs (id uuid);\n")
        rls = [f for f in scan_module.scan(self.root) if f["id"] == "SEC030"]
        self.assertEqual(len(rls), 1)
        self.assertIn("invoices", rls[0]["title"])

    def test_no_rls_check_without_rls_context(self):
        write(self.root, "db/schema.sql", "create table invoices (id int);\n")
        self.assertNotIn("SEC030", {f["id"] for f in scan_module.scan(self.root)})

    def test_permissive_policy(self):
        self.assertIn("SEC022", self.ids("m.sql", 'create policy "p" on docs using (true);\n'))
        self.assertIn("SEC022", self.ids("firestore.rules", "allow read, write: if true;\n"))

    def test_webhook_signature_and_idempotency(self):
        write(self.root, "app/api/webhooks/stripe/route.ts", "export async function POST(req) { await fulfil(await req.json()); }\n")
        write(self.root, "app/api/webhooks/github/route.ts", "const sig = req.headers.get('x-hub-signature-256'); verifySignature(sig);\n")
        write(self.root, "app/api/webhooks/svix/route.ts", "new Webhook(secret).verify(body, h); if (await seen(event.id)) return;\n")
        by_file = {f["file"]: f["id"] for f in scan_module.scan(self.root) if f["id"] in ("SEC031", "SEC034")}
        self.assertEqual(by_file, {"app/api/webhooks/stripe/route.ts": "SEC031", "app/api/webhooks/github/route.ts": "SEC034"})

    def test_mass_assignment_cors_tls(self):
        ids = self.ids("server.js", "await User.create(req.body);\napp.use(cors({ origin: true, credentials: true }));\n"
                                    "https.request({ rejectUnauthorized: false });\n")
        self.assertEqual(sorted(ids), ["SEC005", "SEC016", "SEC019"])

    def test_missing_lockfile(self):
        write(self.root, "package.json", '{"dependencies": {"helmet": "1"}}')
        self.assertIn("SEC033", {f["id"] for f in scan_module.scan(self.root)})
        write(self.root, "package-lock.json", "{}")
        self.assertNotIn("SEC033", {f["id"] for f in scan_module.scan(self.root)})


class ModernControlTests(ScanCase):
    def test_twenty_two_controls(self):
        self.assertEqual(len(scan_module.CONTROLS), 22)
        self.assertIn("| 22 | AI/LLM security and prompt injection | NOT VERIFIED |", scan_module.markdown(self.root, []))

    def test_ssrf_maps_to_control_20(self):
        write(self.root, "proxy.py", "requests.get(request.args['url'])\n")
        hit = next(f for f in scan_module.scan(self.root) if f["id"] == "SEC020")
        self.assertEqual(hit["controls"][0], 20)

    def test_jwt_lifecycle(self):
        write(self.root, "auth.js", 'jwt.sign(p, key, { expiresIn: "365d" });\nconst ok = jwt.verify(token, secret);\n')
        by_id = {f["id"]: f for f in scan_module.scan(self.root)}
        self.assertEqual(by_id["SEC037"]["controls"], [21])
        self.assertEqual(by_id["SEC017"]["controls"][0], 21)
        self.assertNotIn("SEC017", self.ids("ok.js", "jwt.verify(token, secret, { algorithms: ['RS256'] });\n"))

    def test_llm_prompt_injection_and_output_sink(self):
        ids = self.ids("ai.ts", "const systemPrompt = `Context: ${req.body.notes}`;\n"
                                "await db.query(completion.choices[0].message.content);\n")
        self.assertEqual(sorted(ids), ["SEC035", "SEC036"])

    def test_drizzle_rls(self):
        write(self.root, "db/schema.ts", 'export const projects = pgTable("projects", { id: uuid("id") });\n'
                                         'export const orgs = pgTable("orgs", { id: uuid("id") }).enableRLS();\n')
        rls = [f for f in scan_module.scan(self.root) if f["id"] == "SEC030"]
        self.assertEqual(len(rls), 1)
        self.assertIn("projects", rls[0]["title"])

    def test_rls_without_policies(self):
        write(self.root, "supabase/migrations/1.sql", "create table public.notes (id uuid);\n"
                                                      "alter table public.notes enable row level security;\n")
        self.assertIn("SEC038", {f["id"] for f in scan_module.scan(self.root)})
        write(self.root, "supabase/migrations/2.sql", 'create policy "own" on public.notes using (owner = auth.uid());\n')
        self.assertNotIn("SEC038", {f["id"] for f in scan_module.scan(self.root)})

    def test_prisma_model_without_tenant_key(self):
        write(self.root, "schema.prisma", "model Project {\n  id String @id\n  orgId String\n}\n"
                                          "model Invoice {\n  id String @id\n  orgId String\n}\n"
                                          "model AuditEvent {\n  id String @id\n}\nmodel User {\n  id String @id\n}\n")
        names = [f["title"] for f in scan_module.scan(self.root) if f["id"] == "SEC039"]
        self.assertEqual(len(names), 1)
        self.assertIn("AuditEvent", names[0])

    def test_public_gcs_bucket(self):
        self.assertIn("SEC026", self.ids("main.tf", 'member = "allUsers"\n'))


class BehaviourTests(ScanCase):
    def test_skips_node_modules(self):
        write(self.root, "node_modules/bad.js", "eval(userInput)\n")
        self.assertEqual(scan_module.scan(self.root), [])

    def test_test_paths_are_context_marked(self):
        write(self.root, "tests/test_x.py", "eval(x)\n")
        hit = scan_module.scan(self.root)[0]
        self.assertEqual(hit["context"], "test")
        self.assertFalse(scan_module.gate_counts(hit))

    def test_inline_suppression_is_reported_not_dropped(self):
        write(self.root, "a.py", "eval(x)  # security-audit: ignore[SEC002] -- constant expression only\n")
        state = {}
        self.assertEqual(scan_module.scan(self.root, state), [])
        self.assertEqual(state["suppressed"][0]["suppressed"], "constant expression only")

    def test_controls_remain_unverified(self):
        report = scan_module.markdown(self.root, [])
        self.assertIn("NOT VERIFIED", report)
        self.assertIn("does **not** mean the project is secure", report)
        self.assertNotIn("PASS |", report)

    def test_signals_point_to_enforcement(self):
        write(self.root, "src/middleware.ts", "export default clerkMiddleware();\n")
        state = {}
        scan_module.scan(self.root, state)
        self.assertEqual(state["signals"][2]["source"], ["src/middleware.ts:1"])

    def test_fail_on_and_baseline(self):
        write(self.root, "a.py", "eval(x)\n")
        base = self.root.parent / (self.root.name + "-base.json")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scan_module.main(["--root", str(self.root), "--fail-on", "high"]), 1)
                self.assertEqual(scan_module.main(["--root", str(self.root), "--fail-on", "critical"]), 0)
                scan_module.main(["--root", str(self.root), "--format", "json", "--output", str(base)])
            write(self.root, "a.py", "result = safe_parse(x)\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                scan_module.main(["--root", str(self.root), "--format", "json", "--baseline", str(base)])
            comparison = json.loads(out.getvalue())["comparison"]
            self.assertEqual([f["id"] for f in comparison["resolved"]], ["SEC002"])
            self.assertEqual(comparison["new"], [])
        finally:
            base.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

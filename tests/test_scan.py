import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan.py"
spec = importlib.util.spec_from_file_location("scan", SCRIPT)
scan_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_module)

class ScannerTests(unittest.TestCase):
    def test_detects_debug_and_redacts_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('APP_DEBUG = True\nAPI_KEY = "supersecretvalue123"\n', encoding="utf-8")
            findings = scan_module.scan(root)
            ids = {f["id"] for f in findings}
            self.assertIn("SEC001", ids)
            self.assertIn("SEC004", ids)
            secret = next(f for f in findings if f["id"] == "SEC001")
            self.assertNotIn("supersecretvalue123", secret["evidence"])
            self.assertIn("[REDACTED]", secret["evidence"])

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "bad.js").write_text("eval(userInput)\n", encoding="utf-8")
            self.assertEqual(scan_module.scan(root), [])

    def test_controls_remain_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = scan_module.markdown(Path(tmp), [])
            self.assertIn("NOT VERIFIED", report)
            self.assertIn("does **not** mean the project is secure", report)

if __name__ == "__main__":
    unittest.main()

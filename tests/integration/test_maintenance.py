import json
import tempfile
import unittest
from pathlib import Path

from ei.cli import main


class MaintenanceTests(unittest.TestCase):
    def test_maintenance_is_idempotent_and_partial_failure_preserves_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            valid = root / "valid.md"
            valid.write_text("## Reusable knowledge\n- 書込後は再読込して確認する\n", encoding="utf-8")
            codex_home = Path(str(root) + "-codex")
            runtime = Path(str(root) + "-runtime")
            common = ["--repo", str(root), "--codex-home", str(codex_home), "--runtime-root", str(runtime)]
            first_code = main(["maintain", *common, "--source", str(valid), "--json"])
            self.assertEqual(first_code, 0)
            manifest = (root / "knowledge" / "manifest.json").read_bytes()
            second_code = main(["maintain", *common, "--source", str(valid), "--json"])
            self.assertEqual(second_code, 0)
            self.assertEqual(manifest, (root / "knowledge" / "manifest.json").read_bytes())
            invalid = root / "invalid.md"
            invalid.write_bytes(b"\xff\xfe")
            partial_code = main(["maintain", *common, "--source", str(valid), "--source", str(invalid), "--json"])
            self.assertEqual(partial_code, 0)
            health = json.loads((runtime / "health.json").read_text(encoding="utf-8"))
            self.assertEqual(health["status"], "partial")
            self.assertEqual(health["knowledge_stores"]["personal"]["status"], "READY")
            self.assertEqual(health["knowledge_stores"]["team"], {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
            self.assertEqual(manifest, (root / "knowledge" / "manifest.json").read_bytes())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "audit-production-source.py"


class SourceAuditTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(REPO_ROOT), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_repository_production_source_passes_audit(self) -> None:
        result = self._run("--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["violations"], [])

    def test_dependency_lock_and_workflow_action_audit_passes(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "verify-dependency-lock.py"),
                "--pyproject", str(REPO_ROOT / "pyproject.toml"),
                "--build-lock", str(REPO_ROOT / "requirements-build.lock"),
                "--runtime-lock", str(REPO_ROOT / "requirements-runtime.lock"),
                "--ci-lock", str(REPO_ROOT / "requirements-ci.lock"),
                "--workflow-dir", str(REPO_ROOT / ".github" / "workflows"),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_knowledge_setup_source_and_schema_pass_audit(self) -> None:
        result = self._run(
            "--path",
            "src/ei/knowledge_setup.py",
            "--path",
            "schemas/knowledge-setup-operation.schema.json",
            "--json",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["scanned_paths"], 2)

    def test_personal_team_sources_pass_production_audit(self) -> None:
        result = self._run(
            "--path",
            "src/ei/team_store.py",
            "--path",
            "src/ei/team_projection.py",
            "--path",
            "src/ei/installer.py",
            "--json",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["scanned_paths"], 3)

    def test_empty_pass_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.py"
            bad.write_text("def unfinished():\n    pass\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo",
                    str(root),
                    "--path",
                    str(bad),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("EMPTY_PASS", result.stdout)

    def test_forbidden_workspace_and_credential_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.py"
            forbidden_path = "G:" + chr(92) + "unrelated-workspace" + chr(92) + "private-data"
            bad.write_text(
                "value = " + chr(34) + forbidden_path + chr(34) + "\n"
                + "api_key = " + chr(34) + "aaaaaaaaaaaaaaaaaaaaaaaa" + chr(34) + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo",
                    str(root),
                    "--path",
                    str(bad),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FORBIDDEN_WORKSPACE_PATH", result.stdout)
            self.assertIn("POSSIBLE_CREDENTIAL_LITERAL", result.stdout)


if __name__ == "__main__":
    unittest.main()

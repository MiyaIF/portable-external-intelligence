from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

from ei.cli import EXIT_OK, main
from ei.public_export import select_public_paths
from ei.workflow_security import audit_workflows


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"


class PublicWorkflowAcceptanceTests(unittest.TestCase):
    def test_public_docs_contain_only_public_cli_names_and_placeholders(self) -> None:
        root = Path(__file__).resolve().parents[2]
        paths = [
            root / "README.md",
            *(root / "docs" / name for name in (
                "setup.md",
                "update.md",
                "uninstall.md",
                "cli-reference.md",
                "compatibility.md",
                "architecture.md",
                "security-and-privacy.md",
            )),
        ]
        documents = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertNotIn("codex-app", documents.casefold())
        path_markers = (
            "/" + "Users" + "/",
            "/" + "home" + "/",
            "C:" + "\\" + "Users" + "\\",
            "C:/" + "Users" + "/",
        )
        for marker in path_markers:
            self.assertNotIn(marker, documents)
        self.assertNotRegex(documents, r"(?i)(?:team approval|official rules|公式ルール|チーム承認)")
        self.assertNotIn("real-host-certification", documents)
        for host_id in ("codex-cli", "claude-code", "gemini-cli", "qwen-code", "test-compatible-cli"):
            self.assertIn(host_id, documents)
        self.assertIn("scripts/setup.ps1", documents)
        self.assertIn("scripts/setup.sh", documents)

    def test_tracked_tree_has_no_unreviewed_secret_scanner_findings(self) -> None:
        tracked_result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(tracked_result.returncode, 0, tracked_result.stderr.decode("utf-8", "replace"))
        tracked = [item for item in tracked_result.stdout.decode("utf-8").split("\0") if item]
        allowlist = json.loads(
            (ROOT / "config" / "public-export-allowlist.json").read_text(encoding="utf-8")
        )
        selected = select_public_paths(tracked, allowlist)
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "detect_secrets", "scan", "--force-use-all-plugins", *selected],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload.get("results"), {})

    def test_only_hosted_public_workflows_are_active(self) -> None:
        names = sorted(path.name for path in WORKFLOW_ROOT.glob("*.y*ml"))
        self.assertEqual(
            names,
            ["ci.yml", "compatibility.yml", "package.yml", "release-attestation.yml", "security.yml"],
        )
        self.assertFalse((WORKFLOW_ROOT / "real-host-certification.yml").exists())
        result = audit_workflows(WORKFLOW_ROOT)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["findings"], [])

    def test_release_attestation_is_protected_and_uses_fixed_evidence_paths(self) -> None:
        text = (WORKFLOW_ROOT / "release-attestation.yml").read_text(encoding="utf-8")
        self.assertIn("environment: release", text)
        self.assertIn("EVIDENCE_COMMIT:", text)
        self.assertIn("--manifest release/evidence-manifest.json", text)
        self.assertIn("--prerequisites release/prerequisites.json", text)
        self.assertNotIn("--manifest \"$", text)
        self.assertNotIn("--prerequisites \"$", text)
        self.assertNotRegex(text, r"(?m)^\s*run:.*\$\{\{")

    def test_security_dependency_audit_targets_hash_locked_requirements(self) -> None:
        text = (WORKFLOW_ROOT / "security.yml").read_text(encoding="utf-8")
        for lock_name in (
            "requirements-build.lock",
            "requirements-runtime.lock",
            "requirements-ci.lock",
        ):
            self.assertIn(
                f"pip-audit --disable-pip --requirement {lock_name} --require-hashes",
                text,
            )

    def test_ruleset_status_contexts_are_emitted_by_summary_jobs(self) -> None:
        expected = {
            "ci.yml": ("ci", "unit-integration"),
            "compatibility.yml": ("compatibility", "compatibility"),
            "package.yml": ("package", "package"),
        }
        for workflow_name, (context, dependency) in expected.items():
            document = yaml.safe_load((WORKFLOW_ROOT / workflow_name).read_text(encoding="utf-8"))
            jobs = document["jobs"]
            summary = jobs[context + "-status"]
            self.assertEqual(summary["name"], context)
            self.assertEqual(summary["needs"], dependency)
            self.assertEqual(summary["if"], "${{ always() }}")
            self.assertEqual(summary["runs-on"], "ubuntu-latest")
            self.assertLessEqual(summary["timeout-minutes"], 2)

    def test_private_certification_template_is_never_activated_or_exported(self) -> None:
        relative_template = "ops-private-template/real-host-certification.yml"
        allowlist = json.loads(
            (ROOT / "config" / "public-export-allowlist.json").read_text(encoding="utf-8")
        )
        candidates = [*allowlist["required_paths"], relative_template]
        selected = select_public_paths(candidates, allowlist)
        self.assertNotIn(relative_template, selected)
        self.assertNotIn("real-host-certification.yml", [path.name for path in WORKFLOW_ROOT.iterdir()])

    def test_cli_workflow_verifier_returns_machine_readable_pass(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["public-release", "workflows", "verify", "--workflow-dir", str(WORKFLOW_ROOT), "--json"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "passed")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ei.public_export import load_public_export_allowlist, select_public_paths


class PublicRepositoryAuditAcceptanceTests(unittest.TestCase):
    def test_public_document_paths_are_selected_for_public_audit(self) -> None:
        source_root = Path(__file__).resolve().parents[2]
        allowlist = load_public_export_allowlist(source_root / "config" / "public-export-allowlist.json")
        tracked_public_paths = [
            "README.md",
            *("docs/" + name for name in (
                "setup.md",
                "update.md",
                "uninstall.md",
                "cli-reference.md",
                "compatibility.md",
                "architecture.md",
                "security-and-privacy.md",
            )),
        ]
        candidates = list(allowlist["required_paths"]) + tracked_public_paths
        selected = set(select_public_paths(candidates, allowlist))
        self.assertTrue(set(tracked_public_paths).issubset(selected))

    def test_current_public_source_tree_passes_without_reachable_private_history(self) -> None:
        source_root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [
                sys.executable,
                str(source_root / "scripts" / "audit-public-release.py"),
                "--repo",
                str(source_root),
                "--policy",
                str(source_root / "release" / "publication-policy.json"),
                "--working-tree",
                "--json",
            ],
            cwd=source_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "passed")

    def test_audit_cli_emits_machine_readable_check_contract(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ei-public-audit-cli-"))
        source_root = Path(__file__).resolve().parents[2]
        policy = source_root / "tests" / "fixtures" / "publication-policy.valid.json"
        (root / "LICENSE").write_text("Apache License\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(source_root / "scripts" / "audit-public-release.py"),
                "--repo", str(root),
                "--policy", str(policy),
                "--working-tree",
                "--json",
            ],
            cwd=source_root,
            capture_output=True,
            text=True,
        )
        self.assertIn(result.returncode, (0, 1))
        value = json.loads(result.stdout)
        self.assertIn(value["status"], {"passed", "failed"})
        self.assertIn("checks", value)
        self.assertIn("report_digest", value)


if __name__ == "__main__":
    unittest.main()

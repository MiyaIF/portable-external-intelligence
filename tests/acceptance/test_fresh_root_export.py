from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ei.public_export import validate_public_export_receipt


class FreshRootExportAcceptanceTests(unittest.TestCase):
    def test_cli_creates_path_free_fresh_root_without_private_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-fresh-root-") as tmp:
            root = Path(tmp)
            source = root / "development"
            source.mkdir()
            (source / "src").mkdir()
            (source / "LICENSE").write_text("Apache License\n", encoding="utf-8")
            (source / "README.md").write_text("public\n", encoding="utf-8")
            (source / "src" / "engine.py").write_text("VALUE = 1\n", encoding="utf-8")
            (source / "private.txt").write_text("must not leave development root\n", encoding="utf-8")
            policy = source / "policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "license_spdx": "Apache-2.0",
                        "copyright_holder": "Fixture",
                        "public_author": {"name": "Fixture", "email": "12345678+fixture-author@users.noreply.github.com"},
                        "github": {"owner": "fixture-owner", "repository": "fixture-repository", "default_branch": "main"},
                        "security_reporting": {"type": "github_private_vulnerability_reporting", "url": "https://github.com/fixture-owner/fixture-repository/security/advisories/new", "acknowledgement_days": 7, "triage_days": 14},
                        "contribution_policy": {"issues": True, "pull_requests": True, "dco_required": True, "cla_required": False, "response_sla_days": None, "merge_guarantee": False, "bug_bounty": False},
                        "initial_version": "1.0.0",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            allowlist = source / "allowlist.json"
            allowlist.write_text(
                json.dumps(
                    {"schema_version": 1, "include": ["LICENSE", "README.md", "src/**/*.py"], "exclude": [], "text_suffixes": [".md", ".py"], "executable_patterns": [], "required_paths": ["LICENSE", "README.md"]},
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "--quiet", str(source)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "Development"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "development@example.invalid"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(source), "add", "--all"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(source), "commit", "--quiet", "-m", "development"], check=True, capture_output=True, env={**os.environ, "GIT_AUTHOR_DATE": "2026-08-28T00:00:00Z", "GIT_COMMITTER_DATE": "2026-08-28T00:00:00Z"})
            destination = root / "public export"
            receipt = root / "receipt.json"
            command = [sys.executable, str(Path(__file__).resolve().parents[2] / "scripts" / "create-public-export.py"), "--source", str(source), "--destination", str(destination), "--policy", str(policy), "--allowlist", str(allowlist), "--receipt", str(receipt), "--skip-validation", "--no-repeat-check", "--json"]
            result = subprocess.run(command, cwd=source, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(receipt.read_text(encoding="utf-8"))
            validate_public_export_receipt(value)
            self.assertEqual(value["status"], "exported_unvalidated")
            self.assertEqual(value["root_commit_count"], 1)
            self.assertFalse((destination / "private.txt").exists())
            exported_files = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
            self.assertFalse(any(name.startswith(("team-cache/", "team-outbox/", "team-identities/")) for name in exported_files))
            self.assertNotIn(str(source), receipt.read_text(encoding="utf-8"))
            self.assertEqual(subprocess.run(["git", "-C", str(destination), "rev-list", "--count", "--all"], check=True, capture_output=True, text=True).stdout.strip(), "1")


if __name__ == "__main__":
    unittest.main()

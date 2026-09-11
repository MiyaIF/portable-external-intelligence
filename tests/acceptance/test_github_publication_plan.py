from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ei.github_publication import _readme_quick_start, validate_publication_record


class GithubPublicationPlanAcceptanceTests(unittest.TestCase):
    def test_repository_readme_satisfies_the_published_quick_start_contract(self) -> None:
        root = Path(__file__).resolve().parents[2]

        self.assertTrue(
            _readme_quick_start(
                root,
                "https://github.com/MiyaIF/portable-external-intelligence",
            )
        )

    def _source(self, root: Path) -> Path:
        source = root / "public-export"
        (source / "src").mkdir(parents=True)
        (source / "LICENSE").write_text("Apache License\n", encoding="utf-8")
        (source / "README.md").write_text("# Public export\n", encoding="utf-8")
        (source / "src" / "engine.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "Fixture Author"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "config", "user.email", "12345678+fixture-author@users.noreply.github.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "--all"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "--quiet", "-m", "public export"],
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_AUTHOR_DATE": "2026-08-28T00:00:00Z", "GIT_COMMITTER_DATE": "2026-08-28T00:00:00Z"},
        )
        return source

    def _policy(self, root: Path) -> Path:
        path = root / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "license_spdx": "Apache-2.0",
                    "copyright_holder": "Fixture Copyright",
                    "public_author": {"name": "Fixture Author", "email": "12345678+fixture-author@users.noreply.github.com"},
                    "github": {"owner": "fixture-owner", "repository": "fixture-repository", "default_branch": "main"},
                    "security_reporting": {
                        "type": "github_private_vulnerability_reporting",
                        "url": "https://github.com/fixture-owner/fixture-repository/security/advisories/new",
                        "acknowledgement_days": 7,
                        "triage_days": 14,
                    },
                    "contribution_policy": {
                        "issues": True,
                        "pull_requests": True,
                        "dco_required": True,
                        "cla_required": False,
                        "response_sla_days": None,
                        "merge_guarantee": False,
                        "bug_bounty": False,
                    },
                    "initial_version": "1.0.0",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_offline_plan_never_mutates_or_claims_target_absence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-plan-cli-") as tmp:
            root = Path(tmp)
            source = self._source(root)
            policy = self._policy(root)
            output = root / "plan.json"
            script = Path(__file__).resolve().parents[2] / "scripts" / "configure-public-github.py"
            result = subprocess.run(
                [sys.executable, str(script), "plan", "--source", str(source), "--policy", str(policy), "--output", str(output), "--offline"],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            plan = json.loads(output.read_text(encoding="utf-8"))
            validate_publication_record(plan)
            self.assertEqual(plan["status"], "blocked")
            self.assertEqual(plan["target_observation"]["status"], "unknown")
            self.assertFalse(plan["mutations_performed"])
            self.assertEqual(subprocess.run(["git", "-C", str(source), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout, "")
            self.assertFalse((root / "fixture-repository").exists())


if __name__ == "__main__":
    unittest.main()

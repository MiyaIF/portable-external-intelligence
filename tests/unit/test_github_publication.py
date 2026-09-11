from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.github_publication import (
    GithubPublicationError,
    _readme_quick_start,
    _ruleset_api_payload,
    build_publication_plan,
    confirm_plan,
    validate_publication_record,
)


def _policy() -> dict[str, object]:
    return {
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
    }


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def _source(root: Path) -> Path:
    source = root / "source"
    (source / "src").mkdir(parents=True)
    (source / ".github" / "workflows").mkdir(parents=True)
    (source / "LICENSE").write_text("Apache License\n", encoding="utf-8")
    (source / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (source / "src" / "engine.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / ".github" / "workflows" / "ci.yml").write_text("name: CI\n\non:\n  push:\n\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Fixture Author")
    _git(source, "config", "user.email", "12345678+fixture-author@users.noreply.github.com")
    _git(source, "add", "--all")
    _git(
        source,
        "commit",
        "--quiet",
        "-m",
        "public fixture",
        env={**os.environ, "GIT_AUTHOR_DATE": "2026-08-28T00:00:00Z", "GIT_COMMITTER_DATE": "2026-08-28T00:00:00Z"},
    )
    return source


class GithubPublicationTests(unittest.TestCase):
    def test_readme_quick_start_requires_one_shot_wrappers_and_all_knowledge_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-readme-") as tmp:
            root = Path(tmp)
            repository_url = "https://github.com/fixture-owner/fixture-repository"
            (root / "README.md").write_text(
                "\n".join(
                    (
                        "git clone " + repository_url + ".git",
                        r".\scripts\setup.ps1",
                        "sh scripts/setup.sh",
                        "local github-new github-existing",
                        "No second initialization command is part of the normal journey.",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertTrue(_readme_quick_start(root, repository_url))

            (root / "README.md").write_text(
                "\n".join(
                    (
                        "git clone " + repository_url + ".git",
                        r".\scripts\setup.ps1",
                        "sh scripts/setup.sh",
                        "local github-new github-existing",
                        "No second",
                        "initialization command is part of the normal journey.",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertTrue(_readme_quick_start(root, repository_url))

            (root / "README.md").write_text(
                "git clone " + repository_url + ".git\nknowledge init\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_README_QUICK_START_INVALID"):
                _readme_quick_start(root, repository_url)

    def test_plan_is_read_only_and_contains_guarded_settings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-") as tmp:
            source = _source(Path(tmp))
            policy = _policy()
            plan = build_publication_plan(
                source,
                policy,
                target_observation={"status": "not_found", "method": "fixture_observation"},
                generated_at="2026-08-28T00:00:00Z",
            )
            validate_publication_record(plan)
            self.assertEqual(plan["status"], "ready_for_confirmation")
            self.assertEqual(plan["default_branch"], "main")
            self.assertEqual(plan["root_commit_count"], 1)
            self.assertFalse(plan["mutations_performed"])
            self.assertEqual(plan["external_mutations"], [])
            self.assertEqual(plan["feature_states"]["visibility"], "public")
            self.assertFalse(plan["feature_states"]["self_hosted_runner_registered"])
            self.assertEqual(subprocess.run(["git", "-C", str(source), "rev-list", "--all", "--count"], check=True, capture_output=True, text=True).stdout.strip(), "1")

    def test_ruleset_requires_pr_and_checks_without_solo_maintainer_lockout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-ruleset-") as tmp:
            plan = build_publication_plan(
                _source(Path(tmp)),
                _policy(),
                target_observation={"status": "not_found", "method": "fixture_observation"},
                generated_at="2026-08-28T00:00:00Z",
            )
            rules = plan["ruleset"]
            self.assertEqual(rules["required_approving_review_count"], 0)
            self.assertFalse(rules["require_code_owner_reviews"])

            payload = _ruleset_api_payload(rules)
            rule_types = [rule["type"] for rule in payload["rules"]]
            self.assertIn("pull_request", rule_types)
            self.assertIn("required_status_checks", rule_types)
            self.assertIn("deletion", rule_types)
            self.assertIn("non_fast_forward", rule_types)
            pull_request = next(rule for rule in payload["rules"] if rule["type"] == "pull_request")
            self.assertEqual(pull_request["parameters"]["required_approving_review_count"], 0)
            self.assertFalse(pull_request["parameters"]["require_code_owner_review"])
            checks = next(rule for rule in payload["rules"] if rule["type"] == "required_status_checks")
            self.assertEqual(
                [item["context"] for item in checks["parameters"]["required_status_checks"]],
                rules["required_status_checks"],
            )

    def test_existing_target_blocks_confirmation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-conflict-") as tmp:
            plan = build_publication_plan(
                _source(Path(tmp)),
                _policy(),
                target_observation={"status": "exists", "method": "fixture_observation"},
                generated_at="2026-08-28T00:00:00Z",
            )
            self.assertEqual(plan["status"], "blocked")
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_PLAN_NOT_READY"):
                confirm_plan(plan, plan["plan_sha256"])

    def test_unknown_target_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-unknown-") as tmp:
            plan = build_publication_plan(
                _source(Path(tmp)),
                _policy(),
                target_observation={"status": "unknown", "method": "offline_no_network"},
                generated_at="2026-08-28T00:00:00Z",
            )
            self.assertEqual(plan["status"], "blocked")
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_PLAN_NOT_READY"):
                confirm_plan(plan, plan["plan_sha256"])

    def test_digest_confirmation_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-digest-") as tmp:
            plan = build_publication_plan(
                _source(Path(tmp)),
                _policy(),
                target_observation={"status": "not_found", "method": "fixture_observation"},
                generated_at="2026-08-28T00:00:00Z",
            )
            self.assertTrue(confirm_plan(plan, plan["plan_sha256"]))
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_PLAN_CONFIRMATION_MISMATCH"):
                confirm_plan(plan, "sha256:" + "0" * 64)
            tampered = dict(plan)
            tampered["external_mutations"] = ["unexpected_mutation"]
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_RECEIPT_HASH_MISMATCH"):
                validate_publication_record(tampered)

    def test_dirty_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-github-publication-dirty-") as tmp:
            source = _source(Path(tmp))
            (source / "README.md").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_SOURCE_WORKTREE_DIRTY"):
                build_publication_plan(source, _policy(), target_observation={"status": "unknown", "method": "fixture"})


if __name__ == "__main__":
    unittest.main()

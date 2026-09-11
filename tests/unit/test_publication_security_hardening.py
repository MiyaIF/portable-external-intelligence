from __future__ import annotations

import os
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.github_publication as github_publication
from ei.public_export import PublicExportError, _validation_environment, create_public_export
from ei.github_publication import GithubPublicationError, build_publication_plan
from ei.publication_audit import audit_repository
from ei.publication_policy import load_publication_policy


class PublicationSecurityHardeningTests(unittest.TestCase):
    def _directory_link(self, link: Path, target: Path) -> None:
        if os.name == "nt":
            result = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                self.skipTest("directory junction fixture unavailable")
            return
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink fixture unavailable")

    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    def _source(self, root: Path, relative: str, content: bytes) -> Path:
        source = root / "source"
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        (source / "README.md").write_text("public\n", encoding="utf-8")
        (source / "LICENSE").write_text("Apache License\n", encoding="utf-8")
        target.write_bytes(content)
        self._git(source, "init", "--quiet")
        self._git(source, "config", "user.name", "Fixture Author")
        self._git(source, "config", "user.email", "12345678+fixture-author@users.noreply.github.com")
        self._git(source, "add", "--all")
        self._git(source, "commit", "--quiet", "-m", "public fixture")
        return source

    def _allowlist(self, root: Path) -> Path:
        path = root / "allowlist.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "include": ["**"],
                    "exclude": [],
                    "text_suffixes": [".md", ".key"],
                    "executable_patterns": [],
                    "required_paths": ["README.md"],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_private_key_material_is_rejected_before_selected_file_copy(self) -> None:
        markers = (
            b"-----" + b"BEGIN RSA PRIVATE KEY-----\nkey\n" + b"-----" + b"END RSA PRIVATE KEY-----\n",  # pragma: allowlist secret
            b"-----" + b"BEGIN OPENSSH PRIVATE KEY-----\nkey\n" + b"-----" + b"END OPENSSH PRIVATE KEY-----\n",  # pragma: allowlist secret
            b"-----" + b"BEGIN PGP PRIVATE KEY BLOCK-----\nkey\n" + b"-----" + b"END PGP PRIVATE KEY BLOCK-----\n",  # pragma: allowlist secret
        )
        policy = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json"
        for marker in markers:
            with self.subTest(marker=marker.split(b"-----", 2)[1]):
                with tempfile.TemporaryDirectory(prefix="ei-public-key-guard-") as tmp:
                    root = Path(tmp)
                    source = self._source(root, "keys/private.key", marker)
                    destination = root / "public"
                    with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_PRIVATE_KEY_DETECTED"):
                        create_public_export(
                            source,
                            destination,
                            policy_path=policy,
                            allowlist_path=self._allowlist(root),
                            validate=False,
                        )
                    self.assertFalse((destination / "keys" / "private.key").exists())

    def test_subject_commit_sha_is_required_canonical_and_equal_to_head(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-subject-sha-guard-") as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "LICENSE").write_text("Apache License\n", encoding="utf-8")
            (root / "README.md").write_text("public\n", encoding="utf-8")
            self._git(root, "init", "--quiet")
            self._git(root, "config", "user.name", "Fixture Author")
            self._git(root, "config", "user.email", "12345678+fixture-author@users.noreply.github.com")
            self._git(root, "add", "--all")
            self._git(root, "commit", "--quiet", "-m", "public fixture")
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            manifest = root / "release" / "evidence-manifest.json"
            manifest.parent.mkdir()
            policy = load_publication_policy(Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json")

            for subject, check_id in ((None, "EVIDENCE_SHA_INVALID"), ("A" * 40, "EVIDENCE_SHA_INVALID"), ("0" * 40, "EVIDENCE_SHA_STALE")):
                with self.subTest(subject=subject):
                    manifest.write_text(json.dumps({"subject_commit_sha": subject}), encoding="utf-8")
                    result = audit_repository(root, policy, working_tree=True)
                    failures = {item.check_id for item in result.checks if item.status == "failed"}
                    self.assertIn(check_id, failures)

            manifest.write_text(json.dumps({"subject_commit_sha": head}), encoding="utf-8")
            self.assertTrue(audit_repository(root, policy, working_tree=True).passed)

            no_head = Path(tmp) / "no-head"
            no_head.mkdir()
            (no_head / "LICENSE").write_text("Apache License\n", encoding="utf-8")
            (no_head / "README.md").write_text("public\n", encoding="utf-8")
            no_head_manifest = no_head / "release" / "evidence-manifest.json"
            no_head_manifest.parent.mkdir()
            no_head_manifest.write_text(json.dumps({"subject_commit_sha": head}), encoding="utf-8")
            no_head_result = audit_repository(no_head, policy, working_tree=True)
            no_head_failures = {item.check_id for item in no_head_result.checks if item.status == "failed"}
            self.assertIn("EVIDENCE_HEAD_INVALID", no_head_failures)

    def test_github_mutation_requires_exact_repository_security_and_ruleset_readback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-readback-guard-") as tmp:
            root = Path(tmp)
            source = self._source(root, "src/engine.py", b"VALUE = 1\n")
            policy = load_publication_policy(Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json")
            plan = build_publication_plan(
                source,
                policy,
                target_observation={"status": "not_found", "method": "fixture"},
                generated_at="2026-08-28T00:00:00Z",
            )
            owner = str(plan["owner"])
            repository = str(plan["repository"])
            repo_endpoint = f"repos/{owner}/{repository}"
            rules = dict(plan["ruleset"])
            settings = dict(plan["settings"])
            security = dict(settings["security_and_analysis"])
            repository_api_security = {
                key: {"status": security[key]}
                for key in ("secret_scanning", "secret_scanning_push_protection")
            }
            repository_readback = {
                "name": repository,
                "full_name": f"{owner}/{repository}",
                "private": False,
                "visibility": "public",
                "default_branch": "main",
                "has_issues": settings["has_issues"],
                "has_projects": settings["has_projects"],
                "has_wiki": settings["has_wiki"],
                "has_discussions": settings["has_discussions"],
                "security_and_analysis": repository_api_security,
            }
            ruleset_detail = {
                "id": 7,
                "name": rules["name"],
                "target": "branch",
                "enforcement": "active",
                "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
                "rules": [
                    {"type": "deletion"},
                    {"type": "non_fast_forward"},
                    {
                        "type": "pull_request",
                        "parameters": {
                            "required_approving_review_count": rules["required_approving_review_count"],
                            "dismiss_stale_reviews_on_push": rules["dismiss_stale_reviews"],
                            "require_code_owner_review": rules["require_code_owner_reviews"],
                            "require_last_push_approval": False,
                            "required_review_thread_resolution": False,
                            "allowed_merge_methods": ["merge", "squash", "rebase"],
                            "required_reviewers": [],
                            "require_extra_approval_for_unattributed_changes": True,
                        },
                    },
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [{"context": name} for name in rules["required_status_checks"]],
                            "strict_required_status_checks_policy": True,
                            "do_not_enforce_on_create": True,
                        },
                    },
                ],
                "bypass_actors": [],
            }

            def responses(bad: str | None = None) -> tuple[list[tuple[str, str]], list[tuple[str, str, object]], object]:
                calls: list[tuple[str, str]] = []
                mutations: list[tuple[str, str, object]] = []
                repository_value = json.loads(json.dumps(repository_readback))
                security_value = {"enabled": True, "paused": False}
                private_reporting_value = {"enabled": True}
                code_scanning_value = {"state": "configured"}
                ruleset_value = json.loads(json.dumps(ruleset_detail))
                if bad == "repository":
                    repository_value["visibility"] = "private"
                elif bad == "repository_type":
                    repository_value["has_issues"] = 1
                elif bad == "security":
                    repository_value["security_and_analysis"]["secret_scanning"]["status"] = "disabled"
                elif bad == "security_type":
                    security_value = {"enabled": 1, "paused": False}
                elif bad == "private_reporting":
                    private_reporting_value = {"enabled": False}
                elif bad == "ruleset":
                    ruleset_value["enforcement"] = "evaluate"
                elif bad == "ruleset_type":
                    ruleset_value["rules"][2]["parameters"]["required_approving_review_count"] = True

                def api(endpoint: str, *, method: str = "GET", payload: object = None, timeout: float = 120.0) -> object:
                    del timeout
                    calls.append((method, endpoint))
                    if method != "GET":
                        mutations.append((method, endpoint, payload))
                    if endpoint == f"users/{owner}":
                        return {"type": "User"}
                    if endpoint == "user/repos" and method == "POST":
                        return {"full_name": f"{owner}/{repository}", "private": False}
                    if endpoint == repo_endpoint and method == "GET":
                        return repository_value
                    if endpoint == f"{repo_endpoint}/vulnerability-alerts" and method == "GET":
                        return {}
                    if endpoint == f"{repo_endpoint}/private-vulnerability-reporting" and method == "GET":
                        return private_reporting_value
                    if endpoint == f"{repo_endpoint}/automated-security-fixes" and method == "GET":
                        return security_value
                    if endpoint == f"{repo_endpoint}/code-scanning/default-setup" and method == "GET":
                        return code_scanning_value
                    if endpoint == f"{repo_endpoint}/rulesets" and method == "GET":
                        return [{"id": 7, "name": rules["name"], "target": "branch", "enforcement": "active"}]
                    if endpoint == f"{repo_endpoint}/rulesets/7" and method == "GET":
                        return ruleset_value
                    return {}

                return calls, mutations, api

            calls, mutations, api = responses()
            with patch.object(github_publication, "_gh_api", side_effect=api):
                github_publication._create_repository(plan)
            repository_patch = next(
                payload
                for method, endpoint, payload in mutations
                if method == "PATCH" and endpoint == repo_endpoint
            )
            self.assertEqual(
                repository_patch["security_and_analysis"],
                {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            )
            ruleset_post = next(
                payload
                for method, endpoint, payload in mutations
                if method == "POST" and endpoint == f"{repo_endpoint}/rulesets"
            )
            pull_request_rule = next(rule for rule in ruleset_post["rules"] if rule["type"] == "pull_request")
            self.assertFalse(pull_request_rule["parameters"]["required_review_thread_resolution"])
            self.assertEqual(pull_request_rule["parameters"]["allowed_merge_methods"], ["merge", "squash", "rebase"])
            status_rule = next(rule for rule in ruleset_post["rules"] if rule["type"] == "required_status_checks")
            self.assertEqual(
                status_rule["parameters"]["required_status_checks"],
                [{"context": name} for name in rules["required_status_checks"]],
            )
            self.assertTrue(status_rule["parameters"]["do_not_enforce_on_create"])
            self.assertIn(("PUT", f"{repo_endpoint}/private-vulnerability-reporting"), calls)
            for endpoint in (
                repo_endpoint,
                f"{repo_endpoint}/vulnerability-alerts",
                f"{repo_endpoint}/private-vulnerability-reporting",
                f"{repo_endpoint}/automated-security-fixes",
                f"{repo_endpoint}/code-scanning/default-setup",
                f"{repo_endpoint}/rulesets",
                f"{repo_endpoint}/rulesets/7",
            ):
                self.assertIn(("GET", endpoint), calls)

            for bad, code in (
                ("repository", "GITHUB_PUBLICATION_REPOSITORY_READBACK_MISMATCH"),
                ("repository_type", "GITHUB_PUBLICATION_REPOSITORY_READBACK_MISMATCH"),
                ("security", "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH"),
                ("security_type", "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH"),
                ("private_reporting", "GITHUB_PUBLICATION_SECURITY_READBACK_MISMATCH"),
                ("ruleset", "GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH"),
                ("ruleset_type", "GITHUB_PUBLICATION_RULESET_READBACK_MISMATCH"),
            ):
                _, _, api = responses(bad)
                with self.subTest(bad=bad), patch.object(github_publication, "_gh_api", side_effect=api):
                    with self.assertRaisesRegex(GithubPublicationError, code):
                        github_publication._create_repository(plan)

    def test_publication_requires_an_independent_approval_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-approval-guard-") as tmp:
            root = Path(tmp)
            source = self._source(root, "src/engine.py", b"VALUE = 1\n")
            policy_path = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json"
            policy = load_publication_policy(policy_path)
            plan = build_publication_plan(
                source,
                policy,
                target_observation={"status": "not_found", "method": "fixture"},
                generated_at="2026-08-28T00:00:00Z",
            )
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
            script = Path(__file__).resolve().parents[2] / "scripts" / "configure-public-github.py"
            same_file = subprocess.run(
                [
                    os.fspath(Path(sys.executable)),
                    os.fspath(script),
                    "apply",
                    "--source",
                    os.fspath(source),
                    "--policy",
                    os.fspath(policy_path),
                    "--plan",
                    os.fspath(plan_path),
                    "--approval",
                    os.fspath(plan_path),
                    "--output",
                    os.fspath(root / "same-file-receipt.json"),
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(same_file.returncode, 1)
            self.assertIn("GITHUB_PUBLICATION_APPROVAL_MUST_BE_SEPARATE", same_file.stdout)
            old_flag = subprocess.run(
                [
                    os.fspath(Path(sys.executable)),
                    os.fspath(script),
                    "apply",
                    "--source",
                    os.fspath(source),
                    "--policy",
                    os.fspath(policy_path),
                    "--plan",
                    os.fspath(plan_path),
                    "--confirm-plan-digest-from-file",
                    "--output",
                    os.fspath(root / "receipt.json"),
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(old_flag.returncode, 2)

            approval_basis = {
                "approval_type": "github_publication_approval",
                "schema_version": 1,
                "plan_sha256": plan["plan_sha256"],
                "approved_at": "2026-08-28T00:00:00Z",
            }
            approval = dict(approval_basis)
            approval["approval_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(approval_basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.assertTrue(github_publication.confirm_plan_approval(plan, approval))
            wrong_schema_type = dict(approval_basis)
            wrong_schema_type["schema_version"] = True
            wrong_schema = dict(wrong_schema_type)
            wrong_schema["approval_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(wrong_schema_type, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_APPROVAL_TYPE_INVALID"):
                github_publication.confirm_plan_approval(plan, wrong_schema)
            broken = dict(approval)
            broken["approval_sha256"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_APPROVAL_HASH_MISMATCH"):
                github_publication.confirm_plan_approval(plan, broken)

            with self.assertRaisesRegex(GithubPublicationError, "GITHUB_PUBLICATION_APPROVAL_ARTIFACT_REQUIRED"):
                github_publication.publish_publication_plan(
                    source,
                    plan,
                    policy=policy,
                    confirmed_plan_sha256=plan["plan_sha256"],
                )

    def test_publication_source_and_cli_output_reject_directory_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-publication-reparse-") as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            source = self._source(actual, "src/engine.py", b"VALUE = 1\n")
            linked = root / "linked"
            self._directory_link(linked, actual)
            policy_path = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json"
            policy = load_publication_policy(policy_path)
            with self.assertRaisesRegex(GithubPublicationError, "UNSAFE_REPARSE_POINT"):
                build_publication_plan(
                    linked / source.name,
                    policy,
                    target_observation={"status": "not_found", "method": "fixture"},
                    generated_at="2026-08-28T00:00:00Z",
                )

            output_target = root / "output-target"
            output_target.mkdir()
            output_link = root / "output-link"
            self._directory_link(output_link, output_target)
            script = Path(__file__).resolve().parents[2] / "scripts" / "configure-public-github.py"
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(script),
                    "plan",
                    "--source",
                    os.fspath(source),
                    "--policy",
                    os.fspath(policy_path),
                    "--output",
                    os.fspath(output_link / "plan.json"),
                    "--offline",
                    "--generated-at",
                    "2026-08-28T00:00:00Z",
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("UNSAFE_REPARSE_POINT", result.stdout)
            self.assertFalse((output_target / "plan.json").exists())

    def test_validation_environment_uses_only_safe_cross_platform_keys(self) -> None:
        destination = Path("C:/temporary/public-export")
        private_home = str(Path("C:/") / "Users" / "private-user")
        inherited = {
            "PATH": "safe-path",
            "PATHEXT": ".COM;.EXE",
            "SystemRoot": "C:/Windows",
            "USERNAME": "validation-user",
            "USERDOMAIN": "VALIDATION-DOMAIN",
            "PYTHONPATH": "C:/private/inherited",
            "PYTHONHOME": "C:/private/python",
            "GH_TOKEN": "token-value",
            "GITHUB_TOKEN": "token-value",
            "AWS_SECRET_ACCESS_KEY": "secret-value",  # pragma: allowlist secret
            "HOME": private_home,
            "USERPROFILE": private_home,
            "PIP_INDEX_URL": "https://user:password@example.invalid/simple",  # pragma: allowlist secret
        }
        with patch.dict(os.environ, inherited, clear=True):
            environment = _validation_environment(destination)

        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "USERNAME",
            "USERDOMAIN",
            "PYTHONPATH",
            "PYTHONDONTWRITEBYTECODE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GIT_OPTIONAL_LOCKS",
        }
        self.assertTrue(set(environment).issubset(allowed))
        self.assertEqual(environment["PATH"], "safe-path")
        self.assertEqual(environment["USERNAME"], "validation-user")
        self.assertEqual(environment["USERDOMAIN"], "VALIDATION-DOMAIN")
        self.assertEqual(
            environment["PYTHONPATH"],
            os.pathsep.join((str(destination / "src"), str(destination))),
        )
        for forbidden in ("GH_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "HOME", "USERPROFILE", "PYTHONHOME", "PIP_INDEX_URL"):
            self.assertNotIn(forbidden, environment)


if __name__ == "__main__":
    unittest.main()

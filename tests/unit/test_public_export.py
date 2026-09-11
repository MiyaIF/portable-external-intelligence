from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.public_export as public_export
from ei.public_export import (
    PublicExportError,
    _verify_resumable_export,
    allowlist_digest,
    create_public_export,
    resume_public_export_validation,
    run_public_export_validation,
    select_public_paths,
    validate_public_export_receipt,
)
from ei.publication_policy import load_publication_policy


class PublicExportTests(unittest.TestCase):
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

    def _policy(self, root: Path) -> Path:
        path = root / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "license_spdx": "Apache-2.0",
                    "copyright_holder": "Fixture",
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
            newline="\n",
        )
        return path

    def _allowlist(self, root: Path) -> Path:
        path = root / "allowlist.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "include": ["LICENSE", "README.md", "src/**/*.py", "scripts/**/*.sh"],
                    "exclude": ["src/private/**"],
                    "text_suffixes": [".md", ".py", ".sh"],
                    "executable_patterns": ["scripts/**/*.sh"],
                    "required_paths": ["LICENSE", "README.md"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def _source(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "source"
        source.mkdir()
        (source / "src" / "private").mkdir(parents=True)
        (source / "scripts").mkdir()
        (source / "LICENSE").write_text("Apache License\r\n", encoding="utf-8", newline="")
        (source / "README.md").write_text("public\r\n", encoding="utf-8", newline="")
        (source / "src" / "rule.py").write_text("RULE = 'safe'\r\n", encoding="utf-8", newline="")
        (source / "src" / "private" / "secret.py").write_text("PRIVATE = True\n", encoding="utf-8")
        (source / "scripts" / "check.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        (source / "unlisted.txt").write_text("must not be copied\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "Development"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "config", "user.email", "development@example.invalid"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "--all"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "--quiet", "-m", "development"],
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_AUTHOR_DATE": "2026-08-28T00:00:00Z", "GIT_COMMITTER_DATE": "2026-08-28T00:00:00Z"},
        )
        return source, self._policy(root), self._allowlist(root)

    def test_allowlist_selection_and_digest_are_canonical(self) -> None:
        allowlist = {
            "schema_version": 1,
            "include": ["src/**/*.py", "README.md"],
            "exclude": ["src/private/**"],
            "text_suffixes": [".py", ".md"],
            "executable_patterns": [],
            "required_paths": ["README.md"],
        }
        selected = select_public_paths(["README.md", "src/rule.py", "src/private/secret.py"], allowlist)
        self.assertEqual(selected, ("README.md", "src/rule.py"))
        self.assertEqual(allowlist_digest(allowlist), allowlist_digest(dict(reversed(list(allowlist.items())))))

    def test_export_creates_one_clean_owner_authored_root_and_normalizes_text(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-test-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            destination = root / "public root 日本語"
            result = create_public_export(source, destination, policy_path=policy, allowlist_path=allowlist, validate=False)
            self.assertEqual(result.receipt["status"], "exported_unvalidated")
            self.assertEqual(result.receipt["root_commit_count"], 1)
            self.assertTrue((destination / "LICENSE").read_bytes().endswith(b"\n"))
            self.assertNotIn(b"\r", (destination / "LICENSE").read_bytes())
            self.assertFalse((destination / "src" / "private" / "secret.py").exists())
            self.assertFalse((destination / "unlisted.txt").exists())
            validate_public_export_receipt(result.receipt)
            log = subprocess.run(["git", "-C", str(destination), "log", "-1", "--format=%an <%ae>"], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(log, "Fixture Author <12345678+fixture-author@users.noreply.github.com>")
            count = subprocess.run(["git", "-C", str(destination), "rev-list", "--count", "--all"], check=True, capture_output=True, text=True).stdout.strip()
            self.assertEqual(count, "1")
            self.assertEqual(subprocess.run(["git", "-C", str(destination), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout, "")
            self.assertNotIn(str(source), json.dumps(result.receipt, ensure_ascii=False))

    def test_same_source_and_policy_produce_the_same_tree_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-deterministic-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            first = create_public_export(source, root / "one", policy_path=policy, allowlist_path=allowlist, validate=False)
            second = create_public_export(source, root / "two", policy_path=policy, allowlist_path=allowlist, validate=False)
            self.assertEqual(first.receipt["public_tree_id"], second.receipt["public_tree_id"])
            self.assertEqual(first.receipt["public_tree_sha256"], second.receipt["public_tree_sha256"])
            self.assertEqual(first.receipt["public_root_sha"], second.receipt["public_root_sha"])

    def test_export_reads_committed_blobs_when_worktree_changes_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-race-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            destination = root / "public"
            original_tracked_entries = public_export._tracked_entries

            def mutate_after_listing(candidate: Path):
                entries = original_tracked_entries(candidate)
                (candidate / "README.md").write_text("private replacement\n", encoding="utf-8")
                return entries

            with patch("ei.public_export._tracked_entries", side_effect=mutate_after_listing):
                create_public_export(
                    source,
                    destination,
                    policy_path=policy,
                    allowlist_path=allowlist,
                    validate=False,
                )

            self.assertEqual((destination / "README.md").read_text(encoding="utf-8"), "public\n")


    def test_validation_result_uses_the_receipt_status_contract(self) -> None:
        calls: list[tuple[list[str], object]] = []

        def fake_run(argv, **kwargs):
            command = [str(item) for item in argv]
            calls.append((command, kwargs.get("timeout")))
            if any(item.endswith("audit-public-release.py") for item in command):
                output = {"status": "passed", "report_digest": "sha256:" + "a" * 64}
            elif any(item.endswith("audit-production-source.py") for item in command):
                output = {"status": "passed", "report_digest": "sha256:" + "b" * 64}
            elif any(item.endswith("verify-dependency-lock.py") for item in command):
                return subprocess.CompletedProcess(command, 0, stdout=b"locks ok", stderr=b"")
            elif "workflows" in command:
                output = {"status": "passed", "workflow_sha256": "sha256:" + "c" * 64}
            elif any(item.endswith("certify-public-clone.py") for item in command):
                receipt_path = Path(command[command.index("--output") + 1])
                receipt_path.write_text(
                    json.dumps({"status": "PASSED", "receipt_sha256": "sha256:" + "d" * 64}),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
            else:
                self.fail(f"unexpected validation command: {command}")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(output).encode("utf-8"),
                stderr=b"",
            )

        with tempfile.TemporaryDirectory(prefix="ei-public-validation-contract-") as tmp:
            with patch("ei.public_export._run", side_effect=fake_run):
                result = run_public_export_validation(Path(tmp), python_executable=sys.executable)
        self.assertEqual(result["status"], "passed")
        certification_timeout = next(
            timeout
            for command, timeout in calls
            if any(item.endswith("certify-public-clone.py") for item in command)
        )
        self.assertIsInstance(certification_timeout, float)
        self.assertGreaterEqual(certification_timeout, 1800.0)

    def test_resume_validation_accepts_only_the_exact_clean_export(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-resume-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            destination = root / "public"
            receipt_path = root / "receipt.json"
            initial = create_public_export(
                source,
                destination,
                policy_path=policy,
                allowlist_path=allowlist,
                validate=False,
            )
            validation = {
                "status": "passed",
                "step_digests": {"clean_clone_certification": "sha256:" + "e" * 64},
            }
            with patch("ei.public_export.run_public_export_validation", return_value=validation):
                resumed = resume_public_export_validation(
                    source,
                    destination,
                    policy_path=policy,
                    allowlist_path=allowlist,
                    receipt_path=receipt_path,
                )
            self.assertEqual(resumed.receipt["status"], "validated")
            self.assertEqual(resumed.receipt["public_root_sha"], initial.receipt["public_root_sha"])
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), resumed.receipt)
            validate_public_export_receipt(resumed.receipt)

            (destination / "README.md").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_RESUME_DESTINATION_DIRTY"):
                resume_public_export_validation(
                    source,
                    destination,
                    policy_path=policy,
                    allowlist_path=allowlist,
                )

    def test_resume_validation_compares_repository_roots_canonically(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-root-alias-") as tmp:
            destination = Path(tmp) / "public"
            destination.mkdir()
            alias = destination.parent / "PUBLIC~1"
            expected = {
                "public_root_sha": "a" * 40,
                "public_tree_id": "b" * 40,
                "public_tree_sha256": "sha256:" + "c" * 64,
            }

            def fake_git(_repo, *arguments, **_kwargs):
                if arguments == ("rev-parse", "--show-toplevel"):
                    return str(alias).encode("utf-8")
                if arguments[0] == "status":
                    return b""
                if arguments == ("rev-list", "--count", "--all"):
                    return b"1\n"
                if arguments == ("rev-parse", "--verify", "HEAD"):
                    return ("a" * 40 + "\n").encode("ascii")
                self.fail(f"unexpected git arguments: {arguments}")

            def canonical_alias(value, *, require_exists=False):
                del require_exists
                candidate = Path(value)
                return destination if candidate in {destination, alias} else candidate.resolve()

            with patch("ei.public_export._git", side_effect=fake_git), patch(
                "ei.public_export._tree_id",
                return_value="b" * 40,
            ), patch(
                "ei.public_export._tree_listing_digest",
                return_value="sha256:" + "c" * 64,
            ), patch(
                "ei.public_export.canonical_path",
                side_effect=canonical_alias,
                create=True,
            ):
                _verify_resumable_export(destination, expected)

    def test_dirty_source_nonempty_destination_and_containment_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-guards-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "file").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_DESTINATION_NOT_EMPTY"):
                create_public_export(source, nonempty, policy_path=policy, allowlist_path=allowlist, validate=False)
            with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_DESTINATION_NOT_ISOLATED"):
                create_public_export(source, source / "nested", policy_path=policy, allowlist_path=allowlist, validate=False)
            (source / "README.md").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_SOURCE_WORKTREE_DIRTY"):
                create_public_export(source, root / "dirty", policy_path=policy, allowlist_path=allowlist, validate=False)

    def test_export_cli_rejects_source_and_receipt_paths_through_directory_links(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "create-public-export.py"
        with tempfile.TemporaryDirectory(prefix="ei-public-export-cli-reparse-") as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            source, policy, allowlist = self._source(actual)
            linked = root / "linked"
            self._directory_link(linked, actual)

            source_result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(script),
                    "--source",
                    os.fspath(linked / source.name),
                    "--policy",
                    os.fspath(linked / policy.name),
                    "--allowlist",
                    os.fspath(linked / allowlist.name),
                    "--destination",
                    os.fspath(root / "public-source-link"),
                    "--skip-validation",
                    "--no-repeat-check",
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(source_result.returncode, 1)
            self.assertIn("UNSAFE_REPARSE_POINT", source_result.stdout)
            self.assertFalse((root / "public-source-link").exists())

            receipt_target = root / "receipt-target"
            receipt_target.mkdir()
            receipt_link = root / "receipt-link"
            self._directory_link(receipt_link, receipt_target)
            receipt_result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(script),
                    "--source",
                    os.fspath(source),
                    "--policy",
                    os.fspath(policy),
                    "--allowlist",
                    os.fspath(allowlist),
                    "--destination",
                    os.fspath(root / "public-receipt-link"),
                    "--receipt",
                    os.fspath(receipt_link / "receipt.json"),
                    "--skip-validation",
                    "--no-repeat-check",
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(receipt_result.returncode, 1)
            self.assertIn("UNSAFE_REPARSE_POINT", receipt_result.stdout)
            self.assertFalse((receipt_target / "receipt.json").exists())
            self.assertFalse((root / "public-receipt-link").exists())

    def test_export_cli_resume_cannot_bypass_validation(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "create-public-export.py"
        with tempfile.TemporaryDirectory(prefix="ei-public-export-cli-resume-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            destination = root / "public"
            create_public_export(
                source,
                destination,
                policy_path=policy,
                allowlist_path=allowlist,
                validate=False,
            )
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(script),
                    "--source",
                    os.fspath(source),
                    "--policy",
                    os.fspath(policy),
                    "--allowlist",
                    os.fspath(allowlist),
                    "--destination",
                    os.fspath(destination),
                    "--resume-validation",
                    "--skip-validation",
                    "--no-repeat-check",
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("PUBLIC_EXPORT_RESUME_VALIDATION_REQUIRED", result.stdout)

    def test_export_cli_repeat_check_uses_resolved_default_configuration(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "create-public-export.py"
        with tempfile.TemporaryDirectory(prefix="ei-public-export-cli-defaults-") as tmp:
            root = Path(tmp)
            source, policy, allowlist = self._source(root)
            (source / "release").mkdir()
            (source / "config").mkdir()
            (source / "release" / "publication-policy.json").write_bytes(policy.read_bytes())
            (source / "config" / "public-export-allowlist.json").write_bytes(allowlist.read_bytes())
            subprocess.run(["git", "-C", os.fspath(source), "add", "--all"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", os.fspath(source), "commit", "--quiet", "-m", "add defaults"],
                check=True,
                capture_output=True,
                env={**os.environ, "GIT_AUTHOR_DATE": "2026-08-28T00:01:00Z", "GIT_COMMITTER_DATE": "2026-08-28T00:01:00Z"},
            )
            destination = root / "public"
            receipt = root / "public-receipt.json"
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(script),
                    "--source",
                    os.fspath(source),
                    "--destination",
                    os.fspath(destination),
                    "--receipt",
                    os.fspath(receipt),
                    "--skip-validation",
                    "--json",
                ],
                cwd=script.parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "exported_unvalidated")
            validate_public_export_receipt(value)

    def test_export_api_preflights_linked_configuration_and_receipt_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ei-public-export-api-reparse-") as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            source, policy, allowlist = self._source(actual)
            config_link = root / "config-link"
            self._directory_link(config_link, actual)
            linked_destination = root / "public-linked-config"
            with self.assertRaisesRegex(PublicExportError, "PUBLIC_EXPORT_REPARSE_POINT"):
                create_public_export(
                    source,
                    linked_destination,
                    policy_path=config_link / policy.name,
                    allowlist_path=config_link / allowlist.name,
                    validate=False,
                )
            self.assertFalse(linked_destination.exists())

            receipt_target = root / "receipt-target"
            receipt_target.mkdir()
            receipt_link = root / "receipt-link"
            self._directory_link(receipt_link, receipt_target)
            receipt_destination = root / "public-linked-receipt"
            with self.assertRaisesRegex(PublicExportError, "UNSAFE_REPARSE_POINT|PUBLIC_EXPORT_REPARSE_POINT"):
                create_public_export(
                    source,
                    receipt_destination,
                    policy_path=policy,
                    allowlist_path=allowlist,
                    receipt_path=receipt_link / "receipt.json",
                    validate=False,
                )
            self.assertFalse((receipt_target / "receipt.json").exists())
            self.assertFalse(receipt_destination.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.publication_audit import audit_repository
from ei.publication_policy import load_publication_policy


class PublicationAuditTests(unittest.TestCase):
    def _repo(self) -> tuple[Path, dict[str, object]]:
        root = Path(tempfile.mkdtemp(prefix="ei-public-audit-"))
        (root / "release").mkdir()
        policy_path = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json"
        policy = load_publication_policy(policy_path)
        subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "fixture-author"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", policy["public_author"]["email"]], check=True)
        return root, policy

    def _commit(self, root: Path, *, author: str | None = None) -> None:
        subprocess.run(["git", "-C", str(root), "add", "--all"], check=True, capture_output=True)
        command = ["git", "-C", str(root), "commit", "--quiet", "-m", "test"]
        if author:
            command[5:5] = ["--author", author]
        subprocess.run(command, check=True, capture_output=True)

    def _license(self, root: Path) -> None:
        (root / "LICENSE").write_text("Apache License\n", encoding="utf-8")

    def test_forbidden_content_and_missing_license_are_reported_without_echoing_secret(self) -> None:
        root, policy = self._repo()
        forbidden_path = "C:" + chr(92) + "Users" + chr(92) + "private-user" + chr(92) + "secret.txt"
        (root / "bad.py").write_text(
            'path = "' + forbidden_path + '"\n'
            'token = "ghp_' + "A" * 36 + '"\n',
            encoding="utf-8",
        )
        self._commit(root)
        result = audit_repository(root, policy, working_tree=True)
        self.assertFalse(result.passed)
        check_ids = {item["check_id"] for item in result.to_dict()["checks"] if item["status"] == "failed"}
        self.assertIn("TREE_FORBIDDEN_PERSONAL_PATH", check_ids)
        self.assertIn("TREE_SECRET_PATTERN", check_ids)
        self.assertIn("LICENSE_MISSING", check_ids)
        self.assertNotIn("ghp_", json.dumps(result.to_dict()))
        shutil.rmtree(root, ignore_errors=True)

    def test_workflow_identity_and_stale_evidence_are_checked(self) -> None:
        root, policy = self._repo()
        (root / "LICENSE").write_text("Apache License\n", encoding="utf-8")
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "unsafe.yml").write_text(
            "jobs:\n  x:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ inputs.value }}\n",
            encoding="utf-8",
        )
        (root / "release").mkdir(exist_ok=True)
        (root / "release" / "evidence-manifest.json").write_text(
            json.dumps({"subject_commit_sha": "0" * 40}), encoding="utf-8"
        )
        self._commit(root)
        result = audit_repository(root, policy, working_tree=True)
        check_ids = {item["check_id"] for item in result.to_dict()["checks"] if item["status"] == "failed"}
        self.assertIn("WORKFLOW_SELF_HOSTED", check_ids)
        self.assertIn("WORKFLOW_INPUT_INJECTION", check_ids)
        self.assertIn("EVIDENCE_SHA_STALE", check_ids)
        shutil.rmtree(root, ignore_errors=True)

    def test_clean_tree_passes_and_reachable_private_identity_fails(self) -> None:
        root, policy = self._repo()
        self._license(root)
        (root / "README.md").write_text("safe public source\n", encoding="utf-8")
        self._commit(root)
        clean = audit_repository(root, policy, working_tree=True, reachable_history=True)
        self.assertTrue(clean.passed, clean.to_dict())

        (root / "note.md").write_text("later change\n", encoding="utf-8")
        self._commit(root, author="Private Author <private@example.com>")
        history = audit_repository(root, policy, working_tree=True, reachable_history=True)
        check_ids = {item["check_id"] for item in history.to_dict()["checks"] if item["status"] == "failed"}
        self.assertIn("HISTORY_AUTHOR_NOT_ALLOWLISTED", check_ids)
        shutil.rmtree(root, ignore_errors=True)

    def test_portable_home_variables_are_not_treated_as_resolved_paths(self) -> None:
        root, policy = self._repo()
        self._license(root)
        (root / "README.md").write_text(
            "clone to $HOME/repos/example; see https://example.invalid/users/features\n",
            encoding="utf-8",
        )
        self._commit(root)
        result = audit_repository(root, policy, working_tree=True)
        self.assertTrue(result.passed, result.to_dict())
        shutil.rmtree(root, ignore_errors=True)

    def test_reachable_history_batches_blob_reads_without_git_show_per_file(self) -> None:
        root, policy = self._repo()
        self._license(root)
        for index in range(3):
            (root / f"note-{index}.md").write_text(f"safe {index}\n", encoding="utf-8")
            self._commit(root)

        real_run = subprocess.run
        commands: list[tuple[str, ...]] = []

        def recording_run(command, *args, **kwargs):
            commands.append(tuple(str(item) for item in command))
            return real_run(command, *args, **kwargs)

        with patch("ei.publication_audit.subprocess.run", side_effect=recording_run):
            result = audit_repository(root, policy, reachable_history=True)

        self.assertTrue(result.passed, result.to_dict())
        self.assertFalse(any("show" in command for command in commands))
        self.assertEqual(
            sum("cat-file" in command and "--batch" in command for command in commands),
            1,
        )
        shutil.rmtree(root, ignore_errors=True)

    def test_strict_awaiting_public_subject_manifest_is_not_false_stale_evidence(self) -> None:
        root, policy = self._repo()
        self._license(root)
        manifest = {
            "ci_runs": {},
            "evidence_commit_sha": None,
            "evidence_type": "public_release_evidence",
            "generated_at": "2026-08-28T00:00:00Z",
            "index_sha256": "sha256:" + "1" * 64,
            "package_sha256": None,
            "public_tree_audit_sha256": None,
            "publication_policy_sha256": "sha256:" + "2" * 64,
            "receipt_index": [],
            "sbom_sha256": None,
            "states": {
                "effect_validated": "awaiting_sample",
                "production_enabled": False,
                "software_complete": False,
            },
            "status": "awaiting_public_subject",
            "subject_commit_sha": None,
            "workflow_sha256": None,
        }
        (root / "release" / "evidence-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._commit(root)

        result = audit_repository(root, policy, working_tree=True, reachable_history=True)

        self.assertTrue(result.passed, result.to_dict())
        check_ids = {item["check_id"] for item in result.to_dict()["checks"]}
        self.assertIn("EVIDENCE_AWAITING_PUBLIC_SUBJECT", check_ids)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

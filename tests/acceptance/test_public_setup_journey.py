from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import PUBLIC_CLI_HOST_IDS
from ei.installer import SetupSelection, setup


class PublicSetupJourneyTests(unittest.TestCase):
    def _selection(self, root: Path, *, hosts=PUBLIC_CLI_HOST_IDS) -> SetupSelection:
        repo = Path.cwd()
        homes = {host_id: root / "host homes" / host_id for host_id in hosts}
        context_names = {
            "codex-cli": "AGENTS.md",
            "claude-code": "CLAUDE.md",
            "gemini-cli": "GEMINI.md",
            "qwen-code": "QWEN.md",
        }
        for host_id, home in homes.items():
            home.mkdir(parents=True, exist_ok=True)
            context_id = "codex-cli" if host_id == "codex-app" else host_id
            (home / context_names[context_id]).write_text("# user instructions\n", encoding="utf-8")
        return SetupSelection(
            engine_root=repo,
            knowledge_root=root / "private knowledge 日本語 space",
            runtime_root=root / "machine runtime 日本語 space",
            hosts=hosts,
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            host_homes=homes,
            python_exe=Path(__import__("sys").executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def test_check_only_then_apply_uses_only_four_cli_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = self._selection(root)
            checked = setup(selection, check_only=True)
            self.assertTrue(checked.ok, checked.to_dict())
            self.assertEqual(checked.knowledge["mode"], "local")
            self.assertEqual(checked.knowledge["plan"]["actions"][0]["kind"], "initialize-local")
            self.assertEqual(set(selection.hosts), set(PUBLIC_CLI_HOST_IDS))
            self.assertFalse((root / "machine runtime 日本語 space" / "install-manifest.json").exists())
            self.assertFalse((root / "private knowledge 日本語 space").exists())

            applied = setup(selection)
            self.assertTrue(applied.ok, applied.to_dict())
            self.assertEqual(applied.status, "SETUP_COMPLETE")
            self.assertEqual(applied.knowledge["repository"]["status"], "READY")
            self.assertTrue((root / "private knowledge 日本語 space" / "knowledge-repository.json").is_file())
            self.assertFalse(applied.sync["enabled"])
            self.assertEqual(applied.scheduler["status"], "NOT_REQUESTED")
            manifest = json.loads((root / "machine runtime 日本語 space" / "install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 8)
            self.assertEqual(manifest["knowledge_repository"]["mode"], "local")
            self.assertEqual(manifest["knowledge_repository"]["status"], "READY")
            self.assertEqual(set(manifest["hosts"]), set(PUBLIC_CLI_HOST_IDS))
            self.assertEqual(manifest["supported_hosts"], list(PUBLIC_CLI_HOST_IDS))
            self.assertNotIn("codex-app", manifest["hosts"])
            self.assertFalse(applied.host_migrations)

    def test_legacy_codex_app_selection_is_migrated_with_explicit_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = self._selection(root, hosts=("codex-app",))
            self.assertEqual(selection.hosts, ("codex-cli",))
            self.assertEqual(selection.legacy_host_migrations[0]["from_host_id"], "codex-app")
            checked = setup(selection, check_only=True)
            self.assertTrue(checked.ok, checked.to_dict())
            self.assertEqual(checked.host_migrations[0]["status"], "MIGRATED_TO_CLI")

            applied = setup(selection)
            self.assertTrue(applied.ok, applied.to_dict())
            self.assertEqual(applied.status, "SETUP_COMPLETE")
            receipt_path = root / "machine runtime 日本語 space" / "host-migration-receipt.json"
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "MIGRATED")
            self.assertEqual(receipt["entries"][0]["from_host_id"], "codex-app")
            self.assertEqual(receipt["entries"][0]["to_host_id"], "codex-cli")
            self.assertEqual(set(json.loads((root / "machine runtime 日本語 space" / "install-manifest.json").read_text(encoding="utf-8")[0:100000])["hosts"]), {"codex-cli"})

    def test_public_docs_describe_cli_only_setup(self):
        readme = (Path.cwd() / "README.md").read_text(encoding="utf-8")
        self.assertIn("codex-cli", readme)
        self.assertIn("claude-code", readme)
        self.assertIn("gemini-cli", readme)
        self.assertIn("qwen-code", readme)
        self.assertIn("not supported", readme.casefold())

    def test_public_docs_describe_one_shot_setup_and_independent_completion_gates(self):
        root = Path.cwd()
        readme = (root / "README.md").read_text(encoding="utf-8")
        setup_doc = (root / "docs" / "setup.md").read_text(encoding="utf-8")
        restore_doc = (root / "docs" / "restore-new-pc.md").read_text(encoding="utf-8")
        normal_journey = "\n".join((readme, setup_doc, restore_doc))

        self.assertIn("scripts/setup.ps1", normal_journey)
        self.assertIn("scripts/setup.sh", normal_journey)
        self.assertNotIn("knowledge init", normal_journey)
        for mode in ("local", "github-new", "github-existing"):
            self.assertIn(mode, setup_doc)
        self.assertIn("--accept-plan", setup_doc)
        self.assertIn("--confirm-github-create", setup_doc)
        self.assertIn("--check-only", setup_doc)
        for state in (
            "SETUP_COMPLETE",
            "HOST_ACTIVATION_VERIFIED",
            "PRODUCTION_COMPLETE",
            "EFFECT_VALIDATED",
        ):
            self.assertIn(state, normal_journey)

    def test_public_docs_describe_personal_team_and_reconciliation_contract(self):
        root = Path.cwd()
        documents = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("README.md", "docs/setup.md", "docs/cli-reference.md", "docs/update.md", "docs/uninstall.md")
        )
        for option in (
            "--personal-knowledge-root",
            "--team-knowledge-root",
            "--team-member-id",
            "--no-team-knowledge",
            "--knowledge-root",
        ):
            self.assertIn(option, documents)
        for state in (
            "ALREADY_CURRENT",
            "MIGRATION_REQUIRED",
            "MANAGED_TARGET_CONFLICT",
            "ACTIVE_RUNTIME_MISMATCH",
            "TEAM_STORE_VALIDATION_DEFERRED",
            "DEFERRED",
            "DISABLED",
        ):
            self.assertIn(state, documents)
        self.assertIn("omitting", documents.casefold())
        self.assertIn("unverified", documents.casefold())

    def test_public_docs_describe_one_intelligence_roles_scope_and_retention(self):
        root = Path.cwd()
        documents = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in (
                "README.md",
                "docs/setup.md",
                "docs/update.md",
                "docs/uninstall.md",
                "docs/cli-reference.md",
                "docs/compatibility.md",
                "docs/architecture.md",
                "docs/security-and-privacy.md",
            )
        )
        for phrase in (
            "外部知能は1つ",
            "整理AIは1つ",
            "作業・記憶取得CLI",
            "1",
            "1,2",
            "universal",
            "family",
            "host",
            "DEFERRED",
            "既存のactive pattern",
            "削除・初期化しません",
            "表示されません",
            "Hostごとに",
            "複製しません",
            "test-compatible-cli",
            "gemini-compatible",
            "check",
            "doctor",
        ):
            self.assertIn(phrase, documents, phrase)

    def test_selected_scheduler_must_register_before_setup_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = self._selection(root, hosts=("codex-cli",))
            selection = __import__("dataclasses").replace(selection, scheduler=True)
            registered = {
                "ok": True,
                "requested": True,
                "status": "REGISTERED",
                "reason_code": "OK",
                "registered": True,
                "retryable": False,
            }
            with patch("ei.task_scheduler.register_scheduler", return_value=registered):
                result = setup(selection)
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.status, "SETUP_COMPLETE")
            self.assertEqual(result.scheduler["status"], "REGISTERED")

    def test_setup_diagnostics_use_committed_provider_and_experiment_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = self._selection(root, hosts=("codex-cli",))
            selection = __import__("dataclasses").replace(
                selection,
                providers=("subscription-cli",),
                experiment=True,
            )

            result = setup(selection)

            self.assertTrue(result.ok, result.to_dict())
            experiment = next(check for check in result.doctor["checks"] if check["name"] == "experiment")
            provider = next(check for check in result.doctor["checks"] if check["name"] == "provider")
            self.assertTrue(experiment["enabled"])
            self.assertEqual([item["provider_id"] for item in provider["providers"]], ["subscription-cli"])

    def test_scheduler_failure_retains_valid_installation_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = self._selection(root, hosts=("codex-cli",))
            selection = __import__("dataclasses").replace(selection, scheduler=True)
            blocked = {
                "ok": False,
                "requested": True,
                "status": "REGISTRATION_FAILED",
                "reason_code": "SCHEDULER_REGISTRATION_FAILED",
                "registered": False,
                "retryable": True,
            }
            with patch("ei.task_scheduler.register_scheduler", return_value=blocked):
                result = setup(selection)
            self.assertFalse(result.ok)
            self.assertEqual(result.status, "SCHEDULER_SETUP_BLOCKED")
            self.assertTrue((root / "private knowledge 日本語 space" / "knowledge-repository.json").is_file())
            self.assertTrue((root / "machine runtime 日本語 space" / "install-manifest.json").is_file())
            self.assertEqual(result.rollback["status"], "INSTALLATION_RETAINED")


if __name__ == "__main__":
    unittest.main()

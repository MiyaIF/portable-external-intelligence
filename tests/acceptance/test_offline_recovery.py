import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings
from ei.github_knowledge import GitHubKnowledgeError
from ei.journal import append_event
from ei.knowledge_setup import KnowledgeSetupSelection, apply_knowledge_setup, operation_receipt_path, plan_knowledge_setup
from ei.models import Event
from ei.recovery import inspect_setup_operation_recovery
from ei.sync import sync_once


class OfflineRecoveryAcceptanceTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_setup_recovery_rejects_runtime_junction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            runtime = root / "runtime"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(runtime), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not runtime.exists():
                self.skipTest("junction fixture unavailable")
            with self.assertRaisesRegex(ValueError, "RUNTIME_ROOT_INVALID"):
                inspect_setup_operation_recovery(runtime)

    def test_post_create_github_outage_preserves_local_knowledge_and_retry_receipt(self):
        class OfflineAfterCreate:
            def verify_authentication(self):
                return None

            def create_private_repository(self, repository):
                return None

            def inspect_repository(self, repository):
                raise GitHubKnowledgeError("GITHUB_NETWORK_UNAVAILABLE")

            def remote_url(self, repository):
                return f"https://github.com/{repository}.git"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            engine.mkdir()
            selection = KnowledgeSetupSelection(
                mode="github-new",
                engine_root=engine,
                knowledge_root=root / "knowledge",
                runtime_root=root / "runtime",
                github_repository="MiyaIF/offline-private-knowledge",
                sync_enabled=True,
                confirm_github_create="MiyaIF/offline-private-knowledge",
            )
            plan = plan_knowledge_setup(selection)
            with patch("ei.github_knowledge.GitHubKnowledgeClient", return_value=OfflineAfterCreate()):
                result = apply_knowledge_setup(plan)
            self.assertFalse(result.ok)
            self.assertTrue(result.recovery["retryable"])
            self.assertTrue(result.recovery["external_repository_retained"])
            self.assertTrue((selection.knowledge_root / ".git").exists())
            self.assertTrue(operation_receipt_path(plan).is_file())
            recovery = inspect_setup_operation_recovery(selection.runtime_root)
            self.assertEqual(recovery.status, "retry_available")
            self.assertEqual(recovery.resume_stage, result.stage)
            self.assertTrue(recovery.external_repository_retained)

    def test_local_commit_survives_remote_outage_and_retry_state_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            (repo / "README.md").write_text("seed\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True)
            append_event(Event.create("observation.recorded", "2026-08-25T00:00:00+00:00", "test", "machine-a", {"observation_id": "obs_offline", "claim": "offline"}, event_id="evt-offline"), repo / "events")
            home = root / "codex"
            runtime = home / "external-intelligence"
            self.assertFalse(runtime.is_relative_to(repo))
            settings = Settings(
                paths=RuntimePaths(repo, home, runtime, repo / "events", repo / "knowledge", runtime / "state", runtime / "metrics", runtime / "cache", runtime / "locks", home / "config.toml", home / "hooks.json", home / "AGENTS.md"),
                retrieval_max_chars=5000,
                retrieval_max_results=5,
                sync_enabled=True,
                sync_remote="unavailable",
                sync_branch="main",
            )
            result = sync_once(settings)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "OFFLINE_RETRY_SCHEDULED")
            self.assertTrue((runtime / "state" / "sync-state.json").exists())
            self.assertTrue(subprocess.run(["git", "log", "-1", "--pretty=%s"], cwd=repo, capture_output=True, text=True, check=True).stdout.startswith("data: sync"))


if __name__ == "__main__":
    unittest.main()

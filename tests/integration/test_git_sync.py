import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings
from ei.journal import append_event
from ei.models import Event
from ei.remote_assurance import build_remote_assurance_receipt, classify_remote, write_remote_assurance_receipt
from ei.safe_fs import create_ownership_record, tree_digest, write_ownership_record
from ei.sync import CommandResult, _cleanup_worktree as cleanup_worktree, _remote_assurance_reason, sync_once


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def settings_for(repo: Path, root: Path) -> Settings:
    home = root / "codex"
    runtime = home / "external-intelligence"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=home / "config.toml",
        hooks_path=home / "hooks.json",
        agents_path=home / "AGENTS.md",
    )
    return Settings(paths=paths, retrieval_max_chars=5000, retrieval_max_results=5, sync_enabled=True, sync_remote="origin", sync_branch="main")


class GitSyncTests(unittest.TestCase):
    def test_legacy_layout_requires_remote_assurance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "legacy"
            repo.mkdir()
            git(repo, "init", "-b", "main")
            git(repo, "remote", "add", "origin", "https://github.com/MiyaIF/private-without-receipt.git")

            self.assertEqual(
                _remote_assurance_reason(settings_for(repo, root)),
                "REMOTE_ASSURANCE_MISSING",
            )

    def _strict_settings(
        self,
        engine: Path,
        knowledge: Path,
        runtime: Path,
        *,
        fingerprint: str,
        classification: str,
    ) -> Settings:
        return Settings(
            paths=RuntimePaths(engine, knowledge, runtime),
            retrieval_max_chars=5000,
            retrieval_max_results=5,
            sync_enabled=True,
            sync_remote="origin",
            sync_branch="main",
            sync_remote_fingerprint=fingerprint,
            sync_remote_classification=classification,
        )

    def _separate_git_roots(self, root: Path, remote_url: str) -> tuple[Path, Path, Path]:
        engine = root / "engine"
        knowledge = root / "knowledge"
        runtime = root / "runtime"
        engine.mkdir()
        knowledge.mkdir()
        git(engine, "init", "-b", "main")
        git(knowledge, "init", "-b", "main")
        git(knowledge, "remote", "add", "origin", remote_url)
        return engine, knowledge, runtime

    def test_changed_remote_fingerprint_is_blocked_before_staging(self):
        class NoStageRunner:
            def __init__(self):
                self.calls = []

            def run(self, args):
                self.calls.append(tuple(args))
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "https://github.com/MiyaIF/original-private.git"
            changed = "https://github.com/MiyaIF/changed-private.git"
            descriptor = classify_remote(original, visibility="private")
            engine, knowledge, runtime = self._separate_git_roots(root, changed)
            write_remote_assurance_receipt(runtime, build_remote_assurance_receipt(descriptor))
            runner = NoStageRunner()

            with patch("ei.remote_assurance._probe_github_visibility", return_value=("private", "github_api")):
                result = sync_once(
                    self._strict_settings(
                        engine,
                        knowledge,
                        runtime,
                        fingerprint=descriptor.fingerprint,
                        classification=descriptor.classification,
                    ),
                    runner=runner,
                )

            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "REMOTE_FINGERPRINT_MISMATCH")
            self.assertEqual(runner.calls, [])

    def test_missing_assurance_receipt_is_blocked_before_staging(self):
        class NoStageRunner:
            def __init__(self):
                self.calls = []

            def run(self, args):
                self.calls.append(tuple(args))
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = "https://github.com/MiyaIF/private-without-receipt.git"
            descriptor = classify_remote(remote, visibility="private")
            engine, knowledge, runtime = self._separate_git_roots(root, remote)
            runner = NoStageRunner()

            with patch("ei.remote_assurance._probe_github_visibility", return_value=("private", "github_api")):
                result = sync_once(
                    self._strict_settings(
                        engine,
                        knowledge,
                        runtime,
                        fingerprint=descriptor.fingerprint,
                        classification=descriptor.classification,
                    ),
                    runner=runner,
                )

            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "REMOTE_ASSURANCE_MISSING")
            self.assertEqual(runner.calls, [])

    def test_visibility_is_reprobed_before_the_first_network_command(self):
        class SuccessfulRunner:
            def __init__(self):
                self.calls = []
                self.staged = False

            def run(self, args):
                self.calls.append(tuple(args))
                if args[1:] == ["status", "--porcelain", "--untracked-files=all"]:
                    return CommandResult(0, "?? events/2026/08/evt_probe.json\n", "")
                if args[1:] == ["diff", "--cached", "--name-only"]:
                    return CommandResult(0, "events/2026/08/evt_probe.json\n" if self.staged else "", "")
                if args[1:] in (["diff", "--check"], ["diff", "--cached", "--check"]):
                    return CommandResult(0, "", "")
                if args[1:3] == ["add", "--"]:
                    self.staged = True
                    return CommandResult(0, "", "")
                if args[1:] == ["diff", "--cached", "--quiet"]:
                    return CommandResult(1, "", "")
                if args[1] == "commit":
                    return CommandResult(0, "", "")
                if args[1:] == ["rev-parse", "HEAD"]:
                    return CommandResult(0, "0123456789abcdef\n", "")
                if args[1:3] == ["rev-parse", "--verify"]:
                    return CommandResult(1, "", "")
                if args[1:] == ["rev-parse", "--show-toplevel"]:
                    return CommandResult(0, "knowledge\n", "")
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = "https://github.com/MiyaIF/private-visibility-change.git"
            descriptor = classify_remote(remote, visibility="private")
            engine, knowledge, runtime = self._separate_git_roots(root, remote)
            write_remote_assurance_receipt(runtime, build_remote_assurance_receipt(descriptor))
            append_event(
                Event.create(
                    "observation.recorded",
                    "2026-08-25T00:00:00+00:00",
                    "test",
                    "machine-a",
                    {"observation_id": "obs_probe", "claim": "probe"},
                    event_id="evt_probe",
                ),
                knowledge / "events",
            )
            runner = SuccessfulRunner()

            with patch(
                "ei.remote_assurance._probe_github_visibility",
                side_effect=[("private", "github_api"), ("public", "github_api")],
            ) as probe:
                result = sync_once(
                    self._strict_settings(
                        engine,
                        knowledge,
                        runtime,
                        fingerprint=descriptor.fingerprint,
                        classification=descriptor.classification,
                    ),
                    runner=runner,
                )

            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "PRIVATE_REMOTE_REQUIRED")
            self.assertEqual(probe.call_count, 2)
            network_calls = [call for call in runner.calls if len(call) > 1 and call[1] in {"fetch", "push"}]
            self.assertEqual(network_calls, [])

    def test_local_bare_remote_accepts_append_only_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            work = root / "work"
            remote.mkdir()
            work.mkdir()
            git(root, "init", "--bare", str(remote))
            git(work, "init", "-b", "main")
            git(work, "config", "user.name", "Test User")
            git(work, "config", "user.email", "test@example.invalid")
            (work / "README.md").write_text("seed\n", encoding="utf-8")
            git(work, "add", "README.md")
            git(work, "commit", "-m", "seed")
            git(work, "remote", "add", "origin", str(remote))
            append_event(Event.create("observation.recorded", "2026-08-25T00:00:00+00:00", "test", "machine-a", {"observation_id": "obs_a", "claim": "a"}, event_id="evt_a"), work / "events")
            settings = settings_for(work, root)
            result = sync_once(settings)
            self.assertTrue(result.ok, result)
            self.assertEqual(result.reason_code, "SYNCED")
            self.assertIn("evt_a.json", git(remote, "--git-dir", str(remote), "ls-tree", "-r", "main"))
            self.assertFalse((settings.paths.runtime_root / "sync-worktree").exists())
            self.assertFalse((settings.paths.runtime_root / "sync-worktree.ownership.json").exists())
            state = json.loads(
                (settings.paths.local_state_dir / "sync-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["last_status"], "success")
            self.assertEqual(state["last_reason_code"], "SYNCED")

            unchanged = sync_once(settings)
            self.assertTrue(unchanged.ok, unchanged)
            self.assertEqual(unchanged.reason_code, "NO_ENGINE_CHANGES")
            state = json.loads(
                (settings.paths.local_state_dir / "sync-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["last_status"], "success")
            self.assertEqual(state["last_reason_code"], "NO_ENGINE_CHANGES")

    def test_successful_sync_becomes_failure_when_owned_worktree_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            work = root / "work"
            remote.mkdir()
            work.mkdir()
            git(root, "init", "--bare", str(remote))
            git(work, "init", "-b", "main")
            git(work, "config", "user.name", "Test User")
            git(work, "config", "user.email", "test@example.invalid")
            (work / "README.md").write_text("seed\n", encoding="utf-8")
            git(work, "add", "README.md")
            git(work, "commit", "-m", "seed")
            git(work, "remote", "add", "origin", str(remote))
            append_event(
                Event.create(
                    "observation.recorded",
                    "2026-08-25T00:00:00+00:00",
                    "test",
                    "machine-a",
                    {"observation_id": "obs_cleanup", "claim": "cleanup"},
                    event_id="evt_cleanup",
                ),
                work / "events",
            )

            def cleanup_then_report_failure(*args):
                cleanup_worktree(*args)
                return "SYNC_WORKTREE_CLEANUP_FAILED"

            with patch("ei.sync._cleanup_worktree", side_effect=cleanup_then_report_failure):
                result = sync_once(settings_for(work, root))

            state = json.loads(
                (root / "codex" / "external-intelligence" / "state" / "sync-state.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "SYNC_WORKTREE_CLEANUP_FAILED")
            self.assertEqual(state["last_status"], "blocked")
            self.assertEqual(state["last_reason_code"], "SYNC_WORKTREE_CLEANUP_FAILED")

    def test_clean_sync_recovers_an_owned_stale_worktree_before_returning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            work = root / "work"
            remote.mkdir()
            work.mkdir()
            git(root, "init", "--bare", str(remote))
            git(work, "init", "-b", "main")
            git(work, "config", "user.name", "Test User")
            git(work, "config", "user.email", "test@example.invalid")
            (work / "README.md").write_text("seed\n", encoding="utf-8")
            git(work, "add", "README.md")
            git(work, "commit", "-m", "seed")
            git(work, "remote", "add", "origin", str(remote))
            settings = settings_for(work, root)
            settings.paths.runtime_root.mkdir(parents=True, exist_ok=True)
            stale = settings.paths.runtime_root / "sync-worktree"
            receipt = settings.paths.runtime_root / "sync-worktree.ownership.json"
            git(work, "worktree", "add", "--detach", str(stale), "HEAD")
            record = create_ownership_record(
                settings.paths.runtime_root,
                stale,
                kind="sync-worktree",
                expected_digest=tree_digest(stale),
                authority_roots={"source_root": work},
            )
            write_ownership_record(receipt, record, root=settings.paths.runtime_root)

            result = sync_once(settings)

            self.assertTrue(result.ok, result)
            self.assertEqual(result.reason_code, "NO_ENGINE_CHANGES")
            self.assertFalse(stale.exists())
            self.assertFalse(receipt.exists())
            self.assertNotIn(str(stale), git(work, "worktree", "list", "--porcelain"))

    def test_offline_runner_schedules_bounded_retry(self):
        class OfflineRunner:
            def run(self, args):
                if args[1:] == ["status", "--porcelain", "--untracked-files=all"]:
                    return CommandResult(0, "?? events/2026/08/evt_a.json", "")
                if args[1:] == ["diff", "--cached", "--quiet"]:
                    return CommandResult(1, "", "")
                if args[1] == "fetch":
                    return CommandResult(1, "", "network unavailable")
                if args[1] == "rev-parse":
                    return CommandResult(0, "commit-sha\n", "")
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir()
            git(work, "init", "-b", "main")
            git(work, "config", "user.name", "Test User")
            git(work, "config", "user.email", "test@example.invalid")
            (work / "README.md").write_text("seed\n", encoding="utf-8")
            git(work, "add", "README.md")
            git(work, "commit", "-m", "seed")
            append_event(Event.create("observation.recorded", "2026-08-25T00:00:00+00:00", "test", "machine-a", {"observation_id": "obs_a", "claim": "a"}, event_id="evt_a"), work / "events")
            result = sync_once(settings_for(work, root), runner=OfflineRunner())
            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "OFFLINE_RETRY_SCHEDULED")
            self.assertEqual(result.retry_seconds, 300)


if __name__ == "__main__":
    unittest.main()

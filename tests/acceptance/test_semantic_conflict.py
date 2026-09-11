import json
import inspect
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.journal import append_event
from ei.models import Event
from ei.sync import CommandResult, FileLock, classify_git_conflict, schedule_retry, sync_once
from ei.github_knowledge import connect_exact_remote, push_and_verify


def settings_for(repo: Path, root: Path) -> Settings:
    home = root / "codex"
    runtime = home / "external-intelligence"
    return Settings(
        paths=RuntimePaths(
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
        ),
        sync_enabled=True,
        sync_remote="origin",
        sync_branch="main",
    )


class SemanticConflictAcceptanceTests(unittest.TestCase):
    def test_setup_git_mutations_have_no_force_or_reset_route(self):
        source = inspect.getsource(connect_exact_remote) + inspect.getsource(push_and_verify)
        self.assertNotIn("--force", source)
        self.assertNotIn("reset", source)

    def test_conflict_classification_and_retry_are_bounded(self):
        self.assertEqual(
            classify_git_conflict("CONFLICT (content): Merge conflict in policies/privacy-policy.json"),
            "SEMANTIC_POLICY_CONFLICT",
        )
        start = datetime(2026, 8, 27, tzinfo=timezone.utc)
        self.assertEqual((schedule_retry("GIT_FETCH_FAILED", 0, start) - start).total_seconds(), 300)
        self.assertEqual((schedule_retry("GIT_FETCH_FAILED", 99, start) - start).total_seconds(), 21600)

    def test_stale_lock_is_reclaimed_but_live_lock_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sync.lock"
            path.write_text(json.dumps({"pid": 999999, "acquired_at": "2020-01-01T00:00:00+00:00"}), encoding="utf-8")
            with FileLock(path):
                self.assertTrue(path.exists())
            with FileLock(path):
                with self.assertRaises(RuntimeError) as caught:
                    with FileLock(path):
                        pass
                self.assertEqual(str(caught.exception), "SYNC_LOCK_BUSY")

    def test_semantic_conflict_never_uses_force_or_reset(self):
        class ConflictRunner:
            def __init__(self):
                self.calls = []

            def run(self, args):
                self.calls.append(tuple(args))
                if args[1:] == ["status", "--porcelain", "--untracked-files=all"]:
                    return CommandResult(0, "?? events/2026/08/evt_a.json\n", "")
                if args[1:] == ["diff", "--cached", "--name-only"]:
                    return CommandResult(0, "events/2026/08/evt_a.json\n" if any(call[1:3] == ("add", "--") for call in self.calls) else "", "")
                if args[1:] == ["diff", "--check"] or args[1:] == ["diff", "--cached", "--check"]:
                    return CommandResult(0, "", "")
                if args[1:] == ["diff", "--cached", "--quiet"]:
                    return CommandResult(1, "", "")
                if args[1] == "commit":
                    return CommandResult(0, "", "")
                if args[1] == "rev-parse":
                    return CommandResult(0, "0123456789abcdef\n", "")
                if args[1] == "fetch":
                    return CommandResult(0, "", "")
                if args[1] == "rebase" and args[-1] != "--abort":
                    return CommandResult(1, "", "CONFLICT (content): Merge conflict in policies/privacy-policy.json")
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            append_event(
                Event.create("observation.recorded", "2026-08-27T00:00:00+00:00", "test", "machine-a", {"observation_id": "obs_a", "claim": "a"}, event_id="evt_a"),
                repo / "events",
            )
            runner = ConflictRunner()
            result = sync_once(settings_for(repo, root), runner=runner)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "SYNC_BLOCKED")
            flattened = [part for call in runner.calls for part in call]
            self.assertNotIn("--force", flattened)
            self.assertNotIn("reset", flattened)


if __name__ == "__main__":
    unittest.main()

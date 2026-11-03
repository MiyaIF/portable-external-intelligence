import unittest
import tempfile
import subprocess
import os
from pathlib import Path
from unittest.mock import patch

from ei.config import RuntimePaths, Settings
from ei.sync import CommandResult, _sync_root, _validated_status, build_sync_plan
from ei.sync import GitRunner, sync_once
from ei.operation_runtime import OperationBudget


class SyncPlanTests(unittest.TestCase):
    def test_expiry_during_lock_publication_leaves_no_busy_lock(self):
        from ei.sync import FileLock

        class ExpiringBudget:
            remaining = 1
            def check(self):
                if not self.remaining:
                    raise TimeoutError("expired")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.lock"
            budget = ExpiringBudget()
            real_link = os.link
            def expire_after_publication(source, target):
                real_link(source, target)
                budget.remaining = 0
            with patch("ei.sync.os.link", side_effect=expire_after_publication):
                with self.assertRaises(TimeoutError):
                    FileLock(path, budget=budget).__enter__()
            self.assertFalse(path.exists())
            with FileLock(path):
                self.assertTrue(path.exists())

    def test_short_lock_write_cleans_only_owned_staging(self):
        from ei.sync import FileLock
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.lock"
            with patch("ei.sync.os.write", return_value=0):
                with self.assertRaises(OSError):
                    FileLock(path).__enter__()
            self.assertEqual(list(Path(tmp).iterdir()), [])
            with FileLock(path):
                self.assertTrue(path.exists())

    def test_lock_publication_conflict_and_unsupported_link_leave_no_staging(self):
        from ei.sync import FileLock
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.lock"
            path.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError, "SYNC_LOCK_BUSY"):
                FileLock(path).__enter__()
            self.assertEqual(list(Path(tmp).iterdir()), [path])
            path.unlink()
            with patch("ei.sync.os.link", side_effect=OSError("unsupported")):
                with self.assertRaises(OSError):
                    FileLock(path).__enter__()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_replaced_staging_is_retained_without_publishing_lock(self):
        from ei.sync import FileLock
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.lock"
            lock = FileLock(path)
            stage = path.with_name(path.name + "." + lock._token + ".tmp")
            stage.write_bytes(b"owned")
            descriptor = os.open(stage, os.O_RDONLY)
            acquired = os.fstat(descriptor)
            os.close(descriptor)
            replacement = Path(tmp) / "replacement"
            replacement.write_bytes(b"foreign")
            os.replace(replacement, stage)
            lock._release_staging(stage, acquired, expected_links=1)
            self.assertFalse(path.exists())
            self.assertEqual(stage.read_bytes(), b"foreign")

    def test_file_lock_zero_budget_and_bounded_owned_release_after_deadline(self):
        from ei.sync import FileLock
        from tests.integration.test_unattended_operation import RemainingBudget
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "locks" / "one.lock"
            with self.assertRaises(TimeoutError):
                with FileLock(path, budget=OperationBudget(0)):
                    self.fail("expired lock entered")
            self.assertFalse(path.parent.exists())
            budget = RemainingBudget()
            with FileLock(path, budget=budget):
                budget.remaining = 0
            self.assertFalse(path.exists())
            with FileLock(path):
                self.assertTrue(path.exists())
            self.assertFalse(path.exists())

    def test_file_lock_release_retains_replaced_oversize_malformed_and_foreign_token(self):
        import json
        from ei.sync import FileLock
        with tempfile.TemporaryDirectory() as tmp:
            for label in ("malformed", "oversize", "foreign", "replacement"):
                with self.subTest(label=label):
                    path = Path(tmp) / (label + ".lock")
                    if label == "replacement":
                        lock = FileLock(path).__enter__()
                        original = path.read_bytes()
                        replacement = path.with_suffix(".replacement")
                        replacement.write_bytes(original)
                        os.replace(replacement, path)
                        lock.__exit__(None, None, None)
                        self.assertEqual(path.read_bytes(), original)
                        continue
                    with FileLock(path):
                        path.write_bytes(b"invalid" if label == "malformed" else b" " * 4097 if label == "oversize" else json.dumps({"token": "other"}).encode())
                        expected = path.read_bytes()
                    self.assertEqual(path.read_bytes(), expected)

    def test_only_the_exact_projection_attributes_control_path_is_allowed(self):
        self.assertTrue(build_sync_plan(["?? knowledge/.gitattributes"]).allowed)
        for path in (".gitattributes", "knowledge/nested/.gitattributes", "events/.gitattributes", "knowledge/.GITATTRIBUTES"):
            with self.subTest(path=path):
                self.assertFalse(build_sync_plan(["?? " + path]).allowed)

    def test_zero_budget_skips_lock_git_and_state(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            settings = Settings(paths=RuntimePaths(root / "engine", root / "knowledge", root / "runtime"))
            with patch("ei.sync.FileLock", side_effect=AssertionError("no lock")), patch("ei.sync.GitRunner", side_effect=AssertionError("no git")):
                result = sync_once(settings, budget=OperationBudget(0))
            self.assertEqual(result.reason_code, "SYNC_BUDGET_EXHAUSTED")
            self.assertFalse((root / "runtime").exists())

    def test_git_runner_uses_remaining_timeout_and_process_only_noninteractive_env(self):
        with tempfile.TemporaryDirectory() as raw:
            budget = OperationBudget(5000)
            before = dict(os.environ)
            with patch("ei.sync.subprocess.run", side_effect=subprocess.TimeoutExpired(["git", "status"], 1)) as run:
                with self.assertRaises(TimeoutError):
                    GitRunner(Path(raw), budget=budget).run(["git", "status"])
            kwargs = run.call_args.kwargs
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 5)
            self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(kwargs["env"]["GCM_INTERACTIVE"], "Never")
            self.assertEqual(dict(os.environ), before)

    def test_interior_timeout_does_not_run_next_git_or_write_state(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            settings = Settings(paths=RuntimePaths(root / "engine", root / "knowledge", root / "runtime"))
            budget = OperationBudget(5000)

            class ExpiringRunner:
                calls = []
                def run(self, args):
                    self.calls.append(tuple(args))
                    budget.deadline = 0
                    return CommandResult(0, "", "")

            runner = ExpiringRunner()
            result = sync_once(settings, runner=runner, budget=budget)
            self.assertEqual(result.reason_code, "SYNC_BUDGET_EXHAUSTED")
            self.assertEqual(len(runner.calls), 1)
            self.assertFalse((settings.paths.local_state_dir / "sync-state.json").exists())

    def test_ignores_tracked_managed_path_when_git_reports_no_content_diff(self):
        class NormalizedCleanRunner:
            def __init__(self):
                self.calls = []

            def run(self, args):
                self.calls.append(tuple(args))
                if args[1:] == ["status", "--porcelain", "--untracked-files=all"]:
                    return CommandResult(0, " M knowledge/index.json\n", "")
                if args[1:] == ["diff", "--quiet", "--", "knowledge/index.json"]:
                    return CommandResult(0, "", "")
                raise AssertionError(args)

        runner = NormalizedCleanRunner()
        plan, entries, _ = _validated_status(runner, None)

        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "NO_ENGINE_CHANGES")
        self.assertEqual(plan.stage_paths, [])
        self.assertEqual([entry.path for entry in entries], ["knowledge/index.json"])
        self.assertIn(
            ("git", "diff", "--quiet", "--", "knowledge/index.json"),
            runner.calls,
        )

    def test_refuses_unrelated_source_changes(self):
        status = [" M src/ei/retrieve.py", "?? events/2026/08/evt_a.json"]
        plan = build_sync_plan(status)
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "REVIEW_REQUIRED_SOURCE_CHANGE")

    def test_stages_only_engine_managed_data(self):
        status = ["?? events/2026/08/evt_a.json", " M knowledge/index.md"]
        plan = build_sync_plan(status)
        self.assertTrue(plan.allowed)
        self.assertEqual(plan.stage_paths, ["events/2026/08/evt_a.json", "knowledge/index.md"])



    def test_refuses_machine_local_runtime_paths(self):
        plan = build_sync_plan(["?? queue/item.json", "?? events/2026/08/evt_a.json"])
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "UNRELATED_WORKTREE_CHANGES")

    def test_refuses_policy_and_skill_changes_from_automatic_sync(self):
        plan = build_sync_plan([" M policies/privacy-policy.json", "?? events/2026/08/evt_a.json"])
        self.assertFalse(plan.allowed)
        self.assertEqual(plan.reason_code, "REVIEW_REQUIRED_SOURCE_CHANGE")

    def test_refuses_event_modification_and_allows_append_only_add(self):
        modified = build_sync_plan([" M events/2026/08/evt_a.json"])
        self.assertFalse(modified.allowed)
        self.assertEqual(modified.reason_code, "EVENT_JOURNAL_MODIFICATION_FORBIDDEN")
        added = build_sync_plan(["?? events/2026/08/evt_b.json"])
        self.assertTrue(added.allowed)
        self.assertEqual(added.stage_paths, ["events/2026/08/evt_b.json"])

    def test_sync_root_is_personal_store_even_when_team_store_is_configured(self):
        paths = RuntimePaths(
            engine_root=Path("engine"),
            personal_knowledge_root=Path("personal"),
            team_knowledge_root=Path("shared-team"),
            runtime_root=Path("runtime"),
        )
        settings = Settings(paths=paths)
        self.assertEqual(_sync_root(settings), paths.personal_knowledge_root)
if __name__ == "__main__":
    unittest.main()

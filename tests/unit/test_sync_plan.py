import unittest
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.sync import CommandResult, _sync_root, _validated_status, build_sync_plan


class SyncPlanTests(unittest.TestCase):
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

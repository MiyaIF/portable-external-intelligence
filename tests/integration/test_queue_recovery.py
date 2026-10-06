import tempfile
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ei.hooks.registry import normalize_hook_event
from ei.queue import claim_queue_item, enqueue_receipt, recover_emergency_spool
from ei.config import RuntimePaths, Settings
from ei.operation_runtime import OperationBudget
from ei.recovery import reconcile_orphans
from ei.journal import append_event, iter_events




def make_isolated_hook_settings(root: Path) -> Settings:
    root = Path(root).resolve()
    repo = root / "repo"
    runtime = root / "machine-runtime"
    codex_home = root / "codex-home"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=codex_home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=codex_home / "config.toml",
        hooks_path=codex_home / "hooks.json",
        agents_path=codex_home / "AGENTS.md",
    )
    return Settings(paths=paths, retrieval_max_chars=5000, retrieval_max_results=5)


class QueueRecoveryIntegrationTests(unittest.TestCase):
    def test_orphan_zero_budget_has_no_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            with patch("ei.recovery._read_jsonl", side_effect=AssertionError("no read")):
                with self.assertRaises(TimeoutError):
                    reconcile_orphans("codex-cli", None, settings, budget=OperationBudget(0))
            self.assertFalse(settings.paths.runtime_dir.exists())

    def test_orphan_interior_timeout_preserves_diagnostics_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.local_state_dir.mkdir(parents=True)
            rows = [{"host_id": "codex-cli", "source_hash": "sha256:" + char * 64, "source_ref_hash": "sha256:" + "3" * 64, "classification": "private-reusable", "observed_at": "2026-09-18T00:00:00Z"} for char in ("1", "2")]
            (settings.paths.local_state_dir / "orphan-sources.jsonl").write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            health = settings.paths.runtime_dir / "recovery-health.json"
            health.write_text("previous", encoding="utf-8")
            budget = OperationBudget(10000)

            def append_then_expire(*args, **kwargs):
                result = append_event(*args, **kwargs)
                budget.deadline = 0
                return result

            with patch("ei.recovery.append_event", side_effect=append_then_expire):
                with self.assertRaises(TimeoutError):
                    reconcile_orphans("codex-cli", None, settings, budget=budget)
            self.assertEqual(health.read_text(encoding="utf-8"), "previous")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)
            result = reconcile_orphans("codex-cli", None, settings, budget=OperationBudget(10000))
            self.assertEqual(result.recovered, 1)
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 2)

    def test_stale_lease_returns_to_ready_then_claims_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"}, settings)
            enqueue_receipt(event, None, settings, now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            first = claim_queue_item("first", settings, datetime(2026, 8, 26, tzinfo=timezone.utc), lease_seconds=1)
            second = claim_queue_item("second", settings, datetime(2026, 8, 26, 0, 0, 2, tzinfo=timezone.utc), lease_seconds=1)
            self.assertEqual(first.attempts, 1)
            self.assertEqual(second.attempts, 2)
            self.assertEqual(len(recover_emergency_spool(settings)), 0)


if __name__ == "__main__":
    unittest.main()

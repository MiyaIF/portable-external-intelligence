import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.hooks.registry import normalize_hook_event
from ei.queue import claim_queue_item, enqueue_receipt, recover_emergency_spool
from ei.config import RuntimePaths, Settings




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
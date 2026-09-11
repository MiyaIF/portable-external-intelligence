import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.hooks.registry import normalize_hook_event
from ei.queue import enqueue_receipt, recover_emergency_spool, write_emergency_envelope
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


class EmergencySpoolRecoveryTests(unittest.TestCase):
    def test_corrupt_emergency_is_quarantined_and_not_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"}, settings), None, settings, now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            (settings.paths.queue_dir / f"{item.queue_id}.json").unlink()
            write_emergency_envelope(item, settings, reason_code="QUEUE_WRITE_FAILED", now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            emergency = next(settings.paths.emergency_spool_dir.glob("emergency_*.json"))
            emergency.write_text("{not-json", encoding="utf-8")
            recovered = recover_emergency_spool(settings, now=datetime(2026, 8, 26, 0, 0, 1, tzinfo=timezone.utc))
            self.assertEqual(recovered, ())
            self.assertTrue((settings.paths.emergency_spool_dir / "quarantine" / emergency.name).exists())


if __name__ == "__main__":
    unittest.main()
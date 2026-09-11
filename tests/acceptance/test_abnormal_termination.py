import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ei.hooks.registry import normalize_hook_event
from ei.queue import claim_queue_item, enqueue_receipt
from ei.recovery import reconcile_orphans
from ei.spool import read_spool, write_spool
from ei.key_provider import InMemoryKeyProvider
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


class AbnormalTerminationAcceptanceTests(unittest.TestCase):
    def test_missing_session_end_reconciles_only_new_stable_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.local_state_dir.mkdir(parents=True, exist_ok=True)
            rows = [
                {"host_id": "codex-cli", "source_hash": "sha256:" + "1" * 64, "source_ref_hash": "sha256:" + "2" * 64, "source_kind": "private-reusable", "classification": "private-reusable", "observed_at": "2026-08-26T12:00:00Z"},
                {"host_id": "codex-cli", "source_hash": "sha256:" + "3" * 64, "source_ref_hash": "sha256:" + "4" * 64, "source_kind": "private-reusable", "classification": "private-reusable", "observed_at": "not-a-time"},
            ]
            (settings.paths.local_state_dir / "orphan-sources.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            result = reconcile_orphans("codex-cli", None, settings)
            self.assertEqual(result.recovered, 1)
            self.assertEqual(result.parse_deferred, 1)
            self.assertIn("parse_deferred", result.reason_codes)
            self.assertEqual(len(list(settings.paths.event_dir.rglob("*.json"))), 1)
    def test_restart_after_spool_and_claim_preserves_recoverable_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("abnormal", b"a" * 32)
            ref = write_spool("recovered after abnormal termination", "private-reusable", settings, key_provider=key, now=datetime(2026, 8, 26, tzinfo=timezone.utc), spool_id="spool-abnormal")
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"}, settings)
            item = enqueue_receipt(event, ref, settings, now=datetime(2026, 8, 26, tzinfo=timezone.utc))
            claimed = claim_queue_item("worker", settings, datetime(2026, 8, 26, tzinfo=timezone.utc), lease_seconds=1)
            reclaimed = claim_queue_item("restart-worker", settings, datetime(2026, 8, 26, 0, 0, 2, tzinfo=timezone.utc))
            self.assertEqual(reclaimed.queue_id, item.queue_id)
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=datetime(2026, 8, 26, 0, 0, 3, tzinfo=timezone.utc)), b"recovered after abnormal termination")


if __name__ == "__main__":
    unittest.main()
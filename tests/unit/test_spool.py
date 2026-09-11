import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ei.key_provider import InMemoryKeyProvider
from ei.spool import SpoolError, delete_spool, gc_expired_spool, read_spool, spool_health, write_spool
from ei.config import RuntimePaths, Settings


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)

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


class SpoolTests(unittest.TestCase):
    def test_spool_and_emergency_paths_are_outside_git_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            ref = write_spool("allowlisted repository must not contain runtime payload", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-boundary")
            self.assertFalse(ref.spool_id + ".json" in {path.name for path in settings.paths.repo_root.rglob("*.json")})
            self.assertFalse(settings.paths.spool_dir.is_relative_to(settings.paths.repo_root))
            self.assertFalse(settings.paths.emergency_spool_dir.is_relative_to(settings.paths.repo_root))
            self.assertEqual(spool_health(settings).items, 1)

    def test_delete_is_idempotent_and_reason_audit_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            ref = write_spool("delete twice safely", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-delete")
            self.assertTrue(delete_spool(ref, settings, reason_code="NO_DISCARDED"))
            self.assertFalse(delete_spool(ref, settings, reason_code="NO_DISCARDED"))
            audit = (settings.paths.runtime_dir / "spool-audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("delete twice safely", audit)
            self.assertNotIn(str(settings.paths.runtime_dir), audit)
            self.assertIn("NO_DISCARDED", audit)

    def test_expiry_gc_deletes_expired_items_and_keeps_live_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            expired = write_spool("expired gc item", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=1, spool_id="spool-gc-expired")
            live = write_spool("live gc item", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=60, spool_id="spool-gc-live")
            self.assertEqual(gc_expired_spool(settings, now=NOW + timedelta(seconds=2)), 1)
            with self.assertRaisesRegex(SpoolError, "SPOOL_NOT_FOUND"):
                read_spool(expired, settings, key_provider=key, now=NOW + timedelta(seconds=2))
            self.assertEqual(read_spool(live, settings, key_provider=key, now=NOW + timedelta(seconds=2)), b"live gc item")


if __name__ == "__main__":
    unittest.main()
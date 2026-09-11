import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.config import load_settings
from ei.maintainer import run_maintenance, team_status_snapshot
from ei.team_store import initialize_team_store


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


class TeamStoreRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        engine = root / "engine"
        (engine / "config").mkdir(parents=True)
        (engine / "config" / "defaults.json").write_text(
            json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
            encoding="utf-8",
        )
        self.shared = root / "shared-team"
        self.descriptor = initialize_team_store(
            self.shared,
            now=NOW,
            random_id=lambda: "a" * 16,
        )
        self.settings = load_settings(
            None,
            root / "codex",
            engine_root=engine,
            personal_knowledge_root=root / "personal",
            team_knowledge_root=self.shared,
            runtime_root=root / "runtime",
        )

    def test_maintenance_refreshes_recovered_team_store_without_personal_failure(self):
        first = run_maintenance(self.settings, now=NOW, time_budget_ms=5000)
        second = run_maintenance(self.settings, now=NOW, time_budget_ms=5000)
        self.assertEqual(first.status, "success")
        self.assertEqual(first.team["status"], "READY")
        self.assertEqual(second.team["status"], "READY")
        self.assertEqual(second.team["accepted_event_count"], 0)
        self.assertNotIn(str(self.shared), json.dumps(second.to_dict()))

    def test_multiple_writer_shards_raise_health_warning_only(self):
        writers = self.shared / "members" / "member-a" / "writers"
        (writers / ("writer_" + "1" * 16) / "events").mkdir(parents=True)
        (writers / ("writer_" + "2" * 16) / "events").mkdir(parents=True)
        snapshot = team_status_snapshot(self.settings)
        self.assertEqual(snapshot["status"], "READY")
        self.assertIn("TEAM_MEMBER_ID_REUSED", snapshot["issue_codes"])
        self.assertNotIn("member-a", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()

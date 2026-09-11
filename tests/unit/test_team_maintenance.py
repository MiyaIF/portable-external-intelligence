import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.config import load_settings
from ei.doctor import run_doctor
from ei.maintainer import run_maintenance, team_status_snapshot


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


class TeamServicesSpy:
    def __init__(self):
        self.calls = []

    def drain_outbox(self, settings, *, max_items, now):
        self.calls.append(("drain_outbox", settings, max_items, now))
        return {"status": "EMPTY", "attempted": 0, "delivered": 0, "deferred": 0, "failed": 0, "remaining": 0}

    def refresh_projection(self, shared_root, runtime_root, store_id):
        self.calls.append(("refresh_projection", shared_root, runtime_root, store_id))
        return {"status": "UNCHANGED", "accepted_event_count": 0, "issues": ()}


class TeamMaintenanceTests(unittest.TestCase):
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
        self.personal_settings = load_settings(
            None,
            root / "codex-personal",
            engine_root=engine,
            personal_knowledge_root=root / "personal",
            runtime_root=root / "runtime-personal",
        )
        self.team_settings = load_settings(
            None,
            root / "codex-team",
            engine_root=engine,
            personal_knowledge_root=root / "personal-team",
            team_knowledge_root=root / "shared-team-offline",
            runtime_root=root / "runtime-team",
        )

    def test_maintenance_offline_team_keeps_personal_success(self):
        result = run_maintenance(self.team_settings, now=NOW, time_budget_ms=5000)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.personal["status"], "READY")
        self.assertEqual(result.team["status"], "DEFERRED")
        self.assertEqual(result.team["reason_code"], "DEFERRED_TEAM_STORE")
        self.assertEqual(result.to_dict()["knowledge_stores"]["team"]["status"], "DEFERRED")

    def test_disabled_maintenance_does_not_touch_team(self):
        team_spy = TeamServicesSpy()
        result = run_maintenance(self.personal_settings, now=NOW, team_services=team_spy)
        self.assertEqual(result.team, {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
        self.assertEqual(team_spy.calls, [])

    def test_team_status_never_returns_raw_root(self):
        snapshot = team_status_snapshot(self.team_settings)
        self.assertEqual(snapshot["status"], "DEFERRED")
        self.assertNotIn(str(self.team_settings.paths.team_knowledge_root), json.dumps(snapshot))

    def test_doctor_keeps_team_deferred_separate_from_personal(self):
        report = run_doctor(self.team_settings, strict=False)
        stores = report.to_dict()["knowledge_stores"]
        self.assertEqual(stores["personal"]["status"], "READY")
        self.assertEqual(stores["team"]["status"], "DEFERRED")


if __name__ == "__main__":
    unittest.main()

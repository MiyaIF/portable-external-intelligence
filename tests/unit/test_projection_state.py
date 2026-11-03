import importlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from ei.doctor import _projection_check
from ei.index import build_index
from ei.journal import append_event
from ei.models import Event
from ei.project import project_events
from tests.unit.test_queue import make_isolated_hook_settings


def observation(identity="one", claim="確認する", timestamp="2026-01-01T00:00:00+00:00"):
    return Event.create("observation.recorded", timestamp, "test", "test",
                        {"observation_id": "obs_" + identity, "claim": claim,
                         "title": "確認", "classification": "private-reusable"},
                        event_id="evt_" + identity)


class ProjectionStateTests(unittest.TestCase):
    def test_disabled_scheduler_stays_disabled_even_after_successful_manual_run(self):
        module = importlib.import_module("ei.doctor")
        self.assertTrue(hasattr(module, "maintenance_status"), "automatic maintenance status is missing")
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.runtime_dir.mkdir(parents=True)
            health_path = settings.paths.runtime_dir / "health.json"
            health_path.write_text(json.dumps({"status": "success"}), encoding="utf-8")
            before = health_path.read_bytes()
            result = module.maintenance_status(settings, {"scheduler_requested": False})
            self.assertEqual(result["status"], "DISABLED")
            self.assertEqual(result["reason_code"], "AUTOMATIC_MAINTENANCE_DISABLED")
            self.assertEqual(result["last_recorded_status"], "success")
            self.assertEqual(health_path.read_bytes(), before)

    def state_module(self):
        self.assertIsNotNone(importlib.util.find_spec("ei.projection_state"), "projection freshness is missing")
        return importlib.import_module("ei.projection_state")

    def test_fingerprint_detects_late_events_and_same_count_changes(self):
        module = self.state_module()
        first = observation()
        late = observation("late", timestamp="2025-01-01T00:00:00+00:00")
        initial = module.projection_source_state([first])
        for changed in ([first, late], [observation(claim="変更後の確認")]):
            self.assertEqual(module.projection_freshness(initial, module.projection_source_state(changed)), "STALE")
        self.assertEqual(module.projection_source_state([first, late]), module.projection_source_state([late, first]))

    def test_audits_do_not_make_projection_stale_and_legacy_is_unknown(self):
        module = self.state_module()
        event = observation()
        audit = Event.create("maintenance.audit", event.occurred_at, "test", "test", {}, event_id="evt_audit")
        current = module.projection_source_state([event])
        self.assertEqual(module.projection_freshness(current, module.projection_source_state([event, audit])), "CURRENT")
        self.assertEqual(module.projection_freshness(None, current), "UNKNOWN")
        self.assertEqual(module.projection_source_state([])["event_count"], 0)

    def test_generated_index_records_same_snapshot_for_one_shot_iterable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events(iter([observation()]), root)
            doc = json.loads((root / "index.json").read_text(encoding="utf-8"))
            self.assertIn("source_state", doc)
            self.assertEqual(doc["source_state"]["event_count"], 1)
            self.assertEqual(doc["observation_ids"], ["obs_one"])

    def test_invalid_checkpoint_is_rejected_but_legacy_index_remains_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([], root)
            path = root / "index.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc.pop("source_state", None)
            path.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(build_index(root, path).observation_count, 0)
            for invalid in (None, {}, {"schema_version": True, "event_count": 0, "digest": "sha256:" + "a" * 64},
                            {"schema_version": 1, "event_count": -1, "digest": "sha256:" + "a" * 64}):
                with self.subTest(invalid=invalid):
                    path.write_text(json.dumps({**doc, "source_state": invalid}), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "PROJECTION_SOURCE_STATE_INVALID"):
                        build_index(root, path)

    def test_doctor_detects_unprojected_event_without_repairing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            event = observation()
            append_event(event, settings.paths.event_dir)
            project_events([], settings.paths.knowledge_dir)
            index_path = settings.paths.knowledge_dir / "index.json"
            before = index_path.read_bytes()
            report = _projection_check(settings, True, 1)
            self.assertFalse(report["ok"])
            self.assertEqual(report["reason_code"], "PROJECTION_STALE")
            self.assertEqual(report["freshness"], "STALE")
            self.assertEqual(index_path.read_bytes(), before)

    def test_missing_journal_is_not_healthy_just_because_event_count_is_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            project_events([observation()], settings.paths.knowledge_dir)
            report = _projection_check(settings, True, 0)
            self.assertFalse(report["ok"])
            self.assertEqual(report["freshness"], "STALE")

    def test_interrupted_manifest_publication_is_not_a_valid_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([], root)
            previous_manifest = (root / "manifest.json").read_bytes()
            project_events([observation()], root)
            (root / "manifest.json").write_bytes(previous_manifest)
            with self.assertRaisesRegex(ValueError, "PROJECTION_MANIFEST_MISMATCH"):
                build_index(root, root / "index.json")


if __name__ == "__main__":
    unittest.main()

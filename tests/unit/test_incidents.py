import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from ei.incidents import IncidentStateError, notification_due, update_incidents
from ei.operation_health import HealthIssue
from tests.unattended_helpers import NOW, make_settings


def issue(reason: str, component: str, severity: str = "error", pending: int = 1) -> HealthIssue:
    return HealthIssue(reason, component, severity, pending)


class IncidentTests(unittest.TestCase):
    def test_legacy_count_is_unknown_without_mutating_fault_or_delivery(self):
        from ei.incidents import inspect_incidents
        stored = update_incidents(self.settings, (issue("AUTH_FAILED", "organizer", pending=8),), now=NOW)[0]
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        document = json.loads(path.read_bytes())
        document["incidents"][0].pop("pending_count_status", None)
        path.write_text(json.dumps(document), encoding="utf-8")
        before = path.read_bytes()
        row = inspect_incidents(self.settings)["incidents"][0]
        self.assertIsNone(row["pending_count"])
        self.assertEqual(row["pending_count_status"], "UNKNOWN")
        for field in ("incident_id", "reason_code", "delivery", "notification_generation", "occurrence_generation"):
            self.assertEqual(row[field], stored[field])
        self.assertEqual(path.read_bytes(), before)

    def test_storage_reason_survives_durable_incident_and_lease(self):
        from ei.incidents import claim_notification
        try:
            value = HealthIssue("RUNTIME_MEMBERSHIP_UNKNOWN", "pending-store", "error", None, "UNKNOWN")
        except (TypeError, ValueError) as exc:
            self.fail(f"unknown custody issue unavailable: {type(exc).__name__}")
        stored = update_incidents(self.settings, (value,), now=NOW)[0]
        self.assertEqual(stored["reason_family"], "STORAGE_FAILURE")
        self.assertEqual(stored["reason_code"], "RUNTIME_MEMBERSHIP_UNKNOWN")
        lease = claim_notification(self.settings, stored["incident_id"], channel="os", session_hash=None, now=NOW)
        self.assertIsNone(lease.pending_count)
        self.assertEqual(lease.pending_count_status, "UNKNOWN")

    def test_nested_delivery_history_cannot_bypass_read_budget(self):
        from ei.incidents import inspect_incidents
        incident = update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)[0]
        self._update_delivery(incident["incident_id"], "cli", successful_sessions=["session-" + str(i) for i in range(500)])
        class WorkBudget:
            checks = 0
            def check(self):
                self.checks += 1
                if self.checks > 10:
                    raise TimeoutError()
        self.assertEqual(inspect_incidents(self.settings, budget=WorkBudget())["status"], "UNKNOWN")

    def test_contended_incident_update_preserves_prior_document(self):
        from ei.operation_runtime import OperationBudget
        from ei.incidents import _state_root, _acquire, _release
        import time
        update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        before = path.read_bytes()
        descriptor = _acquire(_state_root(self.settings))
        try:
            started = time.monotonic()
            with self.assertRaises((TimeoutError, IncidentStateError)):
                update_incidents(self.settings, (issue("CAPACITY_RISK", "pending-store"),), now=NOW,
                                 budget=OperationBudget(30))
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(path.read_bytes(), before)
        finally:
            _release(descriptor)

    def test_readonly_missing_or_corrupt_cache_never_creates_state(self):
        from ei.incidents import inspect_incidents
        before = list(self.root.rglob("*"))
        result = inspect_incidents(self.settings)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(list(self.root.rglob("*")), before)
        update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        path.write_text("{", encoding="utf-8")
        before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(inspect_incidents(self.settings)["status"], "UNKNOWN")
        self.assertEqual({p: (p.stat().st_mtime_ns, p.read_bytes()) for p in self.root.rglob("*") if p.is_file()}, before)

    def test_expired_update_budget_preserves_persisted_incident(self):
        from ei.operation_runtime import OperationBudget
        update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        before = path.read_bytes()
        with self.assertRaises(TimeoutError):
            update_incidents(self.settings, (issue("CAPACITY_RISK", "pending-store"),), now=NOW,
                             budget=OperationBudget(0))
        self.assertEqual(path.read_bytes(), before)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = make_settings(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def _update_delivery(self, incident_id: str, channel: str = "os", **changes):
        state_path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        document = json.loads(state_path.read_text(encoding="utf-8"))
        incident = next(item for item in document["incidents"] if item["incident_id"] == incident_id)
        incident["delivery"][channel].update(changes)
        state_path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

    def test_restart_preserves_detection_and_absence_does_not_resolve(self):
        first = update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)[0]
        second = update_incidents(self.settings, (), now=NOW + timedelta(hours=2))[0]
        third = update_incidents(
            self.settings,
            (issue("AUTH_FAILED", "organizer", pending=3),),
            now=NOW + timedelta(hours=3),
        )[0]
        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertEqual(second["status"], "OPEN")
        self.assertEqual(third["detected_at"], first["detected_at"])
        self.assertEqual(third["last_observed_at"], "2026-09-18T03:00:00Z")
        self.assertEqual(third["pending_count"], 3)

    def test_only_exact_verified_incident_resolves_and_loss_history_remains(self):
        incidents = update_incidents(
            self.settings,
            (
                issue("SOURCE_UNAVAILABLE", "source-a", "critical"),
                issue("SOURCE_UNAVAILABLE", "source-b", "critical"),
                issue("PENDING_EXPIRED", "sha256:" + "a" * 64, "critical"),
            ),
            now=NOW,
        )
        by_component = {item["component_id"]: item for item in incidents}
        self.assertEqual(by_component["source-a"]["reason_code"], "SOURCE_UNAVAILABLE")
        updated = update_incidents(
            self.settings,
            (),
            now=NOW + timedelta(minutes=1),
            verified_resolutions=(by_component["source-a"]["incident_id"], "inc_unrelated"),
        )
        status = {item["component_id"]: item["status"] for item in updated}
        self.assertEqual(status["source-a"], "RESOLVED")
        self.assertEqual(status["source-b"], "OPEN")
        self.assertEqual(status["sha256:" + "a" * 64], "HISTORICAL")

    def test_expiry_does_not_resolve_cleanup_fault_for_the_same_capture(self):
        capture = "sha256:" + "b" * 64
        incidents = update_incidents(
            self.settings,
            (
                issue("PENDING_EXPIRED", capture, "critical"),
                issue("EXPIRY_CLEANUP_FAILED", capture, "error"),
            ),
            now=NOW,
        )
        self.assertEqual(
            {(item["reason_code"], item["status"]) for item in incidents},
            {("PENDING_EXPIRED", "HISTORICAL"), ("EXPIRY_CLEANUP_FAILED", "OPEN")},
        )
        repeated = update_incidents(
            self.settings,
            (issue("PENDING_EXPIRED", capture, "critical"),),
            now=NOW + timedelta(hours=1),
        )
        cleanup = next(item for item in repeated if item["reason_code"] == "EXPIRY_CLEANUP_FAILED")
        self.assertEqual(cleanup["status"], "OPEN")

    def test_notification_boundaries_escalation_and_cli_session(self):
        incident = update_incidents(
            self.settings,
            (issue("CAPACITY_RISK", "pending-store", "warning"),),
            now=NOW,
        )[0]
        self.assertTrue(notification_due(incident, channel="os", session_hash=None, now=NOW))
        incident["delivery"]["os"].update(
            {
                "last_attempt_at": "2026-09-18T00:00:00Z",
                "last_success_at": "2026-09-18T00:00:00Z",
                "last_result": "SUCCESS",
                "success_generation": 1,
            }
        )
        self.assertFalse(notification_due(incident, channel="os", session_hash=None, now=NOW + timedelta(hours=23, minutes=59, seconds=59)))
        self.assertTrue(notification_due(incident, channel="os", session_hash=None, now=NOW + timedelta(hours=24)))
        incident["severity"] = "error"
        incident["notification_generation"] = 2
        self.assertTrue(notification_due(incident, channel="os", session_hash=None, now=NOW + timedelta(minutes=5)))

        incident["delivery"]["os"].update(
            {"last_attempt_at": "2026-09-18T00:05:00Z", "last_result": "FAILED"}
        )
        self.assertFalse(notification_due(incident, channel="os", session_hash=None, now=NOW + timedelta(hours=1, minutes=4, seconds=59)))
        self.assertTrue(notification_due(incident, channel="os", session_hash=None, now=NOW + timedelta(hours=1, minutes=5)))
        self.assertTrue(notification_due(incident, channel="cli", session_hash="session-a", now=NOW))
        incident["delivery"]["cli"]["successful_sessions"] = ["session-a"]
        self.assertFalse(notification_due(incident, channel="cli", session_hash="session-a", now=NOW))
        self.assertTrue(notification_due(incident, channel="cli", session_hash="session-b", now=NOW))

    def test_recovery_notifies_once_only_when_the_open_incident_was_notified(self):
        base = update_incidents(self.settings, (issue("AUTH_FAILED", "organizer"),), now=NOW)[0]
        base["delivery"]["os"].update(
            {
                "last_attempt_at": "2026-09-18T00:00:00Z",
                "last_success_at": "2026-09-18T00:00:00Z",
                "last_result": "SUCCESS",
                "success_generation": 1,
            }
        )
        resolved = dict(base)
        resolved["status"] = "RESOLVED"
        resolved["resolved_at"] = "2026-09-18T00:01:00Z"
        resolved["notification_generation"] = 2
        self.assertTrue(notification_due(resolved, channel="os", session_hash=None, now=NOW + timedelta(minutes=1)))
        resolved["delivery"] = json.loads(json.dumps(base["delivery"]))
        resolved["delivery"]["os"]["success_generation"] = 2
        self.assertFalse(notification_due(resolved, channel="os", session_hash=None, now=NOW + timedelta(minutes=2)))

        never_notified = dict(resolved)
        never_notified["delivery"] = json.loads(json.dumps(base["delivery"]))
        never_notified["delivery"]["os"].update(
            {"last_attempt_at": None, "last_success_at": None, "last_result": None, "success_generation": 0}
        )
        self.assertFalse(notification_due(never_notified, channel="os", session_hash=None, now=NOW))

    def test_concurrent_updates_preserve_both_incidents(self):
        def record(component: str):
            return update_incidents(
                self.settings,
                (issue("SOURCE_UNAVAILABLE", component, "critical"),),
                now=NOW,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(record, ("source-a", "source-b")))
        persisted = update_incidents(self.settings, (), now=NOW)
        self.assertEqual({item["component_id"] for item in persisted}, {"source-a", "source-b"})

    def test_retained_count_growth_is_quiet_but_new_source_identity_is_due(self):
        initial = update_incidents(
            self.settings,
            (issue("SOURCE_UNAVAILABLE", "source-a", "critical", pending=1),),
            now=NOW,
        )[0]
        self._update_delivery(
            initial["incident_id"],
            last_attempt_at="2026-09-18T00:00:00Z",
            last_success_at="2026-09-18T00:00:00Z",
            last_result="SUCCESS",
            success_generation=1,
        )
        updated = update_incidents(
            self.settings,
            (
                issue("SOURCE_UNAVAILABLE", "source-a", "critical", pending=2),
                issue("SOURCE_UNAVAILABLE", "source-b", "critical", pending=2),
            ),
            now=NOW + timedelta(minutes=5),
        )
        by_source = {item["component_id"]: item for item in updated}
        self.assertEqual(by_source["source-a"]["notification_generation"], 1)
        self.assertEqual(by_source["source-a"]["pending_count"], 2)
        self.assertFalse(
            notification_due(by_source["source-a"], channel="os", session_hash=None, now=NOW + timedelta(minutes=5))
        )
        self.assertTrue(
            notification_due(by_source["source-b"], channel="os", session_hash=None, now=NOW + timedelta(minutes=5))
        )

    def test_reopened_provider_incident_uses_current_observation_and_keeps_failed_attempt_throttle(self):
        opened = update_incidents(
            self.settings,
            (issue("AUTH_FAILED", "organizer", "error"),),
            now=NOW,
        )[0]
        self._update_delivery(
            opened["incident_id"],
            last_attempt_at="2026-09-18T00:00:00Z",
            last_success_at="2026-09-18T00:00:00Z",
            last_result="SUCCESS",
            success_generation=1,
        )
        self._update_delivery(
            opened["incident_id"],
            channel="cli",
            last_attempt_at="2026-09-18T00:00:00Z",
            last_success_at="2026-09-18T00:00:00Z",
            last_result="SUCCESS",
            success_generation=1,
            successful_sessions=["session-a"],
        )
        resolved = update_incidents(
            self.settings,
            (),
            now=NOW + timedelta(minutes=1),
            verified_resolutions=(opened["incident_id"],),
        )[0]
        self.assertEqual((resolved["status"], resolved["notification_generation"]), ("RESOLVED", 2))
        self._update_delivery(
            opened["incident_id"],
            last_attempt_at="2026-09-18T00:02:00Z",
            last_result="FAILED",
        )
        self._update_delivery(
            opened["incident_id"],
            channel="cli",
            last_attempt_at="2026-09-18T00:02:00Z",
            last_result="FAILED",
        )

        transient = update_incidents(
            self.settings,
            (issue("RATE_LIMITED", "organizer", "info"),),
            now=NOW + timedelta(minutes=3),
        )[0]
        self.assertEqual(
            (transient["status"], transient["reason_code"], transient["severity"]),
            ("OPEN", "RATE_LIMITED", "info"),
        )
        self.assertEqual(transient["delivery"]["os"]["last_result"], "FAILED")
        self.assertFalse(
            notification_due(transient, channel="os", session_hash=None, now=NOW + timedelta(minutes=3))
        )

        actionable = update_incidents(
            self.settings,
            (issue("MALFORMED_RESPONSE", "organizer", "error"),),
            now=NOW + timedelta(minutes=4),
        )[0]
        self.assertEqual((actionable["reason_code"], actionable["severity"]), ("MALFORMED_RESPONSE", "error"))
        self.assertFalse(
            notification_due(actionable, channel="os", session_hash=None, now=NOW + timedelta(minutes=59))
        )
        self.assertFalse(
            notification_due(actionable, channel="cli", session_hash="session-a", now=NOW + timedelta(minutes=59))
        )
        self.assertTrue(
            notification_due(actionable, channel="os", session_hash=None, now=NOW + timedelta(hours=1, minutes=2))
        )
        self.assertTrue(
            notification_due(
                actionable,
                channel="cli",
                session_hash="session-a",
                now=NOW + timedelta(hours=1, minutes=2),
            )
        )

    def test_quiet_recurrence_recovery_is_not_notified_from_a_prior_occurrence_success(self):
        opened = update_incidents(
            self.settings,
            (issue("AUTH_FAILED", "organizer", "error"),),
            now=NOW,
        )[0]
        for channel in ("os", "cli"):
            changes = {
                "last_attempt_at": "2026-09-18T00:00:00Z",
                "last_success_at": "2026-09-18T00:00:00Z",
                "last_result": "SUCCESS",
                "success_generation": 1,
            }
            if channel == "cli":
                changes["successful_sessions"] = ["session-a"]
            self._update_delivery(opened["incident_id"], channel=channel, **changes)

        update_incidents(
            self.settings,
            (),
            now=NOW + timedelta(minutes=1),
            verified_resolutions=(opened["incident_id"],),
        )
        for channel in ("os", "cli"):
            self._update_delivery(
                opened["incident_id"],
                channel=channel,
                last_attempt_at="2026-09-18T00:02:00Z",
                last_result="FAILED",
            )
        transient = update_incidents(
            self.settings,
            (issue("RATE_LIMITED", "organizer", "info"),),
            now=NOW + timedelta(minutes=3),
        )[0]
        quiet_recovery = update_incidents(
            self.settings,
            (),
            now=NOW + timedelta(minutes=4),
            verified_resolutions=(transient["incident_id"],),
        )[0]
        self.assertEqual((quiet_recovery["status"], quiet_recovery["notification_generation"]), ("RESOLVED", 4))
        self.assertEqual(quiet_recovery["delivery"]["os"]["success_generation"], 1)
        self.assertEqual(quiet_recovery["delivery"]["os"]["last_success_at"], "2026-09-18T00:00:00Z")
        self.assertFalse(
            notification_due(
                quiet_recovery,
                channel="os",
                session_hash=None,
                now=NOW + timedelta(hours=1, minutes=2),
            )
        )
        self.assertFalse(
            notification_due(
                quiet_recovery,
                channel="cli",
                session_hash="session-a",
                now=NOW + timedelta(hours=1, minutes=2),
            )
        )

    def test_state_and_schema_exclude_free_text_and_paths(self):
        incident = update_incidents(
            self.settings,
            (issue("OPERATION_FAILED", "organizer"),),
            now=NOW,
        )[0]
        state_path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        raw = state_path.read_text(encoding="utf-8")
        schema = json.loads(
            (Path(__file__).parents[2] / "schemas" / "operation-incident.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertTrue(set(schema["required"]).issubset(incident))
        self.assertNotIn(str(self.settings.paths.runtime_dir), raw)
        self.assertNotIn("message", schema["properties"])
        self.assertNotIn("path", schema["properties"])

    def test_actual_read_is_bounded_when_file_size_metadata_is_stale(self):
        update_incidents(self.settings, (), now=NOW)
        state_path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        state_path.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
        real_stat = Path.stat

        class StaleStat:
            def __init__(self, value):
                self._value = value

            def __getattr__(self, name: str):
                return 1 if name == "st_size" else getattr(self._value, name)

        def stale_small_stat(path: Path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if path == state_path:
                return StaleStat(result)
            return result

        with patch.object(Path, "stat", stale_small_stat):
            with self.assertRaisesRegex(IncidentStateError, "^INCIDENT_STATE_TOO_LARGE$"):
                update_incidents(self.settings, (), now=NOW)

    def test_legacy_state_without_occurrence_marker_is_upgraded_on_update(self):
        created = update_incidents(
            self.settings,
            (issue("AUTH_FAILED", "organizer", "error"),),
            now=NOW,
        )[0]
        self._update_delivery(
            created["incident_id"],
            last_attempt_at="2026-09-18T00:00:00Z",
            last_success_at="2026-09-18T00:00:00Z",
            last_result="SUCCESS",
            success_generation=1,
        )
        update_incidents(
            self.settings,
            (),
            now=NOW + timedelta(minutes=1),
            verified_resolutions=(created["incident_id"],),
        )
        state_path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        document = json.loads(state_path.read_text(encoding="utf-8"))
        document["incidents"][0].pop("occurrence_generation", None)
        state_path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        upgraded = update_incidents(self.settings, (), now=NOW + timedelta(minutes=2))[0]
        self.assertEqual(upgraded["incident_id"], created["incident_id"])
        self.assertEqual(upgraded["occurrence_generation"], 1)
        self.assertTrue(
            notification_due(upgraded, channel="os", session_hash=None, now=NOW + timedelta(minutes=2))
        )
        persisted = json.loads(state_path.read_text(encoding="utf-8"))["incidents"][0]
        self.assertEqual(persisted["occurrence_generation"], 1)


if __name__ == "__main__":
    unittest.main()

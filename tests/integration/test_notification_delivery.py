import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ei.incidents import (IncidentStateError, abort_notification, claim_notification, notification_due,
                          read_incidents, settle_notification, update_incidents)
from ei.notifications.base import DeliveryResult, deliver_incident
from ei.operation_health import HealthIssue
from tests.unattended_helpers import NOW, make_settings


class NotificationDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = make_settings(Path(self.temp.name))
        self.initial = self.observe()[0]
        self.identifier = self.initial["incident_id"]

    def observe(self, now=NOW, reason="AUTH_FAILED", severity="error"):
        return update_incidents(self.settings, (HealthIssue(reason, "organizer", severity, 3),), now=now)

    def claim(self, now=NOW, channel="os", session_hash=None):
        return claim_notification(self.settings, self.identifier, channel=channel, session_hash=session_hash, now=now)

    def resolve(self, now):
        return update_incidents(self.settings, (), now=now, verified_resolutions=(self.identifier,))[0]

    def state(self):
        return read_incidents(self.settings)[0]

    def test_concurrent_claim_persists_before_send_and_only_one_wins(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            leases = list(executor.map(lambda _: self.claim(), range(2)))
        lease = next(item for item in leases if item is not None)
        self.assertEqual(sum(item is not None for item in leases), 1)
        state = self.state()["delivery"]["os"]
        self.assertEqual(state["last_result"], "UNKNOWN")
        self.assertEqual(state["last_attempt_at"], "2026-09-18T00:00:00Z")
        self.assertEqual(state["lease"]["token"], lease.token)
        self.assertIsNone(self.claim(NOW + timedelta(minutes=59, seconds=59)))
        self.assertIsNotNone(self.claim(NOW + timedelta(hours=1)))

    def test_api_acceptance_is_not_display_evidence_and_daily_throttle_survives_restart(self):
        lease = self.claim()
        self.assertTrue(settle_notification(self.settings, lease, DeliveryResult("SENT", "OS_ACCEPTED", "42"), now=NOW))
        state = self.state()["delivery"]["os"]
        self.assertEqual((state["last_result"], state["last_status"], state["display_status"]), ("SUCCESS", "SENT", "UNVERIFIED"))
        self.assertEqual(state["success_generation"], 1)
        self.assertIsNone(self.claim(NOW + timedelta(hours=23, minutes=59, seconds=59)))
        self.assertIsNotNone(self.claim(NOW + timedelta(hours=24)))

    def test_unknown_crash_retry_rejects_old_token_and_never_records_old_success(self):
        old = self.claim()
        new = self.claim(NOW + timedelta(hours=1))
        self.assertFalse(settle_notification(self.settings, old, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW + timedelta(hours=1)))
        self.assertEqual(self.state()["delivery"]["os"]["lease"]["token"], new.token)
        self.assertEqual(self.state()["delivery"]["os"]["success_generation"], 0)

    def test_stale_delivery_after_resolve_reopen_cannot_prove_current_recovery(self):
        old = self.claim()
        self.resolve(NOW + timedelta(minutes=1))
        self.observe(NOW + timedelta(minutes=2), "RATE_LIMITED", "info")
        self.assertFalse(settle_notification(self.settings, old, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW + timedelta(minutes=3)))
        state = self.resolve(NOW + timedelta(minutes=4))
        self.assertEqual(state["occurrence_generation"], 3)
        self.assertEqual(state["delivery"]["os"]["success_generation"], 0)
        self.assertFalse(notification_due(state, channel="os", session_hash=None, now=NOW + timedelta(hours=2)))

    def test_escalation_while_inflight_rejects_stale_success_and_keeps_hour_limit(self):
        old = self.claim()
        self.observe(NOW + timedelta(minutes=1), severity="critical")
        self.assertFalse(settle_notification(self.settings, old, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW + timedelta(minutes=2)))
        self.assertIsNone(self.claim(NOW + timedelta(minutes=59)))
        self.assertIsNotNone(self.claim(NOW + timedelta(hours=1)))

    def test_each_failure_status_is_throttled_across_reopening(self):
        for index, status in enumerate(("FAILED", "DENIED", "UNAVAILABLE")):
            with self.subTest(status=status):
                when = NOW + timedelta(hours=3 * index)
                lease = self.claim(when)
                self.assertTrue(settle_notification(self.settings, lease, DeliveryResult(status, "OS_FAILED"), now=when))
                self.resolve(when + timedelta(minutes=1))
                self.observe(when + timedelta(minutes=2))
                self.assertIsNone(self.claim(when + timedelta(minutes=59)))

    def test_cli_session_is_once_and_os_failure_does_not_fake_cli_success(self):
        lease = self.claim(channel="cli", session_hash="session-a")
        settle_notification(self.settings, lease, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW)
        self.assertIsNone(self.claim(channel="cli", session_hash="session-a"))
        self.assertIsNotNone(self.claim(channel="cli", session_hash="session-b"))

    def test_delivery_calls_adapter_after_durable_claim_and_sanitizes_exceptions(self):
        def send(message, *, timeout_seconds):
            self.assertEqual(self.state()["delivery"]["os"]["last_result"], "UNKNOWN")
            self.assertIn("3件", message.body)
            self.assertLessEqual(timeout_seconds, 2.0)
            raise RuntimeError("private source text")

        with patch("ei.notifications.base.send_native_notification", side_effect=send):
            result = deliver_incident(self.settings, self.identifier, now=NOW)
        self.assertEqual(result, DeliveryResult("FAILED", "OS_FAILED"))
        self.assertEqual(self.state()["delivery"]["os"]["last_result"], "FAILED")
        self.assertIsNone(self.state()["delivery"]["cli"]["last_result"])
        raw = (self.settings.paths.runtime_dir / "state" / "operation-incidents.json").read_text(encoding="utf-8")
        self.assertNotIn("private", raw)

    def test_no_send_on_persist_failure_and_settlement_failure_leaves_unknown(self):
        with patch("ei.incidents._write", side_effect=IncidentStateError("INCIDENT_STATE_WRITE_FAILED")), patch("ei.notifications.base.send_native_notification") as send:
            with self.assertRaises(IncidentStateError):
                deliver_incident(self.settings, self.identifier, now=NOW)
            send.assert_not_called()
        lease = self.claim()
        with patch("ei.incidents._write", side_effect=IncidentStateError("INCIDENT_STATE_WRITE_FAILED")):
            with self.assertRaises(IncidentStateError):
                settle_notification(self.settings, lease, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW)
        self.assertEqual(self.state()["delivery"]["os"]["last_result"], "UNKNOWN")

    def test_closed_schema_and_validator_allow_legacy_but_reject_unowned_lease_fields(self):
        legacy = self.initial
        self.assertTrue(notification_due(legacy, channel="os", session_hash=None, now=NOW))
        self.claim()
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["incidents"][0]["delivery"]["os"]["lease"]["private"] = "text"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(IncidentStateError):
            read_incidents(self.settings)

    def test_budget_exhausted_before_send_restores_unattempted_due_intent(self):
        clock = SimpleNamespace(monotonic=Mock(side_effect=[0.0, 0.0, 0.25]))
        with patch("ei.notifications.base.time", clock), patch("ei.notifications.base.send_native_notification") as send:
            result = deliver_incident(self.settings, self.identifier, now=NOW, timeout_seconds=0.2)
            send.assert_not_called()
        self.assertEqual(result, DeliveryResult("FAILED", "BUDGET_EXHAUSTED"))
        self.assertIsNone(self.state()["delivery"]["os"]["last_result"])
        self.assertIsNone(self.state()["delivery"]["os"]["last_attempt_at"])
        self.assertIsNotNone(self.claim(NOW))

    def test_budget_exhausted_after_send_preserves_acceptance_without_durable_success(self):
        clock = SimpleNamespace(monotonic=Mock(side_effect=[0.0, 0.0, 0.05, 0.21]))
        with patch("ei.notifications.base.time", clock), patch("ei.notifications.base.send_native_notification", return_value=DeliveryResult("SENT", "OS_ACCEPTED")) as send:
            result = deliver_incident(self.settings, self.identifier, now=NOW, timeout_seconds=0.2)
            self.assertAlmostEqual(send.call_args.kwargs["timeout_seconds"], 0.15)
        self.assertEqual(result.status, "SENT")
        state = self.state()["delivery"]["os"]
        self.assertEqual((state["last_result"], state["success_generation"]), ("UNKNOWN", 0))

    def test_other_incident_remains_due_while_first_has_an_unknown_lease(self):
        self.claim()
        values = update_incidents(self.settings, (HealthIssue("SOURCE_UNAVAILABLE", "source-a", "critical", 3),), now=NOW)
        other = next(value for value in values if value["incident_id"] != self.identifier)
        lease = claim_notification(self.settings, other["incident_id"], channel="os", session_hash=None, now=NOW)
        self.assertIsNotNone(lease)

    def test_unknown_without_durable_attempt_is_corrupt(self):
        path = self.settings.paths.runtime_dir / "state" / "operation-incidents.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["incidents"][0]["delivery"]["os"]["last_result"] = "UNKNOWN"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(IncidentStateError):
            read_incidents(self.settings)

    def test_aborting_unstarted_retry_restores_previous_failure_and_unknown_metadata(self):
        old = self.claim()
        settle_notification(self.settings, old, DeliveryResult("FAILED", "OS_TIMEOUT"), now=NOW)
        retry = self.claim(NOW + timedelta(hours=1))
        self.assertTrue(abort_notification(self.settings, retry))
        state = self.state()["delivery"]["os"]
        self.assertEqual((state["last_result"], state["last_attempt_at"]), ("FAILED", "2026-09-18T00:00:00Z"))
        prior_unknown = self.claim(NOW + timedelta(hours=1))
        retry = self.claim(NOW + timedelta(hours=2))
        self.assertTrue(abort_notification(self.settings, retry))
        state = self.state()["delivery"]["os"]
        self.assertEqual((state["last_result"], state["last_attempt_at"]), ("UNKNOWN", "2026-09-18T01:00:00Z"))
        self.assertIsNone(state.get("lease"))
        self.assertFalse(settle_notification(self.settings, prior_unknown, DeliveryResult("SENT", "OS_ACCEPTED"), now=NOW + timedelta(hours=2)))

    def test_aborting_old_generation_or_superseded_token_does_not_restore_state(self):
        old = self.claim()
        current = self.claim(NOW + timedelta(hours=1))
        self.assertFalse(abort_notification(self.settings, old))
        self.assertEqual(self.state()["delivery"]["os"]["lease"]["token"], current.token)
        self.observe(NOW + timedelta(hours=1, minutes=1), severity="critical")
        self.assertFalse(abort_notification(self.settings, current))
        self.assertEqual(self.state()["delivery"]["os"]["last_attempt_at"], "2026-09-18T01:00:00Z")

    def test_failed_abort_persistence_keeps_unknown_lease_and_no_false_success(self):
        lease = self.claim()
        with patch("ei.incidents._write", side_effect=IncidentStateError("INCIDENT_STATE_WRITE_FAILED")):
            with self.assertRaises(IncidentStateError):
                abort_notification(self.settings, lease)
        self.assertEqual(self.state()["delivery"]["os"]["last_result"], "UNKNOWN")
        self.assertEqual(self.state()["delivery"]["os"]["lease"]["token"], lease.token)

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell script guard")
    def test_actual_powershell_registration_guards_with_fixture_reads_only(self):
        executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        if not executable.is_file():
            self.skipTest("Windows PowerShell unavailable")
        script = Path(__file__).parents[2] / "scripts/notifications/windows-toast.ps1"
        record = json.dumps({"schema_version": 1, "app_id": "MiyaIF.ExternalIntelligence",
                             "shortcut_sha256": "a" * 64, "target": str(executable)})
        # Invoke the actual script, replacing only registration filesystem reads.
        # Each fixture stops before COM/WinRT; none reads/writes live registration.
        fixtures = (
            "function Test-Path { return $false }",
            "function Test-Path { return $true }; function Get-Item { [pscustomobject]@{Length=1} }; function Get-Content { 'invalid-json' }",
            "function Test-Path { return $true }; function Get-Item { [pscustomobject]@{Length=1} }; function Get-Content { '" + record.replace("'", "''") + "' }; function Get-FileHash { [pscustomobject]@{Hash='" + "b" * 64 + "'} }",
        )
        for fixture in fixtures:
            code = fixture + "; & '" + str(script).replace("'", "''") + "'"
            result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", code], shell=False, creationflags=0x08000000, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            if result.returncode != 0 and "PSSecurityException" in result.stderr:
                self.skipTest("Existing execution policy denies scripts; no bypass")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "UNAVAILABLE")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()

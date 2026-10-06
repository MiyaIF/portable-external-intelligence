import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dataclasses import asdict

from tests.unattended_helpers import NOW, make_settings


class RemainingBudget:
    remaining = 5000

    def check(self):
        if self.remaining <= 0:
            raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")

    def remaining_ms(self):
        return self.remaining


def cache_fixture(settings, snapshot):
    from ei.operation_runtime import write_operation_snapshot, OperationBudget
    write_operation_snapshot(settings, snapshot, now=NOW, budget=OperationBudget(5000))
    return json.loads((settings.paths.runtime_dir / "operation-health.json").read_text())


class UnattendedOperationTests(unittest.TestCase):
    def _registered_closeout_contexts(self, *, turns=2):
        from ei.closeout_context import validate_adapter_context
        from ei.hook_entry import handle_normalized_hook
        from ei.hooks import registry
        from ei.operation_runtime import OperationBudget
        from tests.unit.test_closeout_context import InstalledAdapterFixture

        fixture = InstalledAdapterFixture(self, turns=turns)
        previous = registry._ADAPTERS.get(fixture.host_id)
        registry._ADAPTERS[fixture.host_id] = fixture.adapter

        def restore_adapter():
            if previous is None:
                registry._ADAPTERS.pop(fixture.host_id, None)
            else:
                registry._ADAPTERS[fixture.host_id] = previous

        self.addCleanup(restore_adapter)
        for event in fixture.events:
            self.assertTrue(handle_normalized_hook(event, fixture.settings, budget=OperationBudget(5000)).continue_work)
        validations = []
        for start in range(0, turns, 2):
            validations.append(validate_adapter_context(
                fixture.settings,
                fixture.host_id,
                fixture.control_for(fixture.events[start : start + 2]),
                budget=OperationBudget(5000),
            ))
            self.assertTrue(validations[-1].valid, validations[-1].reason_code)
        return fixture, tuple(validations)

    def _closeout_yes_changeset(self, validation):
        from ei.curator import curate_candidate
        from ei.operation_runtime import OperationBudget

        context = validation.context
        candidate = {
            "decision": "YES",
            "title": "Verified closeout observation",
            "claim": "This verified closeout result records a reusable observation for the bound work scope.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": ["sha256:" + "a" * 64],
            "provenances": ["sha256:" + "a" * 64, "sha256:" + "c" * 64],
            "scopes": ["cli-agent", "general"],
            "applicability": [context.identity.host_id],
            "domain": "fixture-domain",
            "cwd_fingerprint": context.scope.cwd_hash,
            "source_host_id": context.identity.host_id,
            "source_host_family": "codex-compatible",
            "applicability_scope": "host",
            "applicable_host_ids": [context.identity.host_id],
            "applicable_host_families": [],
        }
        return curate_candidate(candidate, [], None, operation_budget=OperationBudget(5000))

    def _expired_pending_closeout(self):
        from datetime import datetime, timedelta, timezone
        from ei import closeout_association as association
        from ei.closeout_store import CloseoutStore
        from ei.operation_runtime import OperationBudget

        now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        fixture, (validation,) = self._registered_closeout_contexts(turns=2)
        changeset = self._closeout_yes_changeset(validation)
        prepared = association.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash="sha256:" + "b" * 64,
            decision="YES",
            changeset=changeset,
            team_prepared=None,
        )
        result = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=prepared.content_hash,
            prepare=lambda: prepared,
            now=now,
            budget=OperationBudget(30000),
        )
        self.assertEqual((result.knowledge, result.association), ("APPLIED", "PENDING"), repr(result))
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            initial = CloseoutStore(fixture.settings, budget=budget).active_records()[0]
        expiry = datetime.fromisoformat(initial["expires_at"].replace("Z", "+00:00")) + timedelta(seconds=1)
        return fixture, validation, initial, expiry

    def test_lost_cleanup_persists_incident_before_later_cache_write_failure(self):
        from ei import closeout_association as association
        from ei.capture_ledger import read_receipt
        from ei.closeout_store import CloseoutStore
        from ei.incidents import inspect_incidents
        from ei.maintainer import run_maintenance
        from ei.operation_runtime import OperationBudget

        fixture, validation, initial, expiry = self._expired_pending_closeout()
        settings = fixture.settings
        spool_ref = initial["spool_ref"]
        deleted = []
        real_delete = association.delete_spool

        def tracked_delete(ref, owner, *, budget=None):
            result = real_delete(ref, owner, budget=budget)
            deleted.append((ref.to_dict(), result))
            return result

        with (
            patch.object(association, "delete_spool", side_effect=tracked_delete),
            patch("ei.operation_runtime.write_operation_snapshot", side_effect=OSError("operation cache unavailable")),
        ):
            maintenance = run_maintenance(settings, now=expiry, time_budget_ms=60000)

        self.assertTrue(any(row["stage"] == "operation_cache" for row in maintenance.errors))
        self.assertEqual(deleted, [(spool_ref, True)])
        with association._capture_lock(settings, OperationBudget(10000)):
            terminal = CloseoutStore(settings, budget=OperationBudget(10000)).read_record(initial["record_id"])
            self.assertEqual(CloseoutStore(settings, budget=OperationBudget(10000)).active_records(), [])
        self.assertEqual(terminal["status"], "LOST")
        self.assertIsNone(terminal["spool_ref"])
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(settings, target_id).state, "SECURED")
        component = "closeout-loss-" + initial["record_id"][3:]
        incident = next((row for row in inspect_incidents(settings)["incidents"] if row["component_id"] == component), None)
        self.assertIsNotNone(incident, "loss must be durable before cache write")
        self.assertEqual((incident["reason_code"], incident["status"]), ("CLOSEOUT_RECOVERY_LOSS", "OPEN"))
        self.assertIsNone(incident["pending_count"])
        self.assertEqual(incident["pending_count_status"], "UNKNOWN")

    def test_lost_cleanup_handoff_failure_keeps_locator_for_retry_and_cursor_timeout_keeps_incident(self):
        from datetime import timedelta
        from ei import closeout_association as association
        from ei.closeout_store import CloseoutStore
        from ei.incidents import inspect_incidents
        from ei.operation_runtime import OperationBudget

        fixture, validation, initial, expiry = self._expired_pending_closeout()
        settings = fixture.settings
        spool_ref = initial["spool_ref"]
        deleted = []
        real_delete = association.delete_spool

        def tracked_delete(ref, owner, *, budget=None):
            result = real_delete(ref, owner, budget=budget)
            deleted.append((ref.to_dict(), result))
            return result

        with (
            patch.object(association, "delete_spool", side_effect=tracked_delete),
            patch("ei.incidents.update_incidents", side_effect=OSError("incident store unavailable")),
        ):
            failed = association.recover_closeout_associations(
                settings, now=expiry, budget=OperationBudget(30000),
            )
        self.assertEqual(failed["results"][0]["association"], "UNKNOWN")
        self.assertEqual(deleted, [(spool_ref, True)])
        retained = self._active_closeout_record(settings, initial["record_id"])
        self.assertEqual(retained["status"], "LOST")
        self.assertIsNone(retained["spool_ref"])
        component = "closeout-loss-" + initial["record_id"][3:]
        self.assertFalse(any(row["component_id"] == component for row in inspect_incidents(settings)["incidents"]))

        real_recovery = association.recover_closeout_associations
        with patch.object(CloseoutStore, "advance_cursor", side_effect=TimeoutError("cursor budget exhausted")):
            with self.assertRaises(TimeoutError):
                real_recovery(settings, now=expiry, budget=OperationBudget(30000))
        self.assertEqual(deleted, [(spool_ref, True)])
        self.assertEqual(self._active_closeout_record(settings, initial["record_id"])["status"], "LOST")
        with association._capture_lock(settings, OperationBudget(10000)):
            self.assertEqual(CloseoutStore(settings, budget=OperationBudget(10000)).active_records(), [])
        incident = next(row for row in inspect_incidents(settings)["incidents"] if row["component_id"] == component)
        self.assertEqual((incident["reason_code"], incident["status"]), ("CLOSEOUT_RECOVERY_LOSS", "OPEN"))

        empty = real_recovery(settings, now=expiry + timedelta(minutes=2), budget=OperationBudget(30000))
        self.assertEqual(empty["results"], [])
        self.assertEqual(self._active_closeout_record(settings, initial["record_id"])["status"], "LOST")
        incident_after_empty = next(
            row for row in inspect_incidents(settings)["incidents"] if row["component_id"] == component
        )
        self.assertEqual(incident_after_empty["status"], "OPEN")

    def _active_closeout_record(self, settings, record_id):
        from ei.closeout_association import _capture_lock
        from ei.closeout_store import CloseoutStore
        from ei.operation_runtime import OperationBudget

        budget = OperationBudget(10000)
        with _capture_lock(settings, budget):
            return CloseoutStore(settings, budget=budget).read_record(record_id)

    def test_terminal_closeout_loss_survives_empty_healthy_maintenance(self):
        from datetime import datetime, timedelta, timezone
        from ei import closeout_association as association
        from ei.capture_ledger import read_receipt
        from ei.closeout_store import CloseoutStore
        from ei.incidents import inspect_incidents
        from ei.maintainer import run_maintenance
        from ei.operation_runtime import OperationBudget
        from ei.notifications.base import DeliveryResult

        now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        fixture, (validation,) = self._registered_closeout_contexts(turns=2)
        changeset = self._closeout_yes_changeset(validation)
        prepared = association.PreparedCloseout(
            candidate_id=changeset.candidate_id,
            content_hash="sha256:" + "b" * 64,
            decision="YES",
            changeset=changeset,
            team_prepared=None,
        )
        first = association.apply_associated_closeout(
            fixture.settings,
            validation,
            content_hash=prepared.content_hash,
            prepare=lambda: prepared,
            now=now,
            budget=OperationBudget(30000),
        )
        self.assertEqual((first.knowledge, first.association), ("APPLIED", "PENDING"), repr(first))
        budget = OperationBudget(10000)
        with association._capture_lock(fixture.settings, budget):
            store = CloseoutStore(fixture.settings, budget=budget)
            initial = store.active_records()[0]
        expiry = datetime.fromisoformat(initial["expires_at"].replace("Z", "+00:00")) + timedelta(seconds=1)
        record_id = initial["record_id"]
        saved_hash = initial["changeset_hash"]
        saved_application_ref = dict(initial["application_ref"])
        saved_witness = list(initial["witness"])
        settings = fixture.settings
        settings.paths.runtime_root.mkdir(parents=True, exist_ok=True)
        (settings.paths.runtime_root / "automatic-operation.json").write_text(json.dumps({
            "schema_version": 1,
            "settings": {
                "notifications": {"enabled": True, "channel": "os"},
                "initial_test": {"allow_model_test": False, "allow_notification_test": False},
            },
            "evidence": {},
        }), encoding="utf-8")
        real_recovery = association.recover_closeout_associations
        recovery_runs = []

        def record_recovery(*args, **kwargs):
            result = real_recovery(*args, **kwargs)
            recovery_runs.append(result)
            return result

        messages = []

        def send(message, **_kwargs):
            messages.append(message.body)
            return DeliveryResult("SENT", "OS_ACCEPTED")

        with (
            patch("ei.closeout_association.recover_closeout_associations", side_effect=record_recovery),
            patch("ei.notifications.base.send_native_notification", side_effect=send),
            patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("recovery invoked provider")),
            patch("ei.curator.curate_candidate", side_effect=AssertionError("recovery curated again")),
            patch.object(association, "apply_changeset", side_effect=AssertionError("recovery reapplied personal changes")),
        ):
            first_maintenance = run_maintenance(settings, now=expiry, time_budget_ms=60000)

        self.assertEqual(recovery_runs[0]["results"][0]["reason_code"], "CLOSEOUT_CACHE_EXPIRED")
        self.assertEqual(recovery_runs[0]["results"][0]["association"], "PENDING")
        self.assertIn("CLOSEOUT_RECOVERY_LOSS", {row["error_code"] for row in first_maintenance.errors})
        self.assertNotIn("CLOSEOUT_METADATA_UNKNOWN", {row["error_code"] for row in first_maintenance.errors})
        with association._capture_lock(settings, OperationBudget(10000)):
            terminal = CloseoutStore(settings, budget=OperationBudget(10000)).read_record(record_id)
            active_after_loss = CloseoutStore(settings, budget=OperationBudget(10000)).active_records()
        self.assertEqual(terminal["status"], "LOST")
        self.assertIsNone(terminal["spool_ref"])
        self.assertEqual(terminal["changeset_hash"], saved_hash)
        self.assertEqual(terminal["application_ref"], saved_application_ref)
        self.assertEqual(terminal["witness"], saved_witness)
        self.assertEqual(active_after_loss, [])
        for target_id in validation.context.target_ids:
            self.assertEqual(read_receipt(settings, target_id).state, "SECURED")
        incidents_after_loss = inspect_incidents(settings)["incidents"]
        loss = next(row for row in incidents_after_loss if row["reason_code"] == "CLOSEOUT_RECOVERY_LOSS")
        self.assertEqual(loss["status"], "OPEN")
        self.assertTrue(loss["component_id"].startswith("closeout-loss-"))
        self.assertIsNone(loss["pending_count"])
        self.assertEqual(loss["pending_count_status"], "UNKNOWN")
        self.assertNotIn(("CLOSEOUT_METADATA_UNKNOWN", "knowledge-projection"),
            {(row["reason_code"], row["component_id"]) for row in incidents_after_loss})
        self.assertIn("CLOSEOUT_RECOVERY_LOSS", first_maintenance.operation["issues"])
        self.assertTrue(any("期限切れの処理を安全に引き継げませんでした。" in message for message in messages))

        with (
            patch("ei.closeout_association.recover_closeout_associations", side_effect=record_recovery),
            patch("ei.notifications.base.send_native_notification", side_effect=send),
        ):
            second_maintenance = run_maintenance(settings, now=expiry + timedelta(minutes=2), time_budget_ms=60000)
        self.assertEqual(recovery_runs[1]["results"], [])
        loss_after_empty = next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == loss["incident_id"])
        self.assertEqual(loss_after_empty["status"], "OPEN")
        self.assertIsNone(loss_after_empty["resolved_at"])
        self.assertEqual(loss_after_empty["occurrence_generation"], loss["occurrence_generation"])
        self.assertEqual(second_maintenance.operation["notifications_sent"], 0)
        self.assertFalse(any(message.startswith("整理処理の復旧を確認しました。") for message in messages))

    def test_closeout_incident_notifications_do_not_claim_retained_candidate_counts(self):
        from datetime import datetime, timezone
        from ei import closeout_association as association
        from ei.closeout_store import CloseoutStore
        from ei.incidents import claim_notification, settle_notification, update_incidents
        from ei.notifications.base import DeliveryResult, render_notification
        from ei.operation_health import evaluate_health
        from ei.operation_runtime import OperationBudget, collect_operation_snapshot

        now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        for kind in ("preparing", "team-pending", "metadata-unknown"):
            with self.subTest(kind=kind):
                fixture, (validation,) = self._registered_closeout_contexts(turns=2)
                settings = fixture.settings
                budget = OperationBudget(30000)
                content_hash = "sha256:" + "b" * 64
                if kind == "team-pending":
                    changeset = self._closeout_yes_changeset(validation)
                    prepared = association.PreparedCloseout(
                        candidate_id=changeset.candidate_id,
                        content_hash=content_hash,
                        decision="YES",
                        changeset=changeset,
                        team_prepared=None,
                    )
                    result = association.apply_associated_closeout(
                        settings, validation, content_hash=content_hash,
                        prepare=lambda: prepared, now=now, budget=budget,
                    )
                    self.assertEqual((result.knowledge, result.association), ("APPLIED", "PENDING"), repr(result))
                else:
                    with association._capture_lock(settings, budget):
                        intent = association._new_intent(settings, validation, content_hash, now, budget)
                        CloseoutStore(settings, budget=budget).reserve(intent)
                    if kind == "metadata-unknown":
                        index_path = settings.paths.runtime_root / "state" / "closeout-associations" / "index.json"
                        index_path.write_text("{", encoding="utf-8")

                recovery = association.recover_closeout_associations(settings, now=now, budget=OperationBudget(30000))
                snapshot, _ = collect_operation_snapshot(
                    settings, now=now, budget=OperationBudget(30000), closeout_recovery=recovery,
                )
                closeout_issues = tuple(issue for issue in evaluate_health(snapshot, now=now) if issue.component_id == "closeout-store")
                self.assertTrue(closeout_issues)
                incidents = update_incidents(settings, closeout_issues, now=now)
                rows = [row for row in incidents if row["component_id"] == "closeout-store"]
                self.assertTrue(rows)
                for row in rows:
                    lease = claim_notification(
                        settings, row["incident_id"], channel="os", session_hash=None, now=now,
                    )
                    self.assertIsNotNone(lease)
                    message = render_notification(
                        lease.reason_code, lease.pending_count,
                        pending_count_status=lease.pending_count_status,
                    )
                    self.assertIn("未整理候補の件数は未確認です。", message.body)
                    self.assertNotIn("保持済み未整理候補:", message.body)
                    self.assertNotIn("新しい候補の受付を保留しています。", message.body)
                    self.assertTrue(settle_notification(
                        settings, lease, DeliveryResult("FAILED", "OS_FAILED"), now=now,
                    ))

    def test_completed_closeout_resolves_its_pending_incident_not_terminal_loss(self):
        from datetime import datetime, timedelta, timezone
        from ei import closeout_association as association
        from ei.closeout_store import CloseoutStore
        from ei.incidents import inspect_incidents, update_incidents
        from ei.operation_health import HealthIssue, evaluate_health
        from ei.operation_runtime import OperationBudget, collect_operation_snapshot
        from ei.spool import SpoolError
        from ei.maintainer import run_maintenance

        now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        fixture, (validation,) = self._registered_closeout_contexts(turns=2)
        settings = fixture.settings
        loss_component = "closeout-loss-" + "f" * 64
        loss_issue = HealthIssue("CLOSEOUT_RECOVERY_LOSS", loss_component, "critical", None, "UNKNOWN")
        update_incidents(settings, (loss_issue,), now=now)
        content_hash = "sha256:" + "d" * 64
        prepared = association.PreparedCloseout(
            candidate_id="no_result_0",
            content_hash=content_hash,
            decision="NO",
            changeset=None,
            team_prepared={
                "schema_version": 1,
                "status": "NOT_ELIGIBLE",
                "reason_code": "TEAM_DISABLED",
                "normalized_payload": None,
                "team_store_id": "",
                "team_member_id": "",
                "writer_id": "",
                "team_root_hash": None,
                "actor_hash": None,
                "machine_hash": None,
                "prepared_at": now.isoformat().replace("+00:00", "Z"),
            },
        )
        with patch("ei.closeout_association.delete_spool", side_effect=SpoolError("test cleanup retry")):
            first = association.apply_associated_closeout(
                settings, validation, content_hash=content_hash,
                prepare=lambda: prepared, now=now, budget=OperationBudget(30000),
            )
        self.assertEqual((first.knowledge, first.association, first.reason_code),
            ("EVALUATED_NONE", "PENDING", "CLOSEOUT_CLEANUP_PENDING"), repr(first))
        real_recovery = association.recover_closeout_associations
        with patch("ei.closeout_association.delete_spool", side_effect=SpoolError("test recovery retry")):
            pending_recovery = real_recovery(settings, now=now, budget=OperationBudget(30000))
        self.assertEqual(pending_recovery["results"][0]["reason_code"], "CLOSEOUT_CLEANUP_PENDING")
        snapshot, _ = collect_operation_snapshot(
            settings, now=now, budget=OperationBudget(30000), closeout_recovery=pending_recovery,
        )
        pending_issues = tuple(issue for issue in evaluate_health(snapshot, now=now)
            if issue.component_id == "closeout-store")
        self.assertIn("CLOSEOUT_ASSOCIATION_PENDING", {issue.reason_code for issue in pending_issues},
            repr((snapshot, pending_recovery)))
        update_incidents(settings, pending_issues, now=now)
        incidents_before = inspect_incidents(settings)["incidents"]
        pending = next(row for row in incidents_before if row["component_id"] == "closeout-store")
        loss = next(row for row in incidents_before if row["component_id"] == loss_component)
        self.assertIn(pending["reason_code"], {"CLOSEOUT_ASSOCIATION_PENDING", "CLOSEOUT_METADATA_UNKNOWN"})
        self.assertEqual(pending["status"], "OPEN")
        self.assertEqual(loss["status"], "OPEN")

        recovery_runs = []

        def record_recovery(*args, **kwargs):
            result = real_recovery(*args, **kwargs)
            recovery_runs.append(result)
            return result

        with patch("ei.closeout_association.recover_closeout_associations", side_effect=record_recovery):
            run_maintenance(settings, now=now + timedelta(minutes=1), time_budget_ms=60000)
        self.assertEqual(recovery_runs[-1]["results"][0]["association"], "COMMITTED")
        active_budget = OperationBudget(10000)
        with association._capture_lock(settings, active_budget):
            self.assertEqual(CloseoutStore(settings, budget=active_budget).active_records(), [])
        incidents_after = inspect_incidents(settings)["incidents"]
        resolved_pending = next(row for row in incidents_after if row["incident_id"] == pending["incident_id"])
        retained_loss = next(row for row in incidents_after if row["incident_id"] == loss["incident_id"])
        self.assertEqual(resolved_pending["status"], "RESOLVED")
        self.assertEqual(retained_loss["status"], "OPEN")

    def test_hook_outer_error_after_deadline_does_not_start_fresh_diagnostic_write(self):
        from ei.hook_entry import run_hook
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            def interrupted(*args, **kwargs):
                kwargs["budget"].deadline = -1
                raise RuntimeError("private error")
            with patch("ei.hook_entry.handle_normalized_hook", side_effect=interrupted):
                result = run_hook("codex-cli", b'{"hook_event_name":"SessionStart","session_id":"one"}', 1000, settings)
            self.assertTrue(result.continue_work)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_duplicate_queue_reference_is_not_two_authenticated_holdings(self):
        from ei import operation_runtime as runtime, queue
        from ei.key_provider import InMemoryKeyProvider
        from ei.pending_capture import accept_candidate
        from tests.unattended_helpers import identity
        from tests.unit.test_pending_capture import observation
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            accept_candidate(settings, identity(), observation(), now=NOW, key_provider=key)
            original = queue.list_queue_items(settings)[0]
            # Two valid queue metadata entries still reference one ciphertext.
            duplicate_key = "sha256:" + "b" * 64
            duplicate = replace(original, queue_id=queue._new_queue_id(original.event_id, duplicate_key, original.source_host_id), idempotency_key=duplicate_key)
            queue._store(queue._root(settings), duplicate)
            with patch("ei.spool.default_key_provider", return_value=key):
                snapshot, _ = runtime.collect_operation_snapshot(settings, now=NOW, budget=runtime.OperationBudget(5000))
            self.assertEqual(snapshot.pending_count, 1)
            self.assertEqual(snapshot.reserved_count, 1)

    def test_cli_start_native_failure_is_sanitized_fail_open(self):
        from ei.operation_runtime import service_cli_start
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("ei.task_scheduler.inspect_scheduler_opportunities", side_effect=RuntimeError("private diagnostic")):
                result = service_cli_start(settings, now=NOW)
            self.assertEqual(result, {"issues": [], "notifications_sent": 0, "reason_code": "OPERATION_STATE_UNAVAILABLE"})
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_only_verified_scheduler_resumption_resolves_stop_and_not_provider_fault(self):
        from ei.operation_runtime import service_cli_start, settings_binding
        from ei.operation_health import HealthIssue, HealthInput
        from ei.incidents import update_incidents, inspect_incidents
        from tests.unit.test_scheduler_opportunities import sample
        from datetime import timedelta
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            update_incidents(settings, (HealthIssue("SCHEDULER_STOPPED", "scheduler", "error", None, "UNKNOWN"), HealthIssue("AUTH_FAILED", "organizer", "error", None, "UNKNOWN")), now=NOW)
            cache_fixture(settings, HealthInput(provider_code="AUTH_FAILED", provider_id="organizer"))
            settings.paths.install_manifest_path.write_text('{"scheduler_requested":true}')
            previous = sample(last_trigger_us=100_000_000, service_activation_us=100_000_000)
            baseline = settings.paths.runtime_root / "scheduler-opportunities.json"
            baseline.write_text(json.dumps({"schema_version": 1, "binding": settings_binding(settings), "sample": previous}))
            later = NOW + timedelta(seconds=4300)
            current = sample(monotonic_us=4500_000_000, awake_us=4500_000_000, observed_at=later.isoformat(), last_exit="success", activation_us=4000_000_000, last_trigger_us=4000_000_000, service_activation_us=4000_000_000, timers=[["OnUnitActiveUSec", 1800_000_000, 5800_000_000], ["OnUnitActiveUSec", 3600_000_000, 7600_000_000]])
            with patch("ei.task_scheduler._native_scheduler_sample", return_value={**current, "generation": "changed"}):
                service_cli_start(settings, now=later)
            self.assertTrue(all(row["status"] == "OPEN" for row in inspect_incidents(settings)["incidents"]))
            baseline.write_text(json.dumps({"schema_version": 1, "binding": settings_binding(settings), "sample": previous}))
            with patch("ei.task_scheduler._native_scheduler_sample", return_value=current):
                service_cli_start(settings, now=later)
            rows = {row["reason_code"]: row for row in inspect_incidents(settings)["incidents"]}
            self.assertEqual(rows["SCHEDULER_STOPPED"]["status"], "RESOLVED")
            self.assertEqual(rows["AUTH_FAILED"]["status"], "OPEN")

    def test_hook_tracking_deadline_is_not_misclassified_as_storage_failure(self):
        from tests.helpers import make_hook_settings
        from ei.hook_entry import normalize_hook_event, handle_normalized_hook
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "one", "turn_id": "one"}, settings)
            with patch("ei.hook_entry.register_target", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")):
                self.assertEqual(handle_normalized_hook(event, settings).status, "DEADLINE_EXCEEDED")

    def test_cli_maintenance_zero_budget_has_no_lock_log_or_state(self):
        from ei import cli
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("ei.cli._settings", return_value=settings), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["maintain", "--time-budget-ms", "0", "--json"]), cli.EXIT_INTERNAL)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_cli_maintenance_passes_exact_root_original_budget_and_skips_expired_log(self):
        from ei import cli, maintainer, capture_recovery
        from ei.operation_runtime import OperationBudget
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            source = Path(tmp) / "valid.md"
            source.write_text("## Reusable knowledge\n- Verify persisted results before reporting completion.\n", encoding="utf-8")
            budget = OperationBudget(10000)
            self.assertIs(capture_recovery.OperationBudget, OperationBudget)
            def maintain(*args, **kwargs):
                self.assertIs(kwargs.get("budget"), budget)
                self.assertEqual(kwargs["source_paths"], (source,))
                value = maintainer.run_maintenance(*args, **kwargs)
                budget.deadline = -1
                return value
            output = io.StringIO()
            with patch("ei.cli._settings", return_value=settings), patch("ei.operation_runtime.OperationBudget", return_value=budget), patch("ei.cli._source_paths", side_effect=AssertionError("eager discovery")), patch("ei.cli.run_maintenance", side_effect=maintain), redirect_stdout(output):
                cli.main(["maintain", "--source", str(source), "--json"])
            self.assertIs(capture_recovery.OperationBudget, OperationBudget)
            result = json.loads(output.getvalue())
            self.assertEqual(result["ingest_created_events"], 1)
            self.assertEqual(result["log_status"], "UNKNOWN")
            self.assertFalse((settings.paths.log_dir / "maintenance.jsonl").exists())
            self.assertFalse((settings.paths.locks_dir / "maintenance.lock").exists())

    def test_last_attempt_and_progress_survive_custody_expiry_without_promoting_counts(self):
        from ei.maintainer import run_maintenance
        from ei.operation_runtime import operation_status
        from datetime import timedelta
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            selected = Path(tmp) / "valid.md"
            selected.write_text("## Reusable knowledge\n- Verify persisted results before reporting completion.\n", encoding="utf-8")
            initial = run_maintenance(settings, source_paths=(selected,), now=NOW, time_budget_ms=10000)
            self.assertEqual(initial.ingest_created_events, 1)
            later = NOW + timedelta(days=2)
            stale = operation_status(settings, now=later)
            self.assertIsNone(stale["snapshot"]["pending_count"])
            self.assertEqual(stale["last_progress_at"], NOW.isoformat())
            self.assertEqual(stale["last_attempt_at"], NOW.isoformat())
            rerun = run_maintenance(settings, source_paths=(), now=later, time_budget_ms=10000)
            self.assertEqual(rerun.operation["last_progress_at"], NOW.isoformat())
            self.assertEqual(rerun.operation["last_attempt_at"], later.isoformat())

    def test_missing_selected_source_does_not_block_other_source_and_only_same_source_resolves(self):
        from ei.maintainer import run_maintenance
        from ei.incidents import inspect_incidents
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            missing, present = Path(tmp) / "missing.md", Path(tmp) / "present.md"
            present.write_text("## Reusable knowledge\n- Verify saved results before reporting completion.\n", encoding="utf-8")
            first = run_maintenance(settings, source_paths=(missing, present), now=NOW, time_budget_ms=10000)
            self.assertEqual(first.ingest_created_events, 1)
            source = next(row for row in inspect_incidents(settings)["incidents"] if row["reason_code"] == "SOURCE_UNAVAILABLE")
            run_maintenance(settings, source_paths=(present,), now=NOW, time_budget_ms=10000)
            self.assertEqual(next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == source["incident_id"])["status"], "OPEN")
            missing.write_text("## Reusable knowledge\n- Retry verified incomplete storage with the same identity.\n", encoding="utf-8")
            final = run_maintenance(settings, source_paths=(missing, present), now=NOW, time_budget_ms=10000)
            self.assertEqual(final.ingest_created_events, 1)
            self.assertEqual(next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == source["incident_id"])["status"], "RESOLVED")

    def test_explicit_disable_silences_old_stop_without_resolving_it(self):
        from ei.operation_runtime import service_operation
        from ei.operation_health import HealthIssue
        from ei.incidents import update_incidents, inspect_incidents
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            update_incidents(settings, (HealthIssue("SCHEDULER_STOPPED", "scheduler", "error", None, "UNKNOWN"),), now=NOW)
            settings.paths.install_manifest_path.write_text('{"scheduler_requested":false}')
            (settings.paths.runtime_dir / "automatic-operation.json").write_text(json.dumps({"schema_version": 1, "settings": {"notifications": {"enabled": True, "channel": "os"}, "initial_test": {"allow_model_test": False, "allow_notification_test": False}}, "evidence": {}}))
            with patch("ei.notifications.base.send_native_notification", side_effect=AssertionError("disabled scheduler warning")):
                result = service_operation(settings, now=NOW, channel="hook", max_ms=5000)
            self.assertEqual(result["notifications_sent"], 0)
            row = inspect_incidents(settings)["incidents"][0]
            self.assertEqual(row["status"], "OPEN")
            self.assertIsNone(row["delivery"]["os"]["last_attempt_at"])

    def test_cli_status_is_read_only_and_never_probes_provider_or_notifies(self):
        from ei import cli
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            output = io.StringIO()
            with patch("ei.cli._settings", return_value=settings), patch("ei.cli.ProviderRouter", side_effect=AssertionError("status provider probe")), patch("ei.notifications.base.send_native_notification", side_effect=AssertionError("status notification")), redirect_stdout(output):
                code = cli.main(["status", "--json"])
            self.assertEqual(code, 0, output.getvalue())
            value = json.loads(output.getvalue())
            self.assertEqual(value["automatic_operation"]["snapshot_status"], "UNKNOWN")
            self.assertIsNone(value["automatic_operation"]["snapshot"]["last_progress_at"])
            self.assertIsNone(value["automatic_operation"]["snapshot"]["last_attempt_at"])
            self.assertEqual(value["automatic_operation"]["detection_limit"], "NO_DETECTION_WHILE_BOTH_HOOK_AND_SCHEDULER_STOPPED")
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_next_cli_query_detects_two_native_misses_without_scheduler_or_custody_cache(self):
        from ei import cli
        from ei.incidents import inspect_incidents
        from ei.operation_runtime import settings_binding
        from tests.unit.test_scheduler_opportunities import sample
        from datetime import timedelta
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_root.mkdir()
            settings.paths.install_manifest_path.write_text('{"scheduler_requested":true}')
            (settings.paths.runtime_root / "scheduler-opportunities.json").write_text(json.dumps({"schema_version": 1, "binding": settings_binding(settings), "sample": sample()}))
            current = sample(monotonic_us=3800_000_000, awake_us=3800_000_000, observed_at=(NOW + timedelta(hours=1)).isoformat())
            output = io.StringIO()
            with patch("ei.cli._settings", return_value=settings), patch("ei.task_scheduler._native_scheduler_sample", return_value=current), patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("CLI scheduler probe")), redirect_stdout(output):
                code = cli.main(["query", "--prompt", "reusable", "--json"])
            self.assertEqual(code, 0, output.getvalue())
            rows = inspect_incidents(settings)["incidents"]
            self.assertEqual([row["reason_code"] for row in rows], ["SCHEDULER_STOPPED"])
            self.assertIsNone(rows[0]["pending_count"])
            self.assertFalse((settings.paths.runtime_root / "operation-health.json").exists())

    def test_hook_ranking_deadline_prevents_exposure_and_success_writes_in_both_modes(self):
        from dataclasses import replace
        from tests.helpers import make_hook_settings
        from ei.hook_entry import normalize_hook_event, handle_normalized_hook
        from ei import retrieve
        for experiment in (False, True):
            with self.subTest(experiment=experiment), tempfile.TemporaryDirectory() as tmp:
                settings = replace(make_hook_settings(Path(tmp), include_formula_pattern=True), experiment_enabled=experiment)
                event = normalize_hook_event("codex-cli", {"hook_event_name": "UserPromptSubmit", "session_id": "one", "turn_id": "one", "prompt": "formula pattern"}, settings)
                budget = RemainingBudget()
                original = retrieve._bm25
                def expire(*args):
                    result = original(*args)
                    budget.remaining = 0
                    return result
                with patch("ei.retrieve._bm25", side_effect=expire):
                    result = handle_normalized_hook(event, settings, budget=budget)
                self.assertEqual(result.status, "DEADLINE_EXCEEDED")
                self.assertEqual(result.additional_context, "")
                for name in ("retrieval-exposures.jsonl", "experiment-exposures.jsonl", "last-successful-query.jsonl"):
                    self.assertFalse((settings.paths.runtime_dir / name).exists(), name)
                self.assertFalse((settings.paths.local_state_dir / "last-successful-query.json").exists())

    def test_unbound_modern_skill_retains_legacy_event_without_inventing_coverage(self):
        from ei.capture import record_agent_observation
        from ei.models import CaptureContext
        from ei.journal import iter_events
        from tests.unit.test_pending_capture import observation
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            context = CaptureContext("session-one", "turn-one", 1, "codex-cli", "codex-compatible")
            first = record_agent_observation(observation(), context, settings)
            self.assertTrue(first.created, first.reason_code)
            events = list(iter_events(settings.paths.event_dir))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].event_id, first.event_id)
            again = record_agent_observation(observation(), context, settings)
            self.assertEqual(again.reason_code, "IDEMPOTENT_REPLAY")
            self.assertFalse(settings.paths.queue_dir.exists())
            self.assertFalse((settings.paths.runtime_root / "capture-ledger").exists())

    def test_fixed_projection_fault_becomes_storage_incident_and_current_projection_resolves_it(self):
        from ei.maintainer import run_maintenance
        from ei.incidents import inspect_incidents
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("ei.maintainer.project_events", side_effect=ValueError("PROJECTION_GENERATION_UNOWNED")):
                failed = run_maintenance(settings, source_paths=(), now=NOW, time_budget_ms=10000)
            self.assertIn("PROJECTION_GENERATION_UNOWNED", failed.operation["issues"])
            records = inspect_incidents(settings)["incidents"]
            incident = next(row for row in records if row["component_id"] == "knowledge-projection")
            self.assertEqual(incident["reason_family"], "STORAGE_FAILURE")
            healthy = run_maintenance(settings, source_paths=(), now=NOW, time_budget_ms=10000)
            self.assertEqual(healthy.projection["freshness"], "CURRENT")
            self.assertEqual(next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == incident["incident_id"])["status"], "RESOLVED")

    def test_first_empty_custody_collection_is_not_a_storage_failure(self):
        from ei.operation_runtime import collect_operation_snapshot, OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, binding = collect_operation_snapshot(make_settings(Path(tmp)), now=NOW, budget=OperationBudget(5000))
            self.assertIsNone(snapshot.storage_code)
            self.assertEqual(snapshot.pending_count_status, "COMPLETE")
            self.assertEqual(snapshot.pending_count, 0)
            self.assertTrue(binding)

    def test_maintenance_zero_budget_creates_nothing_and_never_enters_a_phase(self):
        from ei.maintainer import run_maintenance
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("builtins.input", side_effect=AssertionError("daily prompt")), patch("ei.maintainer._provider_for", side_effect=AssertionError("provider after deadline")):
                result = run_maintenance(settings, time_budget_ms=0, now=NOW)
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.blocked_reason, "OPERATION_BUDGET_EXHAUSTED")
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_maintenance_helpers_cannot_refresh_budget_or_write_after_expiry(self):
        from ei import maintainer
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            budget = OperationBudget(0)
            with self.assertRaises(TimeoutError):
                maintainer._metric_summary(settings, budget=budget)
            with self.assertRaises(TimeoutError):
                maintainer._write_json(settings.paths.runtime_root / "health.json", {"status": "success"}, budget=budget)
            with self.assertRaises(TimeoutError):
                maintainer._append_audit(settings, "DUPLICATE_OBSERVATION", "test", "DUPLICATE_OBSERVATION", budget=budget)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_missing_provider_config_is_not_reread_without_budget(self):
        from ei.maintainer import _provider_for
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("ei.maintainer.ProviderRouter", side_effect=AssertionError("implicit config reread")):
                value = _provider_for(settings, None, budget=OperationBudget(5000))
            self.assertFalse(value.available())
            self.assertEqual(value.reason_code, "INFERENCE_PROVIDER_CONFIG_READ_FAILED")

    def test_selected_team_helpers_pass_the_original_budget_to_internal_reads(self):
        from ei import maintainer
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            budget = OperationBudget(0)
            services = maintainer._DefaultTeamServices()
            with self.assertRaises(TimeoutError):
                services.drain_outbox(settings, max_items=1, now=NOW, budget=budget)
            with self.assertRaises(TimeoutError):
                services.refresh_projection(Path(tmp) / "shared", settings.paths.runtime_root, "team-test", budget=budget)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_maintenance_phases_share_one_budget_and_run_id_with_no_daily_prompt(self):
        from ei import maintainer, pending_capture, capture_recovery, operation_runtime
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            chosen = Path(tmp) / "valid.md"
            chosen.write_text("## Reusable knowledge\n- Verify persisted results before reporting completion.\n", encoding="utf-8")
            calls, budgets, run_ids = [], [], []
            def watch(name, original):
                def invoke(*args, **kwargs):
                    calls.append(name)
                    budgets.append(kwargs.get("budget"))
                    if name == "queue":
                        run_ids.append(kwargs.get("run_id"))
                    return original(*args, **kwargs)
                return invoke
            with ExitStack() as stack:
                for target, name, original in (("ei.pending_capture.reconcile_pending", "pending", pending_capture.reconcile_pending), ("ei.capture_recovery.recover_page", "source", capture_recovery.recover_page), ("ei.maintainer.drain_queue", "queue", maintainer.drain_queue), ("ei.maintainer.project_events", "projection", maintainer.project_events), ("ei.operation_runtime.collect_operation_snapshot", "health", operation_runtime.collect_operation_snapshot), ("ei.operation_runtime.service_operation", "service", operation_runtime.service_operation)):
                    stack.enter_context(patch(target, side_effect=watch(name, original)))
                stack.enter_context(patch("builtins.input", side_effect=AssertionError("daily prompt")))
                stack.enter_context(patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("empty probe")))
                result = maintainer.run_maintenance(settings, source_paths=(chosen,), now=NOW, time_budget_ms=10000)
            self.assertEqual(calls, ["pending", "source", "queue", "projection", "health", "service"])
            self.assertTrue(all(value is budgets[0] and value is not None for value in budgets))
            self.assertEqual(run_ids, [result.to_dict()["operation"]["run_id"]])
            self.assertEqual(result.projection["freshness"], "CURRENT")
            self.assertEqual(result.ingest_created_events, 1)
            self.assertEqual(result.to_dict()["operation"]["notifications_sent"], 0)
            state = operation_runtime.operation_snapshot(settings, now=NOW)
            self.assertEqual(state.last_attempt_at, NOW)
            self.assertEqual(state.last_progress_at, NOW)

    def test_pending_interior_deadline_stops_all_later_maintenance_phases(self):
        from ei import maintainer, pending_capture
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            original = pending_capture.reconcile_pending
            def expire_after_pending(*args, **kwargs):
                result = original(*args, **kwargs)
                kwargs["budget"].deadline = 0
                return result
            with patch("ei.pending_capture.reconcile_pending", side_effect=expire_after_pending), patch("ei.maintainer.drain_queue", side_effect=AssertionError("late queue")), patch("ei.metrics.collect_local_metrics", side_effect=AssertionError("late metric")):
                result = maintainer.run_maintenance(settings, source_paths=(), now=NOW, time_budget_ms=5000)
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.blocked_reason, "OPERATION_BUDGET_EXHAUSTED")
            self.assertFalse(settings.paths.knowledge_dir.exists())
            self.assertFalse((settings.paths.runtime_root / "health.json").exists())

    def test_maintenance_keeps_provider_fault_with_unknown_custody_and_resolves_only_actual_success(self):
        from ei.maintainer import run_maintenance
        from ei.pending_capture import accept_candidate
        from ei.key_provider import InMemoryKeyProvider
        from ei.operation_runtime import operation_snapshot
        from tests.unattended_helpers import identity
        from tests.unit.test_pending_capture import observation
        from tests.unit.test_maintainer import ErrorProvider, YesProvider
        from dataclasses import replace
        from ei.setup_contract import OrganizerSelection
        from ei.organizer_recovery import OrganizerRecovery
        from ei.ids import stable_hash
        from ei.incidents import inspect_incidents
        from datetime import timedelta
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(make_settings(Path(tmp)), organizer=OrganizerSelection("READY", "ollama", None))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            with patch("ei.spool.default_key_provider", return_value=key):
                accept_candidate(settings, identity(), observation(), now=NOW)
                failed = run_maintenance(settings, source_paths=(), provider=ErrorProvider("local-test", "AUTH_FAILED"), now=NOW, time_budget_ms=10000)
            snapshot = operation_snapshot(settings, now=NOW)
            self.assertEqual(snapshot.provider_code, "AUTH_FAILED")
            self.assertTrue(snapshot.provider_needs_action)
            self.assertIn("AUTH_FAILED", failed.to_dict()["operation"]["issues"])
            recovery = OrganizerRecovery(settings.paths.runtime_root / ("organizer-" + stable_hash("local-test") + ".json"), "local-test")
            provider = YesProvider()
            self.assertFalse(recovery.recover(provider, config_fingerprint="sha256:" + "a" * 64))
            self.assertFalse(recovery.recover(provider, config_fingerprint="sha256:" + "a" * 64))
            incident = next(row for row in inspect_incidents(settings)["incidents"] if row["reason_code"] == "AUTH_FAILED")
            self.assertTrue(recovery.recover(provider, config_fingerprint="sha256:" + "b" * 64))
            self.assertEqual(next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == incident["incident_id"])["status"], "OPEN")
            with patch("ei.spool.default_key_provider", return_value=key):
                recovered = run_maintenance(settings, source_paths=(), provider=provider, now=NOW + timedelta(days=1), time_budget_ms=10000)
            self.assertEqual(recovered.queue["completed"], 1)
            self.assertIsNone(operation_snapshot(settings, now=NOW + timedelta(days=1)).provider_code)
            self.assertEqual(next(row for row in inspect_incidents(settings)["incidents"] if row["incident_id"] == incident["incident_id"])["status"], "RESOLVED")


    def test_cache_binding_types_and_actual_interval_are_not_ttl_aliases(self):
        from ei import operation_runtime as runtime
        from ei.config import Settings
        from ei.operation_health import HealthInput
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_root.mkdir()
            anchor = settings.paths.runtime_root / "empty"
            anchor.write_bytes(b"")
            binding = runtime._stat_binding(settings, ["empty"])
            runtime.write_operation_snapshot(settings, HealthInput(pending_count=1, provider_code="AUTH_FAILED", provider_id="subscription-cli"), now=NOW, budget=runtime.OperationBudget(5000), custody_binding=binding)
            path = settings.paths.runtime_root / "operation-health.json"
            value = json.loads(path.read_text())
            value["custody_binding"]["empty"][2] = False
            path.write_text(json.dumps(value))
            cached = runtime.operation_snapshot(settings, now=NOW)
            self.assertIsNone(cached.pending_count)
            self.assertEqual(cached.provider_code, "AUTH_FAILED")
            self.assertNotEqual(runtime.settings_binding(Settings(settings.paths, scheduler_interval_minutes=90)), runtime.settings_binding(Settings(settings.paths, scheduler_interval_minutes=120)))

    def test_pending_page_fault_is_useful_even_without_complete_count(self):
        from ei import operation_runtime as runtime
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            snapshot, _ = runtime.collect_operation_snapshot(settings, now=NOW, budget=runtime.OperationBudget(5000), pending={"processed": [{"reason_code": "RUNTIME_ACCOUNTING_UNKNOWN"}]})
            self.assertEqual(snapshot.storage_code, "RUNTIME_ACCOUNTING_UNKNOWN")

    def test_queue_drain_zero_residual_budget_never_starts_storage_or_inference(self):
        from ei.maintainer import drain_queue
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            with patch("ei.maintainer._provider_for", side_effect=AssertionError("provider initialization after expiry")):
                try:
                    result = drain_queue(settings, budget=OperationBudget(0))
                except TypeError as exc:
                    self.fail(str(exc))
            self.assertEqual(result.attempted, 0)
            self.assertEqual(result.status, "partial")
            self.assertFalse(settings.paths.queue_dir.exists())

    def test_projection_interruption_keeps_result_and_reuses_it_without_second_inference(self):
        from ei.maintainer import drain_queue
        from ei.operation_runtime import OperationBudget
        from ei.key_provider import InMemoryKeyProvider
        from ei.pending_capture import accept_candidate
        from ei.queue import list_queue_items, QueueState, read_queue_item
        from ei.runtime_catalog import lookup
        from tests.unattended_helpers import identity
        from tests.unit.test_pending_capture import observation
        from tests.unit.test_maintainer import YesProvider
        from ei.setup_contract import OrganizerSelection
        from dataclasses import replace
        from datetime import timedelta
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(make_settings(Path(tmp)), organizer=OrganizerSelection("READY", "ollama", None))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            with patch("ei.spool.default_key_provider", return_value=key):
                accept_candidate(settings, identity(), observation(), now=NOW)
                provider = YesProvider()
                with patch.object(provider, "generate", wraps=provider.generate) as generate:
                    with patch("ei.maintainer.project_events", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")):
                        try:
                            first = drain_queue(settings, provider=provider, now=NOW, budget=OperationBudget(10000))
                        except TypeError as exc:
                            self.fail(str(exc))
                    item = list_queue_items(settings)[0]
                    self.assertNotEqual(item.state, QueueState.DONE)
                    self.assertIsNotNone(item.validated_result_ref)
                    self.assertIsNotNone(lookup(settings.paths.spool_dir, item.payload_ref.spool_id))
                    second = drain_queue(settings, provider=provider, now=NOW + timedelta(hours=1), budget=OperationBudget(10000))
                self.assertEqual(second.completed, 1, second)
                self.assertEqual(generate.call_count, 1)
                self.assertEqual(read_queue_item(item.queue_id, settings).state, QueueState.DONE)

    def test_stop_hook_tracks_metadata_without_ai_queue_and_shares_budget(self):
        from dataclasses import replace
        from ei.hook_entry import handle_normalized_hook, normalize_hook_event
        from ei.operation_runtime import OperationBudget
        from ei.capture_ledger import read_receipt
        from ei.capture_contract import capture_key
        from tests.unattended_helpers import identity
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            event = replace(normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t"}, settings), capture_identity=identity())
            budget = OperationBudget(5000)
            with patch("ei.hook_entry.enqueue_receipt", side_effect=AssertionError("metadata reached inference queue")), patch("ei.operation_runtime.service_operation", return_value={}) as service:
                try:
                    result = handle_normalized_hook(event, settings, budget=budget)
                except TypeError as exc:
                    self.fail(str(exc))
            self.assertEqual(result.status, "ok")
            self.assertEqual(read_receipt(settings, capture_key(identity())).state, "WAITING")
            self.assertIs(service.call_args.kwargs["budget"], budget)

    def test_new_trusted_skill_candidate_uses_pending_without_journal_write(self):
        from dataclasses import replace
        from ei.ids import fingerprint
        from ei.capture import record_agent_observation
        from ei.key_provider import InMemoryKeyProvider
        from ei.models import CaptureContext
        from ei.queue import list_queue_items
        from tests.unattended_helpers import identity
        from tests.unit.test_pending_capture import observation
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            context = CaptureContext("session", "turn", 1, "codex-cli", "codex-compatible",
                capture_identity=replace(identity(), session_hash=fingerprint("session")))
            with patch("ei.spool.default_key_provider", return_value=key):
                result = record_agent_observation(observation(), context, settings)
            self.assertTrue(result.created, result)
            self.assertEqual(result.reason_code, "PENDING_SECURED")
            self.assertEqual(len(list_queue_items(settings)), 1)
            self.assertFalse(settings.paths.event_dir.exists())

    def test_custody_producer_authenticates_bounded_page_not_reservations(self):
        from ei import operation_runtime as runtime
        from ei.key_provider import InMemoryKeyProvider
        from ei.pending_capture import accept_candidate
        from tests.unattended_helpers import identity
        from tests.unit.test_pending_capture import observation
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            key = InMemoryKeyProvider("test-key", b"s" * 32)
            for record in ("a", "b"):
                self.assertEqual(accept_candidate(settings, identity(record), observation(), now=NOW, key_provider=key).state, "SECURED")
            collect = getattr(runtime, "collect_operation_snapshot", None)
            self.assertTrue(callable(collect), "bounded custody producer is missing")
            with patch("ei.spool.default_key_provider", return_value=key):
                partial, binding = collect(settings, now=NOW, budget=runtime.OperationBudget(5000), max_records=1)
                self.assertEqual((partial.pending_count_status, partial.pending_count, partial.reserved_count), ("PARTIAL", 1, 2))
                full, binding = collect(settings, now=NOW, budget=runtime.OperationBudget(5000))
                self.assertEqual((full.pending_count_status, full.pending_count), ("COMPLETE", 2))
            runtime.write_operation_snapshot(settings, full, now=NOW, budget=runtime.OperationBudget(5000), custody_binding=binding)
            self.assertEqual(runtime.operation_snapshot(settings, now=NOW).pending_count, 2)
            from ei.queue import list_queue_items
            from ei.runtime_catalog import lookup
            path = lookup(settings.paths.spool_dir, list_queue_items(settings)[0].payload_ref.spool_id)
            path.write_bytes(b"broken")
            self.assertIsNone(runtime.operation_snapshot(settings, now=NOW).pending_count)
            with patch("ei.spool.default_key_provider", return_value=key):
                damaged, _ = collect(settings, now=NOW, budget=runtime.OperationBudget(5000))
            self.assertNotEqual(damaged.pending_count_status, "COMPLETE")
            self.assertIsNotNone(damaged.storage_code)

    def test_v2_cache_has_fresh_binding_and_keeps_fault_without_count_evidence(self):
        from datetime import timedelta
        from ei import operation_runtime as runtime
        from ei.operation_health import HealthInput
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            writer = getattr(runtime, "write_operation_snapshot", None)
            self.assertTrue(callable(writer), "production cache writer is missing")
            snapshot = HealthInput(pending_count=None, pending_bytes=None, pending_count_status="UNKNOWN",
                                   storage_code="RUNTIME_CATALOG_UNAVAILABLE", scheduler_requested=False)
            writer(settings, snapshot, now=NOW, budget=runtime.OperationBudget(5000))
            value = json.loads((settings.paths.runtime_dir / "operation-health.json").read_text())
            self.assertEqual(value["schema_version"], 2)
            self.assertLessEqual(len(json.dumps(value).encode()), 262144)
            status = runtime.operation_status(settings, now=NOW)
            self.assertEqual(status["snapshot_status"], "KNOWN")
            self.assertIsNone(status["snapshot"]["pending_count"])
            self.assertIn("RUNTIME_CATALOG_UNAVAILABLE", status["issues"])
            self.assertEqual(runtime.operation_status(settings, now=NOW + timedelta(hours=1))["snapshot_status"], "UNKNOWN")
            other = make_settings(Path(tmp) / "other")
            other.paths.runtime_dir.mkdir(parents=True)
            (other.paths.runtime_dir / "operation-health.json").write_text(json.dumps(value))
            self.assertEqual(runtime.operation_status(other, now=NOW)["snapshot_status"], "UNKNOWN")

    def test_legacy_cache_never_elevates_old_counts(self):
        from ei.operation_runtime import operation_status
        from ei.operation_health import HealthInput
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_dir.mkdir(parents=True)
            (settings.paths.runtime_dir / "operation-health.json").write_text(json.dumps(
                {"schema_version": 1, "complete": True, "snapshot": asdict(HealthInput(pending_count=9))}))
            status = operation_status(settings, now=NOW)
            self.assertEqual(status["snapshot_status"], "UNKNOWN")
            self.assertEqual(status["snapshot"]["pending_count_status"], "UNKNOWN")
            self.assertIsNone(status["snapshot"]["pending_count"])

    def test_malformed_cache_never_creates_incident_or_sends_notification(self):
        from ei.operation_runtime import operation_status, service_operation
        from ei.operation_health import HealthInput
        from ei.notifications.base import DeliveryResult
        cases = [("schema_version", True), ("schema_version", 1.0)]
        for field in ("source_missing_ids", "expired_capture_ids", "cleanup_failed_capture_ids"):
            cases.extend((field, value) for value in ("abc", {"capture-one": 1}, None, 0,
                [False], [0], [None], [""], [{}], [[]], ["valid", 0]))
        for field in ("host_id", "provider_id"):
            cases.extend((field, value) for value in (False, 0, None, [], {}))
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                settings = make_settings(Path(tmp))
                settings.paths.runtime_dir.mkdir(parents=True)
                cache = cache_fixture(settings, HealthInput())
                (cache if field == "schema_version" else cache["snapshot"])[field] = value
                (settings.paths.runtime_dir / "operation-health.json").write_text(json.dumps(cache), encoding="utf-8")
                policy = {"schema_version": 1, "settings": {"notifications": {"enabled": True, "channel": "os"},
                    "initial_test": {"allow_model_test": False, "allow_notification_test": False}}, "evidence": {}}
                (settings.paths.runtime_dir / "automatic-operation.json").write_text(json.dumps(policy), encoding="utf-8")
                sends = []
                def send(*args, **kwargs):
                    sends.append(args)
                    return DeliveryResult("SENT", "OS_ACCEPTED")
                before = {p: p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file()}
                with patch("ei.notifications.base.send_native_notification", side_effect=send):
                    result = service_operation(settings, now=NOW, channel="maintenance", max_ms=5000)
                self.assertEqual(result["reason_code"], "OPERATION_SNAPSHOT_UNKNOWN")
                self.assertEqual(operation_status(settings, now=NOW)["snapshot_status"], "UNKNOWN")
                self.assertEqual(sends, [])
                self.assertEqual({p: p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file()}, before)

    def test_normal_provider_code_does_not_create_failure_incident(self):
        from ei.operation_runtime import service_operation
        from ei.operation_health import HealthInput
        from ei.incidents import inspect_incidents
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_dir.mkdir(parents=True)
            cache = cache_fixture(settings, HealthInput(provider_code="READY", provider_id="organizer"))
            (settings.paths.runtime_dir / "operation-health.json").write_text(json.dumps(cache), encoding="utf-8")
            result = service_operation(settings, now=NOW, channel="maintenance", max_ms=5000)
            self.assertEqual(result["issues"], ["CLOSEOUT_METADATA_UNKNOWN"])
            incidents = inspect_incidents(settings)["incidents"]
            self.assertEqual([row["reason_code"] for row in incidents], ["CLOSEOUT_METADATA_UNKNOWN"])

    def test_policy_disable_and_malformed_flags_never_enable_notifications(self):
        from ei.operation_runtime import notification_policy
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_dir.mkdir(parents=True)
            path = settings.paths.runtime_dir / "automatic-operation.json"
            for enabled, expected_status in ((False, "KNOWN"), ("false", "UNKNOWN"), (1, "UNKNOWN")):
                value = {"schema_version": 1, "settings": {"notifications": {"enabled": enabled, "channel": "os"},
                    "initial_test": {"allow_model_test": True, "allow_notification_test": True}}, "evidence": {"visible": True}}
                path.write_text(json.dumps(value), encoding="utf-8")
                result = notification_policy(settings)
                self.assertFalse(result["enabled"])
                self.assertEqual(result["status"], expected_status)

    def test_expired_budget_after_claim_starts_no_fresh_state_work(self):
        from datetime import timedelta
        from ei.operation_runtime import _notify
        from ei.operation_health import HealthIssue
        from ei.incidents import update_incidents, inspect_incidents, notification_due
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            incident = update_incidents(settings, (HealthIssue("AUTH_FAILED", "organizer", "error", 1),), now=NOW)[0]
            budget = RemainingBudget()
            from ei.incidents import claim_notification, _state_root
            def exhaust_after_real_claim(*args, **kwargs):
                lease = claim_notification(*args, **kwargs)
                budget.remaining = 0
                return lease
            def no_expired_state_work(*args, **kwargs):
                self.assertGreater(budget.remaining, 0, "fresh state work after deadline")
                return _state_root(*args, **kwargs)
            sends = []
            def send(*args, **kwargs):
                sends.append(args)
                raise AssertionError("send after budget")
            with patch("ei.incidents.claim_notification", side_effect=exhaust_after_real_claim), patch("ei.incidents._state_root", side_effect=no_expired_state_work), patch("ei.notifications.base.send_native_notification", side_effect=send):
                self.assertFalse(_notify(settings, incident["incident_id"], now=NOW, budget=budget))
            self.assertEqual(sends, [])
            saved = inspect_incidents(settings)["incidents"][0]
            self.assertEqual(saved["delivery"]["os"]["last_result"], "UNKNOWN")
            self.assertFalse(notification_due(saved, channel="os", session_hash=None, now=NOW + timedelta(minutes=59)))
            self.assertTrue(notification_due(saved, channel="os", session_hash=None, now=NOW + timedelta(hours=1)))

    def test_unsent_cancellation_preserves_prior_delivery_with_same_budget(self):
        from datetime import timedelta
        from ei.operation_runtime import _notify
        from ei.operation_health import HealthIssue
        from ei.notifications.base import DeliveryResult
        from ei.incidents import update_incidents, inspect_incidents, claim_notification, settle_notification
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            earlier = NOW - timedelta(hours=2)
            incident = update_incidents(settings, (HealthIssue("AUTH_FAILED", "organizer", "error", 1),), now=earlier)[0]
            old_lease = claim_notification(settings, incident["incident_id"], channel="os", session_hash=None, now=earlier)
            settle_notification(settings, old_lease, DeliveryResult("FAILED", "OS_FAILED"), now=earlier)
            before = inspect_incidents(settings)["incidents"][0]["delivery"]["os"]
            before.pop("lease", None)  # Abort never resurrects a previous lease.
            budget = RemainingBudget()
            def little_time_after_claim(*args, **kwargs):
                lease = claim_notification(*args, **kwargs)
                budget.remaining = 25
                return lease
            sends = []
            def send(*args, **kwargs):
                sends.append(args)
                return DeliveryResult("SENT", "OS_ACCEPTED")
            with patch("ei.incidents.claim_notification", side_effect=little_time_after_claim), patch("ei.notifications.base.send_native_notification", side_effect=send):
                self.assertFalse(_notify(settings, incident["incident_id"], now=NOW, budget=budget))
            self.assertEqual(inspect_incidents(settings)["incidents"][0]["delivery"]["os"], before)
            self.assertEqual(sends, [])

    def test_budget_expiring_during_cancel_retains_unknown_attempt(self):
        from datetime import timedelta
        from ei.operation_runtime import _notify
        from ei.operation_health import HealthIssue
        from ei.incidents import update_incidents, inspect_incidents, claim_notification, notification_due, _write
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            incident = update_incidents(settings, (HealthIssue("AUTH_FAILED", "organizer", "error", 1),), now=NOW)[0]
            budget = RemainingBudget()
            def little_time_after_claim(*args, **kwargs):
                lease = claim_notification(*args, **kwargs)
                budget.remaining = 25
                return lease
            def expire_before_cancel_persistence(root, incidents, **kwargs):
                if incidents[incident["incident_id"]]["delivery"]["os"]["last_result"] is None:
                    budget.remaining = 0
                return _write(root, incidents, **kwargs)
            with patch("ei.incidents.claim_notification", side_effect=little_time_after_claim), patch("ei.incidents._write", side_effect=expire_before_cancel_persistence), patch("ei.notifications.base.send_native_notification", side_effect=AssertionError("send instead of cancel")):
                with self.assertRaises(TimeoutError):
                    _notify(settings, incident["incident_id"], now=NOW, budget=budget)
            saved = inspect_incidents(settings)["incidents"][0]
            self.assertEqual(saved["delivery"]["os"]["last_result"], "UNKNOWN")
            self.assertFalse(notification_due(saved, channel="os", session_hash=None, now=NOW + timedelta(minutes=59)))

    def test_invoked_unknown_delivery_retains_hour_throttle(self):
        from datetime import timedelta
        from ei.operation_runtime import _notify, OperationBudget
        from ei.operation_health import HealthIssue
        from ei.incidents import update_incidents, inspect_incidents, notification_due
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            incident = update_incidents(settings, (HealthIssue("AUTH_FAILED", "organizer", "error", 1),), now=NOW)[0]
            with patch("ei.notifications.base.send_native_notification", side_effect=RuntimeError("unknown delivery")):
                self.assertFalse(_notify(settings, incident["incident_id"], now=NOW, budget=OperationBudget(5000)))
            saved = inspect_incidents(settings)["incidents"][0]
            self.assertEqual(saved["delivery"]["os"]["last_result"], "UNKNOWN")
            self.assertFalse(notification_due(saved, channel="os", session_hash=None, now=NOW + timedelta(minutes=59)))
            self.assertTrue(notification_due(saved, channel="os", session_hash=None, now=NOW + timedelta(hours=1)))

    def test_notifications_require_valid_explicit_policy_and_persist_throttle(self):
        from ei.operation_runtime import service_operation
        from ei.operation_health import HealthInput
        from ei.incidents import inspect_incidents
        from ei.notifications.base import DeliveryResult
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            settings.paths.runtime_dir.mkdir(parents=True)
            cache = cache_fixture(settings, HealthInput(provider_code="AUTH_FAILED", provider_id="organizer"))
            (settings.paths.runtime_dir / "operation-health.json").write_text(json.dumps(cache), encoding="utf-8")
            with patch("ei.notifications.base.send_native_notification", side_effect=AssertionError("missing consent")):
                service_operation(settings, now=NOW, channel="maintenance", max_ms=5000)
            policy = {"schema_version": 1, "settings": {"notifications": {"enabled": True, "channel": "os"},
                "initial_test": {"allow_model_test": False, "allow_notification_test": False}}, "evidence": {}}
            (settings.paths.runtime_dir / "automatic-operation.json").write_text(json.dumps(policy), encoding="utf-8")
            with patch("ei.notifications.base.send_native_notification", return_value=DeliveryResult("SENT", "OS_ACCEPTED")):
                first = service_operation(settings, now=NOW, channel="maintenance", max_ms=5000)
            self.assertEqual(first["notifications_sent"], 1)
            stored = inspect_incidents(settings)["incidents"][0]
            self.assertEqual(stored["delivery"]["os"]["last_result"], "SUCCESS")
            self.assertEqual(stored["delivery"]["os"]["display_status"], "UNVERIFIED")
            with patch("ei.notifications.base.send_native_notification", side_effect=AssertionError("duplicate notice")):
                second = service_operation(settings, now=NOW, channel="hook", max_ms=5000)
            self.assertEqual(second["notifications_sent"], 0)

    def test_normal_empty_runtime_does_not_ask_or_run_ai(self):
        from ei.operation_runtime import service_operation
        with tempfile.TemporaryDirectory() as tmp:
            with patch("builtins.input", side_effect=AssertionError("daily prompt")):
                with patch("ei.inference.router.ProviderRouter.generate", side_effect=AssertionError("empty probe")):
                    result = service_operation(make_settings(Path(tmp)), now=NOW,
                                               channel="maintenance", max_ms=200)
            self.assertEqual(result["notifications_sent"], 0)

    def test_snapshot_and_status_do_not_create_missing_runtime(self):
        from ei.operation_runtime import operation_snapshot, operation_status
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            before = list(Path(tmp).rglob("*"))
            snapshot = operation_snapshot(settings, now=NOW)
            status = operation_status(settings, now=NOW)
            self.assertIsNone(snapshot.last_progress_at)
            self.assertEqual(status["snapshot_status"], "UNKNOWN")
            self.assertEqual(list(Path(tmp).rglob("*")), before)

    def test_zero_budget_leaves_no_attempt_or_created_state(self):
        from ei.operation_runtime import service_operation
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            result = service_operation(settings, now=NOW, channel="hook", max_ms=0)
            self.assertEqual(result["reason_code"], "OPERATION_BUDGET_EXHAUSTED")
            self.assertEqual(list(Path(tmp).rglob("*")), [])

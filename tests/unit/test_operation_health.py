import unittest
from dataclasses import replace
from datetime import timedelta

from ei.operation_health import HealthInput, evaluate_health
from tests.unattended_helpers import NOW


class OperationHealthTests(unittest.TestCase):
    def test_storage_failure_with_unknown_custody_is_not_a_provider_failure(self):
        try:
            snapshot = HealthInput(pending_count=None, pending_bytes=None,
                pending_count_status="UNKNOWN", storage_code="RUNTIME_CATALOG_MISSING",
                storage_component_id="pending-store")
        except (TypeError, ValueError) as exc:
            self.fail(f"typed storage/unknown custody input unavailable: {type(exc).__name__}")
        issues = evaluate_health(snapshot, now=NOW)
        self.assertEqual([(i.reason_code, i.component_id, i.pending_count, i.pending_count_status)
            for i in issues], [("RUNTIME_CATALOG_MISSING", "pending-store", None, "UNKNOWN")])

    def test_reservation_risk_keeps_partial_authenticated_count(self):
        try:
            snapshot = HealthInput(pending_count=2, pending_bytes=100,
                pending_count_status="PARTIAL", reserved_count=800, reserved_bytes=100,
                earliest_expiry=NOW + timedelta(hours=23))
        except (TypeError, ValueError) as exc:
            self.fail(f"partial custody input unavailable: {type(exc).__name__}")
        issues = evaluate_health(snapshot, now=NOW)
        self.assertEqual({i.reason_code for i in issues}, {"CAPACITY_RISK", "EXPIRY_RISK"})
        self.assertTrue(all(i.pending_count == 2 and i.pending_count_status == "PARTIAL" for i in issues))

    def test_heartbeat_is_not_progress_and_empty_queue_is_not_stalled(self):
        item = HealthInput(
            pending_count=1,
            oldest_pending_at=NOW - timedelta(days=2),
            last_attempt_at=NOW,
            provider_code="RATE_LIMITED",
        )
        self.assertIn("ACCUMULATION_STALLED", {i.reason_code for i in evaluate_health(item, now=NOW)})
        self.assertNotIn(
            "ACCUMULATION_STALLED",
            {i.reason_code for i in evaluate_health(replace(item, pending_count=0), now=NOW)},
        )

    def test_offline_time_is_not_two_eligible_runs(self):
        self.assertFalse(evaluate_health(HealthInput(missed_eligible_runs=None), now=NOW))

    def test_each_operational_threshold_has_a_distinct_reason(self):
        snapshot = HealthInput(
            pending_count=80,
            pending_bytes=800,
            max_items=100,
            max_bytes=1000,
            earliest_expiry=NOW + timedelta(hours=24),
            last_progress_at=NOW - timedelta(hours=24),
            scheduler_requested=True,
            missed_eligible_runs=2,
        )
        self.assertEqual(
            {issue.reason_code for issue in evaluate_health(snapshot, now=NOW)},
            {"ACCUMULATION_STALLED", "CAPACITY_RISK", "EXPIRY_RISK", "SCHEDULER_STOPPED"},
        )

    def test_provider_action_state_distinguishes_transient_and_finite_malformed_failure(self):
        transient = evaluate_health(
            HealthInput(provider_id="organizer", provider_code="MALFORMED_RESPONSE"),
            now=NOW,
        )
        actionable = evaluate_health(
            HealthInput(
                provider_id="organizer",
                provider_code="MALFORMED_RESPONSE",
                provider_needs_action=True,
            ),
            now=NOW,
        )
        auth = evaluate_health(
            HealthInput(provider_id="organizer", provider_code="AUTH_FAILED"),
            now=NOW,
        )
        unknown = evaluate_health(
            HealthInput(provider_id="organizer", provider_code="secret error text"),
            now=NOW,
        )
        self.assertEqual([(item.reason_code, item.severity) for item in transient], [("MALFORMED_RESPONSE", "info")])
        self.assertEqual([(item.reason_code, item.severity) for item in actionable], [("MALFORMED_RESPONSE", "error")])
        self.assertEqual([(item.reason_code, item.severity) for item in auth], [("AUTH_FAILED", "error")])
        self.assertEqual([(item.reason_code, item.severity) for item in unknown], [("OPERATION_FAILED", "info")])

    def test_source_loss_and_expiry_cleanup_are_component_scoped_but_report_retained_count(self):
        snapshot = HealthInput(
            pending_count=3,
            source_missing_count=2,
            source_missing_ids=("source-a", "source-b"),
            expired_capture_ids=("sha256:" + "a" * 64,),
            cleanup_failed_capture_ids=("sha256:" + "a" * 64,),
        )
        issues = evaluate_health(snapshot, now=NOW)
        observed = {(item.reason_code, item.component_id, item.pending_count) for item in issues}
        self.assertEqual(
            observed,
            {
                ("SOURCE_UNAVAILABLE", "source-a", 3),
                ("SOURCE_UNAVAILABLE", "source-b", 3),
                ("PENDING_EXPIRED", "sha256:" + "a" * 64, 3),
                ("EXPIRY_CLEANUP_FAILED", "sha256:" + "a" * 64, 3),
            },
        )

    def test_closeout_recovery_reports_pending_capacity_expiry_and_unknown_metadata(self):
        snapshot = HealthInput(
            closeout_pending_count=52,
            closeout_pending_bytes=900_000,
            closeout_max_items=64,
            closeout_max_bytes=1_048_576,
            closeout_earliest_expiry=NOW + timedelta(hours=12),
            closeout_pending_status="COMPLETE",
            closeout_unknown_count=1,
        )

        issues = evaluate_health(snapshot, now=NOW)

        scoped = {(item.reason_code, item.component_id) for item in issues}
        self.assertIn(("CLOSEOUT_ASSOCIATION_PENDING", "closeout-store"), scoped)
        self.assertIn(("CAPACITY_RISK", "closeout-store"), scoped)
        self.assertIn(("EXPIRY_RISK", "closeout-store"), scoped)
        self.assertIn(("CLOSEOUT_METADATA_UNKNOWN", "closeout-store"), scoped)

    def test_closeout_health_issues_do_not_claim_metadata_as_retained_candidates(self):
        snapshot = HealthInput(
            closeout_pending_count=52,
            closeout_pending_bytes=900_000,
            closeout_max_items=64,
            closeout_max_bytes=1_048_576,
            closeout_earliest_expiry=NOW + timedelta(hours=12),
            closeout_pending_status="COMPLETE",
            closeout_unknown_count=1,
        )
        issues = evaluate_health(snapshot, now=NOW)
        closeout_issues = [item for item in issues if item.component_id == "closeout-store"]

        self.assertEqual(
            {item.reason_code for item in closeout_issues},
            {"CLOSEOUT_ASSOCIATION_PENDING", "CAPACITY_RISK", "EXPIRY_RISK", "CLOSEOUT_METADATA_UNKNOWN"},
        )
        self.assertTrue(all(item.pending_count is None and item.pending_count_status == "UNKNOWN" for item in closeout_issues))

    def test_closeout_inventory_failure_is_not_reported_as_empty(self):
        snapshot = HealthInput(
            closeout_pending_count=None,
            closeout_pending_bytes=None,
            closeout_pending_status="UNKNOWN",
        )

        issues = evaluate_health(snapshot, now=NOW)

        self.assertIn(
            ("CLOSEOUT_METADATA_UNKNOWN", "closeout-store"),
            {(item.reason_code, item.component_id) for item in issues},
        )

    def test_missing_or_expired_identity_does_not_invent_a_retained_candidate(self):
        snapshot = HealthInput(
            pending_count=0,
            source_missing_count=1,
            source_missing_ids=("source-a",),
            expired_capture_ids=("sha256:" + "a" * 64,),
        )
        self.assertEqual(
            {(item.reason_code, item.pending_count) for item in evaluate_health(snapshot, now=NOW)},
            {("SOURCE_UNAVAILABLE", 0), ("PENDING_EXPIRED", 0)},
        )

    def test_naive_clock_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HEALTH_TIMEZONE_REQUIRED"):
            evaluate_health(HealthInput(), now=NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()

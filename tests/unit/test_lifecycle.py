import unittest
from datetime import datetime, timezone

from ei.lifecycle import evaluate_lifecycle
from ei.models import PromotionPolicy
from tests.helpers import make_cluster_state


class LifecycleTests(unittest.TestCase):
    NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)

    def test_promotes_on_two_provenances_two_scopes_one_benefit(self):
        state = make_cluster_state(
            provenances=frozenset({"rollout:a", "rollout:b"}),
            scopes=frozenset({"cwd:a", "cwd:b"}),
            applicability=("spreadsheet",),
            benefit_count=1,
            contradiction_provenances=frozenset(),
            classification="private-reusable",
            rule="異なる案件で再現した判断を、証拠付きで再利用可能なルールとして保存する" * 3,
        )
        events = evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW)
        self.assertEqual([e.event_type for e in events], ["pattern.promoted"])
        self.assertTrue(events[0].payload["pattern_id"].startswith("pat_"))

    def test_three_independent_contradictions_deprecate_active_pattern(self):
        state = make_cluster_state(
            status="active",
            pattern_id="pat_active",
            contradiction_provenances=frozenset({"a", "b", "c"}),
        )
        events = evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW)
        self.assertEqual(events[0].event_type, "pattern.deprecated")
        self.assertEqual(events[0].payload["reason"], "THREE_INDEPENDENT_CONTRADICTIONS")

    def test_superseded_pattern_tombstones_after_replacement_and_inactivity(self):
        state = make_cluster_state(
            status="superseded",
            pattern_id="pat_old",
            superseded_by="pat_new",
            replacement_active=True,
            last_used_at="2026-05-20T00:00:00+00:00",
            exposure_count=0,
        )
        events = evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW)
        self.assertEqual(events[0].event_type, "pattern.tombstoned")

    def test_stale_active_pattern_without_benefit_is_deprecated(self):
        state = make_cluster_state(
            status="active",
            pattern_id="pat_stale",
            benefit_count=0,
            last_used_at="2025-01-01T00:00:00+00:00",
        )
        events = evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW)
        self.assertEqual([event.event_type for event in events], ["pattern.deprecated"])
        self.assertEqual(events[0].payload["reason"], "STALE_NO_BENEFIT")

    def test_transition_contains_audit_and_idempotency_metadata(self):
        state = make_cluster_state(
            provenances=frozenset({"source:a", "source:b"}),
            scopes=frozenset({"cwd:a", "cwd:b"}),
            applicability=("spreadsheet",),
            benefit_count=1,
            rule="異なる案件で再現した判断を、証拠付きで再利用可能なルールとして保存する" * 3,
        )
        event = evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW)[0]
        self.assertEqual(event.payload["reason_code"], "PROMOTION_ELIGIBLE")
        self.assertIn("evidence_refs", event.payload)
        self.assertEqual(event.payload["policy_version"], "promotion-v1")
        self.assertTrue(event.payload["idempotency_key"].startswith("sha256:"))

    def test_pinned_pattern_does_not_tombstone(self):
        state = make_cluster_state(
            status="deprecated",
            pattern_id="pat_pinned",
            deprecated_at="2025-01-01T00:00:00+00:00",
            last_used_at="2025-01-01T00:00:00+00:00",
            pinned=True,
        )
        self.assertEqual(
            evaluate_lifecycle(state, PromotionPolicy.defaults(), now_utc=self.NOW),
            [],
        )


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime, timezone

from ei.lifecycle import promotion_eligibility, select_always_on, utility_score
from ei.models import PatternState, PromotionPolicy
from tests.helpers import make_cluster_state


class RuleBudgetTests(unittest.TestCase):
    def test_eligibility_reports_each_missing_promotion_requirement(self):
        state = make_cluster_state(
            classification="client-confidential",
            rule="short",
            precondition="",
            failure_mode="",
            applicability=(),
            provenances=frozenset({"only-one"}),
            scopes=frozenset({"one"}),
            benefit_count=0,
        )
        result = promotion_eligibility(state, PromotionPolicy.defaults())
        self.assertFalse(result.valid)
        for reason in (
            "INSUFFICIENT_INDEPENDENT_PROVENANCE",
            "INSUFFICIENT_DISTINCT_SCOPE",
            "INSUFFICIENT_BENEFIT_EVIDENCE",
            "CLASSIFICATION_NOT_PROMOTABLE",
            "RULE_LENGTH_INVALID",
            "PRECONDITION_MISSING",
            "FAILURE_MODE_MISSING",
            "APPLICABILITY_MISSING",
        ):
            self.assertIn(reason, result.reason_codes)

    def test_utility_score_is_deterministic_and_uses_usage_components(self):
        pattern = PatternState(
            pattern_id="pat_a",
            rule="再現可能な判断ルールを条件付きで適用し、検証結果を記録して再作業を避ける。" * 2,
            evidence_ids=("e1", "e2"),
            benefit_refs=("reduced_rework",),
            applicability=("a", "b"),
            updated_at="2026-08-25T00:00:00+00:00",
        )
        usage = {
            "retrieval_frequency": 8,
            "benefit_strength": 1,
            "scope_breadth": 1,
            "evidence_strength": 1,
            "freshness": 1,
        }
        self.assertEqual(utility_score(pattern, usage), utility_score(pattern, usage))
        self.assertGreater(utility_score(pattern, usage), 0)

    def test_always_on_selection_is_bounded_and_deterministic(self):
        base = "このルールは同じ条件で再利用し、実行後に結果を検証して根拠を残す。"
        patterns = [
            PatternState(
                pattern_id=f"pat_{index:02d}",
                rule=base * (index + 1),
                evidence_ids=("e1", "e2"),
                benefit_refs=("reduced_search",),
                applicability=("scope-a", "scope-b"),
                updated_at="2026-08-25T00:00:00+00:00",
                pinned=index == 0,
            )
            for index in range(12)
        ]
        first = select_always_on(patterns, {"freshness": 1}, target_chars=100, hard_cap_chars=240)
        second = select_always_on(patterns, {"freshness": 1}, target_chars=100, hard_cap_chars=240)
        self.assertEqual(tuple(item.pattern_id for item in first), tuple(item.pattern_id for item in second))
        self.assertLessEqual(sum(len(item.rule) for item in first), 240)
        self.assertIn("pat_00", {item.pattern_id for item in first})


if __name__ == "__main__":
    unittest.main()
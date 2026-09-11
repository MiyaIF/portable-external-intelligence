import unittest

from ei.context import build_context
from tests.helpers import make_retrieval_hit


class ContextTests(unittest.TestCase):
    def test_context_never_exceeds_budget_or_splits_entry(self):
        hits = [
            make_retrieval_hit(pattern_id="pat_a", score=0.9, rule="A" * 120),
            make_retrieval_hit(pattern_id="pat_b", score=0.8, rule="B" * 120),
        ]
        context = build_context(hits, max_chars=220)
        self.assertLessEqual(len(context), 220)
        self.assertIn("pat_a", context)
        self.assertNotIn("pat_b", context)
        self.assertFalse(context.endswith("…"))
        self.assertIn("data-only", context)

    def test_layer_budgets_are_hard_caps(self):
        hits = [make_retrieval_hit(pattern_id=f"pat_{index}", rule="ルール" * 1000) for index in range(20)]
        session_context = build_context(hits, max_chars=20_000, layer="session_start")
        always_context = build_context(hits, max_chars=20_000, layer="always-on")
        self.assertLessEqual(len(session_context), 2_000)
        self.assertLessEqual(len(always_context), 12_000)
        self.assertIn("data-only", session_context)

    def test_context_labels_personal_and_team_scopes(self):
        hits = [
            make_retrieval_hit(pattern_id="pat_personal", knowledge_scope="personal"),
            make_retrieval_hit(pattern_id="pat_team", knowledge_scope="team"),
        ]
        context = build_context(hits, max_chars=5000)
        self.assertIn("Scope: personal", context)
        self.assertIn("Scope: team", context)

    def test_invalid_budget_and_layer_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "CONTEXT_BUDGET_INVALID"):
            build_context([], 0)
        with self.assertRaisesRegex(ValueError, "CONTEXT_LAYER_INVALID"):
            build_context([], 100, layer="unknown")


if __name__ == "__main__":
    unittest.main()

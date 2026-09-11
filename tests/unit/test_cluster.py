import unittest

from ei.cluster import assign_cluster
from tests.helpers import make_observation_state


class ClusterTests(unittest.TestCase):
    def test_independent_paraphrases_join_same_cluster(self):
        existing = make_observation_state(
            observation_id="obs_a",
            claim="書込後に対象範囲を再読込して数式を確認する",
            domain="spreadsheet-operations",
            provenance_key="rollout:a",
            cwd_fingerprint="cwd:a",
        )
        incoming = make_observation_state(
            observation_id="obs_b",
            claim="数式を書いたらシートを読み直して反映を検証する",
            domain="spreadsheet-operations",
            provenance_key="rollout:b",
            cwd_fingerprint="cwd:b",
        )
        decision = assign_cluster(incoming, [existing])
        self.assertEqual(decision.kind, "join")
        self.assertEqual(decision.target_observation_id, "obs_a")
        self.assertTrue(decision.independent_provenance)

    def test_negated_claim_becomes_contradiction(self):
        existing = make_observation_state(observation_id="obs_a", claim="書込後に再読込する", provenance_key="a")
        incoming = make_observation_state(observation_id="obs_b", claim="書込後に再読込してはいけない", provenance_key="b")
        decision = assign_cluster(incoming, [existing])
        self.assertEqual(decision.kind, "contradiction")
        self.assertEqual(decision.contradiction_reason, "POLARITY_OPPOSITION")

    def test_exact_same_source_is_duplicate_not_independent_join(self):
        existing = make_observation_state(
            observation_id="obs_a",
            claim="書込後に再読込する",
            provenance_key="source:a",
        )
        incoming = make_observation_state(
            observation_id="obs_b",
            claim="書込後に再読込する",
            provenance_key="source:a",
        )
        decision = assign_cluster(incoming, [existing])
        self.assertEqual(decision.kind, "duplicate")
        self.assertFalse(decision.independent_provenance)

    def test_same_domain_threshold_joins_but_cross_domain_threshold_does_not(self):
        left = make_observation_state(
            observation_id="obs_threshold",
            claim="alpha beta gamma delta epsilon zeta eta theta",
            domain="same",
            provenance_key="source:left",
            cwd_fingerprint="cwd:left",
        )
        same_domain = make_observation_state(
            observation_id="obs_same",
            claim="alpha beta gamma delta epsilon zeta eta iota",
            domain="same",
            provenance_key="source:right",
            cwd_fingerprint="cwd:right",
        )
        cross_domain = make_observation_state(
            observation_id="obs_cross",
            claim=same_domain.claim,
            domain="different",
            provenance_key="source:third",
            cwd_fingerprint="cwd:third",
        )
        self.assertEqual(assign_cluster(same_domain, [left]).kind, "join")
        self.assertEqual(assign_cluster(cross_domain, [left]).kind, "new")

    def test_explicit_alias_joins_even_when_lexical_score_is_low(self):
        left = make_observation_state(
            observation_id="obs_alias_left",
            claim="write reload formula verify",
            domain="x",
            provenance_key="source:left",
            cwd_fingerprint="cwd:left",
        )
        right = make_observation_state(
            observation_id="obs_alias_right",
            claim="書き込みを読み直し、数式を検証する",
            domain="x",
            provenance_key="source:right",
            cwd_fingerprint="cwd:right",
        )
        decision = assign_cluster(right, [left])
        self.assertEqual(decision.kind, "join")
        self.assertTrue(decision.matched_alias)

    def test_incompatible_versions_are_contradictions(self):
        left = make_observation_state(
            observation_id="obs_v1",
            claim="Use API version v1 for the client integration",
            domain="api",
            provenance_key="source:v1",
            cwd_fingerprint="cwd:v1",
        )
        right = make_observation_state(
            observation_id="obs_v2",
            claim="Use API version v2 for the client integration",
            domain="api",
            provenance_key="source:v2",
            cwd_fingerprint="cwd:v2",
        )
        decision = assign_cluster(right, [left])
        self.assertEqual(decision.kind, "contradiction")
        self.assertEqual(decision.contradiction_reason, "INCOMPATIBLE_VERSION")

    def test_opposite_outcomes_are_contradictions(self):
        left = make_observation_state(
            observation_id="obs_success",
            claim="Use cache in build pipeline for faster repeated tests",
            domain="build",
            provenance_key="source:success",
            cwd_fingerprint="cwd:success",
            outcome_status="success",
        )
        right = make_observation_state(
            observation_id="obs_failed",
            claim="Use cache in deployment pipeline for faster repeated tests",
            domain="build",
            provenance_key="source:failed",
            cwd_fingerprint="cwd:failed",
            outcome_status="failed",
        )
        decision = assign_cluster(right, [left])
        self.assertEqual(decision.kind, "contradiction")
        self.assertEqual(decision.contradiction_reason, "OPPOSITE_OUTCOME")


if __name__ == "__main__":
    unittest.main()
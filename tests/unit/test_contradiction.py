import unittest

from ei.cluster import assign_cluster, cluster_polarity
from ei.models import ProvenanceRef
from ei.dedup import is_independent
from tests.helpers import make_observation_state


class ContradictionTests(unittest.TestCase):
    def test_supporting_and_contradicting_provenance_are_distinct(self):
        support = make_observation_state(
            observation_id="obs_support",
            claim="書込後に再読込して検証する",
            provenance_key="source:support",
            source_hash="sha256:support",
            cwd_fingerprint="cwd:support",
        )
        contradiction = make_observation_state(
            observation_id="obs_contradict",
            claim="書込後に再読込してはいけない",
            provenance_key="source:contradict",
            source_hash="sha256:contradict",
            cwd_fingerprint="cwd:contradict",
        )
        decision = assign_cluster(contradiction, [support])
        self.assertEqual(decision.kind, "contradiction")
        self.assertTrue(decision.independent_provenance)
        self.assertEqual(cluster_polarity([support.claim, contradiction.claim]), "MIXED")

    def test_same_copy_source_is_not_independent(self):
        left = ProvenanceRef(
            "sha256:left",
            cwd_hash="cwd:left",
            domain="domain",
            copied_from_hash="sha256:origin",
        )
        right = ProvenanceRef(
            "sha256:right",
            cwd_hash="cwd:right",
            domain="domain",
            copied_from_hash="sha256:origin",
        )
        self.assertFalse(is_independent(left, right))

    def test_same_rollout_and_different_rollout_are_distinguished(self):
        same = ProvenanceRef(
            "sha256:a",
            rollout_id_hash="sha256:rollout-1",
            cwd_hash="cwd:a",
            domain="domain",
        )
        same_again = ProvenanceRef(
            "sha256:b",
            rollout_id_hash="sha256:rollout-1",
            cwd_hash="cwd:b",
            domain="domain",
        )
        other = ProvenanceRef(
            "sha256:c",
            rollout_id_hash="sha256:rollout-2",
            cwd_hash="cwd:c",
            domain="domain",
        )
        self.assertFalse(is_independent(same, same_again))
        self.assertTrue(is_independent(same, other))


if __name__ == "__main__":
    unittest.main()
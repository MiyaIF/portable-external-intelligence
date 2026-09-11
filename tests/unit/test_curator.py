from __future__ import annotations

import unittest

from ei.curator import curate_candidate
from ei.gate import GateDecision


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


class ProviderThatMustNotRun:
    provider_id = "test-provider"

    def generate(self, *args, **kwargs):
        raise AssertionError("curator must not invoke a provider")


class CuratorTests(unittest.TestCase):
    def decision(self, claim: str, refs: tuple[str, ...] = (digest("a"),)) -> GateDecision:
        return GateDecision(
            "YES",
            "evidence_verified",
            "Reusable finding",
            claim,
            refs,
            "reduced_rework",
            "private-reusable",
            0.95,
            "test-provider",
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
        )

    def test_exact_match_attaches_evidence(self):
        claim = "When editing a workbook, reload it and validate formulas before saving."
        changeset = curate_candidate(
            self.decision(claim),
            [
                {"pattern_id": "pat_b", "cluster_id": "cluster_b", "status": "active", "rule": claim},
                {"pattern_id": "pat_a", "cluster_id": "cluster_a", "status": "active", "rule": claim},
            ],
            ProviderThatMustNotRun(),
        )
        self.assertEqual(changeset.operations[0].operation, "ATTACH_EVIDENCE")
        self.assertEqual(changeset.operations[0].target_id, "pat_a")
        self.assertEqual(changeset.operations[0].payload["match_kind"], "exact")

    def test_no_match_records_observation_before_policy_eligible_candidate(self):
        claim = "A reusable process should record the verified failure cause, the recovery step, and the test that proves the repair worked."
        changeset = curate_candidate(
            {
                "decision": "YES",
                "title": "Recovery process",
                "claim": claim,
                "evidence_refs": [digest("a"), digest("b")],
                "provenances": [digest("a"), digest("b")],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "domain": "cli-agent",
            },
            [],
            {"provider_id": "test-provider"},
        )
        self.assertEqual([item.operation for item in changeset.operations], ["CREATE_OBSERVATION", "CREATE_CANDIDATE"])
        self.assertEqual(changeset.operations[0].payload["precondition"], "The same problem structure is observed again")
        self.assertIn("failure_mode", changeset.operations[1].payload)
        self.assertIn("version_constraint", changeset.operations[1].payload)

    def test_similar_match_uses_score_then_lowest_id_tiebreak(self):
        claim = "Use reload and verify when editing a workbook before saving changes."
        patterns = [
            {"pattern_id": "pat_z", "cluster_id": "cluster_z", "status": "active", "rule": "Use reload and verify when editing a workbook before saving changes."},
            {"pattern_id": "pat_a", "cluster_id": "cluster_a", "status": "active", "rule": "Use reload and verify when editing a workbook before saving changes."},
        ]
        changeset = curate_candidate(self.decision(claim, (digest("c"),)), patterns, None)
        self.assertEqual(changeset.operations[0].operation, "ATTACH_EVIDENCE")
        self.assertEqual(changeset.operations[0].target_id, "pat_a")

    def test_contradiction_proposes_revision_or_deprecation_and_never_delete(self):
        existing = "Always use reload and verify when editing a workbook before saving changes."
        contradictory = "Never use reload and verify when editing a workbook before saving changes."
        changeset = curate_candidate(
            self.decision(contradictory, (digest("d"),)),
            [{"pattern_id": "pat_existing", "cluster_id": "cluster_existing", "status": "active", "rule": existing, "contradiction_count": 0}],
            None,
        )
        self.assertIn(changeset.operations[0].operation, {"REVISE_PATTERN", "DEPRECATE_PATTERN"})
        self.assertNotIn(changeset.operations[0].operation, {"DELETE_FILE", "DELETE_EVENT"})
        self.assertEqual(changeset.operations[0].payload.get("reason_code"), "CONTRADICTION_REVIEW")

    def test_insufficient_evidence_returns_no_change(self):
        changeset = curate_candidate(
            {
                "decision": "YES",
                "title": "Incomplete",
                "claim": "This claim has no evidence and must not be inherited.",
                "classification": "private-reusable",
            },
            [],
            None,
        )
        self.assertEqual([item.operation for item in changeset.operations], ["NO_CHANGE"])
        self.assertEqual(changeset.operations[0].payload["reason_code"], "NO_EVIDENCE")

    def test_no_decision_cannot_enter_curator(self):
        with self.assertRaisesRegex(ValueError, "CURATOR_REQUIRES_GATE_YES"):
            curate_candidate({"decision": "NO", "claim": "Do not inherit this candidate."}, [], None)

    def test_provider_is_not_recursively_invoked(self):
        claim = "A verified reusable observation should remain available to the next independent CLI task."
        changeset = curate_candidate(self.decision(claim, (digest("e"),)), [], ProviderThatMustNotRun())
        self.assertTrue(changeset.operations)


if __name__ == "__main__":
    unittest.main()

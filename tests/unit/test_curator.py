from __future__ import annotations

import unittest
import tempfile
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from ei.operation_runtime import OperationBudget

from ei.changeset import apply_changeset
from ei.curator import curate_candidate
from ei.gate import GateDecision
from ei.journal import iter_events


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


class ProviderThatMustNotRun:
    provider_id = "test-provider"

    def generate(self, *args, **kwargs):
        raise AssertionError("curator must not invoke a provider")


class CuratorTests(unittest.TestCase):
    def test_source_refs_are_domain_hashed_before_changeset_persistence(self):
        from tests.unattended_helpers import make_settings

        claim = "A verified reusable process preserves source identity while excluding local paths from shared records."
        base = {
            "decision": "YES",
            "title": "Source identity",
            "claim": claim,
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "source_kind": "codex_memory",
            "domain": "acceptance",
            "source_host_id": "codex-cli",
            "source_host_family": "codex-compatible",
            "applicability_scope": "host",
            "applicable_host_ids": ["codex-cli"],
            "applicable_host_families": [],
        }
        cases = (
            (r"C:\synthetic\memory.md", "sha256:b05b1f6107e8d134b11840056a7c05c145e5f0f29c925d5c9a4acd917553894a", True),
            ("/tmp/synthetic/memory.md", "sha256:507f5e7c3d175f5fe60d85e594a300c087ad06e4179e8cd70749de56455a7ea0", True),
            ("memory://synthetic/record-1", "sha256:0b745cda5fcef6ce1e7a3c2580bf0517505ebed6df942e7a46bcf46a47f8ecfa", True),
            ("sha256:" + "f" * 64, "sha256:" + "f" * 64, False),
        )
        for index, (source_ref, expected_hash, is_raw) in enumerate(cases):
            with self.subTest(source_ref_kind=index), tempfile.TemporaryDirectory() as tmp:
                candidate = {**base, "source_ref": source_ref, "evidence_refs": ["sha256:" + chr(ord("a") + index) * 64]}
                changeset = curate_candidate(candidate, [], None)
                repeated = curate_candidate(candidate, [], None)
                operation = changeset.operations[0]

                self.assertEqual(operation.operation, "CREATE_OBSERVATION")
                self.assertEqual(operation.payload["source_ref"], expected_hash)
                self.assertEqual(repeated.operations[0].payload["source_ref"], expected_hash)
                self.assertEqual(operation.payload["source_hashes"], candidate["evidence_refs"])
                self.assertEqual(operation.payload["evidence_refs"], candidate["evidence_refs"])
                self.assertEqual(operation.payload["provenances"], candidate["evidence_refs"])
                self.assertEqual(operation.payload["source_host_id"], "codex-cli")
                self.assertEqual(operation.payload["source_host_family"], "codex-compatible")
                self.assertEqual(operation.payload["applicability_scope"], "host")
                self.assertEqual(operation.payload["applicable_host_ids"], ["codex-cli"])
                self.assertEqual(operation.payload["applicable_host_families"], [])
                if is_raw:
                    self.assertNotIn(source_ref, json.dumps(changeset.to_dict(), ensure_ascii=False))

                settings = make_settings(Path(tmp))
                applied = apply_changeset(changeset, settings)
                self.assertTrue(applied.applied, applied.reason_code)
                observation = next(event for event in iter_events(settings.paths.event_dir) if event.event_type == "observation.recorded")
                self.assertEqual(observation.payload["source_ref_hash"], expected_hash)
                self.assertEqual(observation.payload["source_hash"], candidate["evidence_refs"][0])
                self.assertEqual(observation.payload["source_hashes"], candidate["evidence_refs"])
                self.assertEqual(observation.payload["source_host_id"], "codex-cli")
                self.assertEqual(observation.payload["source_host_family"], "codex-compatible")
                self.assertEqual(observation.payload["applicability_scope"], "host")
                self.assertEqual(observation.payload["applicable_host_ids"], ["codex-cli"])
                if is_raw:
                    self.assertNotIn(source_ref, json.dumps(observation.to_dict(), ensure_ascii=False))

    def test_forbidden_source_ref_remains_rejected_before_hashing(self):
        source_ref = r"C:\synthetic\auth\memory.md"
        changeset = curate_candidate(
            {
                "decision": "YES",
                "title": "Source identity",
                "claim": "A verified reusable process preserves source identity while excluding local paths from shared records.",
                "evidence_refs": [digest("a")],
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "source_kind": "codex_memory",
                "source_ref": source_ref,
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
            },
            [],
            None,
        )
        self.assertEqual([item.operation for item in changeset.operations], ["NO_CHANGE"])
        self.assertEqual(changeset.operations[0].payload["reason_code"], "PRIVACY_REJECTED")
        self.assertNotIn(source_ref, json.dumps(changeset.to_dict(), ensure_ascii=False))

    def test_observation_preserves_cwd_scope_digest_without_persisting_raw_path(self):
        claim = "A verified reusable process must preserve independent project evidence before promotion."
        base = {"decision": "YES", "title": "Project evidence", "claim": claim,
                "evidence_refs": [digest("a")], "benefit": "reduced_rework",
                "classification": "private-reusable", "domain": "same-domain"}
        observed = []
        for fields, expected in (
            ({"cwd": " project-A "}, "sha256:" + hashlib.sha256(b" project-A ").hexdigest()),
            ({"cwd": " project-A "}, "sha256:" + hashlib.sha256(b" project-A ").hexdigest()),
            ({"cwd": "project-B"}, "sha256:" + hashlib.sha256(b"project-B").hexdigest()),
            ({"cwd_fingerprint": digest("f"), "cwd": "must-not-replace-existing"}, digest("f")),
            ({}, ""),
            ({"cwd": ""}, ""),
            ({"cwd": None}, ""),
            ({"cwd": 123}, ""),
            ({"cwd_fingerprint": "not-a-fingerprint"}, ""),
        ):
            with self.subTest(fields=fields):
                changeset = curate_candidate({**base, **fields}, [], None)
                operation = changeset.operations[0]
                self.assertEqual(operation.operation, "CREATE_OBSERVATION")
                self.assertEqual(operation.payload.get("cwd_fingerprint", ""), expected)
                self.assertNotIn("cwd", operation.payload)
                if isinstance(fields.get("cwd"), str) and fields["cwd"]:
                    self.assertNotIn(fields["cwd"], json.dumps(changeset.to_dict()))
                observed.append(operation.payload.get("cwd_fingerprint", ""))
        self.assertEqual(observed[0], observed[1])
        self.assertNotEqual(observed[0], observed[2])

    def test_operation_deadline_cannot_be_partial_no_change_or_match(self):
        claim = "When editing a workbook, reload it and validate formulas before saving."
        with self.assertRaises(TimeoutError):
            curate_candidate(self.decision(claim), [], None, operation_budget=OperationBudget(0))
        budget = OperationBudget(5000)
        def patterns():
            yield {"pattern_id": "first", "rule": claim, "status": "active"}
            budget.deadline = 0
            yield {"pattern_id": "second", "rule": claim, "status": "active"}
        with self.assertRaises(TimeoutError):
            curate_candidate(self.decision(claim), patterns(), None, operation_budget=budget)
        from ei import curator
        original = curator.similarity
        budget = OperationBudget(5000)
        def compare_then_expire(*args):
            value = original(*args)
            budget.deadline = 0
            return value
        with patch("ei.curator.similarity", side_effect=compare_then_expire):
            with self.assertRaises(TimeoutError):
                curate_candidate(self.decision(claim), [{"pattern_id": "one", "rule": claim + " Carefully.", "status": "active"}], None, operation_budget=budget)

    def test_operation_budget_reaches_index_read_and_preserves_policy_argument(self):
        from ei.project import project_events
        decision = self.decision("A validated and reusable test needs independent source evidence before promotion.", (digest("a"), digest("b")))
        policy = {"promotion_policy": {"independent_provenance_count": 3}}
        with tempfile.TemporaryDirectory() as tmp:
            index = project_events([], Path(tmp))
            from ei import curator
            original = curator.read_index_items
            budget = OperationBudget(5000)
            def read_then_expire(*args, **kwargs):
                value = original(*args, **kwargs)
                self.assertIs(kwargs.get("budget"), budget)
                budget.deadline = 0
                return value
            with patch("ei.curator.read_index_items", side_effect=read_then_expire):
                with self.assertRaises(TimeoutError):
                    curate_candidate(decision, index, None, policy, operation_budget=budget)
        legacy = curate_candidate(decision, [], None, policy)
        bounded = curate_candidate(decision, [], None, policy, operation_budget=OperationBudget(5000))
        self.assertEqual(legacy.operations, bounded.operations)
        self.assertNotIn("CREATE_CANDIDATE", [item.operation for item in bounded.operations])

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

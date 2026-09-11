from __future__ import annotations

import unittest

from ei.experiment import ExperimentConfig, build_effect_evidence, validate_effect_evidence


class ABMeasurementAcceptanceTests(unittest.TestCase):
    subject = "a" * 40
    evidence_index_sha256 = "sha256:" + "b" * 64

    def _evidence(self, summary: dict[str, object]) -> dict[str, object]:
        return build_effect_evidence(
            summary,
            subject_commit_sha=self.subject,
            evidence_index_sha256=self.evidence_index_sha256,
        )

    def _summary(self, *, eligible: int = 50, days: int = 14, power: float = 0.80) -> dict[str, object]:
        config = ExperimentConfig.defaults()
        primary = {
            metric: {
                "status": "AVAILABLE",
                "provenance_status": "verified",
                "control_n": eligible,
                "treatment_n": eligible,
                "unknown_provenance_n": 0,
            }
            for metric in config.primary_metrics
        }
        return {
            "experiment_id": config.experiment_id,
            "protocol_hash": config.protocol_hash,
            "configuration": {"alpha": config.alpha, "primary_metrics": list(config.primary_metrics)},
            "sample": {"variant_counts": {"control": eligible, "treatment": eligible}, "calendar_days": days},
            "primary_metrics": primary,
            "missing_data": {"metrics": [], "outcomes_missing": 0, "orphan_outcomes": 0, "duplicate_outcomes": 0, "invalid_outcomes": 0},
            "audit": {"contamination_count": 0, "assignment_drift_count": 0, "protocol_mismatch_count": 0, "post_treatment_exclusion_count": 0},
            "conclusion": "CAUSAL_EFFECT_ESTIMATED",
            "decision": "REVIEW_EFFECT_WITH_PRE_REGISTERED_RULE",
            "estimated_power": power,
        }

    def test_effect_evidence_requires_the_preregistered_gates(self) -> None:
        evidence = self._evidence(self._summary(power=0.90))
        self.assertTrue(
            validate_effect_evidence(
                evidence,
                expected_subject_commit_sha=self.subject,
                expected_evidence_index_sha256=self.evidence_index_sha256,
            )
        )
        self.assertEqual(evidence["eligible_units_per_arm"], 50)
        self.assertEqual(evidence["duration_days"], 14)

    def test_underpowered_or_short_evidence_never_validates(self) -> None:
        underpowered = self._evidence(self._summary(eligible=49))
        with self.assertRaisesRegex(ValueError, "EFFECT_SAMPLE_BELOW_MINIMUM"):
            validate_effect_evidence(underpowered)
        short = self._evidence(self._summary(days=13))
        with self.assertRaisesRegex(ValueError, "EFFECT_DURATION_BELOW_MINIMUM"):
            validate_effect_evidence(short)

    def test_contamination_and_missingness_are_gate_fields(self) -> None:
        summary = self._summary()
        summary["audit"]["contamination_count"] = 1
        evidence = self._evidence(summary)
        with self.assertRaisesRegex(ValueError, "EFFECT_CONTAMINATION_INVALID"):
            validate_effect_evidence(evidence)

        summary = self._summary()
        summary["missing_data"]["outcomes_missing"] = 1
        evidence = self._evidence(summary)
        with self.assertRaisesRegex(ValueError, "EFFECT_MISSINGNESS_INVALID"):
            validate_effect_evidence(evidence)

    def test_tampered_analysis_digest_is_rejected(self) -> None:
        evidence = self._evidence(self._summary())
        evidence["power"] = 0.95
        with self.assertRaisesRegex(ValueError, "EFFECT_ANALYSIS_HASH_MISMATCH"):
            validate_effect_evidence(evidence)

    def test_effect_evidence_is_bound_to_release_subject_and_index(self) -> None:
        evidence = self._evidence(self._summary())
        with self.assertRaisesRegex(ValueError, "EFFECT_SUBJECT_MISMATCH"):
            validate_effect_evidence(evidence, expected_subject_commit_sha="c" * 40)
        with self.assertRaisesRegex(ValueError, "EFFECT_EVIDENCE_INDEX_MISMATCH"):
            validate_effect_evidence(
                evidence,
                expected_subject_commit_sha=self.subject,
                expected_evidence_index_sha256="sha256:" + "d" * 64,
            )


if __name__ == "__main__":
    unittest.main()

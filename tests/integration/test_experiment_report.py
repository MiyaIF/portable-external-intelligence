import tempfile
import unittest
from pathlib import Path

from ei.experiment import (
    ExperimentConfig,
    assign_arm,
    assign_variant,
    prepare_exposure,
    render_experiment_report,
    summarize_experiment,
)


class ExperimentReportTests(unittest.TestCase):
    def test_control_logs_candidates_without_context_and_treatment_exposes_context(self):
        patterns = [
            {
                "pattern_id": "pat_formula",
                "cluster_id": "cluster_formula",
                "status": "active",
                "rule": "数式を再読込して確認する",
                "evidence_count": 2,
                "benefit_count": 1,
                "updated_at": "2026-08-25T00:00:00+00:00",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exposures.jsonl"
            control_session = next(
                f"control-{index}" for index in range(1000) if assign_variant(f"control-{index}", "retrieval-v1").value == "control"
            )
            treatment_session = next(
                f"treatment-{index}" for index in range(1000) if assign_variant(f"treatment-{index}", "retrieval-v1").value == "treatment"
            )
            control = prepare_exposure(control_session, "retrieval-v1", "数式", patterns, record_path=path)
            treatment = prepare_exposure(treatment_session, "retrieval-v1", "数式", patterns, record_path=path)
            self.assertEqual(control.variant.value, "control")
            self.assertEqual(control.additional_context, "")
            self.assertEqual(control.candidate_ids, ("pat_formula",))
            self.assertEqual(treatment.variant.value, "treatment")
            self.assertIn("pat_formula", treatment.additional_context)
            self.assertEqual(treatment.exposed_ids, ("pat_formula",))
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)

    def test_prepare_exposure_filters_by_host_id_and_family(self):
        patterns = [
            {
                "pattern_id": "pat_family_match",
                "cluster_id": "cluster_family_match",
                "status": "active",
                "classification": "private-reusable",
                "rule": "reuse rule for compatible host",
                "evidence_count": 2,
                "benefit_count": 1,
                "updated_at": "2026-09-09T00:00:00+00:00",
                "source_host_id": "test-compatible-cli",
                "source_host_family": "gemini-compatible",
                "applicability_scope": "family",
                "applicable_host_ids": [],
                "applicable_host_families": ["gemini-compatible"],
            },
            {
                "pattern_id": "pat_family_other",
                "cluster_id": "cluster_family_other",
                "status": "active",
                "classification": "private-reusable",
                "rule": "reuse rule for another family",
                "evidence_count": 2,
                "benefit_count": 1,
                "updated_at": "2026-09-09T00:00:00+00:00",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
                "applicability_scope": "family",
                "applicable_host_ids": [],
                "applicable_host_families": ["codex-compatible"],
            },
        ]
        treatment_session = next(
            f"host-treatment-{index}"
            for index in range(1000)
            if assign_variant(f"host-treatment-{index}", "retrieval-v1").value == "treatment"
        )
        exposure = prepare_exposure(
            treatment_session,
            "retrieval-v1",
            "reuse rule",
            patterns,
            host_id="test-compatible-cli",
            host_family="gemini-compatible",
        )
        self.assertEqual(exposure.candidate_ids, ("pat_family_match",))
        self.assertEqual(exposure.exposed_ids, ("pat_family_match",))
        self.assertIn("pat_family_match", exposure.additional_context)
        self.assertNotIn("pat_family_other", exposure.additional_context)

    def test_preregistered_effect_requires_linked_full_sample_and_power(self):
        config = ExperimentConfig.defaults()
        exposures = []
        outcomes = []
        control_index = 0
        treatment_index = 0
        for index in range(2000):
            session_hash = "sha256:" + format(index + 1, "012x")[-12:]
            arm = assign_arm(session_hash, config.experiment_id)
            if arm == "control":
                if control_index >= config.minimum_sessions_per_variant:
                    continue
                ordinal = control_index
                control_index += 1
            else:
                if treatment_index >= config.minimum_sessions_per_variant:
                    continue
                ordinal = treatment_index
                treatment_index += 1
            session = session_hash
            task = "sha256:" + format(index + 10000, "012x")[-12:]
            exposure = {
                "experiment_id": config.experiment_id,
                "protocol_hash": config.protocol_hash,
                "session_id_hash": session,
                "task_id_hash": task,
                "query_fingerprint": "sha256:" + "a" * 12,
                "arm": arm,
                "candidate_ids": ["pat_fixture"],
                "selected_ids": ["pat_fixture"] if arm == "treatment" else [],
                "injected_chars": 20 if arm == "treatment" else 0,
                "retrieval_latency_ms": 3,
                "host_id": "fixture-host",
                "model_family": "fixture-model",
                "domain": "general",
                "observed_at": "2026-08-01T00:00:00Z" if ordinal % 2 == 0 else "2026-08-15T00:00:00Z",
                "eligible": True,
                "shadow_retrieval": True,
                "context_injected": arm == "treatment",
                "contamination": False,
            }
            exposures.append(exposure)
            outcome = {
                "experiment_id": config.experiment_id,
                "session_id_hash": session,
                "task_id_hash": task,
                "exposure_id": "exp_fixture_" + str(index),
                "observed_at": exposure["observed_at"],
                "host_id": "fixture-host",
                "model_family": "fixture-model",
                "domain": "general",
                "repeated_search": 1 if arm == "treatment" else 3,
                "rework": 0 if arm == "treatment" else 1,
                "failure": 0 if arm == "treatment" else 1,
                "uncached_input": 60 if arm == "treatment" else 100,
                "cached_input": 50 if arm == "treatment" else 80,
                "turns_to_completion": 3 if arm == "treatment" else 5,
                "incorrect_pattern_application": 0,
                "explicit_correction": 0,
                "privacy_incident": 0,
                "completion": 1,
                "metric_sources": {
                    "repeated_search": "fixture_outcome",
                    "rework": "fixture_outcome",
                    "failure": "fixture_outcome",
                    "uncached_input": "fixture_usage",
                    "cached_input": "fixture_usage",
                    "turns_to_completion": "fixture_hook",
                    "incorrect_pattern_application": "fixture_outcome",
                    "explicit_correction": "fixture_outcome",
                    "privacy_incident": "fixture_outcome",
                },
                "provenance": ["sha256:" + "b" * 12],
            }
            outcomes.append(outcome)
            if control_index == config.minimum_sessions_per_variant and treatment_index == config.minimum_sessions_per_variant:
                break
        summary = summarize_experiment(exposures, outcomes, config)
        self.assertEqual(summary["sample"]["variant_counts"], {"control": 50, "treatment": 50})
        self.assertEqual(summary["conclusion"], "CAUSAL_EFFECT_ESTIMATED")
        self.assertTrue(summary["effect_validated"])
        self.assertEqual(summary["audit"]["blocking_reasons"], [])
        self.assertGreaterEqual(summary["estimated_power"], config.power_target)
        self.assertIn("causal_only_after_exposure_linkage", summary["inference"]["cache_quota_association"])

    def test_orphan_outcome_and_missing_provenance_block_causal_claim(self):
        config = ExperimentConfig.defaults()
        session = "sha256:" + "1" * 12
        exposure = {
            "experiment_id": config.experiment_id,
            "protocol_hash": config.protocol_hash,
            "session_id_hash": session,
            "task_id_hash": "sha256:" + "2" * 12,
            "query_fingerprint": "sha256:" + "3" * 12,
            "arm": assign_arm(session, config.experiment_id),
            "candidate_ids": [],
            "selected_ids": [],
            "observed_at": "2026-08-01T00:00:00Z",
            "eligible": True,
        }
        outcome = {
            "experiment_id": config.experiment_id,
            "session_id_hash": "sha256:" + "4" * 12,
            "task_id_hash": "sha256:" + "5" * 12,
            "rework": 1,
            "repeated_search": 1,
        }
        summary = summarize_experiment([exposure], [outcome], config)
        self.assertEqual(summary["conclusion"], "CAUSAL_EFFECT_NOT_IDENTIFIED")
        self.assertIn("OUTCOME_LINKAGE_INCOMPLETE", summary["audit"]["blocking_reasons"])
        self.assertIn("PRIMARY_METRIC_MISSING", summary["audit"]["blocking_reasons"])
    def test_underpowered_or_short_experiment_is_not_identified(self):
        exposures = [
            {"session_id": "s1", "experiment_id": "retrieval-v1", "variant": "control", "observed_at": "2026-08-01T00:00:00Z", "eligible": True},
            {"session_id": "s2", "experiment_id": "retrieval-v1", "variant": "treatment", "observed_at": "2026-08-15T00:00:00Z", "eligible": True},
        ]
        summary = summarize_experiment(exposures, [], ExperimentConfig.defaults())
        self.assertEqual(summary["conclusion"], "CAUSAL_EFFECT_NOT_IDENTIFIED")
        report = render_experiment_report(summary)
        for section in (
            "Experiment configuration",
            "Sample and exclusions",
            "Primary metrics",
            "Secondary metrics",
            "Guardrails",
            "Missing data",
            "Causal conclusion",
            "Decision",
        ):
            self.assertIn(f"## {section}", report)


if __name__ == "__main__":
    unittest.main()

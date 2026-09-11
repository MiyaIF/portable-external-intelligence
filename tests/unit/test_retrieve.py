import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ei.models import PatternState
from ei.retrieve import (
    ExposureRecord,
    RetrievalPolicy,
    RetrievalQuery,
    host_scope_allowed,
    rank_patterns,
    record_retrieval_exposure,
)


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.policy = RetrievalPolicy.defaults()

    @staticmethod
    def _host_pattern(**overrides):
        pattern = {
            "pattern_id": "pat_host_scope",
            "cluster_id": "cluster_host_scope",
            "status": "active",
            "classification": "private-reusable",
            "rule": "reuse rule",
            "evidence_count": 2,
            "benefit_count": 1,
            "updated_at": "2026-09-01T00:00:00+00:00",
            "source_host_id": "test-compatible-cli",
            "source_host_family": "gemini-compatible",
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        }
        pattern.update(overrides)
        return pattern

    def test_universal_scope_is_available_to_any_host(self):
        pattern = self._host_pattern()
        self.assertTrue(
            host_scope_allowed(
                RetrievalQuery(host_id="codex-cli", host_family="codex-compatible"),
                pattern,
            )
        )
        self.assertTrue(
            host_scope_allowed(
                RetrievalQuery(host_id="unknown-agent", host_family=""),
                pattern,
            )
        )

    def test_family_scope_is_available_to_compatible_host_only(self):
        pattern = self._host_pattern(
            applicability_scope="family",
            applicable_host_families=["gemini-compatible"],
        )
        matching = RetrievalQuery(
            prompt="reuse rule",
            host_id="test-compatible-cli",
            host_family="gemini-compatible",
        )
        other = RetrievalQuery(
            prompt="reuse rule",
            host_id="codex-cli",
            host_family="codex-compatible",
        )
        unknown = RetrievalQuery(
            prompt="reuse rule",
            host_id="unknown-agent",
            host_family="",
        )
        self.assertTrue(host_scope_allowed(matching, pattern))
        self.assertFalse(host_scope_allowed(other, pattern))
        self.assertFalse(host_scope_allowed(unknown, pattern))

    def test_host_scope_is_available_to_exact_host_only(self):
        pattern = self._host_pattern(
            applicability_scope="host",
            applicable_host_ids=["gemini-cli"],
            source_host_id="gemini-cli",
            source_host_family="gemini-compatible",
        )
        matching = RetrievalQuery(host_id="gemini-cli", host_family="gemini-compatible")
        other = RetrievalQuery(host_id="codex-cli", host_family="codex-compatible")
        self.assertTrue(host_scope_allowed(matching, pattern))
        self.assertFalse(host_scope_allowed(other, pattern))

    def test_new_host_scope_ignores_cross_host_policy(self):
        pattern = self._host_pattern(
            applicability_scope="host",
            applicable_host_ids=["gemini-cli"],
            source_host_id="gemini-cli",
            source_host_family="gemini-compatible",
        )
        policy = replace(self.policy, allow_cross_host=True)
        result = rank_patterns(
            RetrievalQuery(prompt="reuse rule", host_id="codex-cli", host_family="codex-compatible"),
            [pattern],
            policy,
        )
        self.assertEqual(result, [])

    def test_current_scope_requires_complete_source_pair(self):
        pattern = self._host_pattern(
            applicability_scope="family",
            applicable_host_families=["gemini-compatible"],
            source_host_id="test-compatible-cli",
            source_host_family="",
        )
        query = RetrievalQuery(host_id="test-compatible-cli", host_family="gemini-compatible")
        self.assertFalse(host_scope_allowed(query, pattern))

    def test_current_scope_mixed_with_legacy_selector_is_rejected(self):
        pattern = self._host_pattern(
            applicability_scope="family",
            applicable_host_families=["gemini-compatible"],
            source_host_id="test-compatible-cli",
            source_host_family="gemini-compatible",
            host_ids=["test-compatible-cli"],
        )
        query = RetrievalQuery(host_id="test-compatible-cli", host_family="gemini-compatible")
        self.assertFalse(host_scope_allowed(query, pattern))

    def test_pattern_state_current_scope_and_default_compatibility(self):
        current = PatternState(
            pattern_id="pat_current",
            rule="reuse rule",
            source_host_id="test-compatible-cli",
            source_host_family="gemini-compatible",
            applicability_scope="family",
            applicable_host_families=("gemini-compatible",),
        )
        default = PatternState(pattern_id="pat_default", rule="reuse rule")
        matching = RetrievalQuery(host_id="test-compatible-cli", host_family="gemini-compatible")
        other = RetrievalQuery(host_id="codex-cli", host_family="codex-compatible")
        self.assertTrue(host_scope_allowed(matching, current))
        self.assertFalse(host_scope_allowed(other, current))
        self.assertTrue(host_scope_allowed(other, default))

    def test_legacy_host_ids_and_hostless_patterns_keep_legacy_contract(self):
        legacy_host = {
            "pattern_id": "pat_legacy_host",
            "cluster_id": "legacy-host",
            "status": "active",
            "rule": "reuse rule",
            "host_ids": ["codex-cli"],
            "evidence_count": 2,
            "benefit_count": 1,
        }
        self.assertTrue(host_scope_allowed(RetrievalQuery(host_id="codex-cli"), legacy_host))
        self.assertFalse(host_scope_allowed(RetrievalQuery(host_id="gemini-cli"), legacy_host))
        self.assertTrue(host_scope_allowed(RetrievalQuery(host_id="gemini-cli"), {"pattern_id": "legacy-universal"}))

        policy = replace(self.policy, allow_cross_host=True)
        result = rank_patterns(
            RetrievalQuery(prompt="reuse rule", host_id="gemini-cli"),
            [legacy_host],
            policy,
        )
        self.assertEqual([hit.pattern_id for hit in result], ["pat_legacy_host"])

    def test_host_filtered_patterns_do_not_enter_scoring(self):
        pattern = self._host_pattern(
            applicability_scope="host",
            applicable_host_ids=["gemini-cli"],
            source_host_id="gemini-cli",
            source_host_family="gemini-compatible",
            evidence_count=100,
            benefit_count=100,
            utility=100.0,
        )
        result = rank_patterns(
            RetrievalQuery(prompt="reuse rule", host_id="codex-cli", host_family="codex-compatible"),
            [pattern],
        )
        self.assertEqual(result, [])

    def test_exact_lexical_match_outranks_fresh_unrelated_content(self):
        hits = rank_patterns(
            RetrievalQuery(prompt="再読込 数式", cwd_fingerprint="cwd:x", domain="spreadsheet"),
            [
                {
                    "pattern_id": "pat_exact",
                    "cluster_id": "cluster_exact",
                    "status": "active",
                    "rule": "再読込して数式を確認する",
                    "applicability": ["spreadsheet"],
                    "cwd_fingerprints": ["cwd:x"],
                    "evidence_count": 2,
                    "benefit_count": 1,
                    "updated_at": "2026-01-01T00:00:00+00:00",
                },
                {
                    "pattern_id": "pat_fresh",
                    "cluster_id": "cluster_fresh",
                    "status": "active",
                    "rule": "全く異なる文書の整理方法",
                    "applicability": ["other"],
                    "evidence_count": 5,
                    "benefit_count": 1,
                    "updated_at": "2026-08-25T00:00:00+00:00",
                },
            ],
            self.policy,
        )
        self.assertEqual(hits[0].pattern_id, "pat_exact")

    def test_matching_cwd_adds_scope_score(self):
        patterns = [
            {
                "pattern_id": "pat_match",
                "cluster_id": "cluster_match",
                "status": "active",
                "rule": "同じ問題を確認する",
                "cwd_fingerprints": ["cwd:x"],
                "evidence_count": 1,
                "updated_at": "2026-08-25T00:00:00+00:00",
            },
            {
                "pattern_id": "pat_other",
                "cluster_id": "cluster_other",
                "status": "active",
                "rule": "同じ問題を確認する",
                "cwd_fingerprints": ["cwd:y"],
                "evidence_count": 1,
                "updated_at": "2026-08-25T00:00:00+00:00",
            },
        ]
        hits = rank_patterns(RetrievalQuery(prompt="同じ問題", cwd_fingerprint="cwd:x"), patterns, self.policy)
        self.assertEqual(hits[0].pattern_id, "pat_match")

    def test_host_version_and_scope_filters_are_applied_before_scoring(self):
        patterns = [
            {"pattern_id": "pat_host", "cluster_id": "host", "status": "active", "rule": "CLIで再読込を検証する", "host_ids": ["codex-cli"], "version_constraint": ">=1.2,<2", "applicability": ["spreadsheet"], "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"},
            {"pattern_id": "pat_other_host", "cluster_id": "other", "status": "active", "rule": "CLIで再読込を検証する", "host_ids": ["gemini-cli"], "version_constraint": ">=1.2,<2", "applicability": ["spreadsheet"], "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"},
            {"pattern_id": "pat_other_domain", "cluster_id": "domain", "status": "active", "rule": "CLIで再読込を検証する", "host_ids": ["codex-cli"], "version_constraint": ">=1.2,<2", "applicability": ["other"], "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"},
        ]
        query = RetrievalQuery(prompt="再読込", domain="spreadsheet", host_id="codex-cli", version="1.4.0")
        self.assertEqual([hit.pattern_id for hit in rank_patterns(query, patterns, self.policy)], ["pat_host"])
        self.assertEqual(rank_patterns(replace(query, version="2.1.0"), [patterns[0]], self.policy), [])

    def test_duplicate_cluster_uses_stable_low_id_and_limits_results(self):
        patterns = []
        for index in range(3):
            patterns.append({"pattern_id": f"pat_{index:02d}", "cluster_id": f"cluster_{index:02d}", "status": "active", "rule": "再読込して検証する", "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"})
        patterns.extend([
            {"pattern_id": "pat_z", "cluster_id": "cluster_same", "status": "active", "rule": "再読込して検証する", "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"},
            {"pattern_id": "pat_a", "cluster_id": "cluster_same", "status": "active", "rule": "再読込して検証する", "evidence_count": 2, "benefit_count": 1, "updated_at": "2026-08-25T00:00:00+00:00"},
        ])
        hits = rank_patterns(RetrievalQuery(prompt="再読込"), patterns, self.policy)
        self.assertLessEqual(len(hits), 5)
        self.assertIn("pat_a", [hit.pattern_id for hit in hits])
        self.assertNotIn("pat_z", [hit.pattern_id for hit in hits])

    def test_ineligible_status_secret_and_duplicate_cluster_are_excluded(self):
        hits = rank_patterns(
            RetrievalQuery(prompt="再読込"),
            [
                {"pattern_id": "pat_active", "cluster_id": "cluster", "status": "active", "rule": "再読込して確認", "evidence_count": 2},
                {"pattern_id": "pat_same_cluster", "cluster_id": "cluster", "status": "active", "rule": "再読込して検証", "evidence_count": 1},
                {"pattern_id": "pat_old", "cluster_id": "old", "status": "deprecated", "rule": "再読込", "evidence_count": 3},
                {"pattern_id": "pat_secret", "cluster_id": "secret", "status": "active", "classification": "secret", "rule": "再読込"},
            ],
            self.policy,
        )
        self.assertEqual([hit.pattern_id for hit in hits], ["pat_active"])

    def test_exposure_record_contains_only_hashes_and_selected_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exposures.jsonl"
            record_retrieval_exposure(ExposureRecord("exp_1", "retrieval-v1", "sha256:session", "treatment", ("pat_1",), "sha256:query", 120, 4, "codex-cli", "2026-08-25T00:00:00+00:00"), path)
            text = path.read_text(encoding="utf-8")
            payload = json.loads(text)
            self.assertIn("sha256:query", text)
            self.assertIn("pat_1", text)
            self.assertEqual(payload["candidate_scopes"], ["personal"])
            self.assertEqual(payload["scope"], "personal")
            self.assertNotIn("再読込", text)
            with self.assertRaisesRegex(ValueError, "EXPOSURE_RAW_TEXT_FORBIDDEN"):
                record_retrieval_exposure({"exposure_id": "exp_2", "query_fingerprint": "sha256:q", "prompt": "再読込"}, path)


if __name__ == "__main__":
    unittest.main()

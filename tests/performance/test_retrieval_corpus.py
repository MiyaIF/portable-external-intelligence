import statistics
import time
import unittest

from ei.certification import REQUIRED_EVENT_NAMES
from ei.context import build_context
from ei.retrieve import RetrievalPolicy, RetrievalQuery, rank_patterns
from tests.fixtures.corpus.generate_fixture import generate_patterns


class RetrievalCorpusPerformanceTests(unittest.TestCase):
    def test_1_11m_character_corpus_p95_and_context_budget(self):
        patterns = generate_patterns()
        self.assertGreaterEqual(sum(len(item["rule"]) for item in patterns), 1_110_000)
        self.assertLessEqual(sum(len(item["rule"]) for item in patterns), 1_120_000)
        query = RetrievalQuery(prompt="spreadsheet formula reload verify", domain="spreadsheet")
        durations = []
        for _ in range(20):
            started = time.perf_counter()
            hits = rank_patterns(query, patterns)
            context = build_context(hits, max_chars=5000)
            durations.append(time.perf_counter() - started)
            self.assertLessEqual(len(context), 5000)
        p95 = statistics.quantiles(durations, n=20, method="inclusive")[18]
        self.assertLess(p95, 1.0, msg=f"retrieval p95={p95:.3f}s")
        self.assertEqual(len(REQUIRED_EVENT_NAMES), 4)

    def test_same_corpus_and_query_have_stable_selection(self):
        patterns = generate_patterns()
        query = RetrievalQuery(prompt="spreadsheet formula reload verify", domain="spreadsheet")
        first = rank_patterns(query, patterns)
        second = rank_patterns(query, patterns)
        self.assertEqual(
            [(item.pattern_id, item.score) for item in first],
            [(item.pattern_id, item.score) for item in second],
        )
        self.assertLessEqual(len(build_context(first, max_chars=5000)), 5000)

    def test_disallowed_host_patterns_do_not_consume_context_budget(self):
        patterns = generate_patterns()
        patterns.append(
            {
                "pattern_id": "pat_wrong_host",
                "cluster_id": "cluster_wrong_host",
                "status": "active",
                "classification": "private-reusable",
                "rule": "spreadsheet formula reload verify secret host rule",
                "evidence_count": 100,
                "benefit_count": 100,
                "updated_at": "2026-09-09T00:00:00+00:00",
                "applicability_scope": "host",
                "applicable_host_ids": ["gemini-cli"],
                "applicable_host_families": [],
            }
        )
        query = RetrievalQuery(
            prompt="spreadsheet formula reload verify",
            domain="spreadsheet",
            host_id="codex-cli",
            host_family="codex-compatible",
        )
        hits = rank_patterns(query, patterns, RetrievalPolicy(min_score=0.0, max_results=100))
        self.assertNotIn("pat_wrong_host", {item.pattern_id for item in hits})
        self.assertNotIn("secret host rule", build_context(hits, max_chars=5000))


if __name__ == "__main__":
    unittest.main()

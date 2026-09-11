from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ei.context import build_context
from ei.measurement_events import ExposureRecord as MeasurementExposureRecord
from ei.models import Event, RetrievalHit
from ei.project import project_events
from ei.retrieve import RetrievalPolicy, RetrievalQuery, merge_retrieval_hits, search_index_candidates
from ei.index import build_index


class RetrievalMergeTests(unittest.TestCase):
    def test_legacy_retrieval_hit_positionals_keep_personal_defaults(self) -> None:
        hit = RetrievalHit("pat_1", "cluster_1", 0.8, "再利用する", ("general",), 1, "2026-09-05T00:00:00Z")
        self.assertEqual(hit.knowledge_scope, "personal")
        self.assertEqual(hit.supersedes, ())

    def test_search_index_candidates_is_unbounded_before_merge_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "knowledge"
            events = [
                Event.create(
                    "pattern.promoted",
                    f"2026-09-05T00:0{index}:00+00:00",
                    "test",
                    "machine",
                    {
                        "pattern_id": f"pat_{index}",
                        "cluster_id": f"cluster_{index}",
                        "rule": f"再読込して検証する手順 {index}",
                        "provenances": ["source:a", "source:b"],
                        "scopes": ["general"],
                        "applicability": ["general"],
                        "benefit_count": 1,
                        "classification": "private-reusable",
                    },
                    event_id=f"evt_pattern_{index}",
                )
                for index in range(8)
            ]
            project_events(events, root)
            index = build_index(root, root / "index.json")
            policy = RetrievalPolicy(max_results=2)
            candidates = search_index_candidates(index, RetrievalQuery(prompt="再読込"), policy)
            self.assertGreater(len(candidates), policy.max_results)
            merged = merge_retrieval_hits(candidates, (), policy)
            self.assertEqual(len(merged), policy.max_results)

    def test_merge_deduplicates_cluster_and_prefers_personal_only_on_tie(self) -> None:
        team = RetrievalHit("pat_team", "cluster_same", 0.7, "team", ("general",), 1, "", "team", "sha256:" + "a" * 64)
        personal = RetrievalHit("pat_personal", "cluster_same", 0.7, "personal", ("general",), 1, "", "personal", "sha256:" + "a" * 64)
        other = RetrievalHit("pat_other", "cluster_other", 0.9, "other", ("general",), 1, "")
        merged = merge_retrieval_hits((personal,), (team, other), RetrievalPolicy(max_results=5))
        self.assertEqual([item.pattern_id for item in merged], ["pat_other", "pat_personal"])
        self.assertEqual(merged[-1].knowledge_scope, "personal")

    def test_scope_is_rendered_and_measurement_is_scope_safe(self) -> None:
        hit = RetrievalHit("pat_team", "cluster_team", 0.8, "共有ルール", ("general",), 1, "", "team")
        self.assertIn("team", build_context((hit,), 500))
        exposure = MeasurementExposureRecord(
            experiment_id="retrieval-v1",
            session_id_hash="session",
            candidate_ids=("pat_personal", "pat_team"),
            selected_ids=("pat_team",),
            candidate_scopes=("personal", "team"),
            selected_scopes=("team",),
        )
        self.assertEqual(exposure.selected_scopes, ("team",))
        with self.assertRaisesRegex(ValueError, "MEASUREMENT_CANDIDATE_SCOPES_INVALID"):
            MeasurementExposureRecord(
                experiment_id="retrieval-v1",
                session_id_hash="session",
                candidate_ids=("pat_team",),
                candidate_scopes=("secret",),
            )


if __name__ == "__main__":
    unittest.main()

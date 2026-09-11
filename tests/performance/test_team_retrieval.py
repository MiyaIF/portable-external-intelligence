from __future__ import annotations

import statistics
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.cli import _team_projection_for_recall
from ei.config import RuntimePaths, Settings
from ei.context import build_context
from ei.models import RetrievalHit
from ei.retrieve import RetrievalPolicy, merge_retrieval_hits


def hit(pattern_id: str, rule: str, score: float, scope: str) -> RetrievalHit:
    return RetrievalHit(
        pattern_id=pattern_id,
        cluster_id=pattern_id,
        score=score,
        rule=rule,
        applicability=("general",),
        evidence_count=1,
        updated_at="2026-09-05T00:00:00Z",
        knowledge_scope=scope,
    )


class TeamRetrievalPerformanceTests(unittest.TestCase):
    def test_disabled_personal_path_has_no_team_dependency(self) -> None:
        personal = tuple(hit(f"p{index}", f"検証手順 {index}", 0.8 - index / 1000, "personal") for index in range(80))
        policy = RetrievalPolicy(max_results=5, max_chars=5000)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            settings = Settings(
                paths=RuntimePaths(
                    engine_root=root / "engine",
                    personal_knowledge_root=root / "personal",
                    runtime_root=root / "runtime",
                )
            )
            with patch("ei.team_projection.refresh_team_projection") as refresh:
                team_index, status = _team_projection_for_recall(settings)
                merged = merge_retrieval_hits(personal, team_index or (), policy)

        self.assertIsNone(team_index)
        self.assertEqual(status, {"status": "DISABLED", "reason_code": "TEAM_DISABLED"})
        self.assertEqual(len(merged), policy.max_results)
        refresh.assert_not_called()

    def test_enabled_merge_and_context_p95_stays_below_one_second(self) -> None:
        personal = tuple(hit(f"p{index}", f"個人の検証手順 {index}", 0.85 - index / 1000, "personal") for index in range(100))
        team = tuple(hit(f"t{index}", f"チームの検証手順 {index}", 0.84 - index / 1000, "team") for index in range(100))
        policy = RetrievalPolicy(max_results=5, max_chars=5000)
        durations = []
        for _ in range(20):
            started = time.perf_counter()
            selected = merge_retrieval_hits(personal, team, policy)
            rendered = build_context(selected, max_chars=5000)
            durations.append(time.perf_counter() - started)
            self.assertLessEqual(len(rendered), 5000)
        p95 = statistics.quantiles(durations, n=20, method="inclusive")[18]
        self.assertLessEqual(p95, 1.0, msg=f"team retrieval p95={p95:.3f}s")


if __name__ == "__main__":
    unittest.main()

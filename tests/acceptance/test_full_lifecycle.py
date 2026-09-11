import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ei.certification import REQUIRED_EVENT_NAMES
from ei.config import PUBLIC_CLI_HOST_IDS
from ei.lifecycle import evaluate_lifecycle
from ei.models import Event, PromotionPolicy
from ei.project import project_events
from ei.retrieve import RetrievalQuery, rank_patterns
from tests.helpers import make_cluster_state


class FullLifecycleAcceptanceTests(unittest.TestCase):
    def test_public_lifecycle_matrix_is_cli_only(self):
        self.assertEqual(
            PUBLIC_CLI_HOST_IDS,
            ("codex-cli", "claude-code", "gemini-cli", "qwen-code"),
        )
        self.assertNotIn("codex-app", PUBLIC_CLI_HOST_IDS)

    def test_release_boundary_requires_session_end_event(self):
        self.assertEqual(set(REQUIRED_EVENT_NAMES), {"session.start", "prompt.before", "turn.stop", "session.end"})

    def test_raw_candidate_promotion_revision_deprecation_tombstone_and_rebuild(self):
        now = datetime(2026, 8, 25, tzinfo=timezone.utc)
        rule = "異なる案件で再現した判断を、証拠付きで再利用可能なルールとして保存する" * 3
        raw = make_cluster_state(cluster_id="cluster_formula", rule=rule)
        self.assertEqual(evaluate_lifecycle(raw, PromotionPolicy.defaults(), now), [])
        candidate = replace(raw, status="candidate", provenances=frozenset({"source:a", "source:b"}), scopes=frozenset({"cwd:a", "cwd:b"}), applicability=("spreadsheet",), benefit_count=1)
        promoted = evaluate_lifecycle(candidate, PromotionPolicy.defaults(), now)[0]
        promoted = Event.create(promoted.event_type, promoted.occurred_at, promoted.actor, promoted.machine_id, promoted.payload, event_id="evt_promoted")
        revised = Event.create("pattern.revised", "2026-08-25T00:01:00+00:00", "test", "machine", {"pattern_id": promoted.payload["pattern_id"], "rule": "改訂版の判断ルールを証拠と適用範囲付きで保存する" * 3, "version": 2}, event_id="evt_revised")
        active_patterns = [{"pattern_id": promoted.payload["pattern_id"], "cluster_id": "cluster_formula", "status": "active", "rule": promoted.payload["rule"], "evidence_count": 2, "benefit_count": 1, "updated_at": promoted.occurred_at}]
        self.assertTrue(rank_patterns(RetrievalQuery("再利用ルール"), active_patterns))
        deprecated_state = make_cluster_state(status="active", pattern_id=promoted.payload["pattern_id"], contradiction_provenances=frozenset({"x", "y", "z"}))
        deprecated = evaluate_lifecycle(deprecated_state, PromotionPolicy.defaults(), now)[0]
        deprecated = Event.create(deprecated.event_type, deprecated.occurred_at, deprecated.actor, deprecated.machine_id, deprecated.payload, event_id="evt_deprecated")
        tombstoned = Event.create("pattern.tombstoned", "2026-08-25T00:03:00+00:00", "test", "machine", {"pattern_id": promoted.payload["pattern_id"], "reason": "manual_acceptance"}, event_id="evt_tombstoned")
        events = [promoted, revised, deprecated, tombstoned]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            first = project_events(events, root)
            self.assertTrue((root / "archive" / f"{promoted.payload['pattern_id']}.md").exists())
            self.assertEqual(rank_patterns(RetrievalQuery("再利用ルール"), [{"pattern_id": promoted.payload["pattern_id"], "cluster_id": "cluster_formula", "status": "tombstoned", "rule": revised.payload["rule"]}]), [])
            second = project_events(events, root)
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)


if __name__ == "__main__":
    unittest.main()

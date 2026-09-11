import hashlib
import tempfile
import unittest
from pathlib import Path

from ei.dedup import content_fingerprint
from ei.journal import append_event, iter_events
from ei.models import Event
from ei.reconciliation import reconcile_lifecycle


class ReconciliationTests(unittest.TestCase):
    def _observation(self, index: int, claim: str, source: str, cwd: str, occurred_at: str) -> Event:
        source_digest = "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()
        cwd_digest = "sha256:" + hashlib.sha256(cwd.encode("utf-8")).hexdigest()
        return Event.create(
            "observation.recorded",
            occurred_at,
            "test",
            "test-machine",
            {
                "observation_id": f"obs_{index}",
                "title": f"observation-{index}",
                "claim": claim,
                "source_kind": "rollout_summary",
                "source_ref_hash": source_digest,
                "source_hash": source_digest,
                "cwd_fingerprint": cwd_digest,
                "domain": "spreadsheet-operations",
                "outcome_status": "success",
                "benefit": "reduced_rework",
                "classification": "private-reusable",
                "provenance_key": source_digest,
            },
            event_id=f"evt_observation_{index}",
        )

    def test_two_independent_observations_auto_candidate_and_promotion_are_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_dir = Path(tmp) / "events"
            claim = "外部書込後は対象範囲を再読込し、数式と値を検証してから次の処理へ進めることで再作業を防止する。別案件でも同じ確認を実施し、結果を記録して再現性を確認し、品質を保つ手順として適用する"
            append_event(self._observation(1, claim, "source-a", "cwd-a", "2026-08-01T00:00:00+00:00"), event_dir)
            append_event(self._observation(2, claim, "source-b", "cwd-b", "2026-08-02T00:00:00+00:00"), event_dir)
            first = reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2026-08-25T00:00:00+00:00")
            self.assertEqual(first.candidate_events, 1)
            self.assertEqual(first.promotion_events, 1)
            event_types = [event.event_type for event in iter_events(event_dir)]
            self.assertIn("pattern.candidate_created", event_types)
            self.assertIn("pattern.promoted", event_types)
            transition_events = [event for event in iter_events(event_dir) if event.event_type in {"pattern.candidate_created", "pattern.promoted"}]
            self.assertEqual(len(transition_events), 2)
            for transition in transition_events:
                self.assertEqual(transition.payload["policy_version"], "promotion-v1")
                self.assertTrue(transition.payload["reason"])
                self.assertTrue(transition.payload["evidence_refs"])
                self.assertIn("old_version", transition.payload)
                self.assertIn("new_version", transition.payload)
                self.assertTrue(transition.payload["idempotency_key"].startswith("sha256:"))
            second = reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2026-08-25T00:00:00+00:00")
            self.assertEqual(second.created_events, 0)

    def test_three_independent_contradictions_deprecate_and_block_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_dir = Path(tmp) / "events"
            positive = "外部書込後は対象範囲を再読込し、数式と値を検証してから次の処理へ進めることで再作業を防止する。別案件でも同じ確認を実施し、結果を記録して再現性を確認し、品質を保つ手順として適用する"
            for index, source, cwd in ((1, "source-a", "cwd-a"), (2, "source-b", "cwd-b")):
                append_event(self._observation(index, positive, source, cwd, "2026-08-01T00:00:00+00:00"), event_dir)
            reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2026-08-25T00:00:00+00:00")
            negative_claims = (
                "外部書込後は対象範囲を再読込してはいけないため、数式と値を検証せずに次の処理へ進める。別案件でもこの手順を避け、品質確認を省略する",
                "外部書込後に対象範囲を読み直すことは禁止し、数式と値の確認を行わず処理を継続する。別案件でも同じ方針を採用し、検証手順を省略する",
                "外部書込後の再読込と数式検証は不要であり、検証を実施してはならない。別案件でも確認を省略し、品質確認なしで処理を続ける",
            )
            for index, source, cwd, claim in ((3, "source-c", "cwd-c", negative_claims[0]), (4, "source-d", "cwd-d", negative_claims[1]), (5, "source-e", "cwd-e", negative_claims[2])):
                append_event(self._observation(index, claim, source, cwd, "2026-08-26T00:00:00+00:00"), event_dir)
            deprecated = reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2026-08-26T00:00:00+00:00")
            self.assertGreaterEqual(deprecated.deprecation_events, 1)
            blocked = reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2027-08-27T00:00:00+00:00")
            self.assertEqual(blocked.tombstone_events, 0)

    def test_deprecated_pattern_without_unresolved_contradiction_is_tombstoned(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_dir = Path(tmp) / "events"
            claim = "検証済みの再利用可能な判断ルールを、根拠と適用範囲を付けて保存し、後続案件で同じ条件に再利用する"
            observation = self._observation(1, claim, "source-a", "cwd-a", "2026-01-01T00:00:00+00:00")
            append_event(observation, event_dir)
            cluster_id = "cluster_" + content_fingerprint(claim)[:20]
            pattern_id = "pat_retained"
            append_event(Event.create("pattern.promoted", "2026-01-02T00:00:00+00:00", "test", "machine", {"cluster_id": cluster_id, "pattern_id": pattern_id, "rule": claim, "classification": "private-reusable"}, event_id="evt_promoted_retained"), event_dir)
            append_event(Event.create("pattern.deprecated", "2026-01-03T00:00:00+00:00", "test", "machine", {"cluster_id": cluster_id, "pattern_id": pattern_id, "reason": "STALE"}, event_id="evt_deprecated_retained"), event_dir)
            result = reconcile_lifecycle(list(iter_events(event_dir)), event_dir, now_utc="2027-01-05T00:00:00+00:00")
            self.assertEqual(result.tombstone_events, 1)


if __name__ == "__main__":
    unittest.main()

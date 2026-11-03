import importlib
import hashlib
import tempfile
import unittest
from pathlib import Path

from ei.journal import iter_events
from ei.models import Event
from ei.reconciliation import reconcile_lifecycle


RULE = "異なる案件でも再利用する前に適用範囲と保存された根拠を確認し、条件が合わない場合は以前の方法をそのまま使わない。" * 2


def candidate_observation(identity, scope="scope:a", benefit=""):
    return Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                        {"observation_id": "obs_" + identity, "title": "根拠確認", "claim": RULE,
                         "provenance_key": "sha256:" + hashlib.sha256(identity.encode()).hexdigest(),
                         "cwd_fingerprint": "sha256:" + hashlib.sha256(scope.encode()).hexdigest(),
                         "domain": "general", "benefit": benefit, "classification": "private-reusable"},
                        event_id="evt_" + identity)


class CandidateDiagnosticsTests(unittest.TestCase):
    def diagnostics(self, events):
        module = importlib.import_module("ei.reconciliation")
        self.assertTrue(hasattr(module, "candidate_diagnostics"), "read-only candidate diagnostics are missing")
        return module.candidate_diagnostics(events)

    def candidate_events(self, root):
        events = [candidate_observation("one"), candidate_observation("two")]
        reconcile_lifecycle(events, root, now_utc="2026-01-02T00:00:00+00:00")
        return events + list(iter_events(root))

    def test_missing_scope_and_benefit_are_explained_without_mutating_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events = self.candidate_events(root)
            before = [e.to_dict() for e in events]
            files = {p.name: p.read_bytes() for p in root.glob("*.json")}
            result = self.diagnostics(events)
            self.assertEqual(len(result), 1)
            self.assertFalse(result[0]["eligible"])
            self.assertEqual(result[0]["reason_codes"], ["INSUFFICIENT_DISTINCT_SCOPE", "INSUFFICIENT_BENEFIT_EVIDENCE"])
            self.assertEqual(result[0]["provenance_count"], 2)
            self.assertEqual([e.to_dict() for e in events], before)
            self.assertEqual({p.name: p.read_bytes() for p in root.glob("*.json")}, files)
            self.assertNotIn("rule", result[0])

    def test_eligible_means_pending_not_already_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events = self.candidate_events(root)
            events.append(candidate_observation("three", "scope:b", "reduced_rework"))
            row = self.diagnostics(events)[0]
            self.assertTrue(row["eligible"])
            self.assertEqual(row["reason_codes"], [])
            result = reconcile_lifecycle(events, root, now_utc="2026-01-03T00:00:00+00:00")
            self.assertEqual(result.promotion_events, 1)
            all_events = {e.event_id: e for e in [*events, *iter_events(root)]}
            self.assertEqual(self.diagnostics(all_events.values()), ())
            self.assertEqual(reconcile_lifecycle(all_events.values(), root,
                             now_utc="2026-01-04T00:00:00+00:00").promotion_events, 0)

    def test_orphan_candidate_is_unknown_not_silently_omitted(self):
        event = Event.create("pattern.candidate_created", "2026-01-01T00:00:00+00:00",
                             "test", "test", {"pattern_id": "pat_orphan", "cluster_id": "cluster_orphan"},
                             event_id="evt_orphan")
        result = self.diagnostics([event])
        self.assertEqual(result[0]["reason_codes"], ["CANDIDATE_EVIDENCE_UNAVAILABLE"])
        self.assertFalse(result[0]["eligible"])
        self.assertEqual(self.diagnostics([]), ())


if __name__ == "__main__":
    unittest.main()

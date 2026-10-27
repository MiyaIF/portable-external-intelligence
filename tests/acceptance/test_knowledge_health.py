import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ei.index import read_index_items
from ei.journal import append_event, iter_events
from ei.maintainer import run_maintenance
from ei.project import project_events
from ei.projection_state import projection_freshness, projection_source_state
from tests.unit.test_candidate_diagnostics import candidate_observation
from tests.unit.test_maintainer import make_settings


class KnowledgeHealthTests(unittest.TestCase):
    def test_rebuild_preserves_events_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = candidate_observation("one")
            source = append_event(event, root / "events")
            before_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            knowledge = root / "knowledge"
            index = project_events([event], knowledge)
            document = json.loads((knowledge / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(projection_freshness(document["source_state"], projection_source_state([event])), "CURRENT")
            self.assertEqual(document["observation_ids"], ["obs_one"])
            self.assertEqual(list(read_index_items(index)), [])
            files = {p.relative_to(knowledge): p.read_bytes() for p in knowledge.rglob("*") if p.is_file()}
            project_events([event], knowledge)
            self.assertEqual(before_hash, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(files, {p.relative_to(knowledge): p.read_bytes() for p in knowledge.rglob("*") if p.is_file()})

    def test_maintenance_inherits_only_eligible_knowledge_without_duplicate_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(tmp)
            original = [candidate_observation("one"), candidate_observation("two")]
            for event in original:
                append_event(event, settings.paths.event_dir)
            hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in settings.paths.event_dir.glob("*.json")}
            first = run_maintenance(settings, sync_policy="disabled")
            self.assertEqual(first.projection["active_patterns"], 0)
            self.assertEqual(first.projection["freshness"], "CURRENT")
            self.assertEqual(first.projection["candidate_diagnostics"][0]["reason_codes"],
                             ["INSUFFICIENT_DISTINCT_SCOPE", "INSUFFICIENT_BENEFIT_EVIDENCE"])
            append_event(candidate_observation("three", "scope:b", "reduced_rework"), settings.paths.event_dir)
            second = run_maintenance(settings, sync_policy="disabled")
            self.assertEqual(second.lifecycle["promotion_events"], 1)
            self.assertEqual(second.projection["active_patterns"], 1)
            repeated = run_maintenance(settings, sync_policy="disabled")
            self.assertEqual(repeated.lifecycle["promotion_events"], 0)
            self.assertEqual(repeated.ingest_created_events, 0)
            self.assertEqual(repeated.team["status"], "DISABLED")
            for name, digest in hashes.items():
                self.assertEqual(hashlib.sha256((settings.paths.event_dir / name).read_bytes()).hexdigest(), digest)
            index = project_events(iter_events(settings.paths.event_dir), settings.paths.knowledge_dir)
            self.assertEqual(len(list(read_index_items(index))), 1)


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.index import load_recall_index
from ei.models import Event
from ei.project import project_events
from ei.retrieve import RetrievalQuery, search_index_candidates
from ei.sync import build_sync_plan, sync_once


class GlobalScopeBoundaryTests(unittest.TestCase):
    def test_project_reference_is_exact_cwd_personal_only(self):
        cwd_fingerprint = "sha256:" + "9" * 64
        event = Event.create(
            "observation.recorded", "2026-09-01T00:00:00+00:00", "test", "machine",
            {"observation_id": "obs_global_boundary", "claim": "Keep a single-project verification note local.",
             "cwd_fingerprint": cwd_fingerprint, "classification": "private-reusable"},
            event_id="evt_global_boundary",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "global-knowledge"
            project_events([event], root)
            index = load_recall_index(root, root / "index.json")
            exact = RetrievalQuery(prompt="single project verification", cwd_fingerprint=cwd_fingerprint)
            other = RetrievalQuery(prompt=exact.prompt, cwd_fingerprint="sha256:" + "8" * 64)
            self.assertEqual([hit.pattern_id for hit in search_index_candidates(index, exact)], ["obs_global_boundary"])
            self.assertEqual(search_index_candidates(index, other), [])
            self.assertEqual(search_index_candidates(index, exact, knowledge_scope="team"), [])

    def test_unrelated_external_workspace_is_never_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "engine-repo"
            repo.mkdir()
            unrelated = root / "unrelated-workspace"
            unrelated.mkdir()
            (unrelated / "secret-client-data.md").write_text("client confidential", encoding="utf-8")
            self.assertFalse(build_sync_plan(["?? " + str(unrelated / "secret-client-data.md")]).allowed)
            self.assertFalse(list(repo.rglob("*")))

    def test_sync_plan_accepts_only_engine_roots(self):
        self.assertFalse(build_sync_plan(["?? .env"]).allowed)
        self.assertFalse(build_sync_plan(["?? runtime/spool/item.json"]).allowed)
        self.assertTrue(build_sync_plan(["?? events/2026/08/event.json"]).allowed)

    def test_engine_sync_does_not_scan_sibling_workspaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "unrelated-workspace"
            outside.mkdir()
            marker = "client-marker-should-not-be-read"
            (outside / "notes.md").write_text(marker, encoding="utf-8")
            self.assertNotIn(marker, "\n".join(path.name for path in repo.iterdir()))

if __name__ == "__main__":
    unittest.main()

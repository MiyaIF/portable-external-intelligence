import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ei.models import Event
from ei.project import project_events


class ProjectionTests(unittest.TestCase):
    def test_semantically_identical_crlf_projection_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([], root)
            target = root / "index.md"
            crlf = target.read_bytes().replace(b"\n", b"\r\n")
            target.write_bytes(crlf)
            before_mtime = target.stat().st_mtime_ns

            project_events([], root)

            self.assertEqual(target.read_bytes(), crlf)
            self.assertEqual(target.stat().st_mtime_ns, before_mtime)

    def test_rebuild_removes_projection_files_that_are_no_longer_generated(self):
        observation = Event.create(
            "observation.recorded",
            "2026-08-25T00:00:00+00:00",
            "test",
            "machine",
            {
                "observation_id": "obs_stale",
                "title": "stale",
                "claim": "remove stale projection",
                "classification": "private-reusable",
            },
            event_id="evt_stale",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events([observation], root)
            stale = root / "memories" / "obs_stale.md"
            self.assertTrue(stale.exists())

            project_events([], root)

            self.assertFalse(stale.exists())

    def test_rebuild_is_byte_identical_and_tombstone_is_archived(self):
        events = [
            Event.create(
                "observation.recorded",
                "2026-08-25T00:00:00+00:00",
                "test",
                "machine",
                {
                    "observation_id": "obs_1",
                    "title": "再読込",
                    "claim": "書込後は再読込して検証する",
                    "domain": "spreadsheet",
                    "cwd_fingerprint": "cwd:a",
                    "provenance_key": "source:a",
                    "outcome_status": "success",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "source_hash": "hash:a",
                },
                event_id="evt_observation_1",
            ),
            Event.create(
                "pattern.promoted",
                "2026-08-25T00:01:00+00:00",
                "test",
                "machine",
                {
                    "pattern_id": "pat_1",
                    "cluster_id": "cluster_1",
                    "rule": "再利用ルール",
                    "provenances": ["source:a", "source:b"],
                    "scopes": ["cwd:a", "cwd:b"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                },
                event_id="evt_pattern_1",
            ),
            Event.create(
                "pattern.tombstoned",
                "2026-08-25T00:02:00+00:00",
                "test",
                "machine",
                {"pattern_id": "pat_1", "reason": "SUPERSEDED_INACTIVE"},
                event_id="evt_tombstone_1",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            first = project_events(events, root)
            self.assertTrue((root / "rules" / "always-on.md").exists())
            self.assertTrue((root / "archive" / "pat_1.md").exists())
            index_document = json.loads((root / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index_document["schema_version"], 2)
            self.assertIn("pat_1", index_document["archive_pattern_ids"])
            first_bytes = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            second = project_events(events, root)
            second_bytes = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)
            self.assertEqual(first_bytes, second_bytes)
            self.assertNotIn("pat_1", (root / "index.md").read_text(encoding="utf-8").split("## Active")[1].split("##")[0])
            self.assertIn("pat_1", (root / "index.md").read_text(encoding="utf-8"))
            self.assertTrue((root / "archive" / "pat_1.md").exists())


if __name__ == "__main__":
    unittest.main()

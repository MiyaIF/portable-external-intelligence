import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ei.models import Event
from ei.project import project_events
from ei.index import read_index_items


class ProjectionTests(unittest.TestCase):
    def test_index_links_to_readable_details_and_keeps_legacy_mirrors(self):
        event = Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"observation_id": "obs_guide", "title": "確認の順序",
                              "claim": "変更後に保存結果を確認する", "classification": "private-reusable"},
                             event_id="evt_guide")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([event], root)
            text = (root / "index.md").read_text(encoding="utf-8")
            self.assertIn("[確認の順序](observations/obs_guide.md)", text)
            self.assertIn("有効化済み: 0", text)
            self.assertIn("生成時点", text)
            detail = (root / "observations/obs_guide.md").read_text(encoding="utf-8")
            self.assertIn("2026-01-01T00:00:00+00:00", detail)
            self.assertEqual((root / "memories/obs_guide.md").read_bytes(),
                             (root / "observations/obs_guide.md").read_bytes())

    def test_candidate_explanation_does_not_become_retrieved_rule(self):
        rule = "実際の適用根拠を確認する"
        event = Event.create("pattern.candidate_created", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"pattern_id": "pat_guide", "cluster_id": "cluster_guide", "rule": rule,
                              "classification": "private-reusable"}, event_id="evt_guide")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = project_events([event], root)
            detail = (root / "candidates/pat_guide.md").read_text(encoding="utf-8")
            self.assertIn("CANDIDATE_EVIDENCE_UNAVAILABLE", detail)
            self.assertIn("根拠を復元できない", detail)
            items = list(read_index_items(index, ["pat_guide"]))
            self.assertEqual(items[0]["rule"], rule)

    def test_markdown_title_cannot_inject_an_image_or_extra_list_entry(self):
        event = Event.create("observation.recorded", "2026-01-01T00:00:00+00:00", "test", "test",
                             {"observation_id": "obs_label", "title": "![image](https://example.invalid)\n- extra",
                              "claim": "確認", "classification": "private-reusable"}, event_id="evt_label")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events([event], root)
            text = (root / "index.md").read_text(encoding="utf-8")
            self.assertNotIn("![image]", text)
            self.assertNotIn("\n- extra", text)
            self.assertIn("(observations/obs_label.md)", text)

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

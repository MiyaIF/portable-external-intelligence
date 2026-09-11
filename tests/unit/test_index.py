import json
import tempfile
import unittest
from pathlib import Path

from ei.index import build_index, read_index_item
from ei.models import Event
from ei.project import project_events
from ei.retrieve import RetrievalQuery, search_index


class IndexTests(unittest.TestCase):
    def _events(self):
        return [
            Event.create(
                "pattern.promoted",
                "2026-08-25T00:00:00+00:00",
                "test",
                "machine",
                {
                    "pattern_id": "pat_formula",
                    "cluster_id": "cluster_formula",
                    "rule": "書込後は対象範囲を再読込し数式と値を検証する",
                    "provenances": ["source:a", "source:b"],
                    "scopes": ["cwd:a", "cwd:b"],
                    "applicability": ["spreadsheet"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                },
                event_id="evt_pattern_formula",
            ),
        ]

    def test_build_and_read_index_is_immutable_handle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index = build_index(root, root / "index.json")
            self.assertEqual(index.schema_version, "2")
            self.assertEqual(index.item_count, 1)
            item = read_index_item(index, "pat_formula")
            self.assertEqual(item["rule"], "書込後は対象範囲を再読込し数式と値を検証する")
            self.assertEqual(item["applicability"], ["spreadsheet"])
            hits = search_index(index, RetrievalQuery(prompt="再読込 数式", domain="spreadsheet"))
            self.assertEqual([hit.pattern_id for hit in hits], ["pat_formula"])

    def test_corrupt_projection_is_rejected_by_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index_document = json.loads((root / "index.json").read_text(encoding="utf-8"))
            target = root / "rules" / "pat_formula.md"
            target.write_text(target.read_text(encoding="utf-8") + "改ざん\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "INDEX_FILE_HASH_MISMATCH"):
                build_index(root, root / "index.json")
            index_document["files"] = index_document["files"]

    def test_item_id_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "knowledge"
            project_events(self._events(), root)
            index = build_index(root, root / "index.json")
            with self.assertRaisesRegex(ValueError, "INDEX_ITEM_ID_INVALID"):
                read_index_item(index, "../secret")


if __name__ == "__main__":
    unittest.main()
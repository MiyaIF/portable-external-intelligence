import json
import tempfile
import unittest
from pathlib import Path

from ei.index import build_index, read_index_item
from ei.models import Event
from ei.project import project_events
from ei.retrieve import RetrievalQuery, search_index


class IndexTests(unittest.TestCase):
    def test_bounded_index_rejects_knowledge_root_alias_before_resolution(self):
        import os
        import subprocess
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside, alias = root / "knowledge", root / "alias"
            project_events(self._events(), outside, budget=OperationBudget(10000))
            if os.name == "nt":
                result = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(outside)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0)
            else:
                alias.symlink_to(outside, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, "UNSAFE_REPARSE_POINT"):
                    build_index(alias, alias / "index.json", budget=OperationBudget(5000))
            finally:
                alias.rmdir() if os.name == "nt" else alias.unlink()

    def test_generation_handle_rechecks_bound_index_bytes(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            index = project_events(self._events(), Path(tmp), budget=OperationBudget(10000))
            document = json.loads(index.index_path.read_bytes())
            document["always_on_chars"] = 0
            index.index_path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "PROJECTION_MANIFEST_MISMATCH"):
                read_index_item(index, "pat_formula")

    def test_zero_budget_does_not_read_item(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            index = project_events(self._events(), Path(tmp))
            with self.assertRaises(TimeoutError):
                read_index_item(index, "pat_formula", budget=OperationBudget(0))

    def test_generation_path_must_match_its_manifest_identity(self):
        from ei.operation_runtime import OperationBudget
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            index = project_events(self._events(), root, budget=OperationBudget(10000))
            replacement = index.index_path.parent.with_name("0" * 64)
            index.index_path.parent.rename(replacement)
            path = root / "index.json"
            document = json.loads(path.read_text())
            document["projection_generation"]["path"] = replacement.relative_to(root).as_posix()
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_INVALID"):
                build_index(root, path)

    def test_read_file_rejects_same_path_replacement_during_read(self):
        from ei.index import _read_projection_bytes
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            path.write_bytes(b"first")
            real_fstat = os.fstat
            def changed(fd):
                result = real_fstat(fd)
                path.write_bytes(b"different length")
                return result
            with patch("ei.index.os.fstat", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "INDEX_FILE_CHANGED"):
                    _read_projection_bytes(path)

    def test_present_null_generation_pointer_does_not_fallback_to_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events(self._events(), root)
            path = root / "index.json"
            document = json.loads(path.read_text())
            document["projection_generation"] = None
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "INDEX_GENERATION_INVALID"):
                build_index(root, path)

    def test_budget_exhaustion_is_not_reported_as_corruption(self):
        from ei.operation_runtime import OperationBudget
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_events(self._events(), root)
            with patch("ei.index._read_projection_bytes", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")):
                with self.assertRaises(TimeoutError):
                    build_index(root, root / "index.json", budget=OperationBudget(1000))

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
